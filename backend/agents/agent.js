// backend/agents/agent.js

'use strict';

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

const redisClient = require('../config/redis');
const { createCaepEvent } = require('../utils/caepEventBuilder');
// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const POLL_INTERVAL_MS = 5000;
const REDIS_CHANNEL = 'caep:security_events';
const SESSION_JTI = process.env.SESSION_JTI || null;

// Platform-specific command definitions.
// To add Linux/macOS support later, add a new key here (e.g. 'linux', 'darwin')
// and implement the matching parser functions below.
const PLATFORM_COMMANDS = {
  win32: {
    firewall: 'netsh advfirewall show allprofiles',
    ipconfig: 'ipconfig /all',
    tasklist: 'tasklist',
  },
};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

// Holds the last known state so we only emit events on real changes.
let previousState = {
  firewall: null,       // e.g. { Domain: 'ON', Private: 'ON', Public: 'OFF' }
  ipAddress: null,       // e.g. '192.168.1.20'
  gateway: null,         // e.g. '192.168.1.1'
  processCount: null,    // e.g. 142
};

let pollTimer = null;

// ---------------------------------------------------------------------------
// OS command helpers (Windows implementations)
// ---------------------------------------------------------------------------

/**
 * Runs `netsh advfirewall show allprofiles` and parses ON/OFF state
 * per profile (Domain, Private, Public).
 */
async function getFirewallStatus() {
  const cmd = PLATFORM_COMMANDS.win32.firewall;
  const { stdout } = await execAsync(cmd);

  const profiles = {};
  let currentProfile = null;

  // netsh output looks like:
  // Domain Profile Settings:
  // ----------------------------------------------------------------------
  // State                                 ON
  const profileHeaderRegex = /^\s*(Domain|Private|Public) Profile Settings:/i;
  const stateLineRegex = /^\s*State\s+(ON|OFF)/i;

  stdout.split(/\r?\n/).forEach((line) => {
    const headerMatch = line.match(profileHeaderRegex);
    if (headerMatch) {
      currentProfile = headerMatch[1];
      return;
    }
    const stateMatch = line.match(stateLineRegex);
    if (stateMatch && currentProfile) {
      profiles[currentProfile] = stateMatch[1].toUpperCase();
      currentProfile = null; // consumed
    }
  });

  return profiles; // { Domain: 'ON', Private: 'ON', Public: 'OFF' }
}

/**
 * Runs `ipconfig /all` and extracts the first non-loopback IPv4 address
 * and its associated default gateway.
 */
async function getNetworkInfo() {
  const cmd = PLATFORM_COMMANDS.win32.ipconfig;
  const { stdout } = await execAsync(cmd);

  const blocks = stdout.split(/\r?\n\r?\n/); // adapter blocks are blank-line separated

  let ipAddress = null;
  let gateway = null;

  for (const block of blocks) {
    const ipMatch = block.match(/IPv4 Address[.\s]*:\s*([\d.]+)/i);
    const gwMatch = block.match(/Default Gateway[.\s]*:\s*([\d.]+)/i);

    // Only accept a block if it has both an IP and a non-empty gateway —
    // this filters out virtual adapters / disconnected interfaces.
    if (ipMatch && gwMatch && gwMatch[1]) {
      ipAddress = ipMatch[1];
      gateway = gwMatch[1];
      break;
    }
  }

  return { ipAddress, gateway };
}

/**
 * Runs `tasklist` and returns the number of running processes.
 * (Count only — we do not enumerate or act on individual processes here,
 * keeping this strictly a monitoring signal.)
 */
async function getProcessCount() {
  const cmd = PLATFORM_COMMANDS.win32.tasklist;
  const { stdout } = await execAsync(cmd);

  // tasklist output has a header + separator line, then one line per process.
  const lines = stdout
    .split(/\r?\n/)
    .filter((line) => line.trim().length > 0);

  // Skip header (2 lines: column titles + '===' separator)
  const processLines = lines.slice(2);
  return processLines.length;
}

// ---------------------------------------------------------------------------
// State comparison
// ---------------------------------------------------------------------------

/**
 * Compares two firewall status objects, returns array of change descriptions.
 */
function diffFirewall(prev, curr) {
  if (!prev) return [];
  const changes = [];
  for (const profile of Object.keys(curr)) {
    if (prev[profile] !== curr[profile]) {
      changes.push({
        type: 'FIREWALL_STATE_CHANGE',
        profile,
        from: prev[profile] || 'UNKNOWN',
        to: curr[profile],
      });
    }
  }
  return changes;
}

function diffNetwork(prev, currIp, currGw) {
  const changes = [];
  if (prev.ipAddress !== null && prev.ipAddress !== currIp) {
    changes.push({
      type: 'IP_ADDRESS_CHANGE',
      from: prev.ipAddress,
      to: currIp,
    });
  }
  if (prev.gateway !== null && prev.gateway !== currGw) {
    changes.push({
      type: 'GATEWAY_CHANGE',
      from: prev.gateway,
      to: currGw,
    });
  }
  return changes;
}

function diffProcessCount(prev, curr) {
  if (prev === null || prev === curr) return [];
  return [
    {
      type: 'PROCESS_COUNT_CHANGE',
      from: prev,
      to: curr,
    },
  ];
}

// ---------------------------------------------------------------------------
// Redis publishing
// ---------------------------------------------------------------------------

async function publishSecurityEvent(event) {
  const payload = JSON.stringify({
    specversion: '1.0',

    event_type:
        `https://schemas.openid.net/secevent/caep/event-type/${event.type}`,

    jti: `evt_${Date.now()}`,

    event_timestamp: Math.floor(Date.now() / 1000),

    subject: {
        format: 'complex',
        user: 'unknown',
        session: SESSION_JTI || 'unknown',
        jti: SESSION_JTI || 'unknown'
    },

    event_data: {
        ...event,
        source: 'ZeroPulse-EndpointAgent',
        platform: process.platform
    }
});

  try {
    await redisClient.publish(REDIS_CHANNEL, payload);
    console.log(`[ZeroPulse] Published event -> ${REDIS_CHANNEL}:`, event.type);
  } catch (err) {
    console.error('[ZeroPulse] Failed to publish event to Redis:', err.message);
  }
}

// ---------------------------------------------------------------------------
// Main poll cycle
// ---------------------------------------------------------------------------

async function pollOnce() {
  try {
    const firewall = await getFirewallStatus();
    console.log('[ZeroPulse] Firewall status:', firewall);

    const { ipAddress, gateway } = await getNetworkInfo();
    console.log(`[ZeroPulse] IP Address: ${ipAddress}`);
    console.log(`[ZeroPulse] Gateway: ${gateway}`);

    const processCount = await getProcessCount();
    console.log(`[ZeroPulse] Process count: ${processCount}`);

    // Build the diff against previous state
    const changes = [
      ...diffFirewall(previousState.firewall, firewall),
      ...diffNetwork(previousState, ipAddress, gateway),
      ...diffProcessCount(previousState.processCount, processCount),
    ];

    if (changes.length > 0) {
      console.log(`[ZeroPulse] Detected ${changes.length} security-relevant change(s):`, changes);
      for (const change of changes) {
        await publishSecurityEvent(change);
      }
    }

    // Update state for next cycle
    previousState = {
      firewall,
      ipAddress,
      gateway,
      processCount,
    };
  } catch (err) {
    console.error('[ZeroPulse] Error during poll cycle:', err.message);
  }
}

// ---------------------------------------------------------------------------
// Agent lifecycle
// ---------------------------------------------------------------------------

async function startAgent() {
  console.log('[ZeroPulse] Endpoint Monitoring Agent starting...');
  console.log(`[ZeroPulse] Platform detected: ${process.platform}`);

  if (!PLATFORM_COMMANDS[process.platform]) {
    console.error(
      `[ZeroPulse] Unsupported platform "${process.platform}". Only win32 is implemented currently.`
    );
    process.exit(1);
  }

  // Connect to Redis before starting the poll loop
try {
  if (!redisClient.isOpen) {
    await redisClient.connect();
  }

  await redisClient.ping();

  console.log('[ZeroPulse] Redis connection established.');
} catch (err) {
  console.error('[ZeroPulse] Redis connection failed:', err.message);
  process.exit(1);
}

  console.log('[ZeroPulse] Agent started. Polling every 5 seconds.');

  // Run immediately, then on interval
  await pollOnce();
  pollTimer = setInterval(pollOnce, POLL_INTERVAL_MS);
}

function stopAgent() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
  console.log('[ZeroPulse] Agent stopped.');
}

// Graceful shutdown
process.on('SIGINT', () => {
  stopAgent();
  process.exit(0);
});
process.on('SIGTERM', () => {
  stopAgent();
  process.exit(0);
});

// Allow standalone execution: `node agent.js`
if (require.main === module) {
  startAgent();
}

module.exports = {
  startAgent,
  stopAgent,
  pollOnce,
  getFirewallStatus,
  getNetworkInfo,
  getProcessCount,
};