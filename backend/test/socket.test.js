const test = require('node:test');
const assert = require('node:assert/strict');
const { once } = require('node:events');
const jwt = require('jsonwebtoken');
const { io: createSocketClient } = require('socket.io-client');

require('dotenv').config();
process.env.JWT_SECRET = process.env.JWT_SECRET ||
    require('node:crypto').randomBytes(32).toString('hex');

const redisClient = require('../config/redis');
const pool = require('../config/db');
const originalGet = redisClient.get;
const { startCaepSubscriber } = require('../services/caepSubscriber');
const { enforceRiskPolicy } = require('../services/enforcementEngine');
const { emitThreatEvent } = require('../services/socketService');
const { io, server } = require('../server');

let serverUrl;
const originalExists = redisClient.exists;
const originalIsOpen = Object.getOwnPropertyDescriptor(redisClient, 'isOpen');

function createToken(jti, userId = `user-${jti}`) {
    return jwt.sign({ jti, userId }, process.env.JWT_SECRET, { expiresIn: '5m' });
}

function connectSocket(token) {
    return new Promise((resolve, reject) => {
        const socket = createSocketClient(serverUrl, {
            auth: token ? { token } : {},
            transports: ['websocket'],
            reconnection: false,
            timeout: 2000
        });
        socket.once('connect', () => resolve(socket));
        socket.once('connect_error', (error) => {
            socket.close();
            reject(error);
        });
    });
}

test.before(async () => {
    Object.defineProperty(redisClient, 'isOpen', {
        configurable: true,
        value: true
    });
    redisClient.exists = async () => 0;
    redisClient.get = async (key) => JSON.stringify({
        userId: `user-${key.slice('session:'.length)}`,
        isActive: true
    });

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    serverUrl = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
    redisClient.exists = originalExists;
    redisClient.get = originalGet;
    if (originalIsOpen) {
        Object.defineProperty(redisClient, 'isOpen', originalIsOpen);
    } else {
        delete redisClient.isOpen;
    }
    await new Promise((resolve) => io.close(resolve));
});

test('Socket.IO shares the HTTP server and existing Express routes remain available', async () => {
    assert.equal(typeof io.emit, 'function');
    const response = await fetch(serverUrl);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { message: 'ZeroPulse API is running' });
});

test('Socket.IO rejects missing and invalid credentials', async () => {
    await assert.rejects(connectSocket(null), /Unauthorized/);
    await assert.rejects(connectSocket('not-a-valid-jwt'), /Unauthorized/);
    await assert.rejects(
        connectSocket(jwt.sign(
            { jti: 'expired-session', userId: 'expired-user' },
            process.env.JWT_SECRET,
            { expiresIn: -1 }
        )),
        /Unauthorized/
    );

    redisClient.exists = async () => 1;
    try {
        await assert.rejects(connectSocket(createToken('revoked-socket-session')), /Unauthorized/);
    } finally {
        redisClient.exists = async () => 0;
    }
});

test('authenticated socket joins only its server-derived session room', async () => {
    const jti = 'socket-session-one';
    const socket = await connectSocket(createToken(jti));
    try {
        const serverSocket = io.sockets.sockets.get(socket.id);
        assert.ok(serverSocket);
        assert.equal(serverSocket.rooms.has(`session:${jti}`), true);
        assert.equal(serverSocket.rooms.size, 2);
        socket.emit('join_session', 'another-session');
        await new Promise((resolve) => setTimeout(resolve, 20));
        assert.equal(serverSocket.rooms.has('session:another-session'), false);
    } finally {
        socket.disconnect();
    }
});

test('Redis subscriber broadcasts a processed CAEP threat event without raw details', async () => {
    const subscriber = {
        on() {},
        async connect() {},
        async subscribe(channel, handler) {
            assert.equal(channel, 'caep:security_events');
            this.handler = handler;
        }
    };
    const originalDuplicate = redisClient.duplicate;
    const originalLog = console.log;
    const logOutput = [];
    redisClient.duplicate = () => subscriber;
    const socket = await connectSocket(createToken('threat-session'));
    try {
        const received = once(socket, 'threat_event');
        await startCaepSubscriber();
        console.log = (...args) => {
            logOutput.push(args.map((value) =>
                typeof value === 'string' ? value : JSON.stringify(value)
            ).join(' '));
        };
        try {
            await subscriber.handler(JSON.stringify({
                specversion: '1.0',
                event_type: 'https://schemas.openid.net/secevent/caep/event-type/VPN_DETECTED',
                jti: 'event-vpn-test',
                event_timestamp: Math.floor(Date.now() / 1000),
                subject: { format: 'complex', jti: 'threat-session' },
                event_data: {
                    type: 'VPN_DETECTED',
                    source: 'test',
                    simulated: true,
                    privateDetail: 'must-not-be-broadcast'
                }
            }));
        } finally {
            console.log = originalLog;
        }

        const [payload] = await received;
        assert.equal(payload.eventId, 'event-vpn-test');
        assert.equal(payload.type, 'VPN_DETECTED');
        assert.equal(payload.severity, 'medium');
        assert.equal(payload.riskScore, 55);
        assert.equal(payload.processingStatus, 'allowed');
        assert.equal(Object.hasOwn(payload, 'privateDetail'), false);
        assert.equal(logOutput.join(' ').includes('must-not-be-broadcast'), false);
    } finally {
        console.log = originalLog;
        socket.disconnect();
        redisClient.duplicate = originalDuplicate;
    }
});

test('successful revocation notifies only the affected session room', async () => {
    const originalQuery = pool.query;
    const originalSetEx = redisClient.setEx;
    const originalRedisIsOpen = Object.getOwnPropertyDescriptor(redisClient, 'isOpen');
    const first = await connectSocket(createToken('revoked-session'));
    const second = await connectSocket(createToken('other-session'));
    Object.defineProperty(redisClient, 'isOpen', {
        configurable: true,
        value: true
    });
    pool.query = async (sql) => sql.includes('SELECT expires_at')
        ? { rows: [{ expires_at: new Date(Date.now() + 300000) }] }
        : { rowCount: 1 };
    redisClient.setEx = async () => 'OK';

    try {
        const notification = once(first, 'session_revoked');
        let otherSessionNotified = false;
        second.once('session_revoked', () => { otherSessionNotified = true; });

        const result = await enforceRiskPolicy({
            subject: { jti: 'revoked-session' },
            details: { type: 'TOKEN_HIJACKED' }
        }, 95);
        const [payload] = await notification;
        await new Promise((resolve) => setTimeout(resolve, 50));

        assert.equal(result.revoked, true);
        assert.equal(payload.action, 'REVOKE');
        assert.equal(payload.sessionRef, require('node:crypto')
            .createHash('sha256').update('revoked-session').digest('hex').slice(0, 16));
        assert.equal(otherSessionNotified, false);
    } finally {
        first.disconnect();
        second.disconnect();
        pool.query = originalQuery;
        redisClient.setEx = originalSetEx;
        if (originalRedisIsOpen) {
            Object.defineProperty(redisClient, 'isOpen', originalRedisIsOpen);
        } else {
            delete redisClient.isOpen;
        }
    }
});

test('threat notifications are broadcast only to authenticated sockets', async () => {
    const socket = await connectSocket(createToken('broadcast-session'));
    try {
        const received = once(socket, 'threat_event');
        assert.equal(emitThreatEvent({
            eventId: 'broadcast-test',
            type: 'IMPOSSIBLE_TRAVEL',
            timestamp: Math.floor(Date.now() / 1000),
            subject: { jti: 'broadcast-session' }
        }, 90, { revoked: false }), true);
        const [payload] = await received;
        assert.equal(payload.severity, 'high');
        assert.equal(payload.processingStatus, 'not_revoked');
    } finally {
        socket.disconnect();
    }
});
