'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { createClient } = require('redis');
const { validateEnv } = require('../config/validateEnv');
const { BENCHMARK_RESULTS_CHANNEL } = require('../services/benchmarkTelemetry');

const DEFAULT_BENCHMARK_EMAIL = 'zeropulse-benchmark@example.invalid';

function loadBenchmarkEnvironment() {
    require('dotenv').config({
        path: path.resolve(__dirname, '../../.env'),
        quiet: true
    });
    require('dotenv').config({
        path: path.resolve(__dirname, '../.env'),
        quiet: true
    });
}

function parseInteger(value, name, { min = 1, max = 1000000 } = {}) {
    if (!/^\d+$/.test(String(value))) {
        throw new Error(`${name} must be an integer.`);
    }
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
        throw new Error(`${name} must be between ${min} and ${max}.`);
    }
    return parsed;
}

function parseOptionalSeconds(value, name, maximum = 3600) {
    if (value === undefined || value === null || value === '') {
        return null;
    }
    return parseInteger(value, name, { min: 1, max: maximum });
}

function parseApiBenchmarkOptions(args, env = process.env) {
    const options = {};
    for (let index = 0; index < args.length; index += 1) {
        const argument = args[index];
        if (argument === '--safe-report') {
            options.safeReport = true;
            continue;
        }
        const names = {
            '--requests': 'requests',
            '--concurrency': 'concurrency',
            '--duration': 'durationSeconds'
        };
        if (names[argument]) {
            const value = args[index + 1];
            if (value === undefined) {
                throw new Error(`${argument} requires a value.`);
            }
            options[names[argument]] = value;
            index += 1;
            continue;
        }
        throw new Error(`Unknown benchmark option: ${argument}`);
    }

    const requestsValue = options.requests === undefined
        ? (env.BENCHMARK_REQUESTS === undefined ? '1000' : env.BENCHMARK_REQUESTS)
        : options.requests;
    const requests = requestsValue === '' || String(requestsValue) === '0'
        ? null
        : parseInteger(requestsValue, 'BENCHMARK_REQUESTS', { max: 1000000 });
    const concurrency = parseInteger(
        options.concurrency === undefined
            ? (env.BENCHMARK_CONCURRENCY || '100')
            : options.concurrency,
        'BENCHMARK_CONCURRENCY',
        { max: 1000 }
    );
    const durationSeconds = parseOptionalSeconds(
        options.durationSeconds === undefined
            ? env.BENCHMARK_DURATION_SECONDS
            : options.durationSeconds,
        'BENCHMARK_DURATION_SECONDS'
    );

    if (requests === null && durationSeconds === null) {
        throw new Error('Configure a positive request count or duration.');
    }

    return {
        requests,
        concurrency,
        durationSeconds,
        safeReport: options.safeReport === true
    };
}

function parseRevocationBenchmarkOptions(args, env = process.env) {
    let iterations = env.BENCHMARK_REVOCATION_TESTS || '20';
    let safeReport = false;
    for (let index = 0; index < args.length; index += 1) {
        if (args[index] === '--safe-report') {
            safeReport = true;
        } else if (args[index] === '--iterations') {
            if (args[index + 1] === undefined) {
                throw new Error('--iterations requires a value.');
            }
            iterations = args[index + 1];
            index += 1;
        } else {
            throw new Error(`Unknown benchmark option: ${args[index]}`);
        }
    }

    return {
        iterations: parseInteger(iterations, 'BENCHMARK_REVOCATION_TESTS', {
            min: 20,
            max: 50
        }),
        timeoutMs: parseInteger(
            env.BENCHMARK_TIMEOUT_MS || '10000',
            'BENCHMARK_TIMEOUT_MS',
            { min: 1000, max: 60000 }
        ),
        sessionTtlSeconds: parseInteger(
            env.BENCHMARK_SESSION_TTL_SECONDS || '1800',
            'BENCHMARK_SESSION_TTL_SECONDS',
            { min: 60, max: 86400 }
        ),
        safeReport
    };
}

function assertDedicatedBenchmarkEmail(email) {
    const normalizedEmail = String(email || '').trim().toLowerCase();
    if (!/^zeropulse-benchmark(?:[+._-][a-z0-9._-]+)?@example\.invalid$/.test(normalizedEmail)) {
        throw new Error(
            'Benchmarking requires a dedicated zeropulse-benchmark*@example.invalid account.'
        );
    }
    return normalizedEmail;
}

function getBenchmarkUserConfiguration(env = process.env) {
    const email = assertDedicatedBenchmarkEmail(
        env.BENCHMARK_USER_EMAIL || DEFAULT_BENCHMARK_EMAIL
    );
    const userId = String(env.BENCHMARK_USER_ID || '');
    if (!/^\d+$/.test(userId)) {
        throw new Error('BENCHMARK_USER_ID must be the dedicated benchmark user ID.');
    }
    return { userId, email };
}

function getOrigin(value, name, fallback) {
    let url;
    try {
        url = new URL(value || fallback);
    } catch {
        throw new Error(`${name} must be a valid HTTP(S) origin.`);
    }
    if (
        !['http:', 'https:'].includes(url.protocol) ||
        !url.hostname ||
        url.username ||
        url.password ||
        (url.pathname !== '/' && url.pathname !== '') ||
        url.search ||
        url.hash
    ) {
        throw new Error(`${name} must be an HTTP(S) origin without credentials or a path.`);
    }
    return url.origin;
}

function getApiOrigin(env = process.env) {
    return getOrigin(
        env.BENCHMARK_API_BASE_URL,
        'BENCHMARK_API_BASE_URL',
        'http://backend:5000'
    );
}

function getSocketOrigin(env = process.env) {
    return getOrigin(
        env.BENCHMARK_SOCKET_URL,
        'BENCHMARK_SOCKET_URL',
        'http://backend:5000'
    );
}

async function createDataClients() {
    validateEnv();
    const pool = new Pool({
        host: process.env.DB_HOST,
        port: Number(process.env.DB_PORT),
        database: process.env.DB_NAME,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD
    });
    pool.on('error', () => {
        console.error('[Benchmark] PostgreSQL connection error.');
    });

    const redisClient = createClient({
        url: `redis://${process.env.REDIS_HOST}:${process.env.REDIS_PORT}`,
        socket: { connectTimeout: 5000 }
    });
    redisClient.on('error', () => {
        console.error('[Benchmark] Redis connection error.');
    });

    try {
        await Promise.all([
            pool.query('SELECT 1'),
            redisClient.connect()
        ]);
        await redisClient.ping();
    } catch (error) {
        if (redisClient.isOpen) {
            await redisClient.quit().catch(() => {});
        }
        await pool.end().catch(() => {});
        throw error;
    }

    return { pool, redisClient };
}

async function findBenchmarkUser(pool, userConfiguration) {
    const result = await pool.query(
        'SELECT id, email, role FROM users WHERE id = $1 AND lower(email) = $2',
        [userConfiguration.userId, userConfiguration.email]
    );
    if (result.rows.length !== 1) {
        throw new Error('The configured dedicated benchmark account was not found.');
    }
    return result.rows[0];
}

async function verifyBenchmarkToken(pool, redisClient, token, userConfiguration) {
    if (!token) {
        throw new Error('BENCHMARK_JWT is required for the API benchmark.');
    }
    const claims = jwt.verify(token, process.env.JWT_SECRET);
    if (!claims.jti || String(claims.userId) !== userConfiguration.userId) {
        throw new Error('BENCHMARK_JWT does not belong to the configured benchmark account.');
    }

    const sessionResult = await pool.query(
        `SELECT s.is_active, s.expires_at, u.email
         FROM sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.jwt_jti = $1 AND s.user_id = $2`,
        [claims.jti, userConfiguration.userId]
    );
    const session = sessionResult.rows[0];
    if (
        !session ||
        session.email.toLowerCase() !== userConfiguration.email ||
        !session.is_active ||
        new Date(session.expires_at) <= new Date()
    ) {
        throw new Error('BENCHMARK_JWT must identify an active benchmark session.');
    }
    if (await redisClient.exists(`revoked:jti:${claims.jti}`)) {
        throw new Error('BENCHMARK_JWT identifies a revoked session.');
    }

    let redisSession;
    try {
        redisSession = JSON.parse(await redisClient.get(`session:${claims.jti}`));
    } catch {
        throw new Error('BENCHMARK_JWT does not identify a valid active Redis session.');
    }
    if (
        !redisSession ||
        redisSession.isActive !== true ||
        String(redisSession.userId) !== userConfiguration.userId
    ) {
        throw new Error('BENCHMARK_JWT does not identify a valid active Redis session.');
    }
    return { jti: claims.jti, userId: userConfiguration.userId };
}

async function createBenchmarkSession(pool, redisClient, user, ttlSeconds) {
    const jti = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
    const ipAddress = '127.0.0.1';
    await pool.query(
        `INSERT INTO sessions
            (user_id, jwt_jti, ip_address, user_agent, device_id, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [user.id, jti, ipAddress, 'ZeroPulse isolated benchmark', 'benchmark', expiresAt]
    );

    try {
        await redisClient.set(
            `session:${jti}`,
            JSON.stringify({ userId: user.id, ip: ipAddress, isActive: true }),
            { EX: ttlSeconds }
        );
        const token = jwt.sign(
            { jti, userId: user.id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: ttlSeconds }
        );
        return { jti, token, userId: String(user.id), expiresAt };
    } catch (error) {
        await pool.query(
            'DELETE FROM sessions WHERE user_id = $1 AND jwt_jti = $2',
            [user.id, jti]
        );
        throw error;
    }
}

async function cleanupBenchmarkSession(pool, redisClient, session) {
    if (!session) {
        return;
    }
    await Promise.all([
        pool.query(
            'DELETE FROM sessions WHERE user_id = $1 AND jwt_jti = $2',
            [session.userId, session.jti]
        ),
        redisClient.del([
            `session:${session.jti}`,
            `revoked:jti:${session.jti}`
        ])
    ]);
}

function durationMs(startNs, endNs) {
    if (startNs === null || startNs === undefined ||
        endNs === null || endNs === undefined) {
        return null;
    }
    try {
        const elapsed = BigInt(endNs) - BigInt(startNs);
        return elapsed < 0n ? null : Number(elapsed) / 1e6;
    } catch {
        return null;
    }
}

function calculateMetrics(values) {
    const sorted = values
        .filter((value) => Number.isFinite(value) && value >= 0)
        .slice()
        .sort((left, right) => left - right);
    if (!sorted.length) {
        return {
            count: 0,
            min: null,
            average: null,
            median: null,
            p95: null,
            p99: null,
            max: null
        };
    }
    const percentile = (fraction) =>
        sorted[Math.max(0, Math.ceil(sorted.length * fraction) - 1)];
    const midpoint = Math.floor(sorted.length / 2);
    const median = sorted.length % 2
        ? sorted[midpoint]
        : (sorted[midpoint - 1] + sorted[midpoint]) / 2;
    return {
        count: sorted.length,
        min: sorted[0],
        average: sorted.reduce((sum, value) => sum + value, 0) / sorted.length,
        median,
        p95: percentile(0.95),
        p99: percentile(0.99),
        max: sorted[sorted.length - 1]
    };
}

function summarizeRevocationRecords(records) {
    const successful = records.filter((record) => record.success);
    const stages = [
        'eventProcessingMs',
        'riskEvaluationMs',
        'redisEnforcementMs',
        'postgresDeactivationMs',
        'socketEmissionMs',
        'endToEndMs',
        'socketClientReceiptMs'
    ];
    const latenciesMs = {};
    for (const stage of stages) {
        latenciesMs[stage] = calculateMetrics(
            successful.map((record) => record.latenciesMs[stage])
        );
    }
    return {
        attempted: records.length,
        succeeded: successful.length,
        failed: records.length - successful.length,
        latenciesMs
    };
}

function sanitizeBenchmarkReport(result) {
    const configuration = result.benchmark === 'api-load'
        ? {
            requestCount: result.configuration.requestCount,
            durationSeconds: result.configuration.durationSeconds,
            concurrency: result.configuration.concurrency,
            endpointPath: result.configuration.endpointPath
        }
        : {
            iterations: result.configuration.iterations,
            timeoutMs: result.configuration.timeoutMs,
            sessionTtlSeconds: result.configuration.sessionTtlSeconds,
            eventType: result.configuration.eventType
        };
    const common = {
        schemaVersion: result.schemaVersion,
        benchmark: result.benchmark,
        generatedAt: result.generatedAt,
        executionMode: result.executionMode,
        runtime: result.runtime,
        timing: result.timing,
        configuration
    };
    if (result.benchmark === 'api-load') {
        return {
            ...common,
            metrics: result.metrics,
            statusCodes: result.statusCodes,
            errorCategories: result.errorCategories
        };
    }
    return {
        ...common,
        summary: result.summary,
        failuresByCode: result.failuresByCode,
        records: result.records.map((record) => ({
            sequence: record.sequence,
            success: record.success,
            errorCode: record.errorCode,
            httpStatus: record.httpStatus,
            riskScore: record.riskScore,
            redisRevocationConfirmed: record.redisRevocationConfirmed,
            postgresDeactivationConfirmed: record.postgresDeactivationConfirmed,
            socketNotificationEmitted: record.socketNotificationEmitted,
            socketNotificationReceived: record.socketNotificationReceived,
            latenciesMs: record.latenciesMs
        }))
    };
}

function filenameTimestamp(date) {
    return date.toISOString().replace(/[:.]/g, '-');
}

async function writeBenchmarkResult(result, safeReport = false) {
    const directory = path.resolve(
        __dirname,
        safeReport ? 'reports' : 'results'
    );
    await fs.mkdir(directory, { recursive: true });
    const suffix = safeReport ? '-summary' : '';
    const filename = `${result.benchmark}-${filenameTimestamp(new Date(result.generatedAt))}${suffix}.json`;
    const outputPath = path.join(directory, filename);
    const output = safeReport ? sanitizeBenchmarkReport(result) : result;
    await fs.writeFile(outputPath, `${JSON.stringify(output, null, 2)}\n`, {
        encoding: 'utf8',
        flag: 'wx'
    });
    return outputPath;
}

function getRuntimeMetadata(env = process.env) {
    return {
        nodeVersion: process.version,
        platform: os.platform(),
        architecture: os.arch(),
        executionMode: env.BENCHMARK_EXECUTION_MODE || 'local'
    };
}

async function waitForHttpService(origin, fetchImpl = fetch) {
    const deadline = process.hrtime.bigint() + 30_000_000_000n;
    while (process.hrtime.bigint() < deadline) {
        try {
            const response = await fetchImpl(origin, {
                signal: AbortSignal.timeout(2000)
            });
            if (response.ok) {
                return;
            }
        } catch {
            // Retry while the Compose backend or Nginx is starting.
        }
        await new Promise((resolve) => setTimeout(resolve, 500));
    }
    throw new Error('The configured API service did not become ready.');
}

function createRunId() {
    return crypto.randomUUID();
}

module.exports = {
    BENCHMARK_RESULTS_CHANNEL,
    DEFAULT_BENCHMARK_EMAIL,
    assertDedicatedBenchmarkEmail,
    calculateMetrics,
    cleanupBenchmarkSession,
    createBenchmarkSession,
    createDataClients,
    createRunId,
    durationMs,
    findBenchmarkUser,
    getApiOrigin,
    getBenchmarkUserConfiguration,
    getRuntimeMetadata,
    getSocketOrigin,
    loadBenchmarkEnvironment,
    parseApiBenchmarkOptions,
    parseInteger,
    parseRevocationBenchmarkOptions,
    sanitizeBenchmarkReport,
    summarizeRevocationRecords,
    verifyBenchmarkToken,
    waitForHttpService,
    writeBenchmarkResult
};
