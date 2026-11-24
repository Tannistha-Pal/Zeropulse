'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createServer } = require('node:http');
const express = require('express');
const jwt = require('jsonwebtoken');

const TEST_SECRET = 'security-hardening-test-secret-that-is-long-enough';
process.env.JWT_SECRET = TEST_SECRET;

const pool = require('../config/db');
const redisClient = require('../config/redis');
const { validateEnv } = require('../config/validateEnv');
const authMiddleware = require('../middleware/authMiddleware');
const {
    loginRateLimiter,
    sessionRevocationRateLimiter
} = require('../middleware/rateLimiters');
const authRoutes = require('../routes/auth.routes');

const validEnvironment = {
    JWT_SECRET: TEST_SECRET,
    DB_HOST: 'postgres',
    DB_PORT: '5432',
    DB_NAME: 'zeropulse_test',
    DB_USER: 'zeropulse_test',
    DB_PASSWORD: 'test-password',
    REDIS_HOST: 'redis',
    REDIS_PORT: '6379',
    PORT: '5000',
    NODE_ENV: 'test'
};

function createToken(payload, options = {}) {
    return jwt.sign(payload, TEST_SECRET, options);
}

function createResponse() {
    return {
        statusCode: 200,
        status(code) {
            this.statusCode = code;
            return this;
        },
        json(body) {
            this.body = body;
            return this;
        }
    };
}

async function withRedisState(options, action) {
    const originalExists = redisClient.exists;
    const originalGet = redisClient.get;
    const originalConnect = redisClient.connect;
    const originalIsOpen = Object.getOwnPropertyDescriptor(redisClient, 'isOpen');

    redisClient.exists = options.exists || (async () => 0);
    redisClient.get = options.get || (async (key) => JSON.stringify({
        userId: key.slice('session:'.length),
        isActive: true
    }));
    redisClient.connect = options.connect || originalConnect;
    Object.defineProperty(redisClient, 'isOpen', {
        configurable: true,
        value: options.isOpen === undefined ? true : options.isOpen
    });

    try {
        return await action();
    } finally {
        redisClient.exists = originalExists;
        redisClient.get = originalGet;
        redisClient.connect = originalConnect;
        if (originalIsOpen) {
            Object.defineProperty(redisClient, 'isOpen', originalIsOpen);
        } else {
            delete redisClient.isOpen;
        }
    }
}

async function authenticate(token) {
    const req = { headers: { authorization: `Bearer ${token}` } };
    const res = createResponse();
    let nextCalled = false;
    await authMiddleware(req, res, () => { nextCalled = true; });
    return { req, res, nextCalled };
}

test('environment validation rejects missing secrets and infrastructure configuration', () => {
    const missingJwt = { ...validEnvironment };
    delete missingJwt.JWT_SECRET;
    assert.throws(() => validateEnv(missingJwt), /JWT_SECRET is required/);

    assert.throws(
        () => validateEnv({ ...validEnvironment, JWT_SECRET: '' }),
        /JWT_SECRET is required/
    );

    const missingRedis = { ...validEnvironment };
    delete missingRedis.REDIS_HOST;
    delete missingRedis.REDIS_PORT;
    assert.throws(() => validateEnv(missingRedis), /REDIS_HOST is required/);
    assert.throws(() => validateEnv(missingRedis), /REDIS_PORT is required/);

    const missingDatabase = { ...validEnvironment };
    delete missingDatabase.DB_HOST;
    assert.throws(() => validateEnv(missingDatabase), /DB_HOST is required/);
});

test('environment validation rejects invalid ports and production placeholder secrets', () => {
    assert.throws(
        () => validateEnv({ ...validEnvironment, PORT: '70000' }),
        /PORT must be an integer/
    );
    assert.throws(
        () => validateEnv({ ...validEnvironment, PORT: '' }),
        /PORT must be an integer/
    );
    assert.throws(
        () => validateEnv({ ...validEnvironment, REDIS_PORT: 'not-a-port' }),
        /REDIS_PORT must be an integer/
    );
    assert.throws(
        () => validateEnv({
            ...validEnvironment,
            NODE_ENV: 'production',
            JWT_SECRET: 'replace-with-a-long-random-secret'
        }),
        /JWT_SECRET must be a non-placeholder/
    );
    assert.throws(
        () => validateEnv({
            ...validEnvironment,
            FRONTEND_ORIGIN: 'http://localhost:5173/path'
        }),
        /FRONTEND_ORIGIN must be a valid/
    );

    assert.deepEqual(validateEnv(validEnvironment), {
        port: 5000,
        dbPort: 5432,
        redisPort: 6379,
        frontendOrigin: 'http://localhost:5173'
    });
    assert.equal(validateEnv({
        ...validEnvironment,
        NODE_ENV: 'production',
        JWT_SECRET: 'a-unique-production-secret-with-more-than-32-characters'
    }).port, 5000);
});

test('authentication accepts only valid JWTs with active Redis session state', async () => {
    await withRedisState({}, async () => {
        const token = createToken({ jti: 'active-session', userId: 'active-session' });
        const { req, res, nextCalled } = await authenticate(token);
        assert.equal(res.statusCode, 200);
        assert.equal(nextCalled, true);
        assert.equal(req.user.jti, 'active-session');
    });

    await withRedisState({
        get: async () => JSON.stringify({ userId: 'inactive-session', isActive: false })
    }, async () => {
        const token = createToken({ jti: 'inactive-session', userId: 'inactive-session' });
        const { res, nextCalled } = await authenticate(token);
        assert.equal(res.statusCode, 401);
        assert.equal(nextCalled, false);
    });
});

test('authentication rejects invalid, expired, missing-JTI, and revoked tokens', async () => {
    await withRedisState({ exists: async () => 1 }, async () => {
        const revoked = await authenticate(
            createToken({ jti: 'revoked-session', userId: 'revoked-session' })
        );
        assert.equal(revoked.res.statusCode, 401);
        assert.equal(revoked.res.body.error, 'Session revoked');
        assert.equal(revoked.nextCalled, false);
    });

    const invalid = await authenticate(
        jwt.sign({ jti: 'invalid-session', userId: 1 }, 'different-test-secret')
    );
    const expired = await authenticate(
        createToken({ jti: 'expired-session', userId: 1 }, { expiresIn: -1 })
    );
    const missingJti = await authenticate(createToken({ userId: 1 }));

    for (const result of [invalid, expired, missingJti]) {
        assert.equal(result.res.statusCode, 401);
        assert.equal(result.nextCalled, false);
    }
});

test('Redis connection and command failures deny protected requests with 503', async () => {
    await withRedisState({
        isOpen: false,
        connect: async () => { throw new Error('connection refused'); }
    }, async () => {
        const result = await authenticate(
            createToken({ jti: 'offline-session', userId: 'offline-session' })
        );
        assert.equal(result.res.statusCode, 503);
        assert.equal(result.res.body.error, 'Service Unavailable');
        assert.equal(result.nextCalled, false);
    });

    await withRedisState({
        exists: async () => {
            const error = new Error('Redis command timed out');
            error.code = 'ETIMEDOUT';
            throw error;
        }
    }, async () => {
        const result = await authenticate(
            createToken({ jti: 'timeout-session', userId: 'timeout-session' })
        );
        assert.equal(result.res.statusCode, 503);
        assert.equal(result.nextCalled, false);
    });
});

test('login and authenticated session revocation have separate rate limits and JSON 429 responses', async (t) => {
    const app = express();
    app.set('trust proxy', 1);
    app.use(express.json());
    app.use('/api/auth', authRoutes);
    const server = createServer(app);
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const url = `http://127.0.0.1:${server.address().port}`;
    const forwardedIp = '198.51.100.20';

    t.after(async () => {
        loginRateLimiter.resetKey(forwardedIp);
        sessionRevocationRateLimiter.resetKey(forwardedIp);
        await new Promise((resolve, reject) => {
            server.close((error) => error ? reject(error) : resolve());
            server.closeAllConnections();
        });
    });

    loginRateLimiter.resetKey(forwardedIp);
    let loginResponse;
    for (let attempt = 0; attempt < 11; attempt += 1) {
        loginResponse = await fetch(`${url}/api/auth/login`, {
            method: 'POST',
            headers: {
                'content-type': 'application/json',
                'x-forwarded-for': forwardedIp
            },
            body: JSON.stringify({})
        });
    }
    assert.equal(loginResponse.status, 429);
    assert.deepEqual(await loginResponse.json(), {
        error: 'Too many requests',
        message: 'Too many login attempts. Please try again later.'
    });

    const originalQuery = pool.query;
    const originalSetEx = redisClient.setEx;
    pool.query = async (sql) => sql.includes('SELECT expires_at')
        ? { rows: [{ expires_at: new Date(Date.now() + 60000), is_active: true }] }
        : { rowCount: 1 };
    redisClient.setEx = async () => 'OK';

    try {
        const token = createToken({ jti: 'limited-session', userId: 7 });
        let revokeResponse;
        await withRedisState({
            get: async () => JSON.stringify({ userId: 7, isActive: true })
        }, async () => {
            for (let attempt = 0; attempt < 11; attempt += 1) {
                revokeResponse = await fetch(`${url}/api/auth/revoke-session`, {
                    method: 'POST',
                    headers: {
                        authorization: `Bearer ${token}`,
                        'content-type': 'application/json',
                        'x-forwarded-for': forwardedIp
                    },
                    body: JSON.stringify({})
                });
            }
        });
        assert.equal(revokeResponse.status, 429);
        assert.deepEqual(await revokeResponse.json(), {
            error: 'Too many requests',
            message: 'Too many session revocation attempts. Please try again later.'
        });
    } finally {
        pool.query = originalQuery;
        redisClient.setEx = originalSetEx;
    }
});
