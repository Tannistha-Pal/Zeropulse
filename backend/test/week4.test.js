const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');

const { createCaepEvent } = require('../utils/caepEventBuilder');
const { parseCaepEvent } = require('../services/caepEventParser');
const { calculateRiskScore } = require('../services/riskEngine');
const { enforceRiskPolicy, RISK_THRESHOLD } = require('../services/enforcementEngine');
const pool = require('../config/db');
const redisClient = require('../config/redis');
const authMiddleware = require('../middleware/authMiddleware');

test('CAEP builder and parser produce the simulator event convention', () => {
    const jsonEvent = createCaepEvent(
        'TOKEN_HIJACKED',
        { userId: 'user-1', sessionId: 'session-1', jti: 'jti-1' },
        { source: 'ThreatSimulator', simulated: true }
    );
    const event = parseCaepEvent(jsonEvent);

    assert.equal(event.type, 'TOKEN_HIJACKED');
    assert.equal(event.details.type, 'TOKEN_HIJACKED');
    assert.equal(event.subject.jti, 'jti-1');
});

test('risk engine and threshold classify high and low-risk events', () => {
    const high = calculateRiskScore({
        details: { type: 'IMPOSSIBLE_TRAVEL' }
    });
    const low = calculateRiskScore({
        details: { type: 'VPN_DETECTED' }
    });

    assert.equal(RISK_THRESHOLD, 70);
    assert.equal(high >= RISK_THRESHOLD, true);
    assert.equal(low >= RISK_THRESHOLD, false);
});

test('low-risk event does not revoke a session', async () => {
    const originalQuery = pool.query;
    const originalSetEx = redisClient.setEx;
    let queryCount = 0;
    let redisSetCount = 0;

    pool.query = async () => { queryCount += 1; };
    redisClient.setEx = async () => { redisSetCount += 1; };
    try {
        const result = await enforceRiskPolicy({
            subject: { jti: 'low-risk-jti' }
        }, 55);

        assert.equal(result.revoked, false);
        assert.equal(queryCount, 0);
        assert.equal(redisSetCount, 0);
    } finally {
        pool.query = originalQuery;
        redisClient.setEx = originalSetEx;
    }
});

test('high-risk event revokes Redis JTI and PostgreSQL session', async () => {
    const originalQuery = pool.query;
    const originalSetEx = redisClient.setEx;
    const originalIsOpen = Object.getOwnPropertyDescriptor(redisClient, 'isOpen');
    const queries = [];
    let revokedKey;

    Object.defineProperty(redisClient, 'isOpen', {
        configurable: true,
        value: true
    });
    pool.query = async (sql, params) => {
        queries.push({ sql, params });
        if (sql.includes('SELECT expires_at')) {
            return { rows: [{ expires_at: new Date(Date.now() + 3600000) }] };
        }
        return { rowCount: 1 };
    };
    redisClient.setEx = async (key) => { revokedKey = key; };

    try {
        const result = await enforceRiskPolicy({
            subject: { jti: 'high-risk-jti' }
        }, 90);

        assert.equal(result.revoked, true);
        assert.equal(revokedKey, 'revoked:jti:high-risk-jti');
        assert.equal(queries.length, 2);
        assert.equal(queries[1].sql.includes('UPDATE sessions'), true);
    } finally {
        pool.query = originalQuery;
        redisClient.setEx = originalSetEx;
        if (originalIsOpen) {
            Object.defineProperty(redisClient, 'isOpen', originalIsOpen);
        } else {
            delete redisClient.isOpen;
        }
    }
});

test('protected API middleware returns 401 for a revoked JWT', async () => {
    process.env.JWT_SECRET = 'week4-test-secret';
    const token = jwt.sign(
        { jti: 'revoked-jti', userId: 1, role: 'user' },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );
    const originalExists = redisClient.exists;
    const originalIsOpen = Object.getOwnPropertyDescriptor(redisClient, 'isOpen');
    Object.defineProperty(redisClient, 'isOpen', {
        configurable: true,
        value: true
    });
    redisClient.exists = async () => 1;

    const req = { headers: { authorization: `Bearer ${token}` } };
    const res = {
        statusCode: 200,
        status(code) { this.statusCode = code; return this; },
        json(body) { this.body = body; return this; }
    };

    let nextCalled = false;
    try {
        await authMiddleware(req, res, () => { nextCalled = true; });
        assert.equal(res.statusCode, 401);
        assert.equal(nextCalled, false);
        assert.equal(res.body.error, 'Session revoked');
    } finally {
        redisClient.exists = originalExists;
        if (originalIsOpen) {
            Object.defineProperty(redisClient, 'isOpen', originalIsOpen);
        } else {
            delete redisClient.isOpen;
        }
    }
});
