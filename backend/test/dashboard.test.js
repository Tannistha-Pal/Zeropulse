const test = require('node:test');
const assert = require('node:assert/strict');

const pool = require('../config/db');
const redisClient = require('../config/redis');
const { revokeSession } = require('../controllers/auth.controller');
const { getSessions } = require('../controllers/user.controller');
const { getSafeSessionRef } = require('../services/socketService');

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

test('session listing is scoped to the authenticated user and returns safe references', async () => {
    const originalQuery = pool.query;
    let query;
    pool.query = async (sql, params) => {
        query = { sql, params };
        return {
            rows: [{
                jwt_jti: 'private-jti',
                ip_address: '192.0.2.10',
                user_agent: 'Test device',
                device_id: 'device-1',
                created_at: new Date('2026-01-01T00:00:00.000Z'),
                is_active: true
            }]
        };
    };

    try {
        const response = createResponse();
        await getSessions({ user: { userId: 17 } }, response);
        assert.deepEqual(query.params, [17]);
        assert.match(query.sql, /WHERE user_id = \$1/);
        assert.deepEqual(response.body.sessions[0], {
            sessionRef: getSafeSessionRef('private-jti'),
            ipAddress: '192.0.2.10',
            deviceInfo: 'Test device',
            deviceId: 'device-1',
            loginTime: new Date('2026-01-01T00:00:00.000Z'),
            status: 'ACTIVE'
        });
        assert.equal(JSON.stringify(response.body).includes('private-jti'), false);
    } finally {
        pool.query = originalQuery;
    }
});

test('session revocation resolves a safe reference only among the authenticated user sessions', async () => {
    const originalQuery = pool.query;
    const originalSetEx = redisClient.setEx;
    const queries = [];
    let redisKey;
    pool.query = async (sql, params) => {
        queries.push({ sql, params });
        if (sql.includes('SELECT jwt_jti')) {
            return { rows: [{ jwt_jti: 'owned-jti' }] };
        }
        if (sql.includes('SELECT expires_at')) {
            return {
                rows: [{ expires_at: new Date(Date.now() + 60000), is_active: true }]
            };
        }
        return { rowCount: 1 };
    };
    redisClient.setEx = async (key) => { redisKey = key; };

    try {
        const response = createResponse();
        await revokeSession({
            body: { sessionRef: getSafeSessionRef('owned-jti') },
            user: { userId: 17, jti: 'caller-jti' }
        }, response);

        assert.equal(response.statusCode, 200);
        assert.equal(response.body.jti, 'owned-jti');
        assert.equal(redisKey, 'revoked:jti:owned-jti');
        assert.deepEqual(queries[0].params, [17]);
        assert.deepEqual(queries[1].params, ['owned-jti', 17]);
        assert.deepEqual(queries[2].params, ['owned-jti', 17]);
    } finally {
        pool.query = originalQuery;
        redisClient.setEx = originalSetEx;
    }
});

test('session revocation rejects references not owned by the authenticated user', async () => {
    const originalQuery = pool.query;
    const originalSetEx = redisClient.setEx;
    let redisCalled = false;
    pool.query = async () => ({ rows: [{ jwt_jti: 'another-users-jti' }] });
    redisClient.setEx = async () => { redisCalled = true; };

    try {
        const response = createResponse();
        await revokeSession({
            body: { sessionRef: getSafeSessionRef('not-owned-jti') },
            user: { userId: 17, jti: 'caller-jti' }
        }, response);

        assert.equal(response.statusCode, 404);
        assert.equal(redisCalled, false);
    } finally {
        pool.query = originalQuery;
        redisClient.setEx = originalSetEx;
    }
});
