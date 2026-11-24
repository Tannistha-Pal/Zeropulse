'use strict';

const redisClient = require('../config/redis');
const { connectRedis } = require('../config/redis');

const REDIS_CHECK_TIMEOUT_MS = 5000;

function withTimeout(promise, timeoutMs) {
    let timer;
    return Promise.race([
        promise,
        new Promise((_, reject) => {
            timer = setTimeout(
                () => reject(new Error('Redis session verification timed out.')),
                timeoutMs
            );
        })
    ]).finally(() => clearTimeout(timer));
}

async function getSessionState(jti, userId) {
    await withTimeout(connectRedis(), REDIS_CHECK_TIMEOUT_MS);

    const revoked = await withTimeout(
        redisClient.exists(`revoked:jti:${jti}`),
        REDIS_CHECK_TIMEOUT_MS
    );
    if (revoked) {
        return 'revoked';
    }

    const sessionValue = await withTimeout(
        redisClient.get(`session:${jti}`),
        REDIS_CHECK_TIMEOUT_MS
    );
    if (!sessionValue) {
        return 'inactive';
    }

    try {
        const session = JSON.parse(sessionValue);
        return session.isActive === true &&
            String(session.userId) === String(userId)
            ? 'active'
            : 'inactive';
    } catch {
        console.error('[Authentication] Redis session data is invalid.');
        return 'inactive';
    }
}

module.exports = { getSessionState };
