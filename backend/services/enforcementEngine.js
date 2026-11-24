'use strict';

const pool = require('../config/db');
const redisClient = require('../config/redis');
const { emitSessionRevoked, getSafeSessionRef } = require('./socketService');

const RISK_THRESHOLD = 70;

async function enforceRiskPolicy(event, riskScore) {
    const benchmarkTimings = event.benchmark ? {} : null;

    // Only enforce when risk reaches the threshold
    if (riskScore < RISK_THRESHOLD) {
        console.log(
            `[Enforcement] Risk ${riskScore} is below threshold ${RISK_THRESHOLD}. No action.`
        );
        return { enforced: false, revoked: false };
    }

    const jti = event.subject?.jti;

    if (!jti) {
        console.log(
            '[Enforcement] High-risk event detected, but no JTI was found.'
        );
        return { enforced: false, revoked: false };
    }

    console.log(
        `[Enforcement] HIGH RISK detected: ${riskScore}. Revoking session ${getSafeSessionRef(jti)}`
    );

    try {
        // 1. Find session expiration time
        const result = await pool.query(
            `SELECT expires_at
             FROM sessions
             WHERE jwt_jti = $1`,
            [jti]
        );

        if (result.rows.length === 0) {
            console.log(
                `[Enforcement] Session ${getSafeSessionRef(jti)} not found in PostgreSQL.`
            );
            return { enforced: true, revoked: false };
        }

        // 2. Calculate remaining TTL
        const expiresAt = new Date(result.rows[0].expires_at);
        const remainingTTL = Math.max(
            1,
            Math.floor((expiresAt.getTime() - Date.now()) / 1000)
        );

        // 3. Add JTI to Redis revocation list
        if (!redisClient.isOpen) {
            console.log('[Enforcement] Redis client is closed. Connecting...');
            await redisClient.connect();
        }

        await redisClient.setEx(
            `revoked:jti:${jti}`,
            remainingTTL,
            'revoked'
        );
        if (benchmarkTimings) {
            benchmarkTimings.redisRevocationCompletedAtNs =
                process.hrtime.bigint().toString();
        }

        // 4. Mark session inactive in PostgreSQL
        await pool.query(
            `UPDATE sessions
             SET is_active = FALSE
             WHERE jwt_jti = $1`,
            [jti]
        );
        if (benchmarkTimings) {
            benchmarkTimings.postgresDeactivationCompletedAtNs =
                process.hrtime.bigint().toString();
        }

        console.log(
            `[Enforcement] Session ${getSafeSessionRef(jti)} revoked successfully.`
        );
        const socketNotificationEmitted = emitSessionRevoked(
            jti,
            `High-risk CAEP event (${event.details?.type || 'unknown'}, risk ${riskScore}).`
        );
        if (benchmarkTimings) {
            benchmarkTimings.socketEmissionCompletedAtNs =
                process.hrtime.bigint().toString();
            return {
                enforced: true,
                revoked: true,
                benchmarkTimings,
                socketNotificationEmitted
            };
        }
        return { enforced: true, revoked: true };

    } catch (_error) {
        console.error(
            '[Enforcement] Enforcement failed.'
        );
        return {
            enforced: true,
            revoked: false,
            error: 'enforcement_failed',
            ...(benchmarkTimings ? { benchmarkTimings } : {})
        };
    }
}

module.exports = {
    enforceRiskPolicy,
    RISK_THRESHOLD
};