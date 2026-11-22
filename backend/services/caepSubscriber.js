'use strict';

require("dotenv").config();

const redisClient = require('../config/redis');
const { parseCaepEvent } = require('./caepEventParser');
const { calculateRiskScore } = require('./riskEngine');
const { enforceRiskPolicy } = require('./enforcementEngine');
const { emitThreatEvent } = require('./socketService');

const REDIS_CHANNEL = 'caep:security_events';
let subscriberPromise = null;
const processedEventIds = new Set();

function getSafeEventLogFields(event, riskScore, enforcementResult) {
    const type = typeof event.type === 'string' &&
        /^[A-Z][A-Z0-9_]{0,63}$/.test(event.type)
        ? event.type
        : 'UNKNOWN';
    const severity = riskScore >= 70
        ? 'high'
        : riskScore >= 40
            ? 'medium'
            : 'low';
    const processingStatus = enforcementResult.revoked
        ? 'revoked'
        : enforcementResult.error
            ? 'enforcement_failed'
            : riskScore >= 70
                ? 'not_revoked'
                : 'allowed';
    const timestamp = event.timestamp === null || event.timestamp === undefined
        ? Number.NaN
        : Number(event.timestamp);
    const date = Number.isFinite(timestamp)
        ? new Date(timestamp * 1000)
        : null;

    return {
        type,
        severity,
        riskScore: Number.isFinite(riskScore) ? riskScore : null,
        processingStatus,
        timestamp: date && Number.isFinite(date.getTime())
            ? date.toISOString()
            : 'unknown'
    };
}

async function startCaepSubscriber() {
    if (subscriberPromise) {
        return subscriberPromise;
    }

    subscriberPromise = (async () => {
        try {
            // Redis subscriber must use a duplicated connection
            const subscriber = redisClient.duplicate();

            subscriber.on('error', () => {
                console.error('[CAEP Subscriber] Redis connection error.');
            });

            await subscriber.connect();

        console.log('[CAEP Subscriber] Redis subscriber connected');

            await subscriber.subscribe(
                REDIS_CHANNEL,
                async (message) => {
                    try {
                        const event = parseCaepEvent(message);
                        if (event.eventId && processedEventIds.has(event.eventId)) {
                            return;
                        }
                        if (event.eventId) {
                            processedEventIds.add(event.eventId);
                            if (processedEventIds.size > 1000) {
                                processedEventIds.delete(processedEventIds.values().next().value);
                            }
                        }

                        const riskScore = calculateRiskScore(event);
                        const enforcementResult = await enforceRiskPolicy(event, riskScore);
                        emitThreatEvent(event, riskScore, enforcementResult);
                        console.log(
                            '[CAEP Subscriber] Event processed:',
                            getSafeEventLogFields(event, riskScore, enforcementResult)
                        );

                    } catch (error) {
                        console.error(
                            '[CAEP Subscriber] Event processing failed.'
                        );
                    }
                }
            );

        console.log(
            `[CAEP Subscriber] Listening on ${REDIS_CHANNEL}`
        );

        } catch (error) {
            subscriberPromise = null;
            throw error;
        }
    })();

    return subscriberPromise;
}

if (require.main === module) {
    startCaepSubscriber().catch(() => {
    console.error('[CAEP Subscriber] Failed to start.');
    });
}

module.exports = {
    startCaepSubscriber
};