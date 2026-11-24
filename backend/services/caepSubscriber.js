'use strict';

require("dotenv").config();

const redisClient = require('../config/redis');
const { parseCaepEvent } = require('./caepEventParser');
const { calculateRiskScore } = require('./riskEngine');
const { enforceRiskPolicy } = require('./enforcementEngine');
const { emitThreatEvent } = require('./socketService');
const { publishBenchmarkResult } = require('./benchmarkTelemetry');

const REDIS_CHANNEL = 'caep:security_events';
let subscriberPromise = null;
let subscriberClient = null;
const processedEventIds = new Set();
const SUBSCRIBER_SHUTDOWN_TIMEOUT_MS = 5000;

function withTimeout(promise, timeoutMs) {
    let timer;
    return Promise.race([
        promise,
        new Promise((_, reject) => {
            timer = setTimeout(
                () => reject(new Error('CAEP subscriber shutdown timed out.')),
                timeoutMs
            );
        })
    ]).finally(() => clearTimeout(timer));
}

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
            subscriberClient = subscriber;

            subscriber.on('error', () => {
                console.error('[CAEP Subscriber] Redis connection error.');
            });

            await subscriber.connect();

        console.log('[CAEP Subscriber] Redis subscriber connected');

            await subscriber.subscribe(
                REDIS_CHANNEL,
                async (message) => {
                    const receivedAtNs = process.hrtime.bigint().toString();
                    let event = null;
                    try {
                        event = parseCaepEvent(message);
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
                        const riskEvaluationCompletedAtNs =
                            process.hrtime.bigint().toString();
                        const enforcementResult = await enforceRiskPolicy(event, riskScore);
                        emitThreatEvent(event, riskScore, enforcementResult);
                        await publishBenchmarkResult(redisClient, event, {
                            receivedAtNs,
                            riskEvaluationCompletedAtNs,
                            riskScore,
                            revoked: enforcementResult.revoked === true,
                            enforcementError: enforcementResult.error || null,
                            socketNotificationEmitted:
                                enforcementResult.socketNotificationEmitted === true,
                            benchmarkTimings: enforcementResult.benchmarkTimings || {}
                        });
                        console.log(
                            '[CAEP Subscriber] Event processed:',
                            getSafeEventLogFields(event, riskScore, enforcementResult)
                        );

                    } catch (error) {
                        console.error(
                            '[CAEP Subscriber] Event processing failed.'
                        );
                        if (event?.benchmark) {
                            try {
                                await publishBenchmarkResult(redisClient, event, {
                                    receivedAtNs,
                                    revoked: false,
                                    enforcementError: 'event_processing_failed',
                                    benchmarkTimings: {}
                                });
                            } catch {
                                console.error(
                                    '[CAEP Subscriber] Benchmark result publication failed.'
                                );
                            }
                        }
                    }
                }
            );

        console.log(
            `[CAEP Subscriber] Listening on ${REDIS_CHANNEL}`
        );

        } catch (error) {
            if (subscriberClient && typeof subscriberClient.destroy === 'function') {
                subscriberClient.destroy();
            }
            subscriberClient = null;
            subscriberPromise = null;
            throw error;
        }
    })();

    return subscriberPromise;
}

async function stopCaepSubscriber() {
    const subscriber = subscriberClient;
    if (!subscriber) {
        return;
    }

    try {
        await withTimeout((async () => {
            if (subscriberPromise) {
                await subscriberPromise;
            }
            if (subscriber.isOpen) {
                await subscriber.unsubscribe(REDIS_CHANNEL);
                await subscriber.quit();
            }
        })(), SUBSCRIBER_SHUTDOWN_TIMEOUT_MS);
    } catch (error) {
        if (typeof subscriber.destroy === 'function') {
            subscriber.destroy();
        }
        throw error;
    } finally {
        subscriberClient = null;
        subscriberPromise = null;
    }
}

if (require.main === module) {
    startCaepSubscriber().catch(() => {
    console.error('[CAEP Subscriber] Failed to start.');
    });
}

module.exports = {
    startCaepSubscriber,
    stopCaepSubscriber
};