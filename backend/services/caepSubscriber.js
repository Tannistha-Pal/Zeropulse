'use strict';

require("dotenv").config();

const redisClient = require('../config/redis');
const { parseCaepEvent } = require('./caepEventParser');
const { calculateRiskScore } = require('./riskEngine');
const { enforceRiskPolicy } = require('./enforcementEngine');

const REDIS_CHANNEL = 'caep:security_events';
let subscriberPromise = null;
const processedEventIds = new Set();

async function startCaepSubscriber() {
    if (subscriberPromise) {
        return subscriberPromise;
    }

    subscriberPromise = (async () => {
        try {
            // Redis subscriber must use a duplicated connection
            const subscriber = redisClient.duplicate();

            subscriber.on('error', (err) => {
                console.error('[CAEP Subscriber] Redis error:', err.message);
            });

            await subscriber.connect();

        console.log('[CAEP Subscriber] Redis subscriber connected');

            await subscriber.subscribe(
                REDIS_CHANNEL,
                async (message) => {
                    console.log('\n====================================');
                    console.log('[CAEP Subscriber] Event received');
                    console.log('Channel:', REDIS_CHANNEL);
                    console.log('====================================');

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

                        console.log(
                            '[CAEP Subscriber] Normalized CAEP event:',
                            event
                        );

                        console.log(
                            '[CAEP Subscriber] Event type:',
                            event.type
                        );

                        console.log(
                            '[CAEP Subscriber] Event details:',
                            event.details
                        );

                        const riskScore = calculateRiskScore(event);
                        console.log(
                            '[CAEP Risk Engine] Risk Score:',
                            riskScore
                        );
                        await enforceRiskPolicy(event, riskScore);

                    } catch (error) {

                        console.error(
                            '[CAEP Subscriber] Invalid JSON event:',
                            error.message
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
    startCaepSubscriber().catch((error) => {
        console.error('[CAEP Subscriber] Failed to start:', error.message);
    });
}

module.exports = {
    startCaepSubscriber
};