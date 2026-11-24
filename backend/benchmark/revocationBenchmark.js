'use strict';

const crypto = require('node:crypto');
const { io: createSocketClient } = require('socket.io-client');
const { createCaepEvent } = require('../utils/caepEventBuilder');
const { getSafeSessionRef } = require('../services/socketService');
const {
    BENCHMARK_RESULTS_CHANNEL,
    cleanupBenchmarkSession,
    createBenchmarkSession,
    createDataClients,
    durationMs,
    findBenchmarkUser,
    getApiOrigin,
    getBenchmarkUserConfiguration,
    getRuntimeMetadata,
    getSocketOrigin,
    loadBenchmarkEnvironment,
    parseRevocationBenchmarkOptions,
    summarizeRevocationRecords,
    waitForHttpService,
    writeBenchmarkResult
} = require('./benchmarkUtils');

const CAEP_CHANNEL = 'caep:security_events';
const PROFILE_PATH = '/api/user/profile';

function createBenchmarkEvent(user, session, runId, eventId) {
    const event = JSON.parse(createCaepEvent('TOKEN_HIJACKED', {
        userId: String(user.id),
        sessionId: session.jti,
        jti: session.jti
    }, {
        source: 'ZeroPulse-CAEP-Benchmark',
        platform: 'isolated-benchmark',
        token_compromised: true
    }));
    event.jti = eventId;
    event.benchmark = {
        runId,
        publishedAtNs: '0'
    };
    return event;
}

function waitForSocketConnect(socket, timeoutMs) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            cleanup();
            reject(Object.assign(new Error('Socket connection timed out.'), {
                code: 'socket_connect_timeout'
            }));
        }, timeoutMs);
        const onConnect = () => {
            cleanup();
            resolve();
        };
        const onError = () => {
            cleanup();
            reject(Object.assign(new Error('Socket connection failed.'), {
                code: 'socket_connect_failed'
            }));
        };
        const cleanup = () => {
            clearTimeout(timer);
            socket.off('connect', onConnect);
            socket.off('connect_error', onError);
        };
        socket.once('connect', onConnect);
        socket.once('connect_error', onError);
    });
}

function waitForSocketNotification(socket, expectedSessionRef, timeoutMs) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            cleanup();
            reject(Object.assign(new Error('Socket notification timed out.'), {
                code: 'socket_notification_timeout'
            }));
        }, timeoutMs);
        const onNotification = (payload) => {
            const receivedAtNs = process.hrtime.bigint().toString();
            cleanup();
            if (
                payload?.action !== 'REVOKE' ||
                payload?.sessionRef !== expectedSessionRef
            ) {
                reject(Object.assign(new Error('Unexpected socket notification.'), {
                    code: 'unexpected_socket_notification'
                }));
                return;
            }
            resolve({ receivedAtNs, payload });
        };
        const cleanup = () => {
            clearTimeout(timer);
            socket.off('session_revoked', onNotification);
        };
        socket.once('session_revoked', onNotification);
    });
}

async function createResultCollector(subscriber) {
    const pending = new Map();
    const seenRunIds = new Set();
    const duplicateRunIds = new Set();

    await subscriber.subscribe(BENCHMARK_RESULTS_CHANNEL, (message) => {
        let result;
        try {
            result = JSON.parse(message);
        } catch {
            return;
        }
        if (!result || typeof result.runId !== 'string') {
            return;
        }
        if (seenRunIds.has(result.runId)) {
            duplicateRunIds.add(result.runId);
            return;
        }
        seenRunIds.add(result.runId);
        const handler = pending.get(result.runId);
        if (handler) {
            handler.resolve(result);
        }
    });

    return {
        duplicateRunIds,
        waitForResult(runId, timeoutMs) {
            return new Promise((resolve, reject) => {
                const timer = setTimeout(() => {
                    pending.delete(runId);
                    reject(Object.assign(new Error('CAEP result timed out.'), {
                        code: 'caep_result_timeout'
                    }));
                }, timeoutMs);
                pending.set(runId, {
                    resolve(result) {
                        clearTimeout(timer);
                        pending.delete(runId);
                        resolve(result);
                    },
                    reject(error) {
                        clearTimeout(timer);
                        pending.delete(runId);
                        reject(error);
                    }
                });
            });
        }
    };
}

async function waitForRevocationState(pool, redisClient, session, timeoutMs) {
    const deadlineNs = process.hrtime.bigint() + BigInt(timeoutMs) * 1_000_000n;
    while (process.hrtime.bigint() < deadlineNs) {
        const [revoked, result] = await Promise.all([
            redisClient.exists(`revoked:jti:${session.jti}`),
            pool.query(
                'SELECT is_active FROM sessions WHERE user_id = $1 AND jwt_jti = $2',
                [session.userId, session.jti]
            )
        ]);
        if (revoked && result.rows[0]?.is_active === false) {
            return;
        }
        await new Promise((resolve) => setTimeout(resolve, 50));
    }
    throw Object.assign(new Error('Revocation state was not confirmed.'), {
        code: 'revocation_state_timeout'
    });
}

async function verifyProtectedApiDeniesSession(apiOrigin, session, fetchImpl = fetch) {
    const response = await fetchImpl(
        new URL(PROFILE_PATH, apiOrigin),
        {
            headers: { Authorization: `Bearer ${session.token}` },
            signal: AbortSignal.timeout(5000)
        }
    );
    await response.arrayBuffer();
    if (response.status !== 401) {
        throw Object.assign(new Error('Protected API did not reject the revoked session.'), {
            code: 'post_revocation_api_not_401',
            httpStatus: response.status
        });
    }
}

function createLatencyRecord(record, t1, serverResult, notification) {
    const t2 = serverResult?.receivedAtNs;
    const t3 = serverResult?.riskEvaluationCompletedAtNs;
    const timings = serverResult?.benchmarkTimings || {};
    const t4 = timings.redisRevocationCompletedAtNs;
    const t5 = timings.postgresDeactivationCompletedAtNs;
    const t6 = timings.socketEmissionCompletedAtNs;
    const t7 = notification?.receivedAtNs;

    record.latenciesMs = {
        eventProcessingMs: durationMs(t1, t2),
        riskEvaluationMs: durationMs(t2, t3),
        redisEnforcementMs: durationMs(t3, t4),
        postgresDeactivationMs: durationMs(t4, t5),
        socketEmissionMs: durationMs(t5, t6),
        endToEndMs: durationMs(t1, t6),
        socketClientReceiptMs: durationMs(t1, t7)
    };
}

async function runRevocationCase({
    sequence,
    user,
    pool,
    redisClient,
    resultsCollector,
    apiOrigin,
    socketOrigin,
    options,
    seenEventIds,
    seenSessionJtis
}) {
    const runId = crypto.randomUUID();
    const eventId = crypto.randomUUID();
    const record = {
        sequence,
        runId,
        eventId,
        jti: null,
        success: false,
        errorCode: null,
        httpStatus: null,
        riskScore: null,
        redisRevocationConfirmed: false,
        postgresDeactivationConfirmed: false,
        socketNotificationEmitted: false,
        socketNotificationReceived: false,
        latenciesMs: {}
    };
    let session = null;
    let socket = null;
    let serverResult = null;
    let notification = null;
    let t1 = null;
    let resultPromise = null;
    let notificationPromise = null;

    try {
        session = await createBenchmarkSession(
            pool,
            redisClient,
            user,
            options.sessionTtlSeconds
        );
        record.jti = session.jti;
        socket = createSocketClient(socketOrigin, {
            auth: { token: session.token },
            transports: ['websocket'],
            reconnection: false,
            timeout: options.timeoutMs
        });
        await waitForSocketConnect(socket, options.timeoutMs);
        notificationPromise = waitForSocketNotification(
            socket,
            getSafeSessionRef(session.jti),
            options.timeoutMs
        );

        const event = createBenchmarkEvent(user, session, runId, eventId);
        const serializedEvent = JSON.stringify(event);
        resultPromise = resultsCollector.waitForResult(runId, options.timeoutMs);
        resultPromise.catch(() => {});
        notificationPromise.catch(() => {});
        t1 = process.hrtime.bigint().toString();
        const payload = serializedEvent.replace(
            '"publishedAtNs":"0"',
            `"publishedAtNs":"${t1}"`
        );
        const subscriberCount = await redisClient.publish(CAEP_CHANNEL, payload);
        if (subscriberCount < 1) {
            throw Object.assign(new Error('No CAEP subscribers received the event.'), {
                code: 'caep_no_subscribers'
            });
        }

        [serverResult, notification] = await Promise.all([
            resultPromise,
            notificationPromise
        ]);
        record.riskScore = serverResult.riskScore;
        record.socketNotificationEmitted =
            serverResult.socketNotificationEmitted === true;
        record.socketNotificationReceived = true;

        if (
            serverResult.eventId !== eventId ||
            serverResult.jti !== session.jti ||
            seenEventIds.has(eventId) ||
            seenSessionJtis.has(session.jti) ||
            resultsCollector.duplicateRunIds.has(runId)
        ) {
            throw Object.assign(new Error('Duplicate or mismatched CAEP result.'), {
                code: 'duplicate_or_mismatched_event'
            });
        }
        seenEventIds.add(eventId);
        seenSessionJtis.add(session.jti);

        if (serverResult.revoked !== true || serverResult.enforcementError) {
            throw Object.assign(new Error('CAEP enforcement did not complete.'), {
                code: 'enforcement_not_confirmed'
            });
        }
        if (!record.socketNotificationEmitted || !record.socketNotificationReceived) {
            throw Object.assign(new Error('Socket revocation notification was not confirmed.'), {
                code: 'socket_notification_not_confirmed'
            });
        }

        await waitForRevocationState(
            pool,
            redisClient,
            session,
            options.timeoutMs
        );
        record.redisRevocationConfirmed = true;
        record.postgresDeactivationConfirmed = true;
        await verifyProtectedApiDeniesSession(apiOrigin, session);
        record.success = true;
    } catch (error) {
        record.errorCode = error.code || 'benchmark_case_failed';
        record.httpStatus = error.httpStatus || null;
        if (serverResult) {
            record.riskScore = serverResult.riskScore;
            record.socketNotificationEmitted =
                serverResult.socketNotificationEmitted === true;
        }
        if (notification) {
            record.socketNotificationReceived = true;
        }
    } finally {
        if (t1) {
            createLatencyRecord(record, t1, serverResult, notification);
        }
        if (socket) {
            socket.disconnect();
        }
        if (session) {
            try {
                await cleanupBenchmarkSession(pool, redisClient, session);
            } catch {
                record.success = false;
                record.errorCode = 'session_cleanup_failed';
            }
        }
    }
    return record;
}

async function runRevocationBenchmark(args = process.argv.slice(2)) {
    loadBenchmarkEnvironment();
    const options = parseRevocationBenchmarkOptions(args);
    const userConfiguration = getBenchmarkUserConfiguration();
    const apiOrigin = getApiOrigin();
    const socketOrigin = getSocketOrigin();
    const context = await createDataClients();
    let resultsSubscriber = null;
    const records = [];

    try {
        await waitForHttpService(apiOrigin);
        const user = await findBenchmarkUser(context.pool, userConfiguration);
        resultsSubscriber = context.redisClient.duplicate();
        resultsSubscriber.on('error', () => {
            console.error('[Benchmark] Redis results subscriber error.');
        });
        await resultsSubscriber.connect();
        const resultsCollector = await createResultCollector(resultsSubscriber);
        const seenEventIds = new Set();
        const seenSessionJtis = new Set();

        for (let sequence = 1; sequence <= options.iterations; sequence += 1) {
            const record = await runRevocationCase({
                sequence,
                user,
                pool: context.pool,
                redisClient: context.redisClient,
                resultsCollector,
                apiOrigin,
                socketOrigin,
                options,
                seenEventIds,
                seenSessionJtis
            });
            records.push(record);
        }

        return {
            schemaVersion: 1,
            benchmark: 'caep-revocation',
            generatedAt: new Date().toISOString(),
            executionMode: process.env.BENCHMARK_EXECUTION_MODE || 'local',
            runtime: getRuntimeMetadata(),
            timing: {
                clock: 'process.hrtime.bigint',
                stages: {
                    eventProcessingMs: 'T2 - T1',
                    riskEvaluationMs: 'T3 - T2',
                    redisEnforcementMs: 'T4 - T3',
                    postgresDeactivationMs: 'T5 - T4',
                    socketEmissionMs: 'T6 - T5',
                    endToEndMs: 'T6 - T1',
                    socketClientReceiptMs: 'T7 - T1'
                },
                crossProcessClock:
                    'Run benchmark runner and backend on the same host clock domain.'
            },
            configuration: {
                iterations: options.iterations,
                timeoutMs: options.timeoutMs,
                sessionTtlSeconds: options.sessionTtlSeconds,
                dedicatedUserId: String(user.id),
                dedicatedUserEmail: user.email,
                apiOrigin,
                socketOrigin,
                eventType: 'TOKEN_HIJACKED'
            },
            summary: summarizeRevocationRecords(records),
            failuresByCode: records
                .filter((record) => !record.success)
                .reduce((counts, record) => {
                    counts[record.errorCode] = (counts[record.errorCode] || 0) + 1;
                    return counts;
                }, {}),
            records,
            cleanupSuccessful: !records.some(
                (record) => record.errorCode === 'session_cleanup_failed'
            )
        };
    } finally {
        if (resultsSubscriber?.isOpen) {
            await resultsSubscriber.unsubscribe(BENCHMARK_RESULTS_CHANNEL);
            await resultsSubscriber.quit();
        }
        if (context.redisClient.isOpen) {
            await context.redisClient.quit();
        }
        await context.pool.end();
    }
}

async function main(args) {
    try {
        const result = await runRevocationBenchmark(args);
        const resultPath = await writeBenchmarkResult(
            result,
            args.includes('--safe-report')
        );
        console.log(JSON.stringify({
            benchmark: result.benchmark,
            attempted: result.summary.attempted,
            succeeded: result.summary.succeeded,
            failed: result.summary.failed,
            latenciesMs: result.summary.latenciesMs,
            failuresByCode: result.failuresByCode,
            resultFile: resultPath
        }, null, 2));
        if (result.summary.failed > 0 || !result.cleanupSuccessful) {
            process.exitCode = 1;
        }
    } catch (error) {
        console.error('[Benchmark] CAEP revocation benchmark failed:', error.code || error.name);
        process.exitCode = 1;
    }
}

if (require.main === module) {
    main(process.argv.slice(2));
}

module.exports = {
    CAEP_CHANNEL,
    createResultCollector,
    createBenchmarkEvent,
    createLatencyRecord,
    runRevocationBenchmark,
    summarizeRevocationRecords,
    waitForRevocationState
};
