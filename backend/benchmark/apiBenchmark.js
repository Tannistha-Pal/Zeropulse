'use strict';

const {
    calculateMetrics,
    cleanupBenchmarkSession,
    createDataClients,
    findBenchmarkUser,
    getApiOrigin,
    getBenchmarkUserConfiguration,
    getRuntimeMetadata,
    loadBenchmarkEnvironment,
    parseApiBenchmarkOptions,
    verifyBenchmarkToken,
    waitForHttpService,
    writeBenchmarkResult
} = require('./benchmarkUtils');

const PROFILE_PATH = '/api/user/profile';

async function runApiLoad(config, {
    fetchImpl = fetch,
    token,
    endpoint = new URL(PROFILE_PATH, config.apiOrigin).toString()
}) {
    const startedAtNs = process.hrtime.bigint();
    const deadlineNs = config.durationSeconds
        ? startedAtNs + BigInt(config.durationSeconds) * 1_000_000_000n
        : null;
    const requestLatencies = [];
    const responseLatencies = [];
    const successfulResponseLatencies = [];
    const statusCodes = {};
    const errorCategories = {};
    let nextRequest = 0;
    let failedRequests = 0;

    async function worker() {
        while (true) {
            if (deadlineNs && process.hrtime.bigint() >= deadlineNs) {
                return;
            }
            const requestIndex = nextRequest;
            if (config.requests !== null && requestIndex >= config.requests) {
                return;
            }
            nextRequest += 1;

            const requestStartedAtNs = process.hrtime.bigint();
            try {
                const response = await fetchImpl(endpoint, {
                    method: 'GET',
                    headers: { Authorization: `Bearer ${token}` },
                    signal: AbortSignal.timeout(config.requestTimeoutMs || 15000)
                });
                await response.arrayBuffer();
                const latency = Number(
                    process.hrtime.bigint() - requestStartedAtNs
                ) / 1e6;
                requestLatencies.push(latency);
                responseLatencies.push(latency);
                const status = String(response.status);
                statusCodes[status] = (statusCodes[status] || 0) + 1;
                if (response.status === 200) {
                    successfulResponseLatencies.push(latency);
                } else {
                    failedRequests += 1;
                    const category = response.status === 401
                        ? 'unauthorized'
                        : response.status === 429
                            ? 'rate_limited'
                            : response.status >= 500
                                ? 'server_error'
                                : 'unexpected_status';
                    errorCategories[category] =
                        (errorCategories[category] || 0) + 1;
                }
            } catch {
                requestLatencies.push(Number(
                    process.hrtime.bigint() - requestStartedAtNs
                ) / 1e6);
                failedRequests += 1;
                errorCategories.network_error =
                    (errorCategories.network_error || 0) + 1;
            }
        }
    }

    const workerCount = config.requests === null
        ? config.concurrency
        : Math.min(config.concurrency, config.requests);
    await Promise.all(Array.from({ length: workerCount }, () => worker()));

    const finishedAtNs = process.hrtime.bigint();
    const totalRequests = Object.values(statusCodes)
        .reduce((sum, count) => sum + count, 0) +
        (errorCategories.network_error || 0);
    const elapsedSeconds = Number(finishedAtNs - startedAtNs) / 1e9;
    return {
        totalRequests,
        successfulRequests: totalRequests - failedRequests,
        failedRequests,
        elapsedSeconds,
        requestsPerSecond: elapsedSeconds > 0
            ? totalRequests / elapsedSeconds
            : 0,
        successfulRequestsPerSecond: elapsedSeconds > 0
            ? (totalRequests - failedRequests) / elapsedSeconds
            : 0,
        errorRatePercent: totalRequests
            ? failedRequests / totalRequests * 100
            : 0,
        latencyMs: calculateMetrics(requestLatencies),
        responseLatencyMs: calculateMetrics(responseLatencies),
        successfulResponseLatencyMs: calculateMetrics(successfulResponseLatencies),
        statusCodes,
        errorCategories
    };
}

async function runApiBenchmark(args = process.argv.slice(2)) {
    loadBenchmarkEnvironment();
    const options = parseApiBenchmarkOptions(args);
    const apiOrigin = getApiOrigin();
    const userConfiguration = getBenchmarkUserConfiguration();
    const token = process.env.BENCHMARK_JWT;
    const context = await createDataClients();
    let identity = null;
    let runMetrics = null;
    let cleanupSuccessful = true;
    let result = null;

    try {
        await waitForHttpService(apiOrigin);
        const user = await findBenchmarkUser(context.pool, userConfiguration);
        identity = await verifyBenchmarkToken(
            context.pool,
            context.redisClient,
            token,
            userConfiguration
        );
        runMetrics = await runApiLoad({
            ...options,
            apiOrigin,
            endpoint: new URL(PROFILE_PATH, apiOrigin).toString()
        }, { token });
        result = {
            schemaVersion: 1,
            benchmark: 'api-load',
            generatedAt: new Date().toISOString(),
            executionMode: process.env.BENCHMARK_EXECUTION_MODE || 'local',
            runtime: getRuntimeMetadata(),
            timing: {
                clock: 'process.hrtime.bigint',
                measuredEndpoint: PROFILE_PATH,
                latencyPopulation: {
                    allRequests: 'Includes HTTP responses and network failures',
                    responseLatency: 'Requests with an HTTP response',
                    successfulResponseLatency: 'HTTP 200 responses'
                }
            },
            configuration: {
                requestCount: options.requests,
                durationSeconds: options.durationSeconds,
                concurrency: options.concurrency,
                apiOrigin,
                endpointPath: PROFILE_PATH,
                dedicatedUserId: String(user.id),
                dedicatedUserEmail: user.email,
                validActiveJwtVerified: true
            },
            metrics: {
                ...runMetrics,
                latencyMs: runMetrics.latencyMs,
                statusCode401Count: Number(runMetrics.statusCodes['401'] || 0),
                statusCode429Count: Number(runMetrics.statusCodes['429'] || 0),
                statusCode5xxCount: Object.entries(runMetrics.statusCodes)
                    .filter(([status]) => Number(status) >= 500)
                    .reduce((sum, [, count]) => sum + count, 0)
            },
            statusCodes: runMetrics.statusCodes,
            errorCategories: runMetrics.errorCategories,
            cleanupSuccessful
        };
    } finally {
        if (identity) {
            try {
                await cleanupBenchmarkSession(context.pool, context.redisClient, {
                    ...identity
                });
            } catch {
                cleanupSuccessful = false;
                console.error('[Benchmark] Dedicated API session cleanup failed.');
            }
        }
        if (context.redisClient.isOpen) {
            await context.redisClient.quit();
        }
        await context.pool.end();
    }
    result.cleanupSuccessful = cleanupSuccessful;
    return result;
}

async function main(args) {
    try {
        const result = await runApiBenchmark(args);
        const safeReport = args.includes('--safe-report');
        const resultPath = await writeBenchmarkResult(result, safeReport);
        console.log(JSON.stringify({
            benchmark: result.benchmark,
            requests: result.metrics.totalRequests,
            successful: result.metrics.successfulRequests,
            failed: result.metrics.failedRequests,
            requestsPerSecond: result.metrics.requestsPerSecond,
            latencyMs: result.metrics.latencyMs,
            resultFile: resultPath
        }, null, 2));
        if (result.metrics.failedRequests > 0 || !result.cleanupSuccessful) {
            process.exitCode = 1;
        }
    } catch (error) {
        console.error('[Benchmark] API benchmark failed:', error.code || error.name);
        process.exitCode = 1;
    }
}

if (require.main === module) {
    main(process.argv.slice(2));
}

module.exports = { PROFILE_PATH, runApiBenchmark, runApiLoad };
