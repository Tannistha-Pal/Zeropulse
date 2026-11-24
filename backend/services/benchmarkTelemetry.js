'use strict';

const BENCHMARK_RESULTS_CHANNEL = 'caep:benchmark_results';
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isBenchmarkMetadata(metadata) {
    return Boolean(
        metadata &&
        typeof metadata === 'object' &&
        UUID_PATTERN.test(metadata.runId) &&
        typeof metadata.publishedAtNs === 'string' &&
        /^\d+$/.test(metadata.publishedAtNs)
    );
}

async function publishBenchmarkResult(redisClient, event, result) {
    if (!isBenchmarkMetadata(event.benchmark)) {
        return;
    }

    await redisClient.publish(BENCHMARK_RESULTS_CHANNEL, JSON.stringify({
        runId: event.benchmark.runId,
        eventId: event.eventId,
        jti: event.subject?.jti || null,
        publishedAtNs: event.benchmark.publishedAtNs,
        ...result
    }));
}

module.exports = {
    BENCHMARK_RESULTS_CHANNEL,
    isBenchmarkMetadata,
    publishBenchmarkResult
};
