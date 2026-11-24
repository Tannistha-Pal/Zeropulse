const test = require('node:test');
const assert = require('node:assert/strict');
const {
    assertDedicatedBenchmarkEmail,
    calculateMetrics,
    durationMs,
    parseApiBenchmarkOptions,
    parseRevocationBenchmarkOptions,
    sanitizeBenchmarkReport
} = require('../benchmark/benchmarkUtils');

test('API benchmark defaults to exactly 1,000 requests and supports duration mode', () => {
    assert.deepEqual(parseApiBenchmarkOptions([], {}), {
        requests: 1000,
        concurrency: 100,
        durationSeconds: null,
        safeReport: false
    });
    assert.deepEqual(
        parseApiBenchmarkOptions(['--duration', '15'], {
            BENCHMARK_REQUESTS: '0',
            BENCHMARK_CONCURRENCY: '8'
        }),
        {
            requests: null,
            concurrency: 8,
            durationSeconds: 15,
            safeReport: false
        }
    );
});

test('revocation benchmark allows only 20 to 50 dedicated event trials', () => {
    assert.equal(parseRevocationBenchmarkOptions([], {}).iterations, 20);
    assert.equal(parseRevocationBenchmarkOptions(['--iterations', '50'], {}).iterations, 50);
    assert.throws(
        () => parseRevocationBenchmarkOptions(['--iterations', '19'], {}),
        /between 20 and 50/
    );
});

test('benchmark account guard rejects any non-reserved identity', () => {
    assert.equal(
        assertDedicatedBenchmarkEmail('ZeroPulse-Benchmark@example.invalid'),
        'zeropulse-benchmark@example.invalid'
    );
    assert.throws(
        () => assertDedicatedBenchmarkEmail('real-user@example.com'),
        /dedicated zeropulse-benchmark/
    );
});

test('latency metrics report percentiles and ignore invalid values', () => {
    const metrics = calculateMetrics([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, -1, NaN]);
    assert.equal(metrics.count, 10);
    assert.equal(metrics.min, 1);
    assert.equal(metrics.average, 5.5);
    assert.equal(metrics.median, 5.5);
    assert.equal(metrics.p95, 10);
    assert.equal(metrics.p99, 10);
    assert.equal(metrics.max, 10);
    assert.equal(durationMs('1000000', '3000000'), 2);
    assert.equal(durationMs('3000000', '1000000'), null);
});

test('safe reports exclude account identifiers, origins, and event/session IDs', () => {
    const result = {
        schemaVersion: 1,
        benchmark: 'caep-revocation',
        generatedAt: '2026-01-01T00:00:00.000Z',
        executionMode: 'docker',
        runtime: { nodeVersion: 'v22.0.0', platform: 'linux', architecture: 'x64' },
        timing: { clock: 'process.hrtime.bigint' },
        configuration: {
            iterations: 20,
            timeoutMs: 10000,
            sessionTtlSeconds: 1800,
            eventType: 'TOKEN_HIJACKED',
            dedicatedUserId: '123',
            dedicatedUserEmail: 'zeropulse-benchmark@example.invalid',
            apiOrigin: 'http://frontend',
            socketOrigin: 'http://backend:5000'
        },
        summary: { attempted: 20, succeeded: 20, failed: 0 },
        failuresByCode: {},
        records: [{
            sequence: 1,
            success: true,
            eventId: 'private-event-id',
            jti: 'private-session-id',
            runId: 'private-run-id',
            latenciesMs: { endToEndMs: 1 }
        }]
    };
    const safeReport = sanitizeBenchmarkReport(result);
    const serialized = JSON.stringify(safeReport);
    assert.equal(serialized.includes('example.invalid'), false);
    assert.equal(serialized.includes('private-event-id'), false);
    assert.equal(serialized.includes('private-session-id'), false);
    assert.equal(serialized.includes('private-run-id'), false);
    assert.equal(serialized.includes('http://backend'), false);
    assert.equal(safeReport.records[0].success, true);
    assert.deepEqual(safeReport.records[0].latenciesMs, { endToEndMs: 1 });
});
