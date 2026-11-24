const test = require('node:test');
const assert = require('node:assert/strict');
const { runApiLoad } = require('../benchmark/apiBenchmark');

test('API load runner sends the configured count and classifies non-200 responses', async () => {
    const statuses = [200, 401, 429, 503];
    let requestCount = 0;
    const result = await runApiLoad({
        apiOrigin: 'http://example.test',
        requests: statuses.length,
        concurrency: statuses.length,
        durationSeconds: null
    }, {
        token: 'test-only-token',
        fetchImpl: async (url, options) => {
            assert.equal(url, 'http://example.test/api/user/profile');
            assert.equal(options.headers.Authorization, 'Bearer test-only-token');
            const status = statuses[requestCount];
            requestCount += 1;
            return { status, async arrayBuffer() { return new ArrayBuffer(0); } };
        }
    });

    assert.equal(requestCount, statuses.length);
    assert.equal(result.totalRequests, statuses.length);
    assert.equal(result.successfulRequests, 1);
    assert.equal(result.failedRequests, 3);
    assert.deepEqual(result.statusCodes, { 200: 1, 401: 1, 429: 1, 503: 1 });
    assert.deepEqual(result.errorCategories, {
        unauthorized: 1,
        rate_limited: 1,
        server_error: 1
    });
    assert.equal(result.latencyMs.count, 4);
    assert.equal(result.responseLatencyMs.count, 4);
    assert.equal(result.successfulResponseLatencyMs.count, 1);
});

test('API load runner completes an exact 1,000-request fixed-count run', async () => {
    let requestCount = 0;
    const result = await runApiLoad({
        apiOrigin: 'http://example.test',
        requests: 1000,
        concurrency: 32,
        durationSeconds: null
    }, {
        token: 'test-only-token',
        fetchImpl: async () => {
            requestCount += 1;
            return { status: 200, async arrayBuffer() { return new ArrayBuffer(0); } };
        }
    });

    assert.equal(requestCount, 1000);
    assert.equal(result.totalRequests, 1000);
    assert.equal(result.successfulRequests, 1000);
    assert.equal(result.failedRequests, 0);
});
