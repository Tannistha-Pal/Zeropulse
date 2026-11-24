const test = require('node:test');
const assert = require('node:assert/strict');
const { parseCaepEvent } = require('../services/caepEventParser');
const {
    BENCHMARK_RESULTS_CHANNEL,
    publishBenchmarkResult
} = require('../services/benchmarkTelemetry');

const runId = 'c3b4e8d8-1899-4ad0-9f06-3fb103c9ab7f';

test('CAEP parser retains only well-formed benchmark timing metadata', () => {
    const event = {
        event_type: 'https://schemas.openid.net/secevent/caep/event-type/TOKEN_HIJACKED',
        jti: 'event-1',
        subject: { jti: 'session-1' },
        event_data: { type: 'TOKEN_HIJACKED' },
        benchmark: { runId, publishedAtNs: '123456789' }
    };
    assert.deepEqual(parseCaepEvent(event).benchmark, event.benchmark);
    assert.equal(
        parseCaepEvent({ ...event, benchmark: { runId: 'invalid', publishedAtNs: '1' } }).benchmark,
        null
    );
});

test('benchmark outcomes publish only to the internal benchmark result channel', async () => {
    const event = parseCaepEvent({
        event_type: 'TOKEN_HIJACKED',
        jti: 'event-1',
        subject: { jti: 'session-1' },
        event_data: { type: 'TOKEN_HIJACKED' },
        benchmark: { runId, publishedAtNs: '123456789' }
    });
    let published;
    await publishBenchmarkResult({
        async publish(channel, message) {
            published = { channel, result: JSON.parse(message) };
        }
    }, event, { revoked: true });

    assert.equal(published.channel, BENCHMARK_RESULTS_CHANNEL);
    assert.equal(published.result.eventId, 'event-1');
    assert.equal(published.result.jti, 'session-1');
    assert.equal(published.result.revoked, true);
});
