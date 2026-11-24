const test = require('node:test');
const assert = require('node:assert/strict');
const {
    createBenchmarkEvent,
    createLatencyRecord
} = require('../benchmark/revocationBenchmark');
const { summarizeRevocationRecords } = require('../benchmark/benchmarkUtils');
const { parseCaepEvent } = require('../services/caepEventParser');

test('revocation benchmark creates unique CAEP events targeting its dedicated session', () => {
    const user = { id: '42' };
    const session = { jti: 'dedicated-session-jti' };
    const first = createBenchmarkEvent(
        user,
        session,
        'c3b4e8d8-1899-4ad0-9f06-3fb103c9ab7f',
        'd9d4c6de-155e-4e8d-92c7-ea9fa96af972'
    );
    const second = createBenchmarkEvent(
        user,
        session,
        '15106709-d8a6-4f3d-aed0-e0430d35e7bf',
        'd260e26d-8a30-4ddb-a6f1-43891a527932'
    );
    const parsed = parseCaepEvent(first);

    assert.equal(parsed.type, 'TOKEN_HIJACKED');
    assert.equal(parsed.subject.user, '42');
    assert.equal(parsed.subject.jti, session.jti);
    assert.notEqual(first.jti, second.jti);
    assert.notEqual(first.benchmark.runId, second.benchmark.runId);
});

test('revocation stage timing uses monotonic T1 through T7 timestamps', () => {
    const record = {};
    createLatencyRecord(record, '1000000000', {
        receivedAtNs: '1010000000',
        riskEvaluationCompletedAtNs: '1012000000',
        benchmarkTimings: {
            redisRevocationCompletedAtNs: '1020000000',
            postgresDeactivationCompletedAtNs: '1030000000',
            socketEmissionCompletedAtNs: '1040000000'
        }
    }, { receivedAtNs: '1050000000' });

    assert.deepEqual(record.latenciesMs, {
        eventProcessingMs: 10,
        riskEvaluationMs: 2,
        redisEnforcementMs: 8,
        postgresDeactivationMs: 10,
        socketEmissionMs: 10,
        endToEndMs: 40,
        socketClientReceiptMs: 50
    });
});

test('revocation aggregates keep failed attempts visible without folding them into success latency', () => {
    const summary = summarizeRevocationRecords([
        {
            success: true,
            latenciesMs: {
                eventProcessingMs: 10,
                riskEvaluationMs: 2,
                redisEnforcementMs: 8,
                postgresDeactivationMs: 10,
                socketEmissionMs: 20,
                endToEndMs: 40,
                socketClientReceiptMs: 50
            }
        },
        {
            success: false,
            latenciesMs: {
                eventProcessingMs: null,
                riskEvaluationMs: null,
                redisEnforcementMs: null,
                postgresDeactivationMs: null,
                socketEmissionMs: null,
                endToEndMs: null,
                socketClientReceiptMs: null
            }
        }
    ]);

    assert.equal(summary.attempted, 2);
    assert.equal(summary.succeeded, 1);
    assert.equal(summary.failed, 1);
    assert.equal(summary.latenciesMs.endToEndMs.count, 1);
    assert.equal(summary.latenciesMs.endToEndMs.average, 40);
});
