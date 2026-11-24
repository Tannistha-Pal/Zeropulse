'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const pool = require('../config/db');
const redisClient = require('../config/redis');
const {
    server,
    shutdown,
    registerShutdownHandlers
} = require('../server');
const {
    startCaepSubscriber
} = require('../services/caepSubscriber');

test('SIGTERM shutdown closes HTTP, CAEP, Redis, and PostgreSQL in order and runs once', async () => {
    const order = [];
    const subscriber = {
        isOpen: true,
        on() {},
        async connect() {},
        async subscribe() {},
        async unsubscribe() { order.push('subscriber-unsubscribe'); },
        async quit() {
            order.push('subscriber-quit');
            this.isOpen = false;
        },
        destroy() { this.isOpen = false; }
    };

    const originalDuplicate = redisClient.duplicate;
    const originalQuit = redisClient.quit;
    const originalEnd = pool.end;
    const originalIsOpen = Object.getOwnPropertyDescriptor(redisClient, 'isOpen');
    redisClient.duplicate = () => subscriber;
    redisClient.quit = async () => { order.push('redis-quit'); };
    pool.end = async () => { order.push('postgres-end'); };
    Object.defineProperty(redisClient, 'isOpen', {
        configurable: true,
        value: true
    });

    try {
        await startCaepSubscriber();
        await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
        registerShutdownHandlers();
        process.emit('SIGTERM');
        const firstShutdown = shutdown('SIGTERM');
        const duplicateShutdown = shutdown('SIGTERM');

        assert.strictEqual(firstShutdown, duplicateShutdown);
        await firstShutdown;
        assert.equal(server.listening, false);
        assert.ok(order.indexOf('subscriber-quit') < order.indexOf('redis-quit'));
        assert.ok(order.indexOf('redis-quit') < order.indexOf('postgres-end'));
    } finally {
        redisClient.duplicate = originalDuplicate;
        redisClient.quit = originalQuit;
        pool.end = originalEnd;
        if (originalIsOpen) {
            Object.defineProperty(redisClient, 'isOpen', originalIsOpen);
        } else {
            delete redisClient.isOpen;
        }
    }
});
