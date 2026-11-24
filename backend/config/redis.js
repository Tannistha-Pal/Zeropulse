'use strict';

const redis = require('redis');

const redisClient = redis.createClient({
    url: `redis://${process.env.REDIS_HOST || 'localhost'}:${process.env.REDIS_PORT || 6379}`,
    socket: {
        connectTimeout: 5000
    }
});

let connectionPromise = null;

redisClient.on('connect', () => {
    console.log('Redis connected');
});

redisClient.on('ready', () => {
    console.log('Redis ready');
});

redisClient.on('error', () => {
    console.error('Redis connection error.');
});

redisClient.on('end', () => {
    console.log('Redis connection closed');
});

async function connectRedis() {
    if (redisClient.isReady) {
        return;
    }
    if (connectionPromise) {
        return connectionPromise;
    }
    if (redisClient.isOpen) {
        return;
    }

    connectionPromise = redisClient.connect().finally(() => {
        connectionPromise = null;
    });

    return connectionPromise;
}

module.exports = redisClient;
module.exports.connectRedis = connectRedis;