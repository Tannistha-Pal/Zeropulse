'use strict';

const redis = require('redis');

const redisClient = redis.createClient({
    url: `redis://${process.env.REDIS_HOST || 'localhost'}:${process.env.REDIS_PORT || 6379}`
});

redisClient.on('connect', () => {
    console.log('Redis connected');
});

redisClient.on('ready', () => {
    console.log('Redis ready');
});

redisClient.on('error', (err) => {
    console.error('Redis error:', err.message);
});

redisClient.on('end', () => {
    console.log('Redis connection closed');
});

async function connectRedis() {
    if (!redisClient.isOpen) {
        await redisClient.connect();
    }
}

module.exports = redisClient;
module.exports.connectRedis = connectRedis;