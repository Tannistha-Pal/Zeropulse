const { createClient } = require("redis");

const redisClient = createClient({
    socket: {
        host: process.env.REDIS_HOST || "localhost",
        port: Number(process.env.REDIS_PORT) || 6379,
    },
});

redisClient.on("connect", () => {
    console.log("Redis connected");
});

redisClient.on("ready", () => {
    console.log("Redis ready");
});

redisClient.on("error", (error) => {
    console.error("Redis error:", error);
});

module.exports = redisClient;