'use strict';

const { rateLimit } = require('express-rate-limit');

const loginRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    handler(_req, res) {
        res.status(429).json({
            error: 'Too many requests',
            message: 'Too many login attempts. Please try again later.'
        });
    }
});

const sessionRevocationRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    handler(_req, res) {
        res.status(429).json({
            error: 'Too many requests',
            message: 'Too many session revocation attempts. Please try again later.'
        });
    }
});

module.exports = {
    loginRateLimiter,
    sessionRevocationRateLimiter
};
