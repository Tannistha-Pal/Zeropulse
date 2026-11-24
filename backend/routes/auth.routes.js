const express = require("express");

const {
    login,
    revokeSession
} = require("../controllers/auth.controller");

const authMiddleware = require("../middleware/authMiddleware");
const {
    loginRateLimiter,
    sessionRevocationRateLimiter
} = require("../middleware/rateLimiters");

const router = express.Router();

// Login
router.post("/login", loginRateLimiter, login);

// Revoke current session
router.post(
    "/revoke-session",
    authMiddleware,
    sessionRevocationRateLimiter,
    revokeSession
);

module.exports = router;