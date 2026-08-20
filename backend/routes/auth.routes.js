const express = require("express");

const {
    login,
    revokeSession
} = require("../controllers/auth.controller");

const authMiddleware = require("../middleware/authMiddleware");

const router = express.Router();

// Login
router.post("/login", login);

// Revoke current session
router.post(
    "/revoke-session",
    authMiddleware,
    revokeSession
);

module.exports = router;