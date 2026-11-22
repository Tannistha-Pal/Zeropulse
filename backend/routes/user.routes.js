const express = require("express");

const {
    getProfile,
    getDashboardSummary,
    getSessions,
    getRecentThreatEvents
} = require("../controllers/user.controller");

const authMiddleware = require("../middleware/authMiddleware");

const router = express.Router();

router.get("/profile", authMiddleware, getProfile);

router.get(
    "/dashboard/summary",
    authMiddleware,
    getDashboardSummary
);

router.get("/sessions", authMiddleware, getSessions);

router.get("/threat-events", authMiddleware, getRecentThreatEvents);

module.exports = router;