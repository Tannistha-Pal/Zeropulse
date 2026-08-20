const express = require("express");

const {
    getProfile,
    getDashboardSummary
} = require("../controllers/user.controller");

const authMiddleware = require("../middleware/authMiddleware");

const router = express.Router();

router.get("/profile", authMiddleware, getProfile);

router.get(
    "/dashboard/summary",
    authMiddleware,
    getDashboardSummary
);

module.exports = router;