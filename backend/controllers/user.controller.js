const pool = require("../config/db");
const { getSafeSessionRef, getThreatEvents } = require("../services/socketService");

const getProfile = async (req, res) => {
    res.json({
        message: "Protected profile accessed successfully",
        user: req.user
    });
};

const getDashboardSummary = async (req, res) => {
    res.json({
        message: "Dashboard summary accessed successfully",
        data: {
            activeSessions: 1,
            securityStatus: "Protected",
            riskLevel: "Low",
            lastSecurityCheck: new Date().toISOString()
        }
    });
};

const getSessions = async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT jwt_jti, ip_address, user_agent, device_id, created_at, is_active
             FROM sessions
             WHERE user_id = $1
             ORDER BY created_at DESC`,
            [req.user.userId]
        );

        return res.json({
            sessions: result.rows.map((session) => ({
                sessionRef: getSafeSessionRef(session.jwt_jti),
                ipAddress: session.ip_address,
                deviceInfo: session.user_agent,
                deviceId: session.device_id,
                loginTime: session.created_at,
                status: session.is_active ? "ACTIVE" : "REVOKED"
            }))
        });
    } catch (error) {
        console.error("Session list error:", error.message);
        return res.status(500).json({
            message: "Failed to retrieve sessions"
        });
    }
};

const getRecentThreatEvents = async (_req, res) => {
    return res.json({
        events: getThreatEvents()
    });
};

module.exports = {
    getProfile,
    getDashboardSummary,
    getSessions,
    getRecentThreatEvents
};