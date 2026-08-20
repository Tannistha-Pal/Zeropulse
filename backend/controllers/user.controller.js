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

module.exports = {
    getProfile,
    getDashboardSummary
};