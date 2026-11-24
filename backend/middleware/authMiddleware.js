const jwt = require("jsonwebtoken");
const { getSessionState } = require("../services/sessionVerifier");

const authMiddleware = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
            error: "Unauthorized",
            message: "No authentication token provided."
        });
    }

    let decoded;
    try {
        decoded = jwt.verify(
            authHeader.slice("Bearer ".length),
            process.env.JWT_SECRET
        );
    } catch {
        return res.status(401).json({
            error: "Unauthorized",
            message: "Invalid or expired token."
        });
    }

    if (
        !decoded ||
        typeof decoded !== "object" ||
        typeof decoded.jti !== "string" ||
        !decoded.jti ||
        decoded.userId === undefined ||
        decoded.userId === null
    ) {
        return res.status(401).json({
            error: "Unauthorized",
            message: "Invalid session token."
        });
    }

    let sessionState;
    try {
        sessionState = await getSessionState(decoded.jti, decoded.userId);
    } catch {
        console.error("[Authentication] Redis session verification failed.");
        return res.status(503).json({
            error: "Service Unavailable",
            message: "Authentication is temporarily unavailable. Please try again."
        });
    }

    if (sessionState === "revoked") {
        return res.status(401).json({
            error: "Session revoked",
            message:
                "Your session was terminated due to a security policy update."
        });
    }

    if (sessionState !== "active") {
        return res.status(401).json({
            error: "Unauthorized",
            message: "This session is no longer active."
        });
    }

    req.user = decoded;
    return next();
};

module.exports = authMiddleware;