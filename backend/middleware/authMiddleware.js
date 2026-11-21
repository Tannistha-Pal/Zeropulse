const jwt = require("jsonwebtoken");
const redisClient = require("../config/redis");

const authMiddleware = async (req, res, next) => {
    try {
        // 1. Get Authorization header
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                error: "Unauthorized",
                message: "No authentication token provided."
            });
        }

        // 2. Extract JWT
        const token = authHeader.split(" ")[1];

        // 3. Verify JWT
        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        // 4. Extract jti from JWT
        const jti = decoded.jti;

        if (!jti) {
            return res.status(401).json({
                error: "Unauthorized",
                message: "Invalid session token."
            });
        }

        // 5. Check Redis revocation list
        if (!redisClient.isOpen) {
            await redisClient.connect();
        }
        const revoked = await redisClient.exists(
            `revoked:jti:${jti}`
        );

        // 6. If session has been revoked
        if (revoked) {
            return res.status(401).json({
                error: "Session revoked",
                message:
                    "Your session was terminated due to a security policy update."
            });
        }

        // 7. Attach decoded JWT information to request
        req.user = decoded;

        // 8. Allow request to continue
        next();

    } catch (error) {
        console.error("Auth middleware error:", error.message);

        return res.status(401).json({
            error: "Unauthorized",
            message: "Invalid or expired token."
        });
    }
};

module.exports = authMiddleware;