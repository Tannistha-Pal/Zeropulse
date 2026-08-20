const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");

const pool = require("../config/db");
const redisClient = require("../config/redis");

const login = async (req, res) => {
    try {
        const { email, password } = req.body;

        // 1. Validate input
        if (!email || !password) {
            return res.status(400).json({
                message: "Email and password are required"
            });
        }

        // 2. Find user in PostgreSQL
        const result = await pool.query(
            "SELECT id, email, password_hash, role FROM users WHERE email = $1",
            [email]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }

        const user = result.rows[0];

        // 3. Verify password using bcrypt
        const passwordMatch = await bcrypt.compare(
            password,
            user.password_hash
        );

        if (!passwordMatch) {
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }

        // 4. Generate unique JWT ID
        const jti = uuidv4();

        // 5. Get basic request information
        const ipAddress = req.ip;
        const userAgent = req.get("user-agent") || "Unknown";
        const deviceId = req.get("x-device-id") || null;

        // 6. Session expiration
        const expiresAt = new Date(
            Date.now() + 60 * 60 * 1000
        );

        // 7. Insert session into PostgreSQL
        await pool.query(
            `INSERT INTO sessions
            (user_id, jwt_jti, ip_address, user_agent, device_id, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6)`,
            [
                user.id,
                jti,
                ipAddress,
                userAgent,
                deviceId,
                expiresAt
            ]
        );

        // 8. Store active session in Redis
        const sessionData = {
            userId: user.id,
            ip: ipAddress,
            isActive: true
        };

        await redisClient.set(
            `session:${jti}`,
            JSON.stringify(sessionData),
            {
                EX: 60 * 60
            }
        );

        // 9. Generate JWT
        const token = jwt.sign(
            {
                jti: jti,
                userId: user.id,
                role: user.role
            },
            process.env.JWT_SECRET,
            {
                expiresIn: process.env.JWT_EXPIRES_IN || "1h"
            }
        );

        // 10. Return token
        res.status(200).json({
            message: "Login successful",
            token: token,
            user: {
                id: user.id,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        console.error("Login error:", error);

        res.status(500).json({
            message: "Internal server error"
        });
    }
};

const revokeSession = async (req, res) => {
    try {
        // Get jti from the verified JWT
        const jti = req.user.jti;

        if (!jti) {
            return res.status(400).json({
                message: "Session ID (jti) not found in token"
            });
        }

        // Calculate remaining JWT lifetime in seconds
        const currentTime = Math.floor(Date.now() / 1000);
        const remainingTTL = req.user.exp - currentTime;

        if (remainingTTL <= 0) {
            return res.status(401).json({
                message: "Session has already expired"
            });
        }

        // Add JWT to Redis revocation list
        await redisClient.setEx(
            `revoked:jti:${jti}`,
            remainingTTL,
            "revoked"
        );

        // Mark session as inactive in PostgreSQL
        await pool.query(
            `UPDATE sessions
             SET is_active = FALSE
             WHERE jwt_jti = $1
             AND user_id = $2`,
            [jti, req.user.userId]
        );

        return res.status(200).json({
            message: "Session revoked successfully",
            jti: jti
        });

    } catch (error) {
        console.error("Session revocation error:", error);

        return res.status(500).json({
            message: "Failed to revoke session"
        });
    }
};

module.exports = {
    login,
    revokeSession
};