require("dotenv").config();

const express = require("express");
const cors = require("cors");

const pool = require("./config/db");
const redisClient = require("./config/redis");

const authRoutes = require("./routes/auth.routes");
const userRoutes = require("./routes/user.routes");

const app = express();


// ================================
// Middleware
// ================================

app.use(
    cors({
        origin: "http://localhost:5173",
        methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allowedHeaders: [
            "Content-Type",
            "Authorization",
            "x-device-id"
        ]
    })
);

app.use(express.json());


// ================================
// Basic API Route
// ================================

app.get("/", (req, res) => {
    res.json({
        message: "ZeroPulse API is running"
    });
});


// ================================
// Database Test Route
// ================================

app.get("/api/test-db", async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT id, email, role FROM users"
        );

        res.json({
            message: "PostgreSQL connection successful",
            users: result.rows
        });

    } catch (error) {
        console.error("Database error:", error);

        res.status(500).json({
            message: "Database connection failed"
        });
    }
});


// ================================
// Authentication Routes
// ================================

app.use("/api/auth", authRoutes);


// ================================
// Protected User Routes
// ================================

app.use("/api/user", userRoutes);


// ================================
// Server
// ================================

const PORT = process.env.PORT || 5000;

async function startServer() {
    try {

        // Connect to Redis
        if (!redisClient.isOpen) {
            await redisClient.connect();
        }

        console.log("Redis connected");

        // Start Express server
        app.listen(PORT, () => {
            console.log(
                `ZeroPulse API running on http://localhost:${PORT}`
            );
        });

    } catch (error) {
        console.error("Failed to start server:", error);
        process.exit(1);
    }
}

startServer();