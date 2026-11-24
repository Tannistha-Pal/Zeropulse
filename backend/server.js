require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const { createServer } = require("node:http");

const pool = require("./config/db");
const redisClient = require("./config/redis");
const { connectRedis } = require("./config/redis");

const authRoutes = require("./routes/auth.routes");
const userRoutes = require("./routes/user.routes");
const { startCaepSubscriber, stopCaepSubscriber } = require("./services/caepSubscriber");
const { initializeSocketServer } = require("./services/socketService");
const { validateEnv } = require("./config/validateEnv");

const app = express();
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "http://localhost:5173";
const server = createServer(app);
const io = initializeSocketServer(server, FRONTEND_ORIGIN);
const SHUTDOWN_TIMEOUT_MS = 10000;
let shutdownPromise = null;


// ================================
// Middleware
// ================================

// Compose places one Nginx proxy immediately in front of this service.
app.set("trust proxy", 1);
app.use(helmet());

app.use(
    cors({
        origin: FRONTEND_ORIGIN,
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

    } catch (_error) {
        console.error("Database query failed.");

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

function listen(port) {
    return new Promise((resolve, reject) => {
        const handleError = (error) => {
            server.off("listening", handleListening);
            reject(error);
        };
        const handleListening = () => {
            server.off("error", handleError);
            resolve();
        };

        server.once("error", handleError);
        server.once("listening", handleListening);
        server.listen(port);
    });
}

function withTimeout(promise, timeoutMs, operation) {
    let timer;
    return Promise.race([
        promise,
        new Promise((_, reject) => {
            timer = setTimeout(
                () => reject(new Error(`${operation} timed out.`)),
                timeoutMs
            );
        })
    ]).finally(() => clearTimeout(timer));
}

async function runShutdownStep(name, operation) {
    try {
        await withTimeout(operation(), SHUTDOWN_TIMEOUT_MS, name);
        console.log(`[Shutdown] ${name} complete.`);
        return true;
    } catch {
        console.error(`[Shutdown] ${name} failed or timed out.`);
        return false;
    }
}

function shutdown(signal = "shutdown") {
    if (shutdownPromise) {
        return shutdownPromise;
    }

    shutdownPromise = (async () => {
        console.log(`[Shutdown] Received ${signal}; stopping ZeroPulse.`);
        let successful = true;

        const httpClose = server.listening
            ? new Promise((resolve, reject) => {
                server.close((error) => error ? reject(error) : resolve());
            })
            : Promise.resolve();

        successful = await runShutdownStep(
            "HTTP and Socket.IO shutdown",
            async () => {
                await io.close();
                await httpClose;
            }
        ) && successful;

        successful = await runShutdownStep(
            "CAEP subscriber shutdown",
            stopCaepSubscriber
        ) && successful;

        successful = await runShutdownStep(
            "Redis shutdown",
            async () => {
                if (redisClient.isOpen) {
                    await redisClient.quit();
                }
            }
        ) && successful;

        successful = await runShutdownStep(
            "PostgreSQL pool shutdown",
            () => pool.end()
        ) && successful;

        if (!successful) {
            if (typeof server.closeAllConnections === "function") {
                server.closeAllConnections();
            }
            if (redisClient.isOpen && typeof redisClient.destroy === "function") {
                redisClient.destroy();
            }
            process.exitCode = 1;
            return;
        }

        console.log("[Shutdown] ZeroPulse stopped cleanly.");
    })();

    return shutdownPromise;
}

function registerShutdownHandlers() {
    for (const signal of ["SIGINT", "SIGTERM"]) {
        process.once(signal, () => {
            shutdown(signal).catch(() => {
                console.error("[Shutdown] Unexpected shutdown failure.");
                process.exitCode = 1;
            });
        });
    }
}

async function startServer() {
    try {
        const { port } = validateEnv();
        await connectRedis();

        console.log("Redis connected");
        await startCaepSubscriber();
        console.log("CAEP subscriber started");

        await listen(port);
        console.log(`ZeroPulse API listening on port ${port}`);
        return true;

    } catch (error) {
        if (error.name === "EnvironmentValidationError") {
            console.error(error.message);
        } else {
            console.error("Backend startup failed because a required dependency is unavailable.");
        }
        process.exitCode = 1;
        await shutdown("startup failure");
        return false;
    }
}

if (require.main === module) {
    registerShutdownHandlers();
    startServer();
}

module.exports = {
    app,
    io,
    server,
    startServer,
    shutdown,
    registerShutdownHandlers
};