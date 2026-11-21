'use strict';

const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');
const redisClient = require('../config/redis');

const SESSION_ROOM_PREFIX = 'session';
let ioInstance = null;
let initializedHttpServer = null;

function getSessionRoom(jti) {
    return `${SESSION_ROOM_PREFIX}:${jti}`;
}

function getSafeSessionRef(jti) {
    if (!jti) {
        return null;
    }

    return crypto.createHash('sha256').update(String(jti)).digest('hex').slice(0, 16);
}

function initializeSocketServer(httpServer, corsOrigin) {
    if (ioInstance) {
        if (initializedHttpServer !== httpServer) {
            throw new Error('Socket.IO has already been initialized for another HTTP server.');
        }
        return ioInstance;
    }

    const io = new Server(httpServer, {
        cors: {
            origin: corsOrigin,
            methods: ['GET', 'POST']
        }
    });

    io.use(async (socket, next) => {
        try {
            const authorization = socket.handshake.headers.authorization;
            const token = socket.handshake.auth?.token ||
                (authorization && authorization.startsWith('Bearer ')
                    ? authorization.slice('Bearer '.length)
                    : null);

            if (!token || !process.env.JWT_SECRET) {
                throw new Error('Authentication required.');
            }

            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            if (
                typeof decoded.jti !== 'string' ||
                !decoded.jti ||
                decoded.userId === undefined ||
                decoded.userId === null
            ) {
                throw new Error('Invalid session token.');
            }

            if (!redisClient.isOpen) {
                await redisClient.connect();
            }
            const revoked = await redisClient.exists(`revoked:jti:${decoded.jti}`);
            if (revoked) {
                throw new Error('Session revoked.');
            }

            socket.data.userId = decoded.userId;
            socket.data.jti = decoded.jti;
            socket.data.sessionRoom = getSessionRoom(decoded.jti);
            next();
        } catch (_error) {
            next(new Error('Unauthorized'));
        }
    });

    io.on('connection', (socket) => {
        socket.join(socket.data.sessionRoom);
    });

    ioInstance = io;
    initializedHttpServer = httpServer;
    return io;
}

function emitThreatEvent(event, riskScore, enforcementResult = {}) {
    if (!ioInstance) {
        return false;
    }

    try {
        const jti = event.subject?.jti;
        const timestamp = Number(event.timestamp);
        const severity = riskScore >= 70
            ? 'high'
            : riskScore >= 40
                ? 'medium'
                : 'low';

        ioInstance.emit('threat_event', {
            eventId: event.eventId || null,
            type: event.type,
            severity,
            riskScore,
            timestamp: Number.isFinite(timestamp)
                ? new Date(timestamp * 1000).toISOString()
                : new Date().toISOString(),
            sessionRef: getSafeSessionRef(jti),
            processingStatus: enforcementResult.revoked
                ? 'revoked'
                : enforcementResult.error
                    ? 'enforcement_failed'
                    : riskScore >= 70
                        ? 'not_revoked'
                        : 'allowed'
        });
        return true;
    } catch (error) {
        console.error('[Socket.IO] Failed to broadcast threat event:', error.message);
        return false;
    }
}

function emitSessionRevoked(jti, reason) {
    if (!ioInstance || !jti) {
        return false;
    }

    try {
        ioInstance.to(getSessionRoom(jti)).emit('session_revoked', {
            sessionRef: getSafeSessionRef(jti),
            action: 'REVOKE',
            reason,
            timestamp: new Date().toISOString()
        });
        return true;
    } catch (error) {
        console.error('[Socket.IO] Failed to notify revoked session:', error.message);
        return false;
    }
}

module.exports = {
    emitSessionRevoked,
    emitThreatEvent,
    getSessionRoom,
    initializeSocketServer
};
