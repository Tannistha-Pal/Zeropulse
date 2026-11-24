'use strict';

const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');
const { getSessionState } = require('./sessionVerifier');

const SESSION_ROOM_PREFIX = 'session';
const MAX_THREAT_EVENTS = 100;
let ioInstance = null;
let initializedHttpServer = null;
const threatEvents = [];

function getSessionRoom(jti) {
    return `${SESSION_ROOM_PREFIX}:${jti}`;
}

function getSafeSessionRef(jti) {
    if (!jti) {
        return null;
    }

    return crypto.createHash('sha256').update(String(jti)).digest('hex').slice(0, 16);
}

function getThreatEvents(limit = 50) {
    const safeLimit = Math.min(Math.max(Number.parseInt(limit, 10) || 50, 1), MAX_THREAT_EVENTS);
    return threatEvents.slice(0, safeLimit);
}

function getThreatEventKey(event) {
    return event.eventId || [
        event.type,
        event.timestamp,
        event.sessionRef
    ].join(':');
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

            const sessionState = await getSessionState(decoded.jti, decoded.userId);
            if (sessionState !== 'active') {
                throw new Error('Session is not active.');
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

        const threatEvent = {
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
        };
        const eventKey = getThreatEventKey(threatEvent);
        if (!threatEvents.some((item) => getThreatEventKey(item) === eventKey)) {
            threatEvents.unshift(threatEvent);
            if (threatEvents.length > MAX_THREAT_EVENTS) {
                threatEvents.length = MAX_THREAT_EVENTS;
            }
        }
        ioInstance.emit('threat_event', threatEvent);
        return true;
    } catch (_error) {
        console.error('[Socket.IO] Failed to broadcast threat event.');
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
    } catch (_error) {
        console.error('[Socket.IO] Failed to notify revoked session.');
        return false;
    }
}

module.exports = {
    emitSessionRevoked,
    emitThreatEvent,
    getSessionRoom,
    getSafeSessionRef,
    getThreatEvents,
    initializeSocketServer
};
