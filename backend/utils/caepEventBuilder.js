'use strict';

function createCaepEvent(eventType, sessionInfo, details) {
    return JSON.stringify({
        specversion: "1.0",

        event_type:
            `https://schemas.openid.net/secevent/caep/event-type/${eventType}`,

        jti: `evt_${Date.now()}`,

        event_timestamp: Math.floor(Date.now() / 1000),

        subject: {
            format: "complex",
            user: sessionInfo.userId || "unknown",
            session: sessionInfo.sessionId || "unknown",
            jti: sessionInfo.jti || "unknown"
        },

        event_data: details
    });
}

module.exports = {
    createCaepEvent
};