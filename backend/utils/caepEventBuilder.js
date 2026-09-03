'use strict';

function createCaepEvent(eventType, sessionInfo, details) {
    const event = {
        specversion: "1.0",

        event_type:
            `https://schemas.openid.net/secevent/caep/event-type/${eventType}`,

        jti: `evt_${Date.now()}`,

        event_timestamp: Math.floor(Date.now() / 1000),

        subject: {
            format: "complex",
            user: sessionInfo.userId,
            session: sessionInfo.sessionId,
            jti: sessionInfo.jti
        },

        event_data: details
    };

    return JSON.stringify(event);
}

module.exports = {
    createCaepEvent
};