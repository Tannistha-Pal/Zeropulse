const { createCaepEvent } = require('./caepEventBuilder');

const event = createCaepEvent(
    "FIREWALL_STATE_CHANGE",
    {
        userId: "test-user",
        sessionId: "test-session",
        jti: "test-jti-123"
    },
    {
        profile: "Public",
        from: "ON",
        to: "OFF",
        source: "ThreatSimulator",
        platform: "win32"
    }
);

console.log(event);