'use strict';

function parseCaepEvent(rawMessage) {
    let event;

    // 1. Convert JSON string into object
    try {
        event = typeof rawMessage === 'string'
            ? JSON.parse(rawMessage)
            : rawMessage;
    } catch (error) {
        throw new Error('Invalid CAEP event JSON');
    }

    // 2. Validate basic event structure
    if (!event || typeof event !== 'object') {
        throw new Error('CAEP event must be an object');
    }

    if (!event.event_type) {
    throw new Error('CAEP event type is missing');
    }

    // 3. Normalize the event
    const eventType = event.event_type;
    const eventTypeName = eventType.includes('/')
        ? eventType.substring(eventType.lastIndexOf('/') + 1)
        : eventType;

    return {
    type: eventTypeName,
    eventId: event.jti || null,
    source: event.event_data?.source || 'unknown',
    platform: event.event_data?.platform || 'unknown',
    timestamp: event.event_timestamp || null,

    subject: event.subject || null,

    details: {
        ...(event.event_data || {})
    }
};
}

module.exports = {
    parseCaepEvent
};