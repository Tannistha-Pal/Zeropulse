'use strict';

function calculateRiskScore(event) {
    const eventType = event.details?.type ||
        event.type?.substring(event.type.lastIndexOf('/') + 1);

    switch (eventType) {
        // Week 4 simulator events use the same `event_data.type` field as
        // events emitted by the endpoint agent.  Keep these explicit so the
        // simulator is an additional producer, not a parallel event schema.
        case 'FIREWALL_DISABLED':
            return 85;

        case 'IMPOSSIBLE_TRAVEL':
            return 90;

        case 'VPN_DETECTED':
            return 55;

        case 'TOKEN_HIJACKED':
            return 95;

        case 'FIREWALL_STATE_CHANGE':
            if (event.details?.to === 'OFF') {
                return 85;
            }
            return 0;

        case 'IP_ADDRESS_CHANGE':
            return 40;

        case 'GATEWAY_CHANGE':
            return 30;

        case 'PROCESS_COUNT_CHANGE':
            return 20;

        default:
            return 0;
    }
}

module.exports = {
    calculateRiskScore
};
