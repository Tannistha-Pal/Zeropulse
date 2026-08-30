'use strict';

function calculateRiskScore(event) {
    const eventType = event.details?.type;

    switch (eventType) {
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