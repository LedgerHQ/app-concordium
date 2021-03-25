#ifndef _CONCORDIUM_APP_UPDATE_BAKER_RESTAKE_EARNINGS_H_
#define _CONCORDIUM_APP_UPDATE_BAKER_RESTAKE_EARNINGS_H_

/**
 * Handles the signing flow, including updating the display, for the 'update baker restake earnings'
 * account transaction.
 * @param cdata please see /doc/ins_update_baker_restake_earnings
 */
void handleSignUpdateBakerRestakeEarnings(uint8_t *cdata, volatile unsigned int *flags);

#endif
