#ifndef _CONCORDIUM_APP_ACCOUNT_TRANSFER_H_
#define _CONCORDIUM_APP_ACCOUNT_TRANSFER_H_

/**
 * Handles the signing flow, including updating the display, for the 'simple transfer'
 * account transaction.
 * @param cdata please see /doc/ins_transfer.md for details
 */
void handleSignTransfer(uint8_t *cdata, volatile unsigned int *flags);

#endif
