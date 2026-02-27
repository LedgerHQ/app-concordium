#pragma once

/** P1 value for verify address: new path format (identityProvider/identity/account) */
#define P1_VERIFY_NEW_PATH 0x01

void handleVerifyAddress(uint8_t *cdata,
                         uint8_t p1,
                         uint8_t p2,
                         uint8_t lc,
                         volatile unsigned int *flags);

typedef struct {
    uint8_t display[21];
    unsigned char address[57];
} verifyAddressContext_t;

void uiVerifyAddress(volatile unsigned int *flags);
