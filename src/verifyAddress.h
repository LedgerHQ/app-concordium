#pragma once

/** P1 value for verify address: new path format (identityProvider/identity/account) */
#define P1_LEGACY_PATH 0x00
/** P1 value for verify address: new path format (identityProvider/identity/account) */
#define P1_NEW_PATH 0x01
/** P1 value for verify address: derivation-path format (<n> <node1>...<node n>) */
#define P1_FULL_PATH 0x02

#define P2_MAINNET_DEFAULT 0x00
#define P2_TESTNET         0x01

#define MAINNET true
#define TESTNET false

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
