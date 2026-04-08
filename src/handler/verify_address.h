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

#include <parser.h>

#include <cx.h>

#include "derivation_path.h"
#include "instruction_context.h"

cx_err_t getCredId(uint8_t *prf,
                   size_t prfSize,
                   uint32_t credCounter,
                   uint8_t *credId,
                   size_t credIdSize);

void verify_address_parse_key_path(uint8_t *cdata,
                                   uint8_t p1,
                                   uint8_t p2,
                                   uint8_t lc,
                                   derivation_path_t *derivation_path,
                                   uint32_t *cred_counter);

/** UI flow for address verification; implemented in `ui/display_*.c`. */
void uiVerifyAddress(volatile unsigned int *flags);

/** INS handler; implementation in `verify_address.c`. */
void handle_verify_address(const command_t *cmd, volatile unsigned int *flags);
