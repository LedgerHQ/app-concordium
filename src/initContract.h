#pragma once
#include "globals.h"
#include <parser.h>

typedef enum {
    INIT_CONTRACT_INITIAL = 60,
    INIT_CONTRACT_NAME_FIRST = 61,
    INIT_CONTRACT_NAME_NEXT = 62,
    INIT_CONTRACT_PARAMS_FIRST = 63,
    INIT_CONTRACT_PARAMS_NEXT = 64,
    INIT_CONTRACT_END = 65
} initContractState_t;

/**
 * Handles the INIT_CONTRACT instruction, which initializes a contract
 *
 *
 */
void handleInitContract(const command_t *cmd);

typedef struct {
    uint64_t amount;
    uint8_t moduleRef[COMMON_MODULE_REF_SIZE];
    char amountDisplay[COMMON_AMOUNT_DISPLAY_SIZE];
    char moduleRefDisplay[COMMON_MODULE_REF_SIZE * 2 + 1];
    uint32_t nameLength;
    uint32_t remainingNameLength;
    uint32_t paramsLength;
    uint32_t remainingParamsLength;
    initContractState_t state;
} initContract_t;
