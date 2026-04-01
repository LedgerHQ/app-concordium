#pragma once

/**
 * Handles the DEPLOY_MODULE instruction, which deploys a module
 *
 *
 */
#include "globals.h"
#include <parser.h>

void handleDeployModule(const command_t *cmd);

typedef struct {
    uint32_t version;
    uint32_t sourceLength;
    uint32_t remainingSourceLength;
    uint8_t sourceHash[COMMON_HASH_SIZE];
    char sourceHashDisplay[COMMON_HASH_SIZE * 2 + 1];
    char versionDisplay[11];
} deployModule_t;
