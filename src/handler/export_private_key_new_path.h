#pragma once

#include <parser.h>

void handle_export_private_key_new_path(const command_t *cmd, volatile unsigned int *flags);

/**
 * Export identity-related private keys (legacy and new paths). P1/P2 and buffer sizes: macros in
 * `instruction_context.h`.
 */

int exportNewPathPrivateKeysForPurpose(uint8_t purpose,
                                       uint8_t networkDesignation,
                                       uint32_t identityProvider,
                                       uint32_t identity,
                                       uint32_t account,
                                       uint8_t *outputPrivateKey,
                                       size_t outputPrivateKeySize);