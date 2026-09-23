#pragma once

#include <parser.h>

void handle_export_private_key_new_path(const command_t *cmd, volatile unsigned int *flags);

/**
 * Export identity-related private keys (legacy and new paths). P1/P2 and buffer sizes: macros in
 * `instruction_context.h`.
 *
 * Reports failure through `sw` rather than by throwing, because the caller is a UI approval
 * callback: dispatch_guarded() in app_main.c wraps the dispatch only, so a status word escaping
 * this function would unwind to the SDK handler and exit the app. A BOLOS system exception is
 * still propagated - those are genuine faults the SDK has to see.
 *
 * @param sw  set to SWO_SUCCESS on success, otherwise the status word to answer the host with.
 * @return    bytes written to `outputPrivateKey`; 0 whenever `*sw != SWO_SUCCESS`, with the
 *            buffer already wiped.
 */
int exportNewPathPrivateKeysForPurpose(uint8_t purpose,
                                       uint8_t networkDesignation,
                                       uint32_t identityProvider,
                                       uint32_t identity,
                                       uint32_t account,
                                       uint8_t *outputPrivateKey,
                                       size_t outputPrivateKeySize,
                                       uint16_t *sw);