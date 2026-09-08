#pragma once

#include <stdbool.h>

#include "instruction_context.h"

/** True if any commission-rate field is present (used by UI review flows). */
bool hasCommissionRate(void);

void handle_sign_configure_baker(const command_t *cmd,
                                 volatile unsigned int *flags,
                                 bool isInitialCall);

/**
 * Release the stage parked while a review was on screen and ask the host for the next packet.
 * Wired to the "Continue with transaction" control of every intermediate baker review.
 */
void confirmConfigureBakerStage(void);
