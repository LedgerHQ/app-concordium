#pragma once

#include <parser.h>

#include "instruction_context.h"

void handle_sign_transfer_to_public(const command_t *cmd,
                                    volatile unsigned int *flags,
                                    bool isInitialCall);
