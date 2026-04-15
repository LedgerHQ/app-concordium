#pragma once

#include <parser.h>

#include "instruction_context.h"

void handle_sign_public_information_for_ip(const command_t *cmd,
                                           volatile unsigned int *flags,
                                           bool isInitialCall);
