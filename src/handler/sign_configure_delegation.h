#pragma once

#include <parser.h>

#include "instruction_context.h"

void handle_sign_configure_delegation(const command_t *cmd, volatile unsigned int *flags);
