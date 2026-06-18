#pragma once

#include <parser.h>
#include <stdbool.h>

#include "instruction_context.h"

void handle_update_contract(const command_t *cmd, bool isInitialCall);
