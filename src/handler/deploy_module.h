#pragma once

#include <parser.h>
#include <stdbool.h>
#include <stdint.h>

#include "instruction_context.h"

void handle_deploy_module(const command_t *cmd, bool isInitialCall);
