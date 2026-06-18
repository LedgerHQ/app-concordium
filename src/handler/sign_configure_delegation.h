#pragma once

#include <parser.h>
#include <stdbool.h>

#include "instruction_context.h"

void handle_sign_configure_delegation(const command_t *cmd,
                                      bool isInitialCall,
                                      volatile unsigned int *flags);
