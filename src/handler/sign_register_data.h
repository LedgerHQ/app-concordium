#pragma once

#include <parser.h>
#include <stdbool.h>

void handle_sign_register_data(const command_t *cmd,
                               volatile unsigned int *flags,
                               bool isInitialCall);
