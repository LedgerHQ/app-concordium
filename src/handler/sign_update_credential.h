#pragma once

#include <parser.h>

void handle_sign_update_credential(const command_t *cmd,
                                   volatile unsigned int *flags,
                                   bool isInitialCall);
