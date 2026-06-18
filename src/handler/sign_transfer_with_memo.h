#pragma once

#include <parser.h>
#include <stdbool.h>

void handle_sign_transfer_with_memo(const command_t *cmd,
                                    volatile unsigned int *flags,
                                    bool isInitialCall);
