#pragma once

#include <parser.h>

/** UI continuation after reviewing a verification key (implementation in
 * sign_credential_deployment.c). */
void processNextVerificationKey(void);

void handle_sign_credential_deployment(const command_t *cmd,
                                       volatile unsigned int *flags,
                                       bool isInitialCall);
