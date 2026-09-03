#pragma once

#include <parser.h>

/** UI continuation after reviewing a verification key (implementation in
 * sign_credential_deployment.c). */
void processNextVerificationKey(void);

/** UI continuation after the user confirms an added credential in an update-credential
 * transaction. Advances to the next credential (or to the credential-ID count) and acknowledges
 * the APDU, so an added credential can never be signed without having been displayed. */
void confirmAddedCredential(void);

void handle_sign_credential_deployment(const command_t *cmd,
                                       volatile unsigned int *flags,
                                       bool isInitialCall);
