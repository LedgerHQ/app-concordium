#pragma once

#include <parser.h>

void processNextVerificationKey(void);

void handleSignCredentialDeployment(const command_t *cmd,
                                    volatile unsigned int *flags,
                                    bool isInitialCall);

/**
 * Handle signing an **update credentials** account transaction (`UPDATE_CREDENTIALS`).
 * Consumes the APDU stream by P1/P2 sub-steps (path, header, credential indices, IDs, threshold),
 * updates the transaction hash, and runs the approval UI until the user confirms or rejects.
 *
 * @param cmd            Parsed APDU (`command_t`: p1/p2/lc and cdata).
 * @param flags          BOLOS/UI flags for the asynchronous signing flow.
 * @param isInitialCall  True on the first handler call for this transaction (resets internal
 * state).
 */
void handleSignUpdateCredential(const command_t *cmd,
                                volatile unsigned int *flags,
                                bool isInitialCall);

typedef enum {
    TX_CREDENTIAL_DEPLOYMENT_INITIAL = 4,
    TX_CREDENTIAL_DEPLOYMENT_VERIFICATION_KEYS_LENGTH = 5,
    TX_CREDENTIAL_DEPLOYMENT_VERIFICATION_KEY = 6,
    TX_CREDENTIAL_DEPLOYMENT_SIGNATURE_THRESHOLD = 7,
    TX_CREDENTIAL_DEPLOYMENT_AR_IDENTITY = 8,
    TX_CREDENTIAL_DEPLOYMENT_CREDENTIAL_DATES = 9,
    TX_CREDENTIAL_DEPLOYMENT_ATTRIBUTE_TAG = 10,
    TX_CREDENTIAL_DEPLOYMENT_ATTRIBUTE_VALUE = 11,
    TX_CREDENTIAL_DEPLOYMENT_LENGTH_OF_PROOFS = 12,
    TX_CREDENTIAL_DEPLOYMENT_PROOFS = 13,
    TX_CREDENTIAL_DEPLOYMENT_NEW_OR_EXISTING = 14
} protocolState_t;

typedef enum {
    TX_UPDATE_CREDENTIAL_INITIAL = 0,
    TX_UPDATE_CREDENTIAL_CREDENTIAL_INDEX = 21,
    TX_UPDATE_CREDENTIAL_CREDENTIAL = 22,
    TX_UPDATE_CREDENTIAL_ID_COUNT = 23,
    TX_UPDATE_CREDENTIAL_ID = 24,
    TX_UPDATE_CREDENTIAL_THRESHOLD = 25
} updateCredentialState_t;

typedef struct {
    uint8_t type;
    uint8_t numberOfVerificationKeys;

    uint8_t credentialDeploymentCount;
    uint8_t credentialIdCount;
    char credentialId[102];
    uint8_t threshold[COMMON_THRESHOLD_SIZE];
    updateCredentialState_t updateCredentialState;

    char accountVerificationKey[68];
    uint8_t signatureThreshold[COMMON_THRESHOLD_SIZE];

    uint8_t anonymityRevocationThreshold[13];
    uint16_t anonymityRevocationListLength;

    char regIdCred[48 * 2 + 1];
    char identityProviderIndex[4 * 2 + 1];
    char arIdentity[4 * 2 + 1];
    char encIdCredPubShare[96 * 2 + 1];

    uint8_t validTo[COMMON_TIMESTAMP_SIZE];
    uint8_t createdAt[COMMON_TIMESTAMP_SIZE];

    uint16_t attributeListLength;

    cx_sha256_t attributeHash;
    uint8_t attributeValueLength;

    uint32_t proofLength;
    uint8_t accountAddress[57];

    protocolState_t state;
    bool showIntro;
} signCredentialDeploymentContext_t;
