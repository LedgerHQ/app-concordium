#include "globals.h"

#include <os.h>
#include <cx.h>
#include <io.h>
#include <parser.h>
#include <status_words.h>

#include "apdu/apdu_response.h"
#include "concordium_crypto.h"
#include "derivation_path.h"
#include "display.h"
#include "numberHelpers.h"
#include "tx_hash.h"

#include "sign_credential_deployment.h"

static signCredentialDeploymentContext_t *ctx = &global.signCredentialDeploymentContext;
static tx_state_t *tx_state = &global_tx_state;

#define P2_CREDENTIAL_INITIAL          0x00
#define P2_CREDENTIAL_CREDENTIAL_INDEX 0x01
#define P2_CREDENTIAL_CREDENTIAL       0x02
#define P2_CREDENTIAL_ID_COUNT         0x03
#define P2_CREDENTIAL_ID               0x04
#define P2_THRESHOLD                   0x05

void handle_sign_update_credential(const command_t *cmd,
                                   volatile unsigned int *flags,
                                   bool isInitialCall) {
    uint8_t *dataBuffer = cmd->data;
    uint8_t p1 = cmd->p1;
    uint8_t p2 = cmd->p2;
    uint8_t lc = cmd->lc;

    if (isInitialCall) {
        ctx->updateCredentialState = TX_UPDATE_CREDENTIAL_INITIAL;
    }
    uint8_t remainingDataLength = lc;
    if (p2 == P2_CREDENTIAL_INITIAL && ctx->updateCredentialState == TX_UPDATE_CREDENTIAL_INITIAL) {
        uint8_t offset = parse_derivation_path(dataBuffer, remainingDataLength);
        dataBuffer += offset;
        remainingDataLength -= offset;

        if (cx_sha256_init(&tx_state->hash) != CX_SHA256) {
            THROW(ERROR_FAILED_CX_OPERATION);
        }
        offset = hashAccountTransactionHeaderAndKind(dataBuffer,
                                                     remainingDataLength,
                                                     UPDATE_CREDENTIALS);
        dataBuffer += offset;
        remainingDataLength -= offset;

        if (remainingDataLength < 1) {
            THROW(SWO_INCORRECT_DATA);
        }
        ctx->credentialDeploymentCount = dataBuffer[0];
        update_hash((cx_hash_t *) &tx_state->hash, dataBuffer, 1);
        if (ctx->credentialDeploymentCount == 0) {
            ctx->updateCredentialState = TX_UPDATE_CREDENTIAL_ID_COUNT;
        } else {
            ctx->updateCredentialState = TX_UPDATE_CREDENTIAL_CREDENTIAL_INDEX;
        }

        uiSignUpdateCredentialInitialDisplay(flags);

    } else if (p2 == P2_CREDENTIAL_CREDENTIAL_INDEX &&
               ctx->updateCredentialState == TX_UPDATE_CREDENTIAL_CREDENTIAL_INDEX &&
               ctx->credentialDeploymentCount > 0) {
        if (remainingDataLength < 1) {
            THROW(SWO_INCORRECT_DATA);
        }
        update_hash((cx_hash_t *) &tx_state->hash, dataBuffer, 1);
        ctx->updateCredentialState = TX_UPDATE_CREDENTIAL_CREDENTIAL;
        ctx->state = TX_CREDENTIAL_DEPLOYMENT_VERIFICATION_KEYS_LENGTH;
        send_success_no_idle();
    } else if (p2 == P2_CREDENTIAL_CREDENTIAL &&
               ctx->updateCredentialState == TX_UPDATE_CREDENTIAL_CREDENTIAL &&
               ctx->credentialDeploymentCount > 0) {
        command_t sub =
            {.cla = cmd->cla, .ins = cmd->ins, .p1 = p1, .p2 = p2, .lc = lc, .data = dataBuffer};
        handle_sign_credential_deployment(&sub, flags, false);
    } else if (p2 == P2_CREDENTIAL_ID_COUNT &&
               ctx->updateCredentialState == TX_UPDATE_CREDENTIAL_ID_COUNT) {
        if (remainingDataLength < 1) {
            THROW(SWO_INCORRECT_DATA);
        }
        ctx->credentialIdCount = dataBuffer[0];
        update_hash((cx_hash_t *) &tx_state->hash, dataBuffer, 1);

        if (ctx->credentialIdCount == 0) {
            ctx->updateCredentialState = TX_UPDATE_CREDENTIAL_THRESHOLD;
        } else {
            ctx->updateCredentialState = TX_UPDATE_CREDENTIAL_ID;
        }
        send_success_no_idle();
    } else if (p2 == P2_CREDENTIAL_ID && ctx->updateCredentialState == TX_UPDATE_CREDENTIAL_ID) {
        if (remainingDataLength < 48) {
            THROW(SWO_INCORRECT_DATA);
        }
        update_hash((cx_hash_t *) &tx_state->hash, dataBuffer, 48);
        to_paginated_hex(dataBuffer, 48, ctx->credentialId, sizeof(ctx->credentialId));

        ctx->credentialIdCount -= 1;
        if (ctx->credentialIdCount == 0) {
            ctx->updateCredentialState = TX_UPDATE_CREDENTIAL_THRESHOLD;
        }

        uiSignUpdateCredentialIdDisplay(flags);

    } else if (p2 == P2_THRESHOLD && ctx->updateCredentialState == TX_UPDATE_CREDENTIAL_THRESHOLD) {
        if (remainingDataLength < 1) {
            THROW(SWO_INCORRECT_DATA);
        }
        uint8_t threshold = dataBuffer[0];
        bin_to_dec(ctx->threshold, sizeof(ctx->threshold), threshold);
        update_hash((cx_hash_t *) &tx_state->hash, dataBuffer, 1);

        uiSignUpdateCredentialThresholdDisplay(flags);

    } else {
        THROW(ERROR_INVALID_STATE);
    }
}
