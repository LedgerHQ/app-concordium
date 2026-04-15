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

#include "deploy_module.h"

static deployModule_t *ctx_deploy_module = &global.deployModule;
static tx_state_t *tx_state = &global_tx_state;

#define P1_INITIAL 0x00
#define P1_SOURCE  0x01

void handle_deploy_module(const command_t *cmd) {
    uint8_t *cdata = cmd->data;
    uint8_t p1 = cmd->p1;
    uint8_t lc = cmd->lc;

    if (p1 == P1_INITIAL) {
        if (cx_sha256_init(&tx_state->hash) != CX_SHA256) {
            THROW(ERROR_FAILED_CX_OPERATION);
        }
        size_t offset = parse_derivation_path(cdata, lc);
        if (offset > lc) {
            THROW(SWO_INCORRECT_DATA);
        }
        cdata += offset;
        uint8_t remainingDataLength = lc - offset;

        offset = hashAccountTransactionHeaderAndKind(cdata, remainingDataLength, DEPLOY_MODULE);
        if (offset > lc) {
            THROW(SWO_INCORRECT_DATA);
        }
        cdata += offset;
        remainingDataLength -= offset;
        // hash the version and source length
        if (remainingDataLength < 8) {
            THROW(SWO_INCORRECT_DATA);
        }
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 8);
        ctx_deploy_module->version = U4BE(cdata, 0);
        ctx_deploy_module->sourceLength = U4BE(cdata, 4);
        ctx_deploy_module->remainingSourceLength = ctx_deploy_module->sourceLength;

        number_to_text((uint8_t *) ctx_deploy_module->versionDisplay,
                       sizeof(ctx_deploy_module->versionDisplay),
                       ctx_deploy_module->version);
        send_success_no_idle();
    }

    else if (p1 == P1_SOURCE && ctx_deploy_module->remainingSourceLength > 0) {
        if (ctx_deploy_module->remainingSourceLength < lc) {
            THROW(ERROR_INVALID_SOURCE_LENGTH);
        }
        update_hash((cx_hash_t *) &tx_state->hash, cdata, lc);
        ctx_deploy_module->remainingSourceLength -= lc;
        if (ctx_deploy_module->remainingSourceLength > 0) {
            send_success_no_idle();
        } else if (ctx_deploy_module->remainingSourceLength == 0) {
            uiDeployModuleDisplay();
        }

    } else {
        THROW(ERROR_INVALID_STATE);
    }
}