#include "globals.h"

#include <os.h>
#include <cx.h>
#include <io.h>
#include <parser.h>
#include <status_words.h>
#include <format.h>

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

void handle_deploy_module(const command_t *cmd, bool isInitialCall) {
    uint8_t *cdata = cmd->data;
    uint8_t p1 = cmd->p1;
    uint8_t lc = cmd->lc;

    if (p1 == P1_INITIAL && isInitialCall) {
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
        if (offset > remainingDataLength) {
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

        // Digest the module source separately from the transaction hash, so the code being
        // deployed can be shown on the approval screen rather than only its version.
        if (cx_sha256_init(&ctx_deploy_module->sourceHashCtx) != CX_SHA256) {
            THROW(ERROR_FAILED_CX_OPERATION);
        }
        explicit_bzero(ctx_deploy_module->sourceHashDisplay,
                       sizeof(ctx_deploy_module->sourceHashDisplay));

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
        update_hash((cx_hash_t *) &ctx_deploy_module->sourceHashCtx, cdata, lc);
        ctx_deploy_module->remainingSourceLength -= lc;
        if (ctx_deploy_module->remainingSourceLength > 0) {
            send_success_no_idle();
        } else if (ctx_deploy_module->remainingSourceLength == 0) {
            // Finalise the source digest and render it for the approval screen.
            hash((cx_hash_t *) &ctx_deploy_module->sourceHashCtx,
                 CX_LAST,
                 NULL,
                 0,
                 ctx_deploy_module->sourceHash,
                 sizeof(ctx_deploy_module->sourceHash));
            if (format_hex(ctx_deploy_module->sourceHash,
                           sizeof(ctx_deploy_module->sourceHash),
                           ctx_deploy_module->sourceHashDisplay,
                           sizeof(ctx_deploy_module->sourceHashDisplay)) == -1) {
                THROW(ERROR_BUFFER_OVERFLOW);
            }
            uiDeployModuleDisplay();
        }

    } else {
        THROW(ERROR_INVALID_STATE);
    }
}