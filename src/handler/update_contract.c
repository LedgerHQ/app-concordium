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

#include "update_contract.h"

static updateContract_t *ctx_update_contract = &global.updateContract;
static tx_state_t *tx_state = &global_tx_state;

#define P1_INITIAL 0x00
#define P1_NAME    0x01
#define P1_PARAMS  0x02

void handle_update_contract(const command_t *cmd, bool isInitialCall) {
    uint8_t *cdata = cmd->data;
    uint8_t p1 = cmd->p1;
    uint8_t lc = cmd->lc;

    uint8_t remainingDataLength = lc;
    if (p1 == P1_INITIAL && isInitialCall) {
        if (cx_sha256_init(&tx_state->hash) != CX_SHA256) {
            THROW(ERROR_FAILED_CX_OPERATION);
        }
        size_t offset = parse_derivation_path(cdata, lc);
        if (offset > lc) {
            THROW(SWO_INCORRECT_DATA);
        }
        cdata += offset;
        remainingDataLength -= offset;
        offset = hashAccountTransactionHeaderAndKind(cdata, remainingDataLength, UPDATE_CONTRACT);
        if (offset > lc) {
            THROW(SWO_INCORRECT_DATA);
        }
        cdata += offset;
        remainingDataLength -= offset;
        // hash the amount
        if (remainingDataLength < 8) {
            THROW(SWO_INCORRECT_DATA);
        }
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 8);
        // extract the amount
        ctx_update_contract->amount = U8BE(cdata, 0);
        // Format the amount
        amount_to_ccd_display((uint8_t *) ctx_update_contract->amountDisplay,
                              sizeof(ctx_update_contract->amountDisplay),
                              ctx_update_contract->amount);
        cdata += 8;
        remainingDataLength -= 8;
        // hash the index
        if (remainingDataLength < 8) {
            THROW(SWO_INCORRECT_DATA);
        }
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 8);
        // extract the index
        uint64_t index = U8BE(cdata, 0);
        // format the index
        number_to_text((uint8_t *) ctx_update_contract->indexDisplay,
                       sizeof(ctx_update_contract->indexDisplay),
                       index);
        cdata += 8;
        remainingDataLength -= 8;

        // hash the sub index
        if (remainingDataLength < 8) {
            THROW(SWO_INCORRECT_DATA);
        }
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 8);
        // extract the sub index
        uint64_t subIndex = U8BE(cdata, 0);
        // format the sub index
        number_to_text((uint8_t *) ctx_update_contract->subIndexDisplay,
                       sizeof(ctx_update_contract->subIndexDisplay),
                       subIndex);

        ctx_update_contract->state = UPDATE_CONTRACT_NAME_FIRST;
        send_success_no_idle();
    }

    else if (p1 == P1_NAME) {
        uint8_t lengthSize = 2;
        if (ctx_update_contract->state == UPDATE_CONTRACT_NAME_FIRST) {
            // extract the name length
            if (lc < 2) {
                THROW(SWO_INCORRECT_DATA);
            }
            ctx_update_contract->nameLength = U2BE(cdata, 0);
            // calculate the remaining name length
            ctx_update_contract->remainingNameLength = ctx_update_contract->nameLength + lengthSize;
            // set the state to the next state
            ctx_update_contract->state = UPDATE_CONTRACT_NAME_NEXT;
        } else if (ctx_update_contract->remainingNameLength < lc) {
            THROW(ERROR_INVALID_NAME_LENGTH);
        }
        // hash the whole chunk
        update_hash((cx_hash_t *) &tx_state->hash, cdata, lc);
        // subtract the length of the chunk from the remaining name length
        ctx_update_contract->remainingNameLength -= lc;
        if (ctx_update_contract->remainingNameLength > 0) {
            send_success_no_idle();
        } else if (ctx_update_contract->remainingNameLength == 0) {
            ctx_update_contract->state = UPDATE_CONTRACT_PARAMS_FIRST;
            send_success_no_idle();
        }

    } else if (p1 == P1_PARAMS) {
        uint8_t lengthSize = 2;
        if (ctx_update_contract->state == UPDATE_CONTRACT_PARAMS_FIRST) {
            // extract the params length
            if (lc < 2) {
                THROW(SWO_INCORRECT_DATA);
            }
            ctx_update_contract->paramsLength = U2BE(cdata, 0);
            // calculate the remaining params length
            ctx_update_contract->remainingParamsLength =
                ctx_update_contract->paramsLength + lengthSize;
            // set the state to the next state
            ctx_update_contract->state = UPDATE_CONTRACT_PARAMS_NEXT;
        } else if (ctx_update_contract->remainingParamsLength < lc) {
            THROW(ERROR_INVALID_PARAMS_LENGTH);
        }
        // hash the whole chunk
        update_hash((cx_hash_t *) &tx_state->hash, cdata, lc);
        // subtract the length of the chunk from the remaining params length
        ctx_update_contract->remainingParamsLength -= lc;
        if (ctx_update_contract->remainingParamsLength > 0) {
            send_success_no_idle();
        } else if (ctx_update_contract->remainingParamsLength == 0) {
            uiUpdateContractDisplay();
        }

    } else {
        THROW(ERROR_INVALID_STATE);
    }
}