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

#include "init_contract.h"

static initContract_t *ctx_init_contract = &global.initContract;
static tx_state_t *tx_state = &global_tx_state;

#define P1_INITIAL 0x00
#define P1_NAME    0x01
#define P1_PARAMS  0x02

void handle_init_contract(const command_t *cmd) {
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

        offset = hashAccountTransactionHeaderAndKind(cdata, remainingDataLength, INIT_CONTRACT);
        if (offset > lc) {
            THROW(SWO_INCORRECT_DATA);
        }
        cdata += offset;
        remainingDataLength -= offset;
        if (remainingDataLength < 8) {
            THROW(SWO_INCORRECT_DATA);
        }
        // hash the amount
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 8);
        // extract the amount
        ctx_init_contract->amount = U8BE(cdata, 0);
        // Format the amount
        amount_to_gtu_display((uint8_t *) ctx_init_contract->amountDisplay,
                              sizeof(ctx_init_contract->amountDisplay),
                              ctx_init_contract->amount);
        cdata += 8;
        remainingDataLength -= 8;
        if (remainingDataLength < 32) {
            THROW(SWO_INCORRECT_DATA);
        }
        // hash the module ref
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 32);
        // extract the module ref
        memmove(ctx_init_contract->moduleRef, cdata, 32);
        // Format the module ref
        if (format_hex(ctx_init_contract->moduleRef, 32, ctx_init_contract->moduleRefDisplay, 65) ==
            -1) {
            THROW(ERROR_INVALID_MODULE_REF);
        }
        ctx_init_contract->state = INIT_CONTRACT_NAME_FIRST;
        send_success_no_idle();
    }

    else if (p1 == P1_NAME) {
        uint8_t lengthSize = 2;
        if (ctx_init_contract->state == INIT_CONTRACT_NAME_FIRST) {
            // extract the name length
            if (lc < 2) {
                THROW(SWO_INCORRECT_DATA);
            }
            ctx_init_contract->nameLength = U2BE(cdata, 0);
            // calculate the remaining name length
            ctx_init_contract->remainingNameLength = ctx_init_contract->nameLength + lengthSize;
            // set the state to the next state
            ctx_init_contract->state = INIT_CONTRACT_NAME_NEXT;
        } else if (ctx_init_contract->remainingNameLength < lc) {
            THROW(ERROR_INVALID_NAME_LENGTH);
        }
        // hash the whole chunk
        update_hash((cx_hash_t *) &tx_state->hash, cdata, lc);
        // subtract the length of the chunk from the remaining name length
        ctx_init_contract->remainingNameLength -= lc;
        if (ctx_init_contract->remainingNameLength > 0) {
            send_success_no_idle();
        } else if (ctx_init_contract->remainingNameLength == 0) {
            ctx_init_contract->state = INIT_CONTRACT_PARAMS_FIRST;
            send_success_no_idle();
        }

    } else if (p1 == P1_PARAMS) {
        uint8_t lengthSize = 2;
        if (ctx_init_contract->state == INIT_CONTRACT_PARAMS_FIRST) {
            // extract the params length
            if (lc < 2) {
                THROW(SWO_INCORRECT_DATA);
            }
            ctx_init_contract->paramsLength = U2BE(cdata, 0);
            // calculate the remaining params length
            ctx_init_contract->remainingParamsLength = ctx_init_contract->paramsLength + lengthSize;
            // set the state to the next state
            ctx_init_contract->state = INIT_CONTRACT_PARAMS_NEXT;
        } else if (ctx_init_contract->remainingParamsLength < lc) {
            THROW(ERROR_INVALID_PARAMS_LENGTH);
        }
        // hash the whole chunk
        update_hash((cx_hash_t *) &tx_state->hash, cdata, lc);
        // subtract the length of the chunk from the remaining params length
        ctx_init_contract->remainingParamsLength -= lc;
        if (ctx_init_contract->remainingParamsLength > 0) {
            send_success_no_idle();
        } else if (ctx_init_contract->remainingParamsLength == 0) {
            uiInitContractDisplay();
        }

    } else {
        THROW(ERROR_INVALID_STATE);
    }
}