#include "globals.h"

#include <string.h>

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

void handle_init_contract(const command_t *cmd, bool isInitialCall) {
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

        offset = hashAccountTransactionHeaderAndKind(cdata, remainingDataLength, INIT_CONTRACT);
        if (offset > remainingDataLength) {
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
        amount_to_ccd_display((uint8_t *) ctx_init_contract->amountDisplay,
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
        // The contract name and parameters are hashed into the signed transaction, so both have
        // to reach the approval screen. Parameters are arbitrary binary, so they are digested.
        explicit_bzero(ctx_init_contract->nameDisplay, sizeof(ctx_init_contract->nameDisplay));
        explicit_bzero(ctx_init_contract->paramsHashDisplay,
                       sizeof(ctx_init_contract->paramsHashDisplay));
        if (cx_sha256_init(&ctx_init_contract->paramsHashCtx) != CX_SHA256) {
            THROW(ERROR_FAILED_CX_OPERATION);
        }
        send_success_no_idle();
    }

    else if (p1 == P1_NAME) {
        uint8_t lengthSize = 2;
        uint8_t nameOffset = 0;
        if (ctx_init_contract->state == INIT_CONTRACT_NAME_FIRST) {
            // extract the name length
            if (lc < 2) {
                THROW(SWO_INCORRECT_DATA);
            }
            ctx_init_contract->nameLength = U2BE(cdata, 0);
            // calculate the remaining name length
            ctx_init_contract->remainingNameLength = ctx_init_contract->nameLength + lengthSize;
            if (ctx_init_contract->remainingNameLength < lc) {
                THROW(ERROR_INVALID_NAME_LENGTH);
            }
            // set the state to the next state
            ctx_init_contract->state = INIT_CONTRACT_NAME_NEXT;
            nameOffset = lengthSize;  // skip the length prefix when retaining the name
        } else if (ctx_init_contract->remainingNameLength < lc) {
            THROW(ERROR_INVALID_NAME_LENGTH);
        }
        // hash the whole chunk
        update_hash((cx_hash_t *) &tx_state->hash, cdata, lc);
        // Digest the name alongside the parameters, so the signed name is always represented
        // even when it is too long to render, and retain the text when it does fit.
        if (lc > nameOffset) {
            update_hash((cx_hash_t *) &ctx_init_contract->paramsHashCtx, cdata + nameOffset, lc - nameOffset);
            if (ctx_init_contract->nameLength < sizeof(ctx_init_contract->nameDisplay)) {
                size_t used = strlen(ctx_init_contract->nameDisplay);
                memmove(ctx_init_contract->nameDisplay + used, cdata + nameOffset, lc - nameOffset);
                ctx_init_contract->nameDisplay[used + (lc - nameOffset)] = '\0';
            }
        }
        // subtract the length of the chunk from the remaining name length
        ctx_init_contract->remainingNameLength -= lc;
        if (ctx_init_contract->remainingNameLength > 0) {
            send_success_no_idle();
        } else if (ctx_init_contract->remainingNameLength == 0) {
            if (ctx_init_contract->nameLength >= sizeof(ctx_init_contract->nameDisplay)) {
                // Replaced entirely, not truncated: a shortened entrypoint would let a host
                // disguise the method. The digest below still covers the exact name bytes.
                memmove(ctx_init_contract->nameDisplay,
                        "(too long to display - see hash)",
                        sizeof("(too long to display - see hash)"));
            }
            ctx_init_contract->state = INIT_CONTRACT_PARAMS_FIRST;
            send_success_no_idle();
        }

    } else if (p1 == P1_PARAMS) {
        uint8_t lengthSize = 2;
        uint8_t paramsOffset = 0;
        if (ctx_init_contract->state == INIT_CONTRACT_PARAMS_FIRST) {
            // extract the params length
            if (lc < 2) {
                THROW(SWO_INCORRECT_DATA);
            }
            ctx_init_contract->paramsLength = U2BE(cdata, 0);
            // calculate the remaining params length
            ctx_init_contract->remainingParamsLength = ctx_init_contract->paramsLength + lengthSize;
            if (ctx_init_contract->remainingParamsLength < lc) {
                THROW(ERROR_INVALID_PARAMS_LENGTH);
            }
            // set the state to the next state
            ctx_init_contract->state = INIT_CONTRACT_PARAMS_NEXT;
            paramsOffset = lengthSize;  // skip the length prefix when digesting the parameters
        } else if (ctx_init_contract->remainingParamsLength < lc) {
            THROW(ERROR_INVALID_PARAMS_LENGTH);
        }
        // hash the whole chunk
        update_hash((cx_hash_t *) &tx_state->hash, cdata, lc);
        if (lc > paramsOffset) {
            update_hash((cx_hash_t *) &ctx_init_contract->paramsHashCtx,
                        cdata + paramsOffset,
                        lc - paramsOffset);
        }
        // subtract the length of the chunk from the remaining params length
        ctx_init_contract->remainingParamsLength -= lc;
        if (ctx_init_contract->remainingParamsLength > 0) {
            send_success_no_idle();
        } else if (ctx_init_contract->remainingParamsLength == 0) {
            uint8_t paramsHash[COMMON_HASH_SIZE];
            hash((cx_hash_t *) &ctx_init_contract->paramsHashCtx,
                 CX_LAST,
                 NULL,
                 0,
                 paramsHash,
                 sizeof(paramsHash));
            if (format_hex(paramsHash,
                           sizeof(paramsHash),
                           ctx_init_contract->paramsHashDisplay,
                           sizeof(ctx_init_contract->paramsHashDisplay)) == -1) {
                THROW(ERROR_BUFFER_OVERFLOW);
            }
            uiInitContractDisplay();
        }

    } else {
        THROW(ERROR_INVALID_STATE);
    }
}