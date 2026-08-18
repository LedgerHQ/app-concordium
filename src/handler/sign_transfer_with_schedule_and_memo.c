#include "globals.h"

#include <os.h>
#include <cx.h>
#include <io.h>
#include <parser.h>
#include <status_words.h>

#include "apdu/apdu_response.h"
#include "concordium_crypto.h"
#include "display.h"
#include "fee_display.h"
#include "numberHelpers.h"
#include "cbor_data_blob.h"
#include "tx_hash.h"

#include "sign_transfer_schedule.h"
#include "sign_transfer_with_schedule_and_memo.h"

static signTransferWithScheduleContext_t *ctx =
    &global.withDataBlob.signTransferWithScheduleContext;
static cborContext_t *memo_ctx = &global.withDataBlob.cborContext;
static tx_state_t *tx_state = &global_tx_state;

#define P1_INITIAL_WITH_MEMO        0x02
#define P1_MEMO                     0x03
#define P1_SCHEDULED_TRANSFER_PAIRS 0x01

void handle_sign_transfer_with_schedule_and_memo(const command_t *cmd,
                                                 volatile unsigned int *flags,
                                                 bool isInitialCall) {
    uint8_t *cdata = cmd->data;
    uint8_t p1 = cmd->p1;
    uint8_t dataLength = cmd->lc;
    uint8_t remainingDataLength = dataLength;

    if (isInitialCall) {
        ctx->state = TX_TRANSFER_WITH_SCHEDULE_INITIAL;
    }

    if (p1 == P1_INITIAL_WITH_MEMO && ctx->state == TX_TRANSFER_WITH_SCHEDULE_INITIAL) {
        if (cmd->p2 > P2_SIGN_TX_FEE_DISPLAY) {
            THROW(SWO_WRONG_P1_P2);
        }
        uint8_t fee_suffix = (cmd->p2 == P2_SIGN_TX_FEE_DISPLAY) ? FEE_DISPLAY_U64_SIZE : 0;
        ctx->has_fee_display = false;
        explicit_bzero(ctx->fee_display_str, sizeof(ctx->fee_display_str));

        uint8_t offset = handleHeaderAndToAddress(cdata,
                                                  remainingDataLength,
                                                  TRANSFER_WITH_SCHEDULE_WITH_MEMO,
                                                  ctx->displayStr,
                                                  sizeof(ctx->displayStr));
        cdata += offset;
        remainingDataLength -= offset;
        /* 1 byte: scheduled amount count; 2 bytes: memo CBOR length (U2BE); optional fee */
        if (remainingDataLength != 3 + fee_suffix) {
            THROW(SWO_INCORRECT_DATA);
        }
        ctx->remainingNumberOfScheduledAmounts = cdata[0];
        cdata += 1;

        memo_ctx->cborLength = U2BE(cdata, 0);
        if (memo_ctx->cborLength > MAX_CBOR_BLOB_SIZE) {
            THROW(ERROR_INVALID_PARAM);
        }

        update_hash((cx_hash_t *) &tx_state->hash, cdata, 2);

        if (fee_suffix != 0) {
            fee_display_apply_u64(ctx->fee_display_str,
                                  sizeof(ctx->fee_display_str),
                                  &ctx->has_fee_display,
                                  cdata + 2);
        }

        ctx->state = TX_TRANSFER_WITH_SCHEDULE_MEMO_START;
        send_success_no_idle();
    } else if (p1 == P1_MEMO && ctx->state == TX_TRANSFER_WITH_SCHEDULE_MEMO_START) {
        if (cmd->p2 != P2_SIGN_TX_DEFAULT) {
            THROW(SWO_WRONG_P1_P2);
        }
        update_hash((cx_hash_t *) &tx_state->hash, cdata, dataLength);

        readCborInitial(cdata, dataLength);

        if (memo_ctx->cborLength == 0) {
            finish_memo_scheduled(flags);
        } else {
            ctx->state = TX_TRANSFER_WITH_SCHEDULE_MEMO;
            send_success_no_idle();
        }
    } else if (p1 == P1_MEMO && ctx->state == TX_TRANSFER_WITH_SCHEDULE_MEMO) {
        if (cmd->p2 != P2_SIGN_TX_DEFAULT) {
            THROW(SWO_WRONG_P1_P2);
        }
        update_hash((cx_hash_t *) &tx_state->hash, cdata, dataLength);

        readCborContent(cdata, dataLength);
        if (memo_ctx->cborLength != 0) {
            send_success_no_idle();
        } else {
            finish_memo_scheduled(flags);
        }
    } else if (p1 == P1_SCHEDULED_TRANSFER_PAIRS &&
               ctx->state == TX_TRANSFER_WITH_SCHEDULE_TRANSFER_PAIRS) {
        if (cmd->p2 != P2_SIGN_TX_DEFAULT) {
            THROW(SWO_WRONG_P1_P2);
        }
        handle_transfer_pairs(cdata, dataLength, flags);
    } else {
        THROW(ERROR_INVALID_PARAM);
    }
}
