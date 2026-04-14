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

#include "sign_transfer_with_memo.h"

static signTransferContext_t *ctx = &global.withDataBlob.signTransferContext;
static cborContext_t *memo_ctx = &global.withDataBlob.cborContext;
static tx_state_t *tx_state = &global_tx_state;

#define P1_INITIAL_WITH_MEMO 0x01
#define P1_MEMO              0x02
#define P1_AMOUNT            0x03

static void finish_transfer_memo(void) {
    ctx->state = TX_TRANSFER_AMOUNT;
    send_success_no_idle();
}

void handle_sign_transfer_with_memo(const command_t *cmd,
                                    volatile unsigned int *flags,
                                    bool isInitialCall) {
    uint8_t *cdata = cmd->data;
    uint8_t p1 = cmd->p1;
    uint8_t p2 = cmd->p2;
    uint8_t dataLength = cmd->lc;

    if (isInitialCall) {
        ctx->state = TX_TRANSFER_INITIAL;
    }
    uint8_t remainingDataLength = dataLength;
    if (p1 == P1_INITIAL_WITH_MEMO && ctx->state == TX_TRANSFER_INITIAL) {
        if (p2 > P2_SIGN_TX_FEE_DISPLAY) {
            THROW(SWO_WRONG_P1_P2);
        }
        uint8_t fee_suffix = (p2 == P2_SIGN_TX_FEE_DISPLAY) ? FEE_DISPLAY_U64_SIZE : 0;
        ctx->has_fee_display = false;
        explicit_bzero(ctx->fee_display_str, sizeof(ctx->fee_display_str));

        uint8_t offset = handleHeaderAndToAddress(cdata,
                                                  remainingDataLength,
                                                  TRANSFER_WITH_MEMO,
                                                  ctx->displayStr,
                                                  sizeof(ctx->displayStr));
        cdata += offset;
        remainingDataLength -= offset;
        if (remainingDataLength != 2 + fee_suffix) {
            THROW(SWO_INCORRECT_DATA);
        }
        memo_ctx->cborLength = U2BE(cdata, 0);
        if (memo_ctx->cborLength > MAX_MEMO_CBOR_SIZE) {
            THROW(ERROR_INVALID_PARAM);
        }

        update_hash((cx_hash_t *) &tx_state->hash, cdata, 2);

        if (fee_suffix != 0) {
            fee_display_apply_u64(ctx->fee_display_str,
                                  sizeof(ctx->fee_display_str),
                                  &ctx->has_fee_display,
                                  cdata + 2);
        }

        ctx->state = TX_TRANSFER_MEMO_INITIAL;
        send_success_no_idle();
    } else if (p1 == P1_MEMO && ctx->state == TX_TRANSFER_MEMO_INITIAL) {
        if (p2 != P2_SIGN_TX_DEFAULT) {
            THROW(SWO_WRONG_P1_P2);
        }
        update_hash((cx_hash_t *) &tx_state->hash, cdata, dataLength);

        readCborInitial(cdata, dataLength);
        if (memo_ctx->cborLength == 0) {
            finish_transfer_memo();
        } else {
            ctx->state = TX_TRANSFER_MEMO;
            send_success_no_idle();
        }
    } else if (p1 == P1_MEMO && ctx->state == TX_TRANSFER_MEMO) {
        if (p2 != P2_SIGN_TX_DEFAULT) {
            THROW(SWO_WRONG_P1_P2);
        }
        update_hash((cx_hash_t *) &tx_state->hash, cdata, dataLength);

        readCborContent(cdata, dataLength);
        if (memo_ctx->cborLength != 0) {
            // The memo size is <=256 bytes, so we should always have received the complete memo by
            // this point
            THROW(ERROR_INVALID_STATE);
        }

        finish_transfer_memo();
    } else if (p1 == P1_AMOUNT && ctx->state == TX_TRANSFER_AMOUNT) {
        if (p2 != P2_SIGN_TX_DEFAULT) {
            THROW(SWO_WRONG_P1_P2);
        }
        // Build display value of the amount to transfer, and also add the bytes to the hash.
        if (remainingDataLength < 8) {
            THROW(SWO_INCORRECT_DATA);
        }
        uint64_t amount = U8BE(cdata, 0);
        amount_to_gtu_display(ctx->displayAmount, sizeof(ctx->displayAmount), amount);
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 8);

        startTransferDisplay(true, flags);

    } else {
        THROW(ERROR_INVALID_STATE);
    }
}
