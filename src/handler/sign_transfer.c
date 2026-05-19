#include "globals.h"

#include <os.h>
#include <cx.h>
#include <io.h>
#include <parser.h>
#include <status_words.h>

#include "concordium_crypto.h"
#include "display.h"
#include "fee_display.h"
#include "numberHelpers.h"
#include "tx_hash.h"

#include "sign_transfer.h"

static signTransferContext_t *ctx = &global.withDataBlob.signTransferContext;
static tx_state_t *tx_state = &global_tx_state;

#define P1_INITIAL 0x00

void handle_sign_transfer(const command_t *cmd, volatile unsigned int *flags) {
    uint8_t *cdata = cmd->data;
    uint8_t lc = cmd->lc;
    uint8_t p2 = cmd->p2;

    if (cmd->p1 != P1_INITIAL || p2 > P2_SIGN_TX_FEE_DISPLAY) {
        THROW(SWO_WRONG_P1_P2);
    }
    uint8_t fee_suffix = (p2 == P2_SIGN_TX_FEE_DISPLAY) ? FEE_DISPLAY_U64_SIZE : 0;

    ctx->has_fee_display = false;
    explicit_bzero(ctx->fee_display_str, sizeof(ctx->fee_display_str));

    uint8_t offset =
        handleHeaderAndToAddress(cdata, lc, TRANSFER, ctx->displayStr, sizeof(ctx->displayStr));
    cdata += offset;
    uint8_t remainingDataLength = lc - offset;

    if (remainingDataLength != 8 + fee_suffix) {
        THROW(SWO_INCORRECT_DATA);
    }
    uint64_t amount = U8BE(cdata, 0);
    amount_to_ccd_display(ctx->displayAmount, sizeof(ctx->displayAmount), amount);
    update_hash((cx_hash_t *) &tx_state->hash, cdata, 8);

    if (fee_suffix != 0) {
        fee_display_apply_u64(ctx->fee_display_str,
                              sizeof(ctx->fee_display_str),
                              &ctx->has_fee_display,
                              cdata + 8);
    }

    startTransferDisplay(false, flags);

    // Tell the main process to wait for a button press.
    *flags |= IO_ASYNCH_REPLY;
}
