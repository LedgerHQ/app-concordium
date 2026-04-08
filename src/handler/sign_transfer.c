#include "globals.h"

#include <os.h>
#include <cx.h>
#include <io.h>
#include <parser.h>
#include <status_words.h>

#include "concordium_crypto.h"
#include "display.h"
#include "numberHelpers.h"
#include "tx_hash.h"

#include "sign_transfer.h"

static signTransferContext_t *ctx = &global.withDataBlob.signTransferContext;
static tx_state_t *tx_state = &global_tx_state;

#define P1_INITIAL 0x00

void handle_sign_transfer(const command_t *cmd, volatile unsigned int *flags) {
    uint8_t *cdata = cmd->data;
    uint8_t lc = cmd->lc;

    uint8_t offset = handleHeaderAndToAddress(cdata,
                                              lc,
                                              TRANSFER,
                                              ctx->displayStr,
                                              sizeof(ctx->displayStr),
                                              ctx->energy_amount_str,
                                              sizeof(ctx->energy_amount_str));
    cdata += offset;
    uint8_t remainingDataLength = lc - offset;

    // Build display value of the amount to transfer, and also add the bytes to the hash.
    if (remainingDataLength < 8) {
        THROW(SWO_INCORRECT_DATA);
    }
    uint64_t amount = U8BE(cdata, 0);
    amount_to_gtu_display(ctx->displayAmount, sizeof(ctx->displayAmount), amount);
    update_hash((cx_hash_t *) &tx_state->hash, cdata, 8);

    // Display the transaction information to the user (recipient address and amount to be sent).
    startTransferDisplay(false, flags);

    // Tell the main process to wait for a button press.
    *flags |= IO_ASYNCH_REPLY;
}
