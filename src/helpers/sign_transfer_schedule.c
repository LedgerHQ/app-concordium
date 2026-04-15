#include "globals.h"

#include <os.h>
#include <cx.h>
#include <io.h>
#include <parser.h>
#include <status_words.h>

#include "apdu/apdu_response.h"
#include "concordium_crypto.h"
#include "display.h"
#include "numberHelpers.h"
#include "tx_hash.h"
#include "sign_transfer_schedule.h"

static signTransferWithScheduleContext_t *ctx =
    &global.withDataBlob.signTransferWithScheduleContext;
static tx_state_t *tx_state = &global_tx_state;

void processNextScheduledAmount(uint8_t *buffer) {
    if (buffer == NULL) {
        THROW(ERROR_INVALID_PARAM);
    }
    if (ctx->scheduledAmountsInCurrentPacket == 0) {
        // Current packet has been successfully read, but there are still more data to receive. Ask
        // the caller for more data.
        send_success_no_idle();
    } else {
        // The current packet still has additional timestamp/amount pairs to be added to the hash
        // and displayed for the user.
        if (ctx->pos + 8 > sizeof(ctx->buffer)) {
            THROW(ERROR_BUFFER_OVERFLOW);
        }
        uint64_t timestamp = U8BE(ctx->buffer, ctx->pos) / 1000;
        update_hash((cx_hash_t *) &tx_state->hash, buffer + ctx->pos, 8);
        ctx->pos += 8;
        int valid = secondsToTm(timestamp, &ctx->time);
        if (valid != 0) {
            THROW(ERROR_INVALID_PARAM);
        }

        // If the year is too far into the future, then just fail. This is needed so
        // that we know how much space to reserve to display the date time.
        if (ctx->time.tm_year > 9999) {
            THROW(ERROR_INVALID_PARAM);
        }
        timeToDisplayText(ctx->time, ctx->displayTimestamp, sizeof(ctx->displayTimestamp));
        if (ctx->pos + 8 > sizeof(ctx->buffer)) {
            THROW(ERROR_BUFFER_OVERFLOW);
        }
        uint64_t amount = U8BE(ctx->buffer, ctx->pos);
        update_hash((cx_hash_t *) &tx_state->hash, buffer + ctx->pos, 8);
        ctx->pos += 8;
        amount_to_gtu_display(ctx->displayAmount, sizeof(ctx->displayAmount), amount);

        // We read one more scheduled amount, so count down to keep track of remaining to process.
        ctx->scheduledAmountsInCurrentPacket -= 1;

        // If it is the final schedule pair, then also allow the user to sign or decline the
        // transaction.
        if (ctx->remainingNumberOfScheduledAmounts == 0 &&
            ctx->scheduledAmountsInCurrentPacket == 0) {
            uiSignScheduledTransferPairFlowSignDisplay();
        } else {
            // Display the timestamp and amount for the user to validate it.
            uiSignScheduledTransferPairFlowDisplay();
        }
    }
}

void handle_transfer_pairs(uint8_t *cdata, uint8_t dataLength, volatile unsigned int *flags) {
    // Load the scheduled transfer information.
    // First 8 bytes is the timestamp, the following 8 bytes is the amount.
    // We have room for 255 bytes, so 240 = 15 * 16, i.e. 15 pairs in each packet. Determine how
    // many pairs are in the current packet.
    if (ctx->remainingNumberOfScheduledAmounts <= 15) {
        ctx->scheduledAmountsInCurrentPacket = ctx->remainingNumberOfScheduledAmounts;
        ctx->remainingNumberOfScheduledAmounts = 0;
    } else {
        // The maximum is available in the packet.
        ctx->scheduledAmountsInCurrentPacket = 15;
        ctx->remainingNumberOfScheduledAmounts -= 15;
    }

    // Reset pointer keeping track of where we are in the current packet being processed.
    ctx->pos = 0;

    if (ctx->scheduledAmountsInCurrentPacket * 16 > sizeof(ctx->buffer) ||
        dataLength < ctx->scheduledAmountsInCurrentPacket * 16) {
        THROW(SWO_INCORRECT_DATA);
    }
    memmove(ctx->buffer, cdata, ctx->scheduledAmountsInCurrentPacket * 16);
    processNextScheduledAmount(ctx->buffer);

    // Tell the main process to wait for a button press.
    *flags |= IO_ASYNCH_REPLY;
}

void finish_memo_scheduled(volatile unsigned int *flags) {
    update_hash((cx_hash_t *) &tx_state->hash, &ctx->remainingNumberOfScheduledAmounts, 1);
    ctx->state = TX_TRANSFER_WITH_SCHEDULE_TRANSFER_PAIRS;
    startInitialScheduledTransferDisplay(true);
    *flags |= IO_ASYNCH_REPLY;
}
