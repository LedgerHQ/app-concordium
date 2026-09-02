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

#include "sign_transfer_schedule.h"
#include "sign_transfer_with_schedule.h"

static signTransferWithScheduleContext_t *ctx =
    &global.withDataBlob.signTransferWithScheduleContext;
static tx_state_t *tx_state = &global_tx_state;

#define P1_INITIAL_PACKET           0x00
#define P1_SCHEDULED_TRANSFER_PAIRS 0x01

void confirmInitialScheduledTransfer(void) {
    ctx->state = TX_TRANSFER_WITH_SCHEDULE_TRANSFER_PAIRS;
    send_success_no_idle();
}

void handle_sign_transfer_with_schedule(const command_t *cmd,
                                        volatile unsigned int *flags,
                                        bool isInitialCall) {
    uint8_t *cdata = cmd->data;
    uint8_t p1 = cmd->p1;
    uint8_t lc = cmd->lc;
    uint8_t remainingDataLength = lc;

    if (isInitialCall) {
        ctx->state = TX_TRANSFER_WITH_SCHEDULE_INITIAL;
    }

    if (p1 == P1_INITIAL_PACKET && ctx->state == TX_TRANSFER_WITH_SCHEDULE_INITIAL) {
        if (cmd->p2 > P2_SIGN_TX_FEE_DISPLAY) {
            THROW(SWO_WRONG_P1_P2);
        }
        uint8_t fee_suffix = (cmd->p2 == P2_SIGN_TX_FEE_DISPLAY) ? FEE_DISPLAY_U64_SIZE : 0;
        ctx->has_fee_display = false;
        explicit_bzero(ctx->fee_display_str, sizeof(ctx->fee_display_str));

        uint8_t offset = handleHeaderAndToAddress(cdata,
                                                  remainingDataLength,
                                                  TRANSFER_WITH_SCHEDULE,
                                                  ctx->displayStr,
                                                  sizeof(ctx->displayStr));
        cdata += offset;
        remainingDataLength -= offset;
        if (remainingDataLength != 1 + fee_suffix) {
            THROW(SWO_INCORRECT_DATA);
        }
        ctx->remainingNumberOfScheduledAmounts = cdata[0];
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 1);

        if (fee_suffix != 0) {
            fee_display_apply_u64(ctx->fee_display_str,
                                  sizeof(ctx->fee_display_str),
                                  &ctx->has_fee_display,
                                  cdata + 1);
        }

        ctx->state = TX_TRANSFER_WITH_SCHEDULE_AWAITING_INITIAL_CONFIRM;
        startInitialScheduledTransferDisplay(false);
        *flags |= IO_ASYNCH_REPLY;
    } else if (p1 == P1_SCHEDULED_TRANSFER_PAIRS &&
               ctx->state == TX_TRANSFER_WITH_SCHEDULE_TRANSFER_PAIRS) {
        if (cmd->p2 != P2_SIGN_TX_DEFAULT) {
            THROW(SWO_WRONG_P1_P2);
        }
        handle_transfer_pairs(cdata, lc, flags);
    } else {
        THROW(ERROR_INVALID_PARAM);
    }
}
