#include "globals.h"

#include <os.h>
#include <cx.h>
#include <io.h>
#include <parser.h>
#include <status_words.h>

#include "apdu/apdu_response.h"
#include "concordium_crypto.h"
#include "base58check.h"
#include "derivation_path.h"
#include "display.h"
#include "numberHelpers.h"
#include "tx_hash.h"

#include "sign_transfer_to_public.h"

static signTransferToPublic_t *ctx = &global.signTransferToPublic;
static tx_state_t *tx_state = &global_tx_state;

#define P1_INITIAL          0x00
#define P1_REMAINING_AMOUNT 0x01
#define P1_PROOF            0x02

void handle_sign_transfer_to_public(const command_t *cmd,
                                    volatile unsigned int *flags,
                                    bool isInitialCall) {
    uint8_t *cdata = cmd->data;
    uint8_t p1 = cmd->p1;
    uint8_t dataLength = cmd->lc;

    if (isInitialCall) {
        ctx->state = TX_TRANSFER_TO_PUBLIC_INITIAL;
    }
    uint8_t remainingDataLength = dataLength;
    if (p1 == P1_INITIAL && ctx->state == TX_TRANSFER_TO_PUBLIC_INITIAL) {
        size_t offset = parse_derivation_path(cdata, remainingDataLength);
        if (offset > dataLength) {
            THROW(SWO_INCORRECT_DATA);
        }
        cdata += offset;
        remainingDataLength -= offset;
        if (cx_sha256_init(&tx_state->hash) != CX_SHA256) {
            THROW(ERROR_FAILED_CX_OPERATION);
        }
        offset =
            hashAccountTransactionHeaderAndKind(cdata, remainingDataLength, TRANSFER_TO_PUBLIC);
        if (offset > dataLength) {
            THROW(SWO_INCORRECT_DATA);
        }
        ctx->state = TX_TRANSFER_TO_PUBLIC_REMAINING_AMOUNT;
        // Ask the caller for the next command.
        send_success_no_idle();
    } else if (p1 == P1_REMAINING_AMOUNT && ctx->state == TX_TRANSFER_TO_PUBLIC_REMAINING_AMOUNT) {
        // Hash remaining amount. Remaining amount is encrypted, and so we cannot display it.
        if (remainingDataLength < 192) {
            THROW(SWO_INCORRECT_DATA);
        }
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 192);
        cdata += 192;
        remainingDataLength -= 192;

        // Parse transaction amount so it can be displayed.
        if (remainingDataLength < 8) {
            THROW(SWO_INCORRECT_DATA);
        }
        uint64_t amountToPublic = U8BE(cdata, 0);
        amount_to_ccd_display(ctx->amount, sizeof(ctx->amount), amountToPublic);
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 8);
        cdata += 8;
        remainingDataLength -= 8;

        // Parse Recipient address
        if (remainingDataLength < 32) {
            THROW(SWO_INCORRECT_DATA);
        }
        size_t recipientAddressSize = sizeof(ctx->recipientAddress);
        if (base58check_encode(cdata, 32, ctx->recipientAddress, &recipientAddressSize) == -1) {
            THROW(SWO_INCORRECT_DATA);
        }
        ctx->recipientAddress[55] = '\0';
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 32);
        cdata += 32;
        remainingDataLength -= 32;

        // Hash amount index
        if (remainingDataLength < 8) {
            THROW(SWO_INCORRECT_DATA);
        }
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 8);
        cdata += 8;
        remainingDataLength -= 8;

        // Parse size of incoming proofs.
        if (remainingDataLength < 2) {
            THROW(SWO_INCORRECT_DATA);
        }
        ctx->proofSize = U2BE(cdata, 0);

        ctx->state = TX_TRANSFER_TO_PUBLIC_PROOF;
        send_success_no_idle();
    } else if (p1 == P1_PROOF && ctx->state == TX_TRANSFER_TO_PUBLIC_PROOF) {
        update_hash((cx_hash_t *) &tx_state->hash, cdata, dataLength);

        if (ctx->proofSize == dataLength) {
            // We have received all proof bytes, continue to signing flow.
            uiSignTransferToPublicDisplay(flags);
        } else if (ctx->proofSize < dataLength) {
            // We received more proof bytes than expected, and so the received
            // transaction is invalid.
            THROW(ERROR_INVALID_TRANSACTION);
        } else {
            // There are additional bytes to be received, so ask the caller
            // for more data.
            ctx->proofSize -= dataLength;
            send_success_no_idle();
        }
    } else {
        THROW(ERROR_INVALID_STATE);
    }
}
