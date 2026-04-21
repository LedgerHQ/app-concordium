#include "globals.h"

#include <string.h>

#include <os.h>
#include <cx.h>
#include <io.h>
#include <parser.h>
#include <status_words.h>

#include "concordium_crypto.h"
#include "derivation_path.h"
#include "display.h"
#include "numberHelpers.h"
#include "tx_hash.h"

#include "sign_configure_delegation.h"

static signConfigureDelegationContext_t *ctx = &global.signConfigureDelegation;
static tx_state_t *tx_state = &global_tx_state;

void handle_sign_configure_delegation(const command_t *cmd, volatile unsigned int *flags) {
    uint8_t *cdata = cmd->data;
    uint8_t dataLength = cmd->lc;

    int keyDerivationPathLength = parse_derivation_path(cdata, dataLength);
    if (keyDerivationPathLength > dataLength) {
        THROW(SWO_INCORRECT_DATA);
    }
    cdata += keyDerivationPathLength;

    if (cx_sha256_init(&tx_state->hash) != CX_SHA256) {
        THROW(ERROR_FAILED_CX_OPERATION);
    }
    int accountTransactionHeaderAndKindLength =
        hashAccountTransactionHeaderAndKind(cdata, dataLength, CONFIGURE_DELEGATION);
    if (accountTransactionHeaderAndKindLength > dataLength) {
        THROW(SWO_INCORRECT_DATA);
    }
    cdata += accountTransactionHeaderAndKindLength;
    uint8_t remainingDataLength = dataLength - accountTransactionHeaderAndKindLength;

    // The initial 2 bytes tells us the fields we are receiving.
    if (remainingDataLength < 2) {
        THROW(SWO_INCORRECT_DATA);
    }
    update_hash((cx_hash_t *) &tx_state->hash, cdata, 2);
    uint16_t bitmap = U2BE(cdata, 0);
    cdata += 2;
    remainingDataLength -= 2;
    uint8_t expectedDataLength =
        keyDerivationPathLength + accountTransactionHeaderAndKindLength + 2;

    ctx->hasCapital = (bitmap >> 0) & 1;
    ctx->hasRestakeEarnings = (bitmap >> 1) & 1;
    ctx->hasDelegationTarget = (bitmap >> 2) & 1;

    // The transaction is invalid if neither of the optional fields are available.
    if (!ctx->hasCapital && !ctx->hasRestakeEarnings && !ctx->hasDelegationTarget) {
        THROW(ERROR_INVALID_TRANSACTION);
    }

    if (ctx->hasCapital) {
        if (remainingDataLength < 8) {
            THROW(SWO_INCORRECT_DATA);
        }
        uint64_t capitalAmount = U8BE(cdata, 0);
        if (capitalAmount == 0) {
            ctx->stopDelegation = true;
        } else {
            ctx->stopDelegation = false;
            amount_to_ccd_display(ctx->displayCapital, sizeof(ctx->displayCapital), capitalAmount);
        }
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 8);
        expectedDataLength += 8;
        cdata += 8;
        remainingDataLength -= 8;
    }

    if (ctx->hasRestakeEarnings) {
        if (remainingDataLength < 1) {
            THROW(SWO_INCORRECT_DATA);
        }
        uint8_t restake = cdata[0];
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 1);
        expectedDataLength += 1;
        cdata += 1;
        remainingDataLength -= 1;
        if (restake == 0) {
            memmove(ctx->displayRestake, "No", 3);
        } else if (restake == 1) {
            memmove(ctx->displayRestake, "Yes", 4);
        } else {
            THROW(ERROR_INVALID_TRANSACTION);
        }
    }

    if (ctx->hasDelegationTarget) {
        if (remainingDataLength < 1) {
            THROW(SWO_INCORRECT_DATA);
        }
        uint8_t delegationType = cdata[0];
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 1);
        expectedDataLength += 1;
        cdata += 1;
        remainingDataLength -= 1;
        if (delegationType == 0) {
            memmove(ctx->displayDelegationTarget, "Passive Delegation", 19);
        } else if (delegationType == 1) {
            if (remainingDataLength < 8) {
                THROW(SWO_INCORRECT_DATA);
            }
            uint64_t bakerId = U8BE(cdata, 0);
            expectedDataLength += 8;
            memmove(ctx->displayDelegationTarget, "Baker ID ", 9);
            bin_to_dec(ctx->displayDelegationTarget + 9, 21, bakerId);
            update_hash((cx_hash_t *) &tx_state->hash, cdata, 8);
        } else {
            THROW(ERROR_INVALID_TRANSACTION);
        }
    }

    // There was a mismatch between the transaction and the reported data length.
    if (dataLength != expectedDataLength) {
        THROW(ERROR_INVALID_TRANSACTION);
    }

    startConfigureDelegationDisplay();
    *flags |= IO_ASYNCH_REPLY;
}
