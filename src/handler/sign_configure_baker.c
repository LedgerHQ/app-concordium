#include "globals.h"

#include <string.h>

#include <os.h>
#include <cx.h>
#include <io.h>
#include <parser.h>
#include <status_words.h>

#include "apdu/apdu_response.h"
#include "concordium_crypto.h"
#include "derivation_path.h"
#include "display.h"
#include "numberHelpers.h"
#include "tx_hash.h"

#include "sign_configure_baker.h"

static signConfigureBaker_t *ctx_conf_baker = &global.signConfigureBaker;
static tx_state_t *tx_state = &global_tx_state;

#define P1_INITIAL          0x00
#define P1_FIRST_BATCH      0x01
#define P1_AGGREGATION_KEY  0x02
#define P1_URL_LENGTH       0x03
#define P1_URL              0x04
#define P1_COMMISSION_RATES 0x05
#define P1_SUSPENDED        0x06

bool hasCommissionRate(void) {
    return ctx_conf_baker->hasTransactionFeeCommission ||
           ctx_conf_baker->hasBakingRewardCommission ||
           ctx_conf_baker->hasFinalizationRewardCommission;
}

static void handleCommissionRates(uint8_t *cdata, uint8_t dataLength) {
    if (ctx_conf_baker->hasTransactionFeeCommission) {
        if (dataLength < 4) {
            THROW(SWO_INCORRECT_DATA);
        }
        uint32_t rate = U4BE(cdata, 0);
        fraction_to_percentage_display(
            ctx_conf_baker->commissionRates.transactionFeeCommissionRate,
            sizeof(ctx_conf_baker->commissionRates.transactionFeeCommissionRate),
            rate);
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 4);
        cdata += 4;
        dataLength -= 4;
    }

    if (ctx_conf_baker->hasBakingRewardCommission) {
        if (dataLength < 4) {
            THROW(SWO_INCORRECT_DATA);
        }
        uint32_t rate = U4BE(cdata, 0);
        fraction_to_percentage_display(
            ctx_conf_baker->commissionRates.bakingRewardCommissionRate,
            sizeof(ctx_conf_baker->commissionRates.bakingRewardCommissionRate),
            rate);
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 4);
        cdata += 4;
        dataLength -= 4;
    }

    if (ctx_conf_baker->hasFinalizationRewardCommission) {
        if (dataLength < 4) {
            THROW(SWO_INCORRECT_DATA);
        }
        uint32_t rate = U4BE(cdata, 0);
        fraction_to_percentage_display(
            ctx_conf_baker->commissionRates.finalizationRewardCommissionRate,
            sizeof(ctx_conf_baker->commissionRates.finalizationRewardCommissionRate),
            rate);
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 4);
        dataLength -= 4;
    }

    if (ctx_conf_baker->hasSuspended) {
        ctx_conf_baker->state = CONFIGURE_BAKER_SUSPENDED;
    } else {
        if (dataLength != 0) {
            THROW(SWO_INCORRECT_DATA);
        }
        ctx_conf_baker->state = CONFIGURE_BAKER_END;
    }

    startConfigureBakerCommissionDisplay();
}

void handle_sign_configure_baker(const command_t *cmd,
                                 volatile unsigned int *flags,
                                 bool isInitialCall) {
    uint8_t *cdata = cmd->data;
    uint8_t p1 = cmd->p1;
    uint8_t dataLength = cmd->lc;

    if (isInitialCall) {
        ctx_conf_baker->state = CONFIGURE_BAKER_INITIAL;
    }

    if (P1_INITIAL == p1 && ctx_conf_baker->state == CONFIGURE_BAKER_INITIAL) {
        if (cx_sha256_init(&tx_state->hash) != CX_SHA256) {
            THROW(ERROR_FAILED_CX_OPERATION);
        }
        size_t offset = parse_derivation_path(cdata, dataLength);
        if (offset > dataLength) {
            THROW(SWO_INCORRECT_DATA);
        }
        cdata += offset;
        uint8_t remainingDataLength = dataLength - offset;
        offset = hashAccountTransactionHeaderAndKind(cdata, remainingDataLength, CONFIGURE_BAKER);
        if (offset > remainingDataLength) {
            THROW(SWO_INCORRECT_DATA);
        }
        cdata += offset;
        remainingDataLength -= offset;
        ctx_conf_baker->firstDisplay = true;

        // The initial 2 bytes tells us the fields we are receiving.
        if (remainingDataLength < 2) {
            THROW(SWO_INCORRECT_DATA);
        }
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 2);
        uint16_t bitmap = U2BE(cdata, 0);

        // A transaction with a bit set after the 9th bits place (as there are 9
        // optionals) is invalid.
        if (bitmap > 511) {
            THROW(ERROR_INVALID_TRANSACTION);
        }

        ctx_conf_baker->hasCapital = (bitmap >> 0) & 1;
        ctx_conf_baker->hasRestakeEarnings = (bitmap >> 1) & 1;
        ctx_conf_baker->hasOpenForDelegation = (bitmap >> 2) & 1;
        ctx_conf_baker->hasKeys = (bitmap >> 3) & 1;
        ctx_conf_baker->hasMetadataUrl = (bitmap >> 4) & 1;
        ctx_conf_baker->hasTransactionFeeCommission = (bitmap >> 5) & 1;
        ctx_conf_baker->hasBakingRewardCommission = (bitmap >> 6) & 1;
        ctx_conf_baker->hasFinalizationRewardCommission = (bitmap >> 7) & 1;
        ctx_conf_baker->hasSuspended = (bitmap >> 8) & 1;

        if (ctx_conf_baker->hasCapital || ctx_conf_baker->hasRestakeEarnings ||
            ctx_conf_baker->hasOpenForDelegation || ctx_conf_baker->hasKeys) {
            ctx_conf_baker->state = CONFIGURE_BAKER_FIRST;
        } else if (ctx_conf_baker->hasMetadataUrl) {
            ctx_conf_baker->state = CONFIGURE_BAKER_URL_LENGTH;
        } else if (hasCommissionRate()) {
            ctx_conf_baker->state = CONFIGURE_BAKER_COMMISSION_RATES;
        } else if (ctx_conf_baker->hasSuspended) {
            ctx_conf_baker->state = CONFIGURE_BAKER_SUSPENDED;
        }

        send_success_no_idle();
    } else if (P1_FIRST_BATCH == p1 && ctx_conf_baker->state == CONFIGURE_BAKER_FIRST) {
        int lengthCheck = dataLength;

        if (ctx_conf_baker->hasCapital) {
            if (lengthCheck < 8) {
                THROW(SWO_INCORRECT_DATA);
            }
            uint64_t capitalAmount = U8BE(cdata, 0);
            if (capitalAmount == 0) {
                ctx_conf_baker->capitalRestakeDelegation.stopBaking = true;
            } else {
                ctx_conf_baker->capitalRestakeDelegation.stopBaking = false;
                amount_to_ccd_display(
                    ctx_conf_baker->capitalRestakeDelegation.displayCapital,
                    sizeof(ctx_conf_baker->capitalRestakeDelegation.displayCapital),
                    capitalAmount);
            }
            update_hash((cx_hash_t *) &tx_state->hash, cdata, 8);
            cdata += 8;
            lengthCheck -= 8;
        }

        if (ctx_conf_baker->hasRestakeEarnings) {
            if (lengthCheck < 1) {
                THROW(SWO_INCORRECT_DATA);
            }
            uint8_t restake = cdata[0];
            update_hash((cx_hash_t *) &tx_state->hash, cdata, 1);
            cdata += 1;
            lengthCheck -= 1;
            if (restake == 0) {
                memmove(ctx_conf_baker->capitalRestakeDelegation.displayRestake, "No", 3);
            } else if (restake == 1) {
                memmove(ctx_conf_baker->capitalRestakeDelegation.displayRestake, "Yes", 4);
            } else {
                THROW(ERROR_INVALID_TRANSACTION);
            }
        }

        if (ctx_conf_baker->hasOpenForDelegation) {
            if (lengthCheck < 1) {
                THROW(SWO_INCORRECT_DATA);
            }
            uint8_t openForDelegation = cdata[0];
            update_hash((cx_hash_t *) &tx_state->hash, cdata, 1);
            cdata += 1;
            lengthCheck -= 1;

            if (openForDelegation == 0) {
                memmove(ctx_conf_baker->capitalRestakeDelegation.displayOpenForDelegation,
                        "Open for all",
                        13);
            } else if (openForDelegation == 1) {
                memmove(ctx_conf_baker->capitalRestakeDelegation.displayOpenForDelegation,
                        "Closed for new",
                        15);
            } else if (openForDelegation == 2) {
                memmove(ctx_conf_baker->capitalRestakeDelegation.displayOpenForDelegation,
                        "Closed for all",
                        15);
            } else {
                THROW(ERROR_INVALID_TRANSACTION);
            }
        }

        if (ctx_conf_baker->hasKeys) {
            // We are expecting the signature and election verification keys (each 32 bytes) and
            // their proofs (each 64 bytes).
            if (lengthCheck != 192) {
                THROW(SWO_INCORRECT_DATA);
            }

            // We do not display the verification keys to the user, as they are difficult
            // for the user to verify. If need be, we can start showing them by parsing
            // the values into hex strings here.
            // Election verify key
            update_hash((cx_hash_t *) &tx_state->hash, cdata, 32);
            cdata += 32;

            // Election Proof
            update_hash((cx_hash_t *) &tx_state->hash, cdata, 64);
            cdata += 64;

            // Signature verify key
            update_hash((cx_hash_t *) &tx_state->hash, cdata, 32);
            cdata += 32;

            // Signature Proof
            update_hash((cx_hash_t *) &tx_state->hash, cdata, 64);

            // We delay the display until we get the aggregation key.
            ctx_conf_baker->state = CONFIGURE_BAKER_AGGREGATION_KEY;
            send_success_no_idle();
        } else {
            if (lengthCheck != 0) {
                THROW(SWO_INCORRECT_DATA);
            }

            if (ctx_conf_baker->hasMetadataUrl) {
                ctx_conf_baker->state = CONFIGURE_BAKER_URL_LENGTH;
            } else if (hasCommissionRate()) {
                ctx_conf_baker->state = CONFIGURE_BAKER_COMMISSION_RATES;
            } else if (ctx_conf_baker->hasSuspended) {
                ctx_conf_baker->state = CONFIGURE_BAKER_SUSPENDED;
            } else {
                ctx_conf_baker->state = CONFIGURE_BAKER_END;
            }

            startConfigureBakerDisplay();
            *flags |= IO_ASYNCH_REPLY;
        }
    } else if (P1_AGGREGATION_KEY == p1 &&
               ctx_conf_baker->state == CONFIGURE_BAKER_AGGREGATION_KEY) {
        if (!ctx_conf_baker->hasKeys || dataLength != 160) {
            THROW(SWO_INCORRECT_DATA);
        }

        // Aggregation verify key
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 96);
        cdata += 96;

        // Election Proof
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 64);

        if (ctx_conf_baker->hasMetadataUrl) {
            ctx_conf_baker->state = CONFIGURE_BAKER_URL_LENGTH;
        } else if (hasCommissionRate()) {
            ctx_conf_baker->state = CONFIGURE_BAKER_COMMISSION_RATES;
        } else if (ctx_conf_baker->hasSuspended) {
            ctx_conf_baker->state = CONFIGURE_BAKER_SUSPENDED;
        } else {
            ctx_conf_baker->state = CONFIGURE_BAKER_END;
        }

        startConfigureBakerDisplay();
        *flags |= IO_ASYNCH_REPLY;
    } else if (P1_URL_LENGTH == p1 && ctx_conf_baker->state == CONFIGURE_BAKER_URL_LENGTH) {
        if (!ctx_conf_baker->hasMetadataUrl) {
            THROW(ERROR_INVALID_TRANSACTION);
        }
        if (dataLength < 2) {
            THROW(SWO_INCORRECT_DATA);
        }
        ctx_conf_baker->url.urlLength = U2BE(cdata, 0);
        if (ctx_conf_baker->url.urlLength > 2048) {
            THROW(ERROR_INVALID_TRANSACTION);
        }

        update_hash((cx_hash_t *) &tx_state->hash, cdata, 2);

        if (ctx_conf_baker->url.urlLength == 0) {
            // If the url has length zero, we don't wait for the url bytes.
            if (hasCommissionRate()) {
                ctx_conf_baker->state = CONFIGURE_BAKER_COMMISSION_RATES;
            } else if (ctx_conf_baker->hasSuspended) {
                ctx_conf_baker->state = CONFIGURE_BAKER_SUSPENDED;
            } else {
                ctx_conf_baker->state = CONFIGURE_BAKER_END;
            }

            startConfigureBakerUrlDisplay(true);
            *flags |= IO_ASYNCH_REPLY;
        } else {
            ctx_conf_baker->state = CONFIGURE_BAKER_URL;
            send_success_no_idle();
        }
    } else if (P1_URL == p1 && ctx_conf_baker->state == CONFIGURE_BAKER_URL) {
        if (ctx_conf_baker->url.urlLength > dataLength) {
            if (dataLength >= sizeof(ctx_conf_baker->url.urlDisplay)) {
                THROW(SWO_INCORRECT_DATA);
            }
            update_hash((cx_hash_t *) &tx_state->hash, cdata, dataLength);
            ctx_conf_baker->url.urlLength -= dataLength;
            explicit_bzero(ctx_conf_baker->url.urlDisplay, sizeof(ctx_conf_baker->url.urlDisplay));
            memmove(ctx_conf_baker->url.urlDisplay, cdata, dataLength);
            ctx_conf_baker->url.urlDisplay[dataLength] = '\0';
            startConfigureBakerUrlDisplay(false);
            *flags |= IO_ASYNCH_REPLY;
        } else if (ctx_conf_baker->url.urlLength == dataLength) {
            if (dataLength >= sizeof(ctx_conf_baker->url.urlDisplay)) {
                THROW(SWO_INCORRECT_DATA);
            }
            explicit_bzero(ctx_conf_baker->url.urlDisplay, sizeof(ctx_conf_baker->url.urlDisplay));
            memmove(ctx_conf_baker->url.urlDisplay, cdata, ctx_conf_baker->url.urlLength);
            ctx_conf_baker->url.urlDisplay[ctx_conf_baker->url.urlLength] = '\0';
            update_hash((cx_hash_t *) &tx_state->hash, cdata, ctx_conf_baker->url.urlLength);

            if (hasCommissionRate()) {
                ctx_conf_baker->state = CONFIGURE_BAKER_COMMISSION_RATES;
            } else if (ctx_conf_baker->hasSuspended) {
                ctx_conf_baker->state = CONFIGURE_BAKER_SUSPENDED;
            } else {
                ctx_conf_baker->state = CONFIGURE_BAKER_END;
            }

            startConfigureBakerUrlDisplay(true);
            *flags |= IO_ASYNCH_REPLY;
        } else {
            THROW(SWO_INCORRECT_DATA);
        }
    } else if (P1_COMMISSION_RATES == p1 &&
               ctx_conf_baker->state == CONFIGURE_BAKER_COMMISSION_RATES) {
        handleCommissionRates(cdata, dataLength);
        *flags |= IO_ASYNCH_REPLY;
    } else if (P1_SUSPENDED == p1 && ctx_conf_baker->state == CONFIGURE_BAKER_SUSPENDED) {
        if (dataLength < 1) {
            THROW(SWO_INCORRECT_DATA);
        }
        uint8_t suspended = cdata[0];
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 1);
        dataLength -= 1;

        if (dataLength != 0) {
            THROW(SWO_INCORRECT_DATA);
        }

        if (suspended == 0) {
            memmove(ctx_conf_baker->suspended, "Resume validator", 17);
        } else if (suspended == 1) {
            memmove(ctx_conf_baker->suspended, "Suspend validator", 18);
        } else {
            THROW(ERROR_INVALID_TRANSACTION);
        }
        startConfigureBakerSuspendedDisplay();
        *flags |= IO_ASYNCH_REPLY;
    } else {
        THROW(ERROR_INVALID_STATE);
    }
}
