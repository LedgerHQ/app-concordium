#include "globals.h"

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

#include "sign_public_information_for_ip.h"

static signPublicInformationForIp_t *ctx = &global.signPublicInformationForIp;
static tx_state_t *tx_state = &global_tx_state;

#define P1_INITIAL          0x00
#define P1_VERIFICATION_KEY 0x01
#define P1_THRESHOLD        0x02

void handle_sign_public_information_for_ip(const command_t *cmd,
                                           volatile unsigned int *flags,
                                           bool isInitialCall) {
    uint8_t *cdata = cmd->data;
    uint8_t p1 = cmd->p1;
    uint8_t lc = cmd->lc;

    if (isInitialCall) {
        ctx->state = TX_PUBLIC_INFO_FOR_IP_INITIAL;
    }
    uint8_t remainingDataLength = lc;

    if (p1 == P1_INITIAL && ctx->state == TX_PUBLIC_INFO_FOR_IP_INITIAL) {
        uint8_t offset = parse_derivation_path(cdata, remainingDataLength);
        cdata += offset;
        remainingDataLength -= offset;
        if (cx_sha256_init(&tx_state->hash) != CX_SHA256) {
            THROW(ERROR_FAILED_CX_OPERATION);
        }
        // Parse IdCredPub
        if (remainingDataLength < 48) {
            THROW(SWO_INCORRECT_DATA);
        }
        if (format_hex(cdata, 48, ctx->idCredPub, sizeof(ctx->idCredPub)) == -1) {
            THROW(SWO_INCORRECT_DATA);
        }
        ctx->idCredPub[48 * 2] = '\0';
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 48);
        cdata += 48;
        remainingDataLength -= 48;

        // Parse CredId
        if (remainingDataLength < 48) {
            THROW(SWO_INCORRECT_DATA);
        }
        if (format_hex(cdata, 48, ctx->credId, sizeof(ctx->credId)) == -1) {
            THROW(SWO_INCORRECT_DATA);
        }
        ctx->credId[48 * 2] = '\0';
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 48);
        cdata += 48;
        remainingDataLength -= 48;

        // Parse number of public-keys that will be received next.
        if (remainingDataLength < 1) {
            THROW(SWO_INCORRECT_DATA);
        }
        ctx->publicKeysLength = cdata[0];
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 1);

        ctx->showIntro = true;
        ctx->state = TX_PUBLIC_INFO_FOR_IP_VERIFICATION_KEY;
        send_success_no_idle();
    } else if (p1 == P1_VERIFICATION_KEY && ctx->state == TX_PUBLIC_INFO_FOR_IP_VERIFICATION_KEY) {
        if (ctx->publicKeysLength <= 0) {
            THROW(ERROR_INVALID_STATE);
        }
        // Parse key type
        if (remainingDataLength < 1) {
            THROW(SWO_INCORRECT_DATA);
        }
        if (format_hex(cdata, 1, ctx->keyType, sizeof(ctx->keyType)) == -1) {
            THROW(SWO_INCORRECT_DATA);
        }
        ctx->keyType[2] = '\0';
        // Hash key type
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 1);
        cdata += 1;
        remainingDataLength -= 1;
        // Hash key index
        if (remainingDataLength < 1) {
            THROW(SWO_INCORRECT_DATA);
        }

        update_hash((cx_hash_t *) &tx_state->hash, cdata, 1);
        cdata += 1;
        remainingDataLength -= 1;
        uint8_t publicKey[32];
        if (remainingDataLength < 32) {
            THROW(SWO_INCORRECT_DATA);
        }
        memmove(publicKey, cdata, 32);
        update_hash((cx_hash_t *) &tx_state->hash, publicKey, 32);
        to_paginated_hex(publicKey, 32, ctx->publicKey, sizeof(ctx->publicKey));

        ctx->publicKeysLength -= 1;
        if (ctx->publicKeysLength > 0) {
            if (ctx->showIntro) {
                // For the first key, we also display the initial view
                ctx->showIntro = false;
                uiReviewPublicInformationForIpDisplay();
            } else {
                uiSignPublicInformationForIpPublicKeyDisplay();
            }
            *flags |= IO_ASYNCH_REPLY;
        } else {
            ctx->state = TX_PUBLIC_INFO_FOR_IP_THRESHOLD;
            // We don't display the last public key here. It is displayed in the final flow.
            send_success_no_idle();
        }
    } else if (p1 == P1_THRESHOLD && ctx->state == TX_PUBLIC_INFO_FOR_IP_THRESHOLD) {
        // Read the threshold byte and parse it to display it.
        if (remainingDataLength < 1) {
            THROW(SWO_INCORRECT_DATA);
        }
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 1);
        bin_to_dec(ctx->threshold, sizeof(ctx->threshold), cdata[0]);

        if (ctx->showIntro) {
            // If the initial view has not been displayed yet, we display the entire flow
            uiSignPublicInformationForIpCompleteDisplay();
        } else {
            uiSignPublicInformationForIpFinalDisplay();
        }
        *flags |= IO_ASYNCH_REPLY;
    } else {
        THROW(ERROR_INVALID_STATE);
    }
}
