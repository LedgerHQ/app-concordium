#include "globals.h"

#include <os.h>
#include <cx.h>
#include <io.h>
#include <parser.h>
#include <status_words.h>

#include "apdu/apdu_response.h"
#include "concordium_crypto.h"
#include "derivation_path.h"
#include "display.h"
#include "cbor_data_blob.h"
#include "tx_hash.h"

#include "sign_register_data.h"

static signRegisterData_t *ctx = &global.withDataBlob.signRegisterData;
static cborContext_t *data_ctx = &global.withDataBlob.cborContext;
static tx_state_t *tx_state = &global_tx_state;

#define P1_INITIAL 0x00
#define P1_DATA    0x01

void handle_sign_register_data(const command_t *cmd,
                               volatile unsigned int *flags,
                               bool isInitialCall) {
    uint8_t *cdata = cmd->data;
    uint8_t p1 = cmd->p1;
    uint8_t dataLength = cmd->lc;

    if (isInitialCall) {
        ctx->state = TX_REGISTER_DATA_INITIAL;
    }
    uint8_t remainingDataLength = dataLength;
    if (p1 == P1_INITIAL && ctx->state == TX_REGISTER_DATA_INITIAL) {
        size_t offset = parse_derivation_path(cdata, remainingDataLength);
        if (offset > dataLength) {
            THROW(SWO_INCORRECT_DATA);
        }
        cdata += offset;
        remainingDataLength -= offset;
        if (cx_sha256_init(&tx_state->hash) != CX_SHA256) {
            THROW(ERROR_FAILED_CX_OPERATION);
        }

        offset = hashAccountTransactionHeaderAndKind(cdata, remainingDataLength, REGISTER_DATA);
        if (offset > dataLength) {
            THROW(SWO_INCORRECT_DATA);
        }
        cdata += offset;
        remainingDataLength -= offset;
        if (remainingDataLength < 2) {
            THROW(SWO_INCORRECT_DATA);
        }
        ctx->dataLength = U2BE(cdata, 0);
        if (ctx->dataLength > MAX_DATA_SIZE) {
            THROW(ERROR_INVALID_PARAM);
        }
        data_ctx->cborLength = ctx->dataLength;
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 2);

        ctx->state = TX_REGISTER_DATA_PAYLOAD_START;

        uiRegisterDataInitialDisplay(flags);

    } else if (p1 == P1_DATA) {
        if (ctx->dataLength < dataLength) {
            THROW(ERROR_INVALID_TRANSACTION);
        }
        ctx->dataLength -= dataLength;
        update_hash((cx_hash_t *) &tx_state->hash, cdata, dataLength);

        switch (ctx->state) {
            case TX_REGISTER_DATA_PAYLOAD_START:
                ctx->state = TX_REGISTER_DATA_PAYLOAD;
                readCborInitial(cdata, dataLength);
                break;
            case TX_REGISTER_DATA_PAYLOAD:
                if (ctx->dataLength != 0) {
                    THROW(ERROR_INVALID_STATE);
                }
                readCborContent(cdata, dataLength);
                break;
            default:
                THROW(ERROR_INVALID_STATE);
        }

        if (ctx->dataLength == 0) {
            uiRegisterDataPayloadDisplay(flags);
        } else {
            send_success_no_idle();
        }
    } else {
        THROW(ERROR_INVALID_STATE);
    }
}
