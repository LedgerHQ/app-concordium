#include "globals.h"

#include <stdbool.h>
#include <string.h>

#include <os.h>
#include <cx.h>
#include <io.h>
#include <parser.h>
#include <status_words.h>

#include <cbor.h>

#include "apdu/apdu_response.h"
#include "apdu/helpers.h"
#include "concordium_crypto.h"
#include "helpers/derivation_path.h"
#include "helpers/tx_hash.h"

#include "sign_plt.h"

/* P1 values for the PLT multi-step flow. */
#define PLT_P1_INIT 0x00
#define PLT_P1_CONT 0x01

static signPltContext_t *ctx = &global.signPlt;
static tx_state_t *tx_state = &global_tx_state;

/* ------------------------------------------------------------------ */
/* CBOR debug dump (only meaningful when HAVE_PRINTF is defined).      */
/* ------------------------------------------------------------------ */

/*
 * Recursively log one CBOR value at *it and advance *it past it.
 * Depth-limited to avoid stack overflow on deeply nested inputs.
 * Returns false and stops on any tinycbor error.
 */
static bool dump_cbor_recursive(CborValue *it, int depth) {
    if (cbor_value_at_end(it)) {
        return true;
    }
    if (depth > 6) {
        PRINTF("...");
        return cbor_value_advance(it) == CborNoError;
    }

    CborError err;

    if (cbor_value_is_map(it)) {
        PRINTF("{");
        CborValue map;
        err = cbor_value_enter_container(it, &map);
        if (err != CborNoError) {
            return false;
        }
        bool first = true;
        while (!cbor_value_at_end(&map)) {
            if (!first) PRINTF(",");
            first = false;
            /* key */
            if (!dump_cbor_recursive(&map, depth + 1)) return false;
            PRINTF(":");
            /* value */
            if (!dump_cbor_recursive(&map, depth + 1)) return false;
        }
        err = cbor_value_leave_container(it, &map);
        PRINTF("}");
        return err == CborNoError;
    }

    if (cbor_value_is_array(it)) {
        PRINTF("[");
        CborValue arr;
        err = cbor_value_enter_container(it, &arr);
        if (err != CborNoError) {
            return false;
        }
        bool first = true;
        while (!cbor_value_at_end(&arr)) {
            if (!first) PRINTF(",");
            first = false;
            if (!dump_cbor_recursive(&arr, depth + 1)) return false;
        }
        err = cbor_value_leave_container(it, &arr);
        PRINTF("]");
        return err == CborNoError;
    }

    if (cbor_value_is_text_string(it)) {
        size_t len = 0;
        if (cbor_value_get_string_length(it, &len) != CborNoError) {
            return false;
        }
        if (len <= 64) {
            char buf[65];
            size_t copyLen = sizeof(buf) - 1;
            err = cbor_value_copy_text_string(it, buf, &copyLen, it);
            buf[copyLen < sizeof(buf) - 1 ? copyLen : sizeof(buf) - 1] = '\0';
            PRINTF("\"%s\"", buf);
        } else {
            PRINTF("<str:%u>", (unsigned) len);
            err = cbor_value_advance(it);
        }
        return err == CborNoError;
    }

    if (cbor_value_is_byte_string(it)) {
        size_t len = 0;
        cbor_value_get_string_length(it, &len);
        PRINTF("<bstr:%u>", (unsigned) len);
        err = cbor_value_advance(it);
        return err == CborNoError;
    }

    if (cbor_value_is_unsigned_integer(it)) {
        uint64_t n = 0;
        cbor_value_get_uint64(it, &n);
        PRINTF("%u", (unsigned) n);
        err = cbor_value_advance(it);
        return err == CborNoError;
    }

    if (cbor_value_is_negative_integer(it)) {
        uint64_t n = 0;
        cbor_value_get_raw_integer(it, &n);
        PRINTF("-%u", (unsigned) (n + 1));
        err = cbor_value_advance(it);
        return err == CborNoError;
    }

    if (cbor_value_is_boolean(it)) {
        bool b = false;
        cbor_value_get_boolean(it, &b);
        PRINTF(b ? "true" : "false");
        err = cbor_value_advance(it);
        return err == CborNoError;
    }

    if (cbor_value_is_null(it)) {
        PRINTF("null");
        err = cbor_value_advance(it);
        return err == CborNoError;
    }

    if (cbor_value_is_tag(it)) {
        CborTag tag = 0;
        cbor_value_get_tag(it, &tag);
        PRINTF("tag(%u):", (unsigned) tag);
        CborValue tagged;
        err = cbor_value_enter_container(it, &tagged);
        if (err != CborNoError) return false;
        if (!dump_cbor_recursive(&tagged, depth + 1)) return false;
        err = cbor_value_leave_container(it, &tagged);
        return err == CborNoError;
    }

    /* Unknown / unsupported type — skip. */
    PRINTF("?");
    err = cbor_value_advance(it);
    return err == CborNoError;
}

/*
 * Parse the fully-accumulated CBOR blob in ctx->cborBuf and stream
 * fields to the PRINTF debug log.  Does NOT throw on parse errors —
 * it just logs what it can.  This is intentionally non-fatal because
 * blind signing does not require successful decoding; the hash over
 * the raw bytes is what gets signed.
 */
static void log_plt_cbor(void) {
    CborParser parser;
    CborValue it;
    CborError err =
        cbor_parser_init(ctx->cborBuf, ctx->cborReceived, 0, &parser, &it);
    if (err != CborNoError) {
        PRINTF("PLT CBOR parse init error: %d\n", (int) err);
        return;
    }
    PRINTF("PLT CBOR payload (tokenId len=%u): ", (unsigned) ctx->tokenIdLength);
    dump_cbor_recursive(&it, 0);
    PRINTF("\n");
}

/* ------------------------------------------------------------------ */
/* APDU handler                                                        */
/* ------------------------------------------------------------------ */

void handle_sign_plt(const command_t *cmd,
                     volatile unsigned int *flags,
                     bool isInitialCall) {
    (void) flags;  /* blind signing: no async UI */

    uint8_t *cdata = cmd->data;
    uint8_t p1 = cmd->p1;
    uint8_t lc = cmd->lc;

    if (isInitialCall) {
        ctx->state = TX_PLT_INITIAL;
    }

    /* ---- P1=0x00 INIT ---- */
    if (p1 == PLT_P1_INIT) {
        if (ctx->state != TX_PLT_INITIAL) {
            THROW(ERROR_INVALID_STATE);
        }
        if (cmd->p2 != 0x00) {
            THROW(SWO_WRONG_P1_P2);
        }

        /* Parse BIP-32 derivation path (variable length prefix). */
        size_t pathLen = parse_derivation_path(cdata, lc);
        cdata += pathLen;
        uint8_t remaining = lc - (uint8_t) pathLen;

        /* Init SHA-256 and hash account transaction header (60 bytes) + kind byte (=27). */
        if (cx_sha256_init(&tx_state->hash) != CX_SHA256) {
            THROW(ERROR_FAILED_CX_OPERATION);
        }
        int headerAndKind =
            hashAccountTransactionHeaderAndKind(cdata, remaining, (uint8_t) PLT);
        cdata += headerAndKind;
        remaining -= (uint8_t) headerAndKind;

        /* token_id_length[1] */
        if (remaining < 1) {
            THROW(ERROR_PLT_DATA_ERROR);
        }
        uint8_t tokenIdLen = cdata[0];
        if (tokenIdLen < 1 || tokenIdLen > PLT_TOKEN_ID_MAX) {
            THROW(ERROR_PLT_DATA_ERROR);
        }
        cdata += 1;
        remaining -= 1;

        /* token_id[tokenIdLen] */
        if (remaining < tokenIdLen + 4u) {
            THROW(ERROR_PLT_DATA_ERROR);
        }
        update_hash((cx_hash_t *) &tx_state->hash,
                    cdata - 1,  /* hash token_id_length byte too */
                    1 + tokenIdLen);
        memmove(ctx->tokenId, cdata, tokenIdLen);
        ctx->tokenIdLength = tokenIdLen;
        cdata += tokenIdLen;
        remaining -= tokenIdLen;

        /* cbor_total_length[4] big-endian */
        uint32_t cborTotal = U4BE(cdata, 0);
        if (cborTotal == 0 || cborTotal > APP_PLT_CBOR_MAX) {
            THROW(ERROR_PLT_BUFFER_ERROR);
        }
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 4);
        remaining -= 4;

        if (remaining != 0) {
            THROW(SWO_INCORRECT_DATA);
        }

        ctx->cborTotalLength = cborTotal;
        ctx->cborReceived = 0;
        ctx->state = TX_PLT_CBOR;

        send_success_no_idle();
        return;
    }

    /* ---- P1=0x01 CONT ---- */
    if (p1 == PLT_P1_CONT) {
        if (ctx->state != TX_PLT_CBOR) {
            THROW(ERROR_INVALID_STATE);
        }
        if (cmd->p2 != 0x00) {
            THROW(SWO_WRONG_P1_P2);
        }
        if (lc == 0) {
            THROW(ERROR_PLT_CBOR_ERROR);
        }
        if ((uint32_t) lc > ctx->cborTotalLength - ctx->cborReceived) {
            THROW(ERROR_PLT_CBOR_ERROR);
        }

        /* Hash this chunk. */
        update_hash((cx_hash_t *) &tx_state->hash, cdata, lc);

        /* Accumulate into buffer. */
        memmove(ctx->cborBuf + ctx->cborReceived, cdata, lc);
        ctx->cborReceived += (uint32_t) lc;

        if (ctx->cborReceived == ctx->cborTotalLength) {
            /* All CBOR received: log fields and sign blindly. */
            log_plt_cbor();
            buildAndSignTransactionHash();
        } else {
            send_success_no_idle();
        }
        return;
    }

    THROW(ERROR_INVALID_PARAM);
}
