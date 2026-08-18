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
#include "display.h"
#include "helpers/base58check.h"
#include "helpers/derivation_path.h"
#include "helpers/numberHelpers.h"
#include "helpers/tx_hash.h"

#include "sign_plt.h"

/*
 * Worst-case single PLT transfer CBOR with a 256-byte memo is ~347 bytes.
 * APP_PLT_CBOR_MAX = 512 provides ~47% headroom for future op types without
 * exceeding BSS budgets on constrained targets.  If you reduce this constant,
 * re-derive the bound: sum CBOR overhead for every field of the largest op.
 */
_Static_assert(APP_PLT_CBOR_MAX >= 512,
               "PLT CBOR buffer too small — worst-case transfer+memo needs ~347 B; "
               "do not go below 512 without recalculating");
_Static_assert(sizeof(signPltContext_t) <= 1400,
               "signPltContext_t exceeds BSS budget — check cborBuf / address / display fields");

/* P1 values for the PLT multi-step flow. */
#define PLT_P1_INIT 0x00
#define PLT_P1_CONT 0x01

/* CBOR tag numbers used by CIS-7. */
#define CBOR_TAG_DECIMAL_FRACTION 4u
#define CBOR_TAG_ACCOUNT_ADDRESS  40307u

/* Longest op-name key in the CIS-7 spec: "removeAllowList" = 15 chars. */
#define PLT_OP_NAME_MAX 16u

/* Memo: bytes copied from CBOR for display; we never need the full 256. */
#define MEMO_DISPLAY_BYTES 14u

static signPltContext_t *ctx = &global.signPlt;
static tx_state_t *tx_state = &global_tx_state;

/* ------------------------------------------------------------------ */
/* CBOR field parsers                                                  */
/* ------------------------------------------------------------------ */

/*
 * Parse a CIS-7 token-amount: CBOR tag 4 wrapping [exponent, significand].
 * On success advances *it past the tag and stores result in ctx.
 */
static bool parse_amount_value(CborValue *it) {
    if (!cbor_value_is_tag(it)) return false;
    CborTag tag = 0;
    cbor_value_get_tag(it, &tag);
    if (tag != CBOR_TAG_DECIMAL_FRACTION) return false;

    CborValue tagged;
    if (cbor_value_enter_container(it, &tagged) != CborNoError) return false;

    if (!cbor_value_is_array(&tagged)) {
        cbor_value_leave_container(it, &tagged);
        return false;
    }

    CborValue arr;
    if (cbor_value_enter_container(&tagged, &arr) != CborNoError) {
        cbor_value_leave_container(it, &tagged);
        return false;
    }

    /* Exponent: negative integer (most common) or zero (unsigned 0). */
    int8_t exponent = 0;
    if (cbor_value_is_negative_integer(&arr)) {
        uint64_t raw = 0;
        cbor_value_get_raw_integer(&arr, &raw);
        if (raw >= 255u) {
            cbor_value_leave_container(&tagged, &arr);
            cbor_value_leave_container(it, &tagged);
            return false;
        }
        exponent = (int8_t) (-(int64_t) (raw + 1u));
    } else if (cbor_value_is_unsigned_integer(&arr)) {
        uint64_t v = 0;
        cbor_value_get_uint64(&arr, &v);
        if (v != 0u) {
            cbor_value_leave_container(&tagged, &arr);
            cbor_value_leave_container(it, &tagged);
            return false; /* CIS-7: exponent ≤ 0 */
        }
        exponent = 0;
    } else {
        cbor_value_leave_container(&tagged, &arr);
        cbor_value_leave_container(it, &tagged);
        return false;
    }
    if (cbor_value_advance(&arr) != CborNoError) {
        cbor_value_leave_container(&tagged, &arr);
        cbor_value_leave_container(it, &tagged);
        return false;
    }

    /* Significand: unsigned 64-bit integer. */
    if (!cbor_value_is_unsigned_integer(&arr)) {
        cbor_value_leave_container(&tagged, &arr);
        cbor_value_leave_container(it, &tagged);
        return false;
    }
    uint64_t sig = 0;
    cbor_value_get_uint64(&arr, &sig);
    if (cbor_value_advance(&arr) != CborNoError) {
        cbor_value_leave_container(&tagged, &arr);
        cbor_value_leave_container(it, &tagged);
        return false;
    }

    if (cbor_value_leave_container(&tagged, &arr) != CborNoError) {
        cbor_value_leave_container(it, &tagged);
        return false;
    }
    if (cbor_value_leave_container(it, &tagged) != CborNoError) return false;

    ctx->amountSignificand = sig;
    ctx->amountExponent = exponent;
    return true;
}

/*
 * Parse a CIS-7 tagged account address: CBOR tag 40307 wrapping a 32-byte bstr.
 * On success advances *it past the tag and stores raw bytes in ctx->address.
 */
static bool parse_address_value(CborValue *it) {
    if (!cbor_value_is_tag(it)) return false;
    CborTag tag = 0;
    cbor_value_get_tag(it, &tag);
    if (tag != CBOR_TAG_ACCOUNT_ADDRESS) return false;

    CborValue tagged;
    if (cbor_value_enter_container(it, &tagged) != CborNoError) return false;

    if (!cbor_value_is_byte_string(&tagged)) {
        cbor_value_leave_container(it, &tagged);
        return false;
    }

    size_t addrLen = ADDRESS_LENGTH;
    if (cbor_value_copy_byte_string(&tagged, ctx->address, &addrLen, &tagged) != CborNoError ||
        addrLen != ADDRESS_LENGTH) {
        cbor_value_leave_container(it, &tagged);
        return false;
    }

    return cbor_value_leave_container(it, &tagged) == CborNoError;
}

/*
 * Populate ctx->displayMemo from up to MEMO_DISPLAY_BYTES of bytes.
 * Displays as ASCII when all sampled bytes are printable (0x20-0x7E),
 * otherwise falls back to a "0x<hex>" prefix.
 */
static void format_memo_display(const uint8_t *bytes, size_t displayLen, size_t totalLen) {
    static const char hex[] = "0123456789abcdef";

    bool is_ascii = true;
    for (size_t i = 0; i < displayLen; i++) {
        if (bytes[i] < 0x20 || bytes[i] > 0x7E) {
            is_ascii = false;
            break;
        }
    }

    if (is_ascii && totalLen <= sizeof(ctx->displayMemo) - 1u) {
        memmove(ctx->displayMemo, bytes, displayLen);
        ctx->displayMemo[displayLen] = '\0';
    } else if (is_ascii) {
        /* Truncate long ASCII with ellipsis. */
        size_t fit = sizeof(ctx->displayMemo) - 4u; /* leave room for "...\0" */
        memmove(ctx->displayMemo, bytes, fit);
        ctx->displayMemo[fit] = '.';
        ctx->displayMemo[fit + 1] = '.';
        ctx->displayMemo[fit + 2] = '.';
        ctx->displayMemo[fit + 3] = '\0';
    } else {
        /* Hex prefix: "0x" + up to MEMO_DISPLAY_BYTES bytes. */
        ctx->displayMemo[0] = '0';
        ctx->displayMemo[1] = 'x';
        size_t hexBytes = displayLen < MEMO_DISPLAY_BYTES ? displayLen : MEMO_DISPLAY_BYTES;
        for (size_t i = 0; i < hexBytes; i++) {
            ctx->displayMemo[2u + i * 2u] = hex[bytes[i] >> 4];
            ctx->displayMemo[2u + i * 2u + 1u] = hex[bytes[i] & 0x0Fu];
        }
        ctx->displayMemo[2u + hexBytes * 2u] = '\0';
    }
}

/*
 * Parse a CIS-7 memo field: either a raw bstr or tag-24 (embedded CBOR) bstr.
 * Advances *it past the value and populates ctx->displayMemo.
 */
static bool parse_memo_value(CborValue *it) {
    ctx->hasMemo = true;

    uint8_t tmp[MEMO_DISPLAY_BYTES];
    size_t totalLen = 0;

    if (cbor_value_is_tag(it)) {
        /* tag 24 = byte string containing embedded CBOR; unwrap one level. */
        CborValue tagged;
        if (cbor_value_enter_container(it, &tagged) != CborNoError) goto skip;
        if (!cbor_value_is_byte_string(&tagged)) {
            cbor_value_leave_container(it, &tagged);
            goto skip;
        }
        cbor_value_get_string_length(&tagged, &totalLen);
        size_t copyLen = totalLen < sizeof(tmp) ? totalLen : sizeof(tmp);
        cbor_value_copy_byte_string(&tagged, tmp, &copyLen, &tagged);
        if (cbor_value_leave_container(it, &tagged) != CborNoError) goto skip;
        format_memo_display(tmp, copyLen, totalLen);
        return true;
    }

    if (cbor_value_is_byte_string(it)) {
        cbor_value_get_string_length(it, &totalLen);
        size_t copyLen = totalLen < sizeof(tmp) ? totalLen : sizeof(tmp);
        if (cbor_value_copy_byte_string(it, tmp, &copyLen, it) != CborNoError) goto skip;
        format_memo_display(tmp, copyLen, totalLen);
        return true;
    }

skip:
    ctx->hasMemo = false;
    if (!cbor_value_at_end(it)) cbor_value_advance(it);
    return true; /* non-fatal: treat unreadable memo as absent */
}

/* ------------------------------------------------------------------ */
/* Main CBOR parser                                                    */
/* ------------------------------------------------------------------ */

/*
 * Parse the fully-accumulated CBOR in ctx->cborBuf.
 * Returns false on structural errors; THROW(ERROR_PLT_MULTI_OP) when the
 * outer array contains more than one operation.
 * On success populates ctx->opType, ctx->amountSignificand/Exponent,
 * ctx->address, ctx->hasMemo, and ctx->displayMemo.
 */
static bool parse_plt_cbor(void) {
    CborParser parser;
    CborValue it;
    if (cbor_parser_init(ctx->cborBuf, ctx->cborReceived, 0, &parser, &it) != CborNoError) {
        return false;
    }

    /* Outer array: [ single-op ] */
    if (!cbor_value_is_array(&it)) return false;
    CborValue arr;
    if (cbor_value_enter_container(&it, &arr) != CborNoError) return false;
    if (cbor_value_at_end(&arr)) return false; /* empty array */

    /* Single op: a map { "opName": { ...fields... } } */
    if (!cbor_value_is_map(&arr)) return false;
    CborValue op_map;
    if (cbor_value_enter_container(&arr, &op_map) != CborNoError) return false;

    /* Read op name key. */
    if (!cbor_value_is_text_string(&op_map)) return false;
    char opName[PLT_OP_NAME_MAX];
    size_t opNameLen = sizeof(opName) - 1u;
    if (cbor_value_copy_text_string(&op_map, opName, &opNameLen, &op_map) != CborNoError) {
        return false;
    }
    opName[opNameLen] = '\0';

    if (strcmp(opName, "transfer") == 0)
        ctx->opType = PLT_OP_TRANSFER;
    else if (strcmp(opName, "mint") == 0)
        ctx->opType = PLT_OP_MINT;
    else if (strcmp(opName, "burn") == 0)
        ctx->opType = PLT_OP_BURN;
    else if (strcmp(opName, "addAllowList") == 0)
        ctx->opType = PLT_OP_ADD_ALLOW_LIST;
    else if (strcmp(opName, "removeAllowList") == 0)
        ctx->opType = PLT_OP_REM_ALLOW_LIST;
    else if (strcmp(opName, "addDenyList") == 0)
        ctx->opType = PLT_OP_ADD_DENY_LIST;
    else if (strcmp(opName, "removeDenyList") == 0)
        ctx->opType = PLT_OP_REM_DENY_LIST;
    else if (strcmp(opName, "pause") == 0)
        ctx->opType = PLT_OP_PAUSE;
    else if (strcmp(opName, "unpause") == 0)
        ctx->opType = PLT_OP_UNPAUSE;
    else
        return false; /* unknown operation */

    /* Parse fields map (order not guaranteed by CIS-7). */
    if (!cbor_value_is_map(&op_map)) return false;
    CborValue inner;
    if (cbor_value_enter_container(&op_map, &inner) != CborNoError) return false;

    ctx->hasMemo = false;

    while (!cbor_value_at_end(&inner)) {
        if (!cbor_value_is_text_string(&inner)) return false;
        char fieldName[12];
        size_t fieldLen = sizeof(fieldName) - 1u;
        if (cbor_value_copy_text_string(&inner, fieldName, &fieldLen, &inner) != CborNoError) {
            return false;
        }
        fieldName[fieldLen] = '\0';

        if (strcmp(fieldName, "amount") == 0) {
            if (!parse_amount_value(&inner)) return false;
        } else if (strcmp(fieldName, "recipient") == 0 || strcmp(fieldName, "target") == 0) {
            if (!parse_address_value(&inner)) return false;
        } else if (strcmp(fieldName, "memo") == 0) {
            if (!parse_memo_value(&inner)) return false;
        } else {
            /* Unknown field — skip its value. */
            if (cbor_value_advance(&inner) != CborNoError) return false;
        }
    }

    if (cbor_value_leave_container(&op_map, &inner) != CborNoError) return false;
    if (cbor_value_leave_container(&arr, &op_map) != CborNoError) return false;

    /* Multi-op guard: outer array must be exhausted after the first op. */
    if (!cbor_value_at_end(&arr)) {
        THROW(ERROR_PLT_MULTI_OP);
    }

    return true;
}

/* ------------------------------------------------------------------ */
/* Display string formatter                                            */
/* ------------------------------------------------------------------ */

/*
 * Populate all ctx->displayXxx strings from the already-parsed CBOR fields.
 * Called after parse_plt_cbor() succeeds.
 */
static void format_plt_display(void) {
    /* Operation name. */
    static const char *const op_names[] = {
        [PLT_OP_TRANSFER] = "Transfer",
        [PLT_OP_MINT] = "Mint",
        [PLT_OP_BURN] = "Burn",
        [PLT_OP_ADD_ALLOW_LIST] = "Add to allow list",
        [PLT_OP_REM_ALLOW_LIST] = "Remove from allow list",
        [PLT_OP_ADD_DENY_LIST] = "Add to deny list",
        [PLT_OP_REM_DENY_LIST] = "Remove from deny list",
        [PLT_OP_PAUSE] = "Pause",
        [PLT_OP_UNPAUSE] = "Unpause",
    };
    const char *name = op_names[ctx->opType];
    size_t nameLen = strlen(name);
    if (nameLen >= sizeof(ctx->displayOp)) nameLen = sizeof(ctx->displayOp) - 1u;
    memmove(ctx->displayOp, name, nameLen);
    ctx->displayOp[nameLen] = '\0';

    /* Amount — for transfer, mint, burn. */
    if (ctx->opType == PLT_OP_TRANSFER || ctx->opType == PLT_OP_MINT ||
        ctx->opType == PLT_OP_BURN) {
        plt_amount_to_display(ctx->displayAmount,
                              sizeof(ctx->displayAmount),
                              ctx->amountSignificand,
                              ctx->amountExponent,
                              (const char *) ctx->tokenId,
                              ctx->tokenIdLength);
    }

    /* Address — for transfer (recipient) and allow/deny list ops (target). */
    if (ctx->opType == PLT_OP_TRANSFER || ctx->opType == PLT_OP_ADD_ALLOW_LIST ||
        ctx->opType == PLT_OP_REM_ALLOW_LIST || ctx->opType == PLT_OP_ADD_DENY_LIST ||
        ctx->opType == PLT_OP_REM_DENY_LIST) {
        size_t addrOutLen = sizeof(ctx->displayAddress);
        if (base58check_encode(ctx->address,
                               ADDRESS_LENGTH,
                               (unsigned char *) ctx->displayAddress,
                               &addrOutLen) != 0) {
            /* Encoding failure: show raw hex prefix as fallback. */
            ctx->displayAddress[0] = '?';
            ctx->displayAddress[1] = '\0';
        }
    }
}

/* ------------------------------------------------------------------ */
/* APDU handler                                                        */
/* ------------------------------------------------------------------ */

void handle_sign_plt(const command_t *cmd, volatile unsigned int *flags, bool isInitialCall) {
    uint8_t *cdata = cmd->data;
    uint8_t p1 = cmd->p1;
    uint8_t lc = cmd->lc;

    if (isInitialCall) {
        ctx->state = TX_PLT_INITIAL;
    }

    /* ---- P1=0x00 INIT ---- */
    if (p1 == PLT_P1_INIT) {
        if (ctx->state != TX_PLT_INITIAL) THROW(ERROR_INVALID_STATE);
        if (cmd->p2 != 0x00) THROW(SWO_WRONG_P1_P2);

        size_t pathLen = parse_derivation_path(cdata, lc);
        cdata += pathLen;
        uint8_t remaining = lc - (uint8_t) pathLen;

        if (cx_sha256_init(&tx_state->hash) != CX_SHA256) THROW(ERROR_FAILED_CX_OPERATION);
        int headerAndKind = hashAccountTransactionHeaderAndKind(cdata, remaining, (uint8_t) PLT);
        cdata += headerAndKind;
        remaining -= (uint8_t) headerAndKind;

        /* token_id_length[1] */
        if (remaining < 1u) THROW(ERROR_PLT_DATA_ERROR);
        uint8_t tokenIdLen = cdata[0];
        if (tokenIdLen < 1u || tokenIdLen > PLT_TOKEN_ID_MAX) THROW(ERROR_PLT_DATA_ERROR);
        cdata += 1;
        remaining -= 1;

        /* token_id[tokenIdLen] + cbor_total_length[4] */
        if (remaining < (uint8_t) (tokenIdLen + 4u)) THROW(ERROR_PLT_DATA_ERROR);
        update_hash((cx_hash_t *) &tx_state->hash,
                    cdata - 1, /* include the length byte in the hash */
                    1u + tokenIdLen);
        memmove(ctx->tokenId, cdata, tokenIdLen);
        ctx->tokenId[tokenIdLen] = '\0'; /* NUL-terminate for display */
        ctx->tokenIdLength = tokenIdLen;
        cdata += tokenIdLen;
        remaining -= tokenIdLen;

        /* cbor_total_length[4] big-endian */
        uint32_t cborTotal = U4BE(cdata, 0);
        if (cborTotal == 0u || cborTotal > APP_PLT_CBOR_MAX) THROW(ERROR_PLT_BUFFER_ERROR);
        update_hash((cx_hash_t *) &tx_state->hash, cdata, 4u);
        remaining -= 4u;

        if (remaining != 0u) THROW(SWO_INCORRECT_DATA);

        ctx->cborTotalLength = cborTotal;
        ctx->cborReceived = 0;
        ctx->state = TX_PLT_CBOR;

        send_success_no_idle();
        return;
    }

    /* ---- P1=0x01 CONT ---- */
    if (p1 == PLT_P1_CONT) {
        if (ctx->state != TX_PLT_CBOR) THROW(ERROR_INVALID_STATE);
        if (cmd->p2 != 0x00) THROW(SWO_WRONG_P1_P2);
        if (lc == 0u) THROW(ERROR_PLT_CBOR_ERROR);
        if ((uint32_t) lc > ctx->cborTotalLength - ctx->cborReceived) THROW(ERROR_PLT_CBOR_ERROR);

        update_hash((cx_hash_t *) &tx_state->hash, cdata, lc);
        memmove(ctx->cborBuf + ctx->cborReceived, cdata, lc);
        ctx->cborReceived += (uint32_t) lc;

        if (ctx->cborReceived == ctx->cborTotalLength) {
            /* All CBOR received: parse, format display strings, show UI. */
            if (!parse_plt_cbor()) THROW(ERROR_PLT_CBOR_ERROR);
            format_plt_display();
            startPltDisplay(flags);
            *flags |= IO_ASYNCH_REPLY;
        } else {
            send_success_no_idle();
        }
        return;
    }

    THROW(ERROR_INVALID_PARAM);
}
