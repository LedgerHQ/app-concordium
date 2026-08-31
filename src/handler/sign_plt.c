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
#include "helpers/fee_display.h"
#include "helpers/numberHelpers.h"
#include "helpers/tx_hash.h"

#include "sign_plt.h"

/*
 * Worst-case single PLT transfer CBOR with a 256-byte memo is ~355 bytes.
 * APP_PLT_CBOR_MAX = 512 provides ~44% headroom for future op types without
 * exceeding BSS budgets on constrained targets.  If you reduce this constant,
 * re-derive the bound: sum CBOR overhead for every field of the largest op.
 */
_Static_assert(APP_PLT_CBOR_MAX >= 512,
               "PLT CBOR buffer too small — worst-case transfer+memo needs ~355 B; "
               "do not go below 512 without recalculating");
_Static_assert(sizeof(signPltContext_t) <= 1400,
               "signPltContext_t exceeds BSS budget — check cborBuf / address / display fields");
/* displayAmount must hold "<number> <tokenId>\0".
 * 40 = FPU64_TMP_LEN (max formatted uint64 with up to 18 decimal places).
 * If PLT_TOKEN_ID_MAX or FPU64_TMP_LEN changes, update PLT_AMOUNT_DISPLAY_SIZE in app_sizes.h. */
_Static_assert(sizeof(((signPltContext_t *) 0)->displayAmount) >= 40 + 1 + PLT_TOKEN_ID_MAX + 1,
               "displayAmount too small — must fit FPU64_TMP_LEN + space + PLT_TOKEN_ID_MAX + NUL");

/* P1 values for the PLT multi-step flow. */
#define PLT_P1_INIT 0x00
#define PLT_P1_CONT 0x01

/* CBOR tag numbers used by CIS-7. */
#define CBOR_TAG_DECIMAL_FRACTION 4u
#define CBOR_TAG_ACCOUNT_ADDRESS  40307u /* BCR-2020-009 crypto-address */
#define CBOR_TAG_COININFO         40305u /* BCR-2020-007 coin-info     */

/*
 * Map keys inside a tag-40307 address (BCR-2020-009):
 *   1 = info (optional coininfo), 2 = address type (unused by CIS-7), 3 = data.
 * Map key inside a tag-40305 coininfo: 1 = SLIP-44 coin type
 * (2 = network, which CIS-7 declares unsupported).
 */
#define ADDRESS_KEY_INFO  1u
#define ADDRESS_KEY_DATA  3u
#define COININFO_KEY_TYPE 1u

/* SLIP-44 coin type for CCD; the only value CIS-7 permits in coininfo. */
#define CCD_COIN_TYPE 919u

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

    /*
     * Tags are not containers in tinycbor (cbor_value_is_container is false
     * for CborTagType).  Use advance_fixed to skip the tag header bytes; the
     * tinycbor internals treat CborTagType as a fixed-width item and do NOT
     * decrement the parent container's remaining count, so after this call
     * `it` points at the tagged content with the parent remaining unchanged.
     */
    if (cbor_value_advance_fixed(it) != CborNoError) return false;

    if (!cbor_value_is_array(it)) return false;

    CborValue arr;
    if (cbor_value_enter_container(it, &arr) != CborNoError) return false;

    /* Exponent: negative integer (most common) or zero (unsigned 0). */
    int8_t exponent = 0;
    if (cbor_value_is_negative_integer(&arr)) {
        uint64_t raw = 0;
        cbor_value_get_raw_integer(&arr, &raw);
        if (raw > 127u) {
            cbor_value_leave_container(it, &arr);
            return false;
        }
        exponent = (int8_t) (-(int64_t) (raw + 1u));
    } else if (cbor_value_is_unsigned_integer(&arr)) {
        uint64_t v = 0;
        cbor_value_get_uint64(&arr, &v);
        if (v != 0u) {
            cbor_value_leave_container(it, &arr);
            return false; /* CIS-7: exponent ≤ 0 */
        }
        exponent = 0;
    } else {
        cbor_value_leave_container(it, &arr);
        return false;
    }
    if (cbor_value_advance(&arr) != CborNoError) {
        cbor_value_leave_container(it, &arr);
        return false;
    }

    /* Significand: unsigned 64-bit integer. */
    if (!cbor_value_is_unsigned_integer(&arr)) {
        cbor_value_leave_container(it, &arr);
        return false;
    }
    uint64_t sig = 0;
    cbor_value_get_uint64(&arr, &sig);
    if (cbor_value_advance(&arr) != CborNoError) {
        cbor_value_leave_container(it, &arr);
        return false;
    }

    if (cbor_value_leave_container(it, &arr) != CborNoError) return false;

    ctx->amountSignificand = sig;
    ctx->amountExponent = exponent;
    return true;
}

/*
 * Parse a CIS-7 coininfo: CBOR tag 40305 wrapping { 1: 919 }.
 * Advances *it past the value.  A coin type other than CCD means the payload
 * carries another chain's address, so it is rejected rather than displayed.
 */
static bool parse_coininfo_value(CborValue *it) {
    if (!cbor_value_is_tag(it)) return false;
    CborTag tag = 0;
    cbor_value_get_tag(it, &tag);
    if (tag != CBOR_TAG_COININFO) return false;

    /* Skip the tag header (same reasoning as parse_amount_value above). */
    if (cbor_value_advance_fixed(it) != CborNoError) return false;

    if (!cbor_value_is_map(it)) return false;

    CborValue info;
    if (cbor_value_enter_container(it, &info) != CborNoError) return false;

    bool typeSeen = false;
    while (!cbor_value_at_end(&info)) {
        if (!cbor_value_is_unsigned_integer(&info)) return false;
        uint64_t key = 0;
        cbor_value_get_uint64(&info, &key);
        if (cbor_value_advance(&info) != CborNoError) return false;

        /* Only the coin type is defined; anything else (e.g. BCR key 2 =
         * network) is not part of CIS-7 and must not be signed blindly. */
        if (key != COININFO_KEY_TYPE || typeSeen) return false;

        if (!cbor_value_is_unsigned_integer(&info)) return false;
        uint64_t coinType = 0;
        cbor_value_get_uint64(&info, &coinType);
        if (coinType != CCD_COIN_TYPE) return false;
        typeSeen = true;

        if (cbor_value_advance(&info) != CborNoError) return false;
    }

    if (cbor_value_leave_container(it, &info) != CborNoError) return false;
    return typeSeen;
}

/*
 * Parse a CIS-7 tagged account address:
 *
 *   #6.40307({ ? 1: #6.40305({1: 919}), 3: bstr .size 32 })
 *
 * The info field (key 1) is optional per CIS-7 — an address with no info is
 * assumed to be a Concordium address.  Key 3 is mandatory.  Keys are iterated
 * rather than read positionally, so either serialization order is accepted.
 * On success advances *it past the tag and stores raw bytes in ctx->address.
 */
static bool parse_address_value(CborValue *it) {
    if (!cbor_value_is_tag(it)) return false;
    CborTag tag = 0;
    cbor_value_get_tag(it, &tag);
    if (tag != CBOR_TAG_ACCOUNT_ADDRESS) return false;

    /* Skip the tag header (same reasoning as parse_amount_value above). */
    if (cbor_value_advance_fixed(it) != CborNoError) return false;

    if (!cbor_value_is_map(it)) return false;

    CborValue addr;
    if (cbor_value_enter_container(it, &addr) != CborNoError) return false;

    bool dataSeen = false;
    while (!cbor_value_at_end(&addr)) {
        if (!cbor_value_is_unsigned_integer(&addr)) return false;
        uint64_t key = 0;
        cbor_value_get_uint64(&addr, &key);
        if (cbor_value_advance(&addr) != CborNoError) return false;

        if (key == ADDRESS_KEY_INFO) {
            if (!parse_coininfo_value(&addr)) return false;
        } else if (key == ADDRESS_KEY_DATA) {
            if (dataSeen) return false; /* duplicate key */
            if (!cbor_value_is_byte_string(&addr)) return false;
            size_t addrLen = ADDRESS_LENGTH;
            if (cbor_value_copy_byte_string(&addr, ctx->address, &addrLen, &addr) != CborNoError ||
                addrLen != ADDRESS_LENGTH) {
                return false;
            }
            dataSeen = true;
        } else {
            /* Includes BCR key 2 (address type), unused by CIS-7.  An unknown
             * key could change what the address means — reject, do not skip. */
            return false;
        }
    }

    if (cbor_value_leave_container(it, &addr) != CborNoError) return false;
    return dataSeen;
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
        if (fit > displayLen) fit = displayLen;     /* don't overread the sample buffer */
        memmove(ctx->displayMemo, bytes, fit);
        ctx->displayMemo[fit] = '.';
        ctx->displayMemo[fit + 1] = '.';
        ctx->displayMemo[fit + 2] = '.';
        ctx->displayMemo[fit + 3] = '\0';
    } else {
        /* Hex prefix: "0x" + up to MEMO_DISPLAY_BYTES bytes. */
        ctx->displayMemo[0] = '0';
        ctx->displayMemo[1] = 'x';
        /* "0x" prefix + hexBytes*2 hex chars + NUL must fit in displayMemo[30]:
         * 2 + hexBytes*2 + 1 <= 30  =>  hexBytes <= 13. */
        size_t hexMax = (sizeof(ctx->displayMemo) - 3u) / 2u; /* = 13 */
        size_t hexBytes = displayLen < hexMax ? displayLen : hexMax;
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
        /* tag 24 = byte string containing embedded CBOR; unwrap one level.
         * Tags are not containers in tinycbor — use advance_fixed to skip the
         * tag header, then treat the content as a plain byte string. */
        if (cbor_value_advance_fixed(it) != CborNoError) goto skip;
        if (!cbor_value_is_byte_string(it)) goto skip;
        cbor_value_get_string_length(it, &totalLen);
        size_t copyLen = totalLen < sizeof(tmp) ? totalLen : sizeof(tmp);
        if (cbor_value_copy_byte_string(it, tmp, &copyLen, it) != CborNoError) goto skip;
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
static uint16_t parse_plt_cbor(void) {
    PRINTF("DBG: parse_plt entry len=%u buf[0]=%02x\n",
           (unsigned) ctx->cborReceived,
           (unsigned) (ctx->cborReceived > 0 ? ctx->cborBuf[0] : 0xff));
    CborParser parser;
    CborValue it;
    if (cbor_parser_init(ctx->cborBuf, ctx->cborReceived, 0, &parser, &it) != CborNoError) {
        PRINTF("DBG: parse_plt: cbor_parser_init fail\n");
        return ERROR_PLT_CBOR_ERROR;
    }

    /* Outer array: [ single-op ] */
    if (!cbor_value_is_array(&it)) {
        PRINTF("DBG: parse_plt: not array\n");
        return ERROR_PLT_CBOR_ERROR;
    }
    CborValue arr;
    if (cbor_value_enter_container(&it, &arr) != CborNoError) {
        PRINTF("DBG: parse_plt: enter arr fail\n");
        return ERROR_PLT_CBOR_ERROR;
    }
    if (cbor_value_at_end(&arr)) {
        PRINTF("DBG: parse_plt: arr empty\n");
        return ERROR_PLT_CBOR_ERROR;
    }

    /* Single op: a map { "opName": { ...fields... } } */
    if (!cbor_value_is_map(&arr)) {
        PRINTF("DBG: parse_plt: first item not map\n");
        return ERROR_PLT_CBOR_ERROR;
    }
    CborValue op_map;
    if (cbor_value_enter_container(&arr, &op_map) != CborNoError) return ERROR_PLT_CBOR_ERROR;

    /* Read op name key. */
    if (!cbor_value_is_text_string(&op_map)) return ERROR_PLT_CBOR_ERROR;
    char opName[PLT_OP_NAME_MAX];
    size_t opNameLen = sizeof(opName) - 1u;
    if (cbor_value_copy_text_string(&op_map, opName, &opNameLen, &op_map) != CborNoError) {
        return ERROR_PLT_CBOR_ERROR;
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
        return ERROR_PLT_CBOR_ERROR; /* unknown operation */

    /* Parse fields map (order not guaranteed by CIS-7). */
    if (!cbor_value_is_map(&op_map)) return ERROR_PLT_CBOR_ERROR;
    CborValue inner;
    if (cbor_value_enter_container(&op_map, &inner) != CborNoError) return ERROR_PLT_CBOR_ERROR;

    ctx->hasMemo = false;
    bool amountSeen = false, addressSeen = false;

    while (!cbor_value_at_end(&inner)) {
        if (!cbor_value_is_text_string(&inner)) return ERROR_PLT_CBOR_ERROR;
        char fieldName[PLT_OP_NAME_MAX + 1];
        size_t fieldLen = sizeof(fieldName) - 1u;
        CborError fieldErr = cbor_value_copy_text_string(&inner, fieldName, &fieldLen, &inner);
        if (fieldErr == CborErrorDataTooLarge) {
            /* Field name too long to be any known CIS-7 key — skip its value. */
            if (cbor_value_advance(&inner) != CborNoError) return ERROR_PLT_CBOR_ERROR;
            continue;
        }
        if (fieldErr != CborNoError) return ERROR_PLT_CBOR_ERROR;
        fieldName[fieldLen] = '\0';

        if (strcmp(fieldName, "amount") == 0) {
            if (!parse_amount_value(&inner)) return ERROR_PLT_CBOR_ERROR;
            amountSeen = true;
            /* The app renders at most 18 decimal places; see doc/ins_sign_plt.md.
             * Reject early so the host gets a dedicated SW instead of ERROR_INVALID_TRANSACTION. */
            if (ctx->amountExponent < -18) return ERROR_PLT_UNSUPPORTED_DECIMALS;
        } else if (strcmp(fieldName, "recipient") == 0 || strcmp(fieldName, "target") == 0) {
            if (!parse_address_value(&inner)) return ERROR_PLT_CBOR_ERROR;
            addressSeen = true;
        } else if (strcmp(fieldName, "memo") == 0) {
            if (!parse_memo_value(&inner)) return ERROR_PLT_CBOR_ERROR;
        } else {
            /* Unknown field — skip its value. */
            if (cbor_value_advance(&inner) != CborNoError) return ERROR_PLT_CBOR_ERROR;
        }
    }

    if (cbor_value_leave_container(&op_map, &inner) != CborNoError) return ERROR_PLT_CBOR_ERROR;
    if (cbor_value_leave_container(&arr, &op_map) != CborNoError) return ERROR_PLT_CBOR_ERROR;

    /* Validate required fields per operation type. Missing fields would cause the display
     * to show stale or zero values, violating the clear-signing guarantee. */
    switch (ctx->opType) {
        case PLT_OP_TRANSFER:
            if (!amountSeen || !addressSeen) return ERROR_PLT_CBOR_ERROR;
            break;
        case PLT_OP_MINT:
        case PLT_OP_BURN:
            if (!amountSeen) return ERROR_PLT_CBOR_ERROR;
            break;
        case PLT_OP_ADD_ALLOW_LIST:
        case PLT_OP_REM_ALLOW_LIST:
        case PLT_OP_ADD_DENY_LIST:
        case PLT_OP_REM_DENY_LIST:
            if (!addressSeen) return ERROR_PLT_CBOR_ERROR;
            break;
        default:
            break; /* pause / unpause have no required fields */
    }

    /* Multi-op guard: outer array must be exhausted after the first op. */
    PRINTF("DBG: parse_plt: arr.remaining=%u at_end=%d\n",
           (unsigned) arr.remaining,
           (int) cbor_value_at_end(&arr));
    if (!cbor_value_at_end(&arr)) {
        PRINTF("DBG: parse_plt: multi-op rejected\n");
        return ERROR_PLT_MULTI_OP;
    }

    PRINTF("DBG: parse_plt: success opType=%d\n", ctx->opType);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Display string formatter                                            */
/* ------------------------------------------------------------------ */

/*
 * Populate all ctx->displayXxx strings from the already-parsed CBOR fields.
 * Called after parse_plt_cbor() succeeds.
 */
static void format_plt_display(void) {
    PRINTF("DBG: fmt entry opType=%d\n", ctx->opType);

/* Copying string literals with sizeof avoids strlen — which can fault on
 * Cortex-M0 when the literal lives at an unaligned flash address, because
 * some strlen implementations use word-aligned loads.  sizeof(literal)
 * is a compile-time constant so no runtime load is needed. */
#define COPY_OP_NAME(str) memmove(ctx->displayOp, str, sizeof(str))
    switch (ctx->opType) {
        case PLT_OP_TRANSFER:
            COPY_OP_NAME("Transfer");
            break;
        case PLT_OP_MINT:
            COPY_OP_NAME("Mint");
            break;
        case PLT_OP_BURN:
            COPY_OP_NAME("Burn");
            break;
        case PLT_OP_ADD_ALLOW_LIST:
            COPY_OP_NAME("Add to allow list");
            break;
        case PLT_OP_REM_ALLOW_LIST:
            COPY_OP_NAME("Remove from allow list");
            break;
        case PLT_OP_ADD_DENY_LIST:
            COPY_OP_NAME("Add to deny list");
            break;
        case PLT_OP_REM_DENY_LIST:
            COPY_OP_NAME("Remove from deny list");
            break;
        case PLT_OP_PAUSE:
            COPY_OP_NAME("Pause");
            break;
        case PLT_OP_UNPAUSE:
            COPY_OP_NAME("Unpause");
            break;
        default:
            COPY_OP_NAME("?");
            break;
    }
#undef COPY_OP_NAME
    PRINTF("DBG: displayOp=%s\n", ctx->displayOp);

    /* Amount — for transfer, mint, burn. */
    if (ctx->opType == PLT_OP_TRANSFER || ctx->opType == PLT_OP_MINT ||
        ctx->opType == PLT_OP_BURN) {
        PRINTF("DBG: calling plt_amount_to_display sig=%llu exp=%d\n",
               (unsigned long long) ctx->amountSignificand,
               ctx->amountExponent);
        plt_amount_to_display(ctx->displayAmount,
                              sizeof(ctx->displayAmount),
                              ctx->amountSignificand,
                              ctx->amountExponent,
                              (const char *) ctx->tokenId,
                              ctx->tokenIdLength);
        PRINTF("DBG: amount=%s\n", ctx->displayAmount);
    }

    /* Address — for transfer (recipient) and allow/deny list ops (target). */
    if (ctx->opType == PLT_OP_TRANSFER || ctx->opType == PLT_OP_ADD_ALLOW_LIST ||
        ctx->opType == PLT_OP_REM_ALLOW_LIST || ctx->opType == PLT_OP_ADD_DENY_LIST ||
        ctx->opType == PLT_OP_REM_DENY_LIST) {
        PRINTF("DBG: calling base58check_encode addr[0]=%02x\n", ctx->address[0]);
        size_t addrOutLen = sizeof(ctx->displayAddress);
        int b58ret = base58check_encode(ctx->address,
                                        ADDRESS_LENGTH,
                                        (unsigned char *) ctx->displayAddress,
                                        &addrOutLen);
        PRINTF("DBG: b58ret=%d addrOutLen=%u\n", b58ret, (unsigned) addrOutLen);
        if (b58ret <= 0) {
            ctx->displayAddress[0] = '?';
            ctx->displayAddress[1] = '\0';
        } else {
            ctx->displayAddress[b58ret] = '\0';
        }
        PRINTF("DBG: addr=%s\n", ctx->displayAddress);
    }
    PRINTF("DBG: fmt done\n");
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
        if (cmd->p2 != P2_SIGN_TX_DEFAULT && cmd->p2 != P2_SIGN_TX_FEE_DISPLAY)
            THROW(SWO_WRONG_P1_P2);

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
        cdata += 4u;
        remaining -= 4u;

        ctx->hasFeeDisplay = false;
        explicit_bzero(ctx->displayFee, sizeof(ctx->displayFee));
        if (cmd->p2 == P2_SIGN_TX_FEE_DISPLAY) {
            if (remaining != FEE_DISPLAY_U64_SIZE) THROW(SWO_INCORRECT_DATA);
            /* displayFee is char[] so the UI layers can use it without casting;
             * fee_display_apply_u64 writes bytes, hence the cast here. */
            fee_display_apply_u64((uint8_t *) ctx->displayFee,
                                  sizeof(ctx->displayFee),
                                  &ctx->hasFeeDisplay,
                                  cdata);
        } else {
            if (remaining != 0u) THROW(SWO_INCORRECT_DATA);
        }

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
        if (lc == 0u) {
            ctx->state = TX_PLT_INITIAL;
            io_send_sw(ERROR_PLT_CBOR_ERROR);
            return;
        }
        if ((uint32_t) lc > ctx->cborTotalLength - ctx->cborReceived) {
            ctx->state = TX_PLT_INITIAL;
            io_send_sw(ERROR_PLT_CBOR_ERROR);
            return;
        }

        update_hash((cx_hash_t *) &tx_state->hash, cdata, lc);
        memmove(ctx->cborBuf + ctx->cborReceived, cdata, lc);
        ctx->cborReceived += (uint32_t) lc;

        if (ctx->cborReceived == ctx->cborTotalLength) {
            /* All CBOR received: parse, format display strings, show UI. */
            PRINTF("DBG: calling parse_plt_cbor\n");
            uint16_t parseErr = parse_plt_cbor();
            if (parseErr != 0) {
                ctx->state = TX_PLT_INITIAL;
                io_send_sw(parseErr);
                return;
            }
            PRINTF("DBG: parse_plt_cbor OK, opType=%d\n", ctx->opType);
            format_plt_display();
            PRINTF("DBG: format_plt_display OK\n");
            startPltDisplay(flags);
            PRINTF("DBG: startPltDisplay OK\n");
            *flags |= IO_ASYNCH_REPLY;
        } else {
            send_success_no_idle();
        }
        return;
    }

    THROW(ERROR_INVALID_PARAM);
}
