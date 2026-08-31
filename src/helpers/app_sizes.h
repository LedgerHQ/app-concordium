#pragma once

/**
 * Shared size constants (keys, display buffers, module refs). Included early from `globals.h`.
 */
#define KEY_LENGTH 32

#define COMMON_SIGNATURE_SIZE      64
#define COMMON_HASH_SIZE           KEY_LENGTH
#define COMMON_ADDRESS_SIZE        57
#define COMMON_AMOUNT_DISPLAY_SIZE 30
#define COMMON_URL_DISPLAY_SIZE    256
#define COMMON_MODULE_REF_SIZE     32
#define COMMON_THRESHOLD_SIZE      4
#define COMMON_TIMESTAMP_SIZE      8
#define COMMON_COMMISSION_SIZE     8

#define U32_BYTES        4
#define MAX_CDATA_LENGTH 255

// CBOR blob wire bounds (shared across memo, register-data, and future CBOR flows)
// MAX_CBOR_STRING_SIZE=255 → CBOR header is 0x78 (1B) + 1-byte length = 2 bytes.
// (A 3-byte header would only arise for strings ≥256 bytes, which we do not support.)
#define MAX_CBOR_STRING_SIZE 255
#define MAX_CBOR_BLOB_SIZE   (2 + MAX_CBOR_STRING_SIZE)  // 2-byte CBOR header + payload
#define MAX_DATA_SIZE        MAX_CBOR_BLOB_SIZE

#define ACCOUNT_TRANSACTION_HEADER_LENGTH 60
#define UPDATE_HEADER_LENGTH              28

/* Maximum PLT CBOR blob the device will buffer (single-operation limit).
 * Worst-case single transfer: ~10B "transfer" key + ~13B amount (tag4)
 * + ~10B "recipient" key + 48B recipient (tag40307 map with tag40305 coininfo)
 * + ~5B "memo" key + ~260B memo (4B header + 256B payload) + ~4B framing ≈ 355 B.
 * 512 gives ~44% headroom for future mint/burn ops without touching device BSS limits.
 * A _Static_assert in sign_plt.c verifies this stays below target BSS budgets. */
#define APP_PLT_CBOR_MAX 512

/* Maximum token-id byte length (1..PLT_TOKEN_ID_MAX per CIS-7 §3). */
#define PLT_TOKEN_ID_MAX 128

/* Display buffer for "<number> <tokenId>\0".
 * 40 = FPU64_TMP_LEN (max formatted number incl. decimal point and 18 dp).
 * 1  = space separator.
 * PLT_TOKEN_ID_MAX = max token-id bytes.
 * 1  = NUL terminator.
 * Keep in sync with FPU64_TMP_LEN in numberHelpers.c. */
#define PLT_AMOUNT_DISPLAY_SIZE (40 + 1 + PLT_TOKEN_ID_MAX + 1)
