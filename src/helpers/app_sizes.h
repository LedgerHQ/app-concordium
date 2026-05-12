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
#define MAX_CBOR_STRING_SIZE 255
#define MAX_CBOR_BLOB_SIZE   (2 + MAX_CBOR_STRING_SIZE)  // 2-byte CBOR header + payload
#define MAX_DATA_SIZE        MAX_CBOR_BLOB_SIZE

#define ACCOUNT_TRANSACTION_HEADER_LENGTH 60
#define UPDATE_HEADER_LENGTH              28

/* Maximum PLT CBOR blob the device will buffer (single-operation limit).
 * Worst-case single transfer: ~9B map key + ~13B amount (tag4) + ~36B recipient (tag40307)
 * + ~264B memo (5B header + 256B payload) + ~5B framing ≈ 347 B.
 * 512 gives ~47% headroom for future mint/burn ops without touching device BSS limits.
 * A _Static_assert in sign_plt.c verifies this stays below target BSS budgets. */
#define APP_PLT_CBOR_MAX 512

/* Maximum token-id byte length (1..PLT_TOKEN_ID_MAX per CIS-7 §3). */
#define PLT_TOKEN_ID_MAX 128
