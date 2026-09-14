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

// Revealed identity attributes. The longest registry name is "Country of residence"; the value
// length is a host-supplied uint8, so UINT8_MAX + 1 always fits the value plus its terminator.
#define ATTRIBUTE_NAME_SIZE  24
#define ATTRIBUTE_VALUE_SIZE 256

// Private-key export approval screens: the P2-selected detail (network for INS 0x37, key format
// for INS 0x05) and the list of key types the selected purpose releases.
#define EXPORT_DETAIL_TITLE_SIZE 16
#define EXPORT_DETAIL_SIZE       24
#define EXPORT_KEY_TYPES_SIZE    40

// Contract init/receive names shown on the signing screens, plus room for a NUL. The protocol
// length field is a uint16, so a name can exceed any buffer; one that does not fit is replaced
// wholesale by a marker rather than truncated, and the digest still covers its exact bytes.
#define CONTRACT_NAME_SIZE 256
// Hex digest of a hashed payload (module source, contract name + parameters), plus a NUL.
#define HASH_DISPLAY_SIZE (COMMON_HASH_SIZE * 2 + 1)

// Signed `energy_amount` from the account transaction header, as decimal text.
// UINT64_MAX is 20 digits, plus a NUL.
#define ENERGY_DISPLAY_SIZE 21

// Network label derived from the signing path's coin type ("Mainnet", "Testnet", ...). Sized for
// the longest label in derivation_path.h, which asserts the fit at compile time.
#define NETWORK_DISPLAY_SIZE 24

// VERIFY_ADDRESS path row. The compact formats render "idp/identity/counter", but the full-path
// format renders every node that feeds key derivation ("44'/919'/403'/404'/8'"), so the buffer is
// sized for DERIVATION_PATH_NODES_MAX nodes of "4294967295'" plus separators and a NUL.
#define VERIFY_ADDRESS_PATH_DISPLAY_SIZE 104
// Label for that row: "Identity" for the compact formats, "Derivation path" for the full one.
#define VERIFY_ADDRESS_LABEL_SIZE 20

// Public-key comparison snapshot (see comparePublicKey_t). Sized to match the corresponding
// fields of exportPublicKeyContext_t, which get_public_key.c asserts.
#define COMPARE_IDENTITY_DISPLAY_SIZE 21
#define COMPARE_PUBLIC_KEY_HEX_SIZE   68

// CBOR major-type label shown beside a memo / register-data value ("Unsigned integer",
// "Negative integer", "Text"), plus a NUL.
#define CBOR_TYPE_LABEL_SIZE 20

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
