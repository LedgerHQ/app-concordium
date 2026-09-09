#pragma once

/**
 * Shared size constants (keys, display buffers, module refs). Included early from `globals.h`.
 */
#define KEY_LENGTH 32

#define COMMON_SIGNATURE_SIZE      64
#define COMMON_HASH_SIZE           KEY_LENGTH
#define COMMON_ADDRESS_SIZE        57
#define COMMON_DISPLAY_SIZE        255
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

#define U32_BYTES        4
#define MAX_CDATA_LENGTH 255

#define ACCOUNT_TRANSACTION_HEADER_LENGTH 60
#define UPDATE_HEADER_LENGTH              28
