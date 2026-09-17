#pragma once

#include <stdint.h>

/*
 * Minimal stand-in for ledger-secure-sdk/include/os_pki.h.
 *
 * Only the key-usage constant set_trusted_name.c passes to check_signature_with_pki() is
 * needed; the real header drags in the BOLOS syscall surface. The value must stay in step
 * with the SDK enum, so it is asserted against it below.
 */
typedef enum {
    CERTIFICATE_PUBLIC_KEY_USAGE_GENUINE_CHECK        = 0x01,
    CERTIFICATE_PUBLIC_KEY_USAGE_EXCHANGE_PAYLOAD     = 0x02,
    CERTIFICATE_PUBLIC_KEY_USAGE_NFT_METADATA         = 0x03,
    CERTIFICATE_PUBLIC_KEY_USAGE_TRUSTED_NAME         = 0x04,
    CERTIFICATE_PUBLIC_KEY_USAGE_BACKUP_PROVIDER      = 0x05,
    CERTIFICATE_PUBLIC_KEY_USAGE_RECOVER_ORCHESTRATOR = 0x06,
    CERTIFICATE_PUBLIC_KEY_USAGE_PLUGIN_METADATA      = 0x07,
    CERTIFICATE_PUBLIC_KEY_USAGE_COIN_META            = 0x08,
    CERTIFICATE_PUBLIC_KEY_USAGE_SEED_ID_AUTH         = 0x09,
} os_pki_certificate_key_usage_t;
