#pragma once

#include "buffer.h"
#include "ledger/cx.h"

/*
 * Mirrors ledger-secure-sdk/lib_pki/ledger_pki.h. The verdict itself is supplied by the fuzz
 * stub in stubs.c, driven by the input, so a harness can model both an accepted and a rejected
 * descriptor without holding a real PKI certificate (finding V-099).
 */
typedef enum check_signature_with_pki_status_e {
    CHECK_SIGNATURE_WITH_PKI_SUCCESS                 = 0,
    CHECK_SIGNATURE_WITH_PKI_MISSING_CERTIFICATE     = 1,
    CHECK_SIGNATURE_WITH_PKI_WRONG_CERTIFICATE_USAGE = 2,
    CHECK_SIGNATURE_WITH_PKI_WRONG_CERTIFICATE_CURVE = 3,
    CHECK_SIGNATURE_WITH_PKI_WRONG_SIGNATURE         = 4,
} check_signature_with_pki_status_t;

check_signature_with_pki_status_t check_signature_with_pki(const buffer_t hash,
                                                          const uint8_t *expected_key_usage,
                                                          const cx_curve_t *expected_curve,
                                                          const buffer_t signature);

/*
 * Fuzz-build-only policy control: the status check_signature_with_pki() reports.
 *
 * Production requires a PKI-signed descriptor, and this does not weaken that; it lets the
 * harness reach the code *after* verification (field validation, the challenge comparison,
 * the name/address copy, the single-use clearing) as well as the rejection path, which no
 * target could reach at all while the whole handler was a no-op.
 */
extern check_signature_with_pki_status_t g_fuzz_pki_status;
