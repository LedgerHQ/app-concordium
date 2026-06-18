#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

/* ── error type and codes ─────────────────────────────────────────────── */
typedef uint32_t cx_err_t;

#define CX_OK    0x00000000u
#define CX_CARRY 0x00000001u

/* ── flags ────────────────────────────────────────────────────────────── */
#define CX_LAST (1u << 0)

/* ── hash algorithm IDs ───────────────────────────────────────────────── */
typedef enum cx_md_e {
    CX_NONE      = 0,
    CX_RIPEMD160 = 1,
    CX_SHA224    = 2,
    CX_SHA256    = 3,
    CX_SHA384    = 4,
    CX_SHA512    = 5,
    CX_KECCAK    = 6,
    CX_SHA3      = 7,
    CX_GROESTL   = 8,
    CX_BLAKE2B   = 9,
    CX_SHAKE128  = 10,
    CX_SHAKE256  = 11,
    CX_SHA3_256  = 12,
    CX_SHA3_512  = 13,
} cx_md_t;

#define CX_SHA256_SIZE 32

/* ── hash header / base type ─────────────────────────────────────────── */
struct cx_hash_header_s {
    cx_md_t  md_type;
    uint8_t  _opaque[56]; /* large enough for function-pointer table */
};
typedef struct cx_hash_header_s cx_hash_t;

/* ── SHA-256 ──────────────────────────────────────────────────────────── */
struct cx_sha256_s {
    cx_hash_t header;
    size_t    blen;
    uint8_t   block[64];
    uint8_t   acc[32];
};
typedef struct cx_sha256_s cx_sha256_t;

/* ── SHA-3 / Keccak ───────────────────────────────────────────────────── */
struct cx_sha3_s {
    cx_hash_t header;
    size_t    blen;
    uint8_t   block[136];
    uint8_t   acc[200];
};
typedef struct cx_sha3_s cx_sha3_t;

/* ── RIPEMD-160 ───────────────────────────────────────────────────────── */
struct cx_ripemd160_s {
    cx_hash_t header;
    size_t    blen;
    uint8_t   block[64];
    uint8_t   acc[20];
};
typedef struct cx_ripemd160_s cx_ripemd160_t;

/* ── SHA-512 ──────────────────────────────────────────────────────────── */
struct cx_sha512_s {
    cx_hash_t header;
    size_t    blen;
    uint8_t   block[128];
    uint8_t   acc[64];
};
typedef struct cx_sha512_s cx_sha512_t;

/* ── curve IDs ────────────────────────────────────────────────────────── */
typedef enum cx_curve_e {
    CX_CURVE_NONE          = 0,
    CX_CURVE_256K1         = 0x21,
    CX_CURVE_256R1         = 0x22,
    CX_CURVE_Ed25519       = 0x33,
    CX_CURVE_BLS12_381_G1  = 0x39,
} cx_curve_t;

/* ── EC key types (flexible array members replaced with fixed buffer) ─── */
struct cx_ecfp_public_key_s {
    cx_curve_t curve;
    size_t     W_len;
    uint8_t    W[65];
};
typedef struct cx_ecfp_public_key_s cx_ecfp_public_key_t;

struct cx_ecfp_private_key_s {
    cx_curve_t curve;
    size_t     d_len;
    uint8_t    d[32];
};
typedef struct cx_ecfp_private_key_s cx_ecfp_private_key_t;

/* ── BN handle (opaque uint32) ───────────────────────────────────────── */
typedef uint32_t cx_bn_t;

/* ── EC point ─────────────────────────────────────────────────────────── */
struct cx_ec_point_s {
    cx_curve_t curve;
    cx_bn_t    x;
    cx_bn_t    y;
    cx_bn_t    z;
};
typedef struct cx_ec_point_s cx_ecpoint_t;

/* ── CX_CHECK helper ──────────────────────────────────────────────────── */
#define CX_CHECK(call)         \
    do {                       \
        error = (call);        \
        if (error) goto end;   \
    } while (0)

/* ── hash function declarations ──────────────────────────────────────── */
cx_err_t cx_sha256_init_no_throw(cx_sha256_t *hash);

static inline int cx_sha256_init(cx_sha256_t *hash) {
    cx_sha256_init_no_throw(hash);
    return CX_SHA256;
}

cx_err_t cx_hash_no_throw(cx_hash_t *hash, uint32_t mode,
                           const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t out_len);

size_t cx_hash_sha256(const uint8_t *in, size_t len,
                      uint8_t *out, size_t out_len);

cx_err_t cx_hash_init(cx_hash_t *hash, cx_md_t hash_id);
cx_err_t cx_hash_update(cx_hash_t *hash, const uint8_t *in, size_t in_len);
cx_err_t cx_hash_final(cx_hash_t *hash, uint8_t *digest);
size_t   cx_hash_get_size(const cx_hash_t *ctx);

/* ── BN function declarations ────────────────────────────────────────── */
cx_err_t cx_bn_lock(size_t word_nbytes, uint32_t flags);
cx_err_t cx_bn_unlock(void);
cx_err_t cx_bn_alloc(cx_bn_t *x, size_t nbytes);
cx_err_t cx_bn_alloc_init(cx_bn_t *x, size_t nbytes, const uint8_t *value, size_t value_nbytes);
cx_err_t cx_bn_destroy(cx_bn_t *x);
cx_err_t cx_bn_set_u32(cx_bn_t x, uint32_t n);
cx_err_t cx_bn_get_u32(const cx_bn_t x, uint32_t *n);
cx_err_t cx_bn_export(const cx_bn_t x, uint8_t *bytes, size_t nbytes);
cx_err_t cx_bn_init(cx_bn_t x, const uint8_t *value, size_t value_nbytes);
cx_err_t cx_bn_copy(cx_bn_t a, const cx_bn_t b);
cx_err_t cx_bn_mod_add(cx_bn_t r, const cx_bn_t a, const cx_bn_t b, const cx_bn_t n);
cx_err_t cx_bn_mod_invert_nprime(cx_bn_t r, const cx_bn_t a, const cx_bn_t n);
cx_err_t cx_bn_cmp(const cx_bn_t a, const cx_bn_t b, int *diff);
cx_err_t cx_bn_cmp_u32(const cx_bn_t a, uint32_t b, int *diff);
cx_err_t cx_bn_nbytes(const cx_bn_t x, size_t *nbytes);
cx_err_t cx_bn_is_odd(const cx_bn_t n, bool *odd);

/* ── EC point function declarations ──────────────────────────────────── */
cx_err_t cx_ecpoint_alloc(cx_ecpoint_t *P, cx_curve_t cv);
cx_err_t cx_ecpoint_destroy(cx_ecpoint_t *P);
cx_err_t cx_ecpoint_init(cx_ecpoint_t *P,
                         const uint8_t *x, size_t x_len,
                         const uint8_t *y, size_t y_len);
cx_err_t cx_ecpoint_scalarmul_bn(cx_ecpoint_t *P, const cx_bn_t k);
cx_err_t cx_ecpoint_neg(cx_ecpoint_t *P);
cx_err_t cx_ecpoint_export_bn(const cx_ecpoint_t *P, cx_bn_t *x, cx_bn_t *y);

/* ── ECFP function declarations ──────────────────────────────────────── */
cx_err_t cx_ecfp_init_private_key_no_throw(cx_curve_t curve,
                                           const uint8_t *raw_key,
                                           size_t key_len,
                                           cx_ecfp_private_key_t *key);
cx_err_t cx_ecfp_generate_pair_no_throw(cx_curve_t curve,
                                        cx_ecfp_public_key_t *pubkey,
                                        cx_ecfp_private_key_t *privkey,
                                        bool keep_privkey);
cx_err_t cx_eddsa_sign_no_throw(const cx_ecfp_private_key_t *pvkey,
                                cx_md_t hashID,
                                const uint8_t *hash, size_t hash_len,
                                uint8_t *sig, size_t sig_len);
