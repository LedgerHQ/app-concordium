#pragma once

#include <stddef.h>

/** Raw account address size (bytes before base58check). */
#define ADDRESS_LENGTH 32
/** Display size for base58check account address string (incl. nul in app buffers). */
#define BASE58_ADDRESS_LENGTH 55

#define BASE58_VERSION_BYTE 1
#define BASE58_CHECKSUM_LEN 4

/**
 * Base58 encodes the input and writes the encoding to the supplied out destination. Returns a
 * non-zero value if the input cannot be validly base58 encoded, i.e. the input is malformed.
 * N.B. The encoding contains a space for every 10th character.
 * An error is thrown if the input length is not exactly 32.
 * @return 0 if input was validly base58 encoded, or -1 if it was not valid base58
 */
int base58check_encode(const unsigned char *in,
                       size_t inlength,
                       unsigned char *out,
                       size_t *outlen);
