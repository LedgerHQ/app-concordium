
// ========== STEP 1: STANDARD INCLUDES ==========
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ========== STEP 2: TYPES (keep in sync with firmware) ==========
// Mirrors src/common/util/derivation_path.h — derivation_path_key_idx_t
// Values are the last path segment index for each exportable key (BIP32 child index).
typedef enum {
    LEGACY_ID_CRED_SEC = 0,
    LEGACY_PRF_KEY = 1,
    NEW_ID_CRED_SEC = 2,
    NEW_PRF_KEY = 3,
    NEW_SIGNATURE_BLINDING_RANDOMNESS = 4,
    NEW_COMMITMENT_RANDOMNESS = 5,
} derivation_path_key_idx_t;

// APDU response codes (copied from globals.h)
#define ERROR_INVALID_PARAM 0x6B00
#define ERROR_INVALID_PATH  0x6A80
#define SUCCESS             0x9000

// Constants from exportPrivateKey.h
#define MAX_KEYS_TO_EXPORT          3
#define LENGTH_AND_PRIVATE_KEY_SIZE 33

// Purpose constants (from exportPrivateKey.h)
#define P1_IDENTITY_CREDENTIAL_CREATION 0x00
#define P1_ACCOUNT_CREATION             0x01
#define P1_ID_RECOVERY                  0x02
#define P1_ACCOUNT_CREDENTIAL_DISCOVERY 0x03
#define P1_CREATION_OF_ZK_PROOF         0x04

//// NEW P2 PATHS ////
#define P2_MAINNET 0x00
#define P2_TESTNET 0x01

// Derivation path constants
#define DERIVATION_PATH_NODES_MAX 8
#define NEW_PURPOSE               44
#define NEW_MAINNET_COIN_TYPE 919
#define NEW_TESTNET_COIN_TYPE 1
#define HARDENED_OFFSET       0x80000000

typedef struct {
    uint32_t nodes[DERIVATION_PATH_NODES_MAX];
    uint8_t len;
} derivation_path_t;

// ========== STEP 3: MOCK IMPLEMENTATIONS ==========

// Mock PRINTF - just use regular printf for debugging
#define PRINTF printf

// Mock THROW - instead of crashing, just return early
#define THROW(exception)                                          \
    do {                                                          \
        printf("MOCK THROW: 0x%x (%s)\n", exception, #exception); \
        return;                                                   \
    } while (0)

// Mock explicit_bzero - secure memory clearing
void explicit_bzero(void *ptr, size_t size) {
    if (ptr) {
        volatile uint8_t *p = (volatile uint8_t *) ptr;
        for (size_t i = 0; i < size; i++) {
            p[i] = 0;
        }
    }
}

// Mock bin2dec - convert binary to decimal string
size_t bin2dec(uint8_t *dst, size_t dst_size, uint32_t value) {
    int ret = snprintf((char *) dst, dst_size, "%u", value);
    return (ret > 0 && ret < (int) dst_size) ? ret + 1 : 0;
}

// Mock number helpers - simplified versions
void numberToText(uint8_t *dst, size_t dst_size, uint64_t number) {
    snprintf((char *) dst, dst_size, "%llu", number);
}

uint8_t lengthOfNumber(uint64_t number) {
    if (number == 0) return 1;
    uint8_t length = 0;
    while (number > 0) {
        length++;
        number /= 10;
    }
    return length;
}

// Mock crypto functions - return fake but valid-looking keys
void getPrivateKey(const derivation_path_t *path, uint8_t *privateKey) {
    printf("MOCK getPrivateKey: path_length=%d\n", path->len);
    if (privateKey) {
        memset(privateKey, 0xAB, 32);  // Fake private key
    }
}

void getBlsPrivateKey(const derivation_path_t *path, uint8_t *privateKey, size_t privateKeySize) {
    (void) privateKeySize;
    printf("MOCK getBlsPrivateKey: path_length=%d\n", path->len);
    if (privateKey) {
        memset(privateKey, 0xCD, 32);  // Fake BLS private key
    }
}

// Utility macro for reading big-endian 32-bit integers
#define U4BE(buf, off)                                                                 \
    ((uint32_t) (((buf)[off] << 24) | ((buf)[off + 1] << 16) | ((buf)[off + 2] << 8) | \
                 ((buf)[off + 3])))

// ========== STEP 4: MOCK exportNewPathPrivateKeysForPurpose ==========
// Simplified version of the real function

int exportNewPathPrivateKeysForPurpose(derivation_path_key_idx_t keyType,
                                       uint8_t networkDesignation,
                                       uint32_t identityProvider,
                                       uint32_t identity,
                                       uint32_t account,
                                       uint8_t *outputPrivateKey,
                                       size_t outputPrivateKeySize) {
    printf("MOCK exportNewPathPrivateKeysForPurpose: keyType=%d, network=%d, idp=%u, id=%u, account=%u\n",
           (int) keyType,
           networkDesignation,
           identityProvider,
           identity,
           account);

    derivation_path_t dp;
    memset(&dp, 0, sizeof(dp));
    dp.len = 4;
    dp.nodes[0] = NEW_PURPOSE | HARDENED_OFFSET;

    switch (networkDesignation) {
        case P2_MAINNET:
            dp.nodes[1] = NEW_MAINNET_COIN_TYPE | HARDENED_OFFSET;
            break;
        case P2_TESTNET:
            dp.nodes[1] = NEW_TESTNET_COIN_TYPE | HARDENED_OFFSET;
            break;
    }

    dp.nodes[2] = identityProvider | HARDENED_OFFSET;
    dp.nodes[3] = identity | HARDENED_OFFSET;

    switch (keyType) {
        case NEW_ID_CRED_SEC:
        case NEW_PRF_KEY:
        case NEW_SIGNATURE_BLINDING_RANDOMNESS:
            dp.nodes[dp.len++] = keyType | HARDENED_OFFSET;
            break;
        case NEW_COMMITMENT_RANDOMNESS:
            dp.nodes[dp.len++] = NEW_COMMITMENT_RANDOMNESS | HARDENED_OFFSET;
            dp.nodes[dp.len++] = account | HARDENED_OFFSET;
            break;
        default:
            printf("Invalid keyType: %d\n", (int) keyType);
            return 0;
    }

    uint8_t fakeKey[32];
    uint8_t tx = 0;

    if (outputPrivateKeySize < LENGTH_AND_PRIVATE_KEY_SIZE) {
        return 0;
    }

    getPrivateKey(&dp, fakeKey);

    // Write length + key to output
    outputPrivateKey[tx++] = 32;  // Key length
    memcpy(outputPrivateKey + tx, fakeKey, 32);
    tx += 32;

    return tx;
}

// ========== STEP 5: THE MAIN TARGET FUNCTION ==========
// Simplified version of handleExportPrivateKeyNewPath

void handleExportPrivateKeyNewPath(uint8_t *dataBuffer,
                                   uint8_t p1,
                                   uint8_t p2,
                                   uint8_t lc,
                                   volatile unsigned int *flags) {
    printf("=== handleExportPrivateKeyNewPath ===\n");
    printf("p1=%d, p2=%d, lc=%d\n", p1, p2, lc);

    // Validate p1 parameter
    if (p1 != P1_IDENTITY_CREDENTIAL_CREATION && p1 != P1_ACCOUNT_CREATION &&
        p1 != P1_ID_RECOVERY && p1 != P1_ACCOUNT_CREDENTIAL_DISCOVERY &&
        p1 != P1_CREATION_OF_ZK_PROOF) {
        THROW(ERROR_INVALID_PARAM);
    }
    // Validate p2 parameter
    if ((p2 != 0 && p2 != 1)) {
        THROW(ERROR_INVALID_PARAM);
    }

    size_t offset = 0;
    uint8_t remainingDataLength = lc;

    // Extract identity provider (4 bytes)
    if (remainingDataLength < 4) {
        THROW(ERROR_INVALID_PATH);
    }
    uint32_t identityProvider = U4BE(dataBuffer, offset);
    offset += 4;
    remainingDataLength -= 4;
    printf("identityProvider=%u\n", identityProvider);

    // Extract identity (4 bytes)
    if (remainingDataLength < 4) {
        THROW(ERROR_INVALID_PATH);
    }
    uint32_t identity = U4BE(dataBuffer, offset);
    offset += 4;
    remainingDataLength -= 4;
    printf("identity=%u\n", identity);
    // Extract account (if needed)
    uint32_t account = 0xFFFFFFFF;
    if (p1 == P1_ACCOUNT_CREATION || p1 == P1_CREATION_OF_ZK_PROOF) {
        if (remainingDataLength < 4) {
            THROW(ERROR_INVALID_PATH);
        }
        account = U4BE(dataBuffer, offset);
        printf("account=%u\n", account);
    }

    // Generate the private keys
    uint8_t outputBuffer[MAX_KEYS_TO_EXPORT * LENGTH_AND_PRIVATE_KEY_SIZE];
    int bytesWritten = exportNewPathPrivateKeysForPurpose(
        (derivation_path_key_idx_t) (2 + (p1 % 4)),  /* map fuzz input into 2..5 range */
        (p2 == P2_MAINNET) ? P2_MAINNET : P2_TESTNET,  // Ensure valid network
        identityProvider,
        identity,
        account,
        outputBuffer,
        sizeof(outputBuffer));

    printf("Generated %d bytes of private key data\n", bytesWritten);

    // In real implementation, this would call UI and send the keys
    // For fuzzing, we just print what would have been dispatched to the UI and say success
    printf("Display would have been: identityProvider=%u, identity=%u, account=%u\n",
           identityProvider,
           identity,
           account);

    printf("=== handleExportPrivateKeyNewPath completed successfully ===\n");
}

// ========== STEP 6: THE FUZZER ==========

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Need at least 10 bytes for a meaningful test
    if (size < 10) return 0;

    printf("\n=== FUZZER ITERATION (size=%zu) ===\n", size);

    // Extract parameters from fuzz input
    uint8_t p1 = data[0];
    uint8_t p2 = data[1];

    // Clamp lc to available data
    uint8_t lc = size - 2;

    const uint8_t *command_data = data + 2;

    printf("Fuzzing with p1=%d, p2=%d, lc=%d\n", p1, p2, lc);

    // Call the target function
    volatile unsigned int flags = 0;
    handleExportPrivateKeyNewPath((uint8_t *) command_data, p1, p2, lc, &flags);

    printf("Fuzzer iteration completed successfully\n");
    return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    printf("=== CONCORDIUM EXPORT PRIVATE KEY FUZZER ===\n");
    printf("Standalone fuzzer - no external dependencies!\n");
    printf("Target: handleExportPrivateKeyNewPath\n\n");
    return 0;
}
