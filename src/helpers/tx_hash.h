#pragma once

#include <stddef.h>
#include <stdint.h>

/**
 * Concordium account transaction type byte (serialized header `kind` field).
 * Used with hashAccountTransactionHeaderAndKind / handleHeaderAndToAddress.
 */
typedef enum {
    DEPLOY_MODULE = 0,
    INIT_CONTRACT = 1,
    UPDATE_CONTRACT = 2,
    TRANSFER = 3,
    UPDATE_CREDENTIAL_KEYS = 13,
    TRANSFER_TO_PUBLIC = 18,
    TRANSFER_WITH_SCHEDULE = 19,
    UPDATE_CREDENTIALS = 20,
    REGISTER_DATA = 21,
    TRANSFER_WITH_MEMO = 22,
    TRANSFER_WITH_SCHEDULE_WITH_MEMO = 24,
    CONFIGURE_BAKER = 25,
    CONFIGURE_DELEGATION = 26,
} transactionKind_e;

/** Byte offset of energy field in Concordium account transaction header. */
#define ENERGY_OFFSET_IN_HEADER 40

/** Serialized u64 numerator + u64 denominator (e.g. commission rate). */
#define U64_RATIO_BYTES 16

int hashAccountTransactionHeaderAndKind(uint8_t *cdata,
                                        uint8_t dataLength,
                                        uint8_t validTransactionKind);

int hashUpdateHeaderAndType(uint8_t *cdata, uint8_t dataLength, uint8_t validUpdateType);

int handleHeaderAndToAddress(uint8_t *cdata,
                             uint8_t dataLength,
                             uint8_t kind,
                             uint8_t *recipientDst,
                             size_t recipientSize,
                             uint8_t *feesDst,
                             size_t feesSize);

size_t hashAndLoadU64Ratio(uint8_t *cdata, uint8_t *dst, uint8_t sizeOfDst);

/** Finalize SHA-256 hash, Ed25519-sign, and send signature in APDU response. */
void buildAndSignTransactionHash(void);
