/*******************************************************************************
 *   Ledger App - Bitcoin Wallet
 *   (c) 2016-2019 Ledger
 *
 *  - Only the 'base58_encode()' method (renamed from btchip_encode_base58).
 *    Reformatting of the method has been done, and removal of all PRINTF()
 *    invocations, and changed the algorithm to insert a space for every 10 characters.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/
#include "globals.h"

int base58check_encode(const unsigned char *in, size_t length, unsigned char *out, size_t *outlen) {
    if (length != ADDRESS_LENGTH) {
        THROW(ERROR_INVALID_TRANSACTION);
    }

    // We need room for the version byte, input, and the first 4 bytes of the checksum.
    uint8_t buffer[1 + ADDRESS_LENGTH + BASE58_CHECKSUM_LEN];

    // Concordium uses a hardcoded version value of '1', therefore this byte is not received from
    // the computer.
    buffer[0] = BASE58_VERSION_BYTE;

    memmove(&buffer[1], in, ADDRESS_LENGTH);

    // Calculate SHA256(SHA256(version + in)), and append the first 4 bytes to the (version + in)
    // bytes.
    uint8_t hash[ADDRESS_LENGTH];
    cx_err_t error = 0;
    error = cx_hash_sha256(buffer, ADDRESS_LENGTH + 1, hash, sizeof(hash));
    if (error == 0) {
        THROW(ERROR_FAILED_CX_OPERATION);
    }
    error = cx_hash_sha256(hash, sizeof(hash), hash, sizeof(hash));
    if (error == 0) {
        THROW(ERROR_FAILED_CX_OPERATION);
    }
    memmove(&buffer[1 + ADDRESS_LENGTH], hash, BASE58_CHECKSUM_LEN);

    return base58_encode(buffer, 1 + ADDRESS_LENGTH + BASE58_CHECKSUM_LEN, (char *) out, *outlen);
}
