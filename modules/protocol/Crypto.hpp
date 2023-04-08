/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once

#ifndef PLATFORM_NRF9160
#include "mbedtls/md.h"
#endif

#include "AuthToken.hpp"
#include "Config.hpp"

using namespace std;

typedef struct _block {
    const unsigned char *block;
    int                  size;
} Block;

class Crypto
{
public:
    static const int ENC_KEY_SIZE    = 256;
    static const int ATTEST_KEY_SIZE = 256;
    static const int AUTH_KEY_SIZE   = 256;

    static const int ENC_KEY_BYTES    = ENC_KEY_SIZE / 8;
    static const int ATTEST_KEY_BYTES = ATTEST_KEY_SIZE / 8;
    static const int AUTH_KEY_BYTES   = AUTH_KEY_SIZE / 8;

    static const int IV_SIZE             = 16;
    static const int FW_DIGEST_LEN       = 32;
    static const int DATA_CHECKSUM_BYTES = 32;

    // JEDI: encKey is used only for OS version encryption.
    char encKey[ENC_KEY_BYTES + 1]       = "603DEB1015CA71BE2B73AEF0857D7781";
    char attestKey[ATTEST_KEY_BYTES + 1] = "603DEB1015CA71BE2B73AEF0857D7781";
    char authKey[AUTH_KEY_BYTES + 1]     = "603DEB1015CA71BE2B73AEF0857D7781";

#ifndef PLATFORM_NRF9160
    mbedtls_md_context_t mbed_ctx;
#endif

private:

public:
    Crypto()
    {
        init();
    }

    virtual ~Crypto()
    { }

    virtual int init();
    virtual int encrypt(unsigned char *message, long message_size,
      unsigned char *encrypted, int encrypted_size,
      unsigned char *iv, int iv_size);
    virtual int decrypt(unsigned char *message, long message_size,
      unsigned char *encrypted, int encrypted_size,
      unsigned char *iv, int iv_size);
    static int encrypt(const unsigned char *key, int key_size,
      unsigned char *message, long message_size,
      unsigned char *encrypted, int encrypted_size,
      unsigned char *iv, int iv_size);
    static int decrypt(const unsigned char *key, int key_size,
      unsigned char *message, long message_size,
      unsigned char *encrypted, int encrypted_size,
      unsigned char *iv, int iv_size);

    virtual int checksum(KeyPurpose keyPurpose, Block *blocks, int block_count, uint8_t *digest, int digest_size);
    static int checksum(const unsigned char *key, int key_size, Block *blocks, int block_count, uint8_t *digest,
      int digest_size);

    static int sha256(const unsigned char *input, int input_size, unsigned char *output, int output_size);

    static void getRandomBytes(void *dst, size_t len);

    char * getKey(KeyPurpose keyPurpose)
    {
        switch (keyPurpose) {
        case KEY_ENCRYPTION:
            return encKey;

        case KEY_ATTESTATION:
            return attestKey;

        case KEY_AUTH:
            return authKey;

        default:
            return NULL;
        }
    }

    static int getKeySize(KeyPurpose keyPurpose)
    {
        switch (keyPurpose) {
        case KEY_ENCRYPTION:
            return ENC_KEY_SIZE;

        case KEY_ATTESTATION:
            return ATTEST_KEY_SIZE;

        case KEY_AUTH:
            return AUTH_KEY_SIZE;

        default:
            return 0;
        }
    }

    void calDigest(AuthToken &authToken, uint8_t *serialized, uint32_t len, int offset)
    {
        vector<uint8_t> &digest = authToken.getDigest();

        digest.resize(DATA_CHECKSUM_BYTES);

        Block blocks[] = {
            { .block = (const uint8_t *) serialized + offset, .size = (int) len - offset },
        };

        checksum(KEY_AUTH, blocks, sizeof(blocks) / sizeof(Block), &digest[0], DATA_CHECKSUM_BYTES);
    }

    bool authenticate(AuthToken &authToken, uint8_t *serialized, uint32_t len, int offset)
    {
        vector<uint8_t> &digest = authToken.getDigest();

        uint8_t saved[digest.size()];

        memcpy((char *) saved, (char *) &digest[0], digest.size());

        calDigest(authToken, serialized, len, offset);

        if (memcmp((char *) &digest[0], saved, digest.size()) == 0) {
            return true;
        }
        else {
            SD_LOG(LOG_ERR, "message not authenticated");
            SD_LOG(LOG_DEBUG, "expected digest %s", Log::toHex((char *) saved, digest.size()).c_str());
            return false;
        }
    }

    bool changeKey(KeyPurpose keyPurpose, unsigned char *new_key, int key_size)
    {
        char *old_key    = NULL;
        int old_key_size = 0;

        switch (keyPurpose) {
        case KEY_ENCRYPTION:
            old_key      = encKey;
            old_key_size = ENC_KEY_BYTES;
            break;
        case KEY_ATTESTATION:
            old_key      = attestKey;
            old_key_size = ATTEST_KEY_BYTES;
            break;
        case KEY_AUTH:
            old_key      = authKey;
            old_key_size = AUTH_KEY_BYTES;
            break;
        default:
            SD_LOG(LOG_ERR, "Crypto::changeKey - unsupported key purpose: %s", TO_KEY_PURPOSE(keyPurpose).c_str());
            break;
        }
        if (old_key == NULL || old_key_size != key_size) {
            SD_LOG(LOG_ERR, "Crypto::changeKey - bad key purpose or or unmatched key size: %d v.s. %d",
              old_key_size, key_size);
            return false;
        }
        memcpy(old_key, new_key, key_size);

        return true;
    }

};
