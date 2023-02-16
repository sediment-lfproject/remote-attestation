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
    virtual bool changeKey(KeyPurpose keyPurpose, unsigned char *key, int key_size);

    void calDigest(AuthToken &authToken, uint8_t *serialized, uint32_t len, int offset);
    virtual int checksum(KeyPurpose keyPurpose, Block *blocks, int block_count, uint8_t *digest, int digest_size);
    static int checksum(const unsigned char *key, int key_size, Block *blocks, int block_count, uint8_t *digest,
      int digest_size);
    virtual bool authenticate(AuthToken &authToken, uint8_t *serialized, uint32_t len, int offset);

    static int sha256(const unsigned char *input, int input_size, unsigned char *output, int output_size);

    static void getRandomBytes(void *dst, size_t len);
    static int getKeySize(KeyPurpose keyPurpose);
    char * getKey(KeyPurpose keyPurpose);
};
