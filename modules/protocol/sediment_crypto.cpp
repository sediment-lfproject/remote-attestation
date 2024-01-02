/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#include "Crypto.hpp"
#include "sediment_crypto.h"

int sediment_encrypt(const unsigned char *key, int key_size,
  unsigned char *message, long message_size,
  unsigned char *encrypted, int encrypted_size,
  unsigned char *iv, int iv_size)
{
    return Crypto::encrypt(key, key_size, message, message_size,
             encrypted, encrypted_size, iv, iv_size);
}

int sediment_decrypt(const unsigned char *key, int key_size,
  unsigned char *message, long message_size,
  unsigned char *encrypted, int encrypted_size,
  unsigned char *iv, int iv_size)
{
    return Crypto::decrypt(key, key_size, message, message_size,
             encrypted, encrypted_size, iv, iv_size);
}

int sediment_checksum(const unsigned char *key, int key_size, Block *blocks, int block_count,
  uint8_t *digest, int digest_size)
{
    return Crypto::checksum(key, key_size, blocks, block_count, digest, digest_size);
}

int sediment_sha256(const unsigned char *input, int input_size, unsigned char *output, int output_size)
{
    return Crypto::sha256(input, input_size, output, output_size);
}

int sediment_random_bytes(unsigned char *buf, int buf_size)
{
    Crypto::getRandomBytes(buf, buf_size);

    return 1; // as in openssl.RAND_bytes
}
