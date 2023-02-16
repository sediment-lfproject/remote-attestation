/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#ifndef SEDIMENT_CRYPTO_H_
#define SEDIMENT_CRYPTO_H_

#include "Crypto.hpp"

#if 0
#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC

typedef unsigned char uint8_t;

typedef struct _block {
    const unsigned char *block;
    int                  size;
} Block;

#endif // ifdef __cplusplus
#endif // if 0
#define EXTERNC

EXTERNC int sediment_encrypt(const unsigned char *key, int key_size,
  unsigned char *message, long message_size,
  unsigned char *encrypted, int encrypted_size,
  unsigned char *iv, int iv_size);
EXTERNC int sediment_decrypt(const unsigned char *key, int key_size,
  unsigned char *message, long message_size,
  unsigned char *encrypted, int encrypted_size,
  unsigned char *iv, int iv_size);
EXTERNC int sediment_checksum(const unsigned char *key, int key_size,
  Block *blocks, int block_count,
  uint8_t *digest, int digest_size);

EXTERNC int sediment_sha256(const unsigned char *input, int input_size, unsigned char *output, int output_size);
EXTERNC int sediment_random_bytes(unsigned char *buf, int buf_size);

// #undef EXTERNC

#endif // SEDIMENT_CRYPTO_H_
