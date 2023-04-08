/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#include <iomanip>
#include <fcntl.h>

#if defined(PLATFORM_GIANT_GECKO) || defined(PLATFORM_NRF9160)
#include <random/rand32.h>
#endif

// #ifndef PLATFORM_NRF9160
#include "mbedtls/aes.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
// #endif

#include "sediment.h"

#include "Crypto.hpp"
#include "Codec.hpp"
#include "Log.hpp"

using namespace std;

#ifdef PLATFORM_NRF9160
#if defined(USE_SPM)

int Crypto::init()
{
    return 0;
}

int Crypto::encrypt(unsigned char *message, long message_size,
  unsigned char *encrypted, int encrypted_size,
  unsigned char *iv, int iv_size)
{
    (void) encrypted_size;

    mbedtls_aes_context context_in;

    getRandomBytes(iv, iv_size);

    uint8_t tmpIV[iv_size];
    memcpy(tmpIV, iv, iv_size);

    mbedtls_aes_setkey_enc(&context_in, (const unsigned char *) encKey, ENC_KEY_SIZE);
    mbedtls_aes_crypt_cbc(&context_in, MBEDTLS_AES_ENCRYPT, message_size, (unsigned char *) tmpIV, message, encrypted);

    return message_size;
}

int Crypto::decrypt(unsigned char *message, long message_size,
  unsigned char *encrypted, int encrypted_size,
  unsigned char *iv, int iv_size)
{
    (void) encrypted_size;

    mbedtls_aes_context context_out;

    uint8_t tmpIV[iv_size];
    memcpy(tmpIV, iv, iv_size);

    mbedtls_aes_setkey_dec(&context_out, (const unsigned char *) encKey, ENC_KEY_SIZE);
    mbedtls_aes_crypt_cbc(&context_out, MBEDTLS_AES_DECRYPT, message_size, (unsigned char *) tmpIV, encrypted, message);

    return 0;
}

int Crypto::encrypt(const unsigned char *key, int key_size,
  unsigned char *message, long message_size,
  unsigned char *encrypted, int encrypted_size,
  unsigned char *iv, int iv_size)
{
    (void) encrypted_size;

    mbedtls_aes_context context_in;

    // TODO
    //    getRandomBytes(iv, iv_size);
    memset(iv, 'z', iv_size);

    uint8_t tmpIV[iv_size];
    memcpy(tmpIV, iv, iv_size);

    mbedtls_aes_setkey_enc(&context_in, key, key_size);
    mbedtls_aes_crypt_cbc(&context_in, MBEDTLS_AES_ENCRYPT, message_size, (unsigned char *) tmpIV, message, encrypted);

    return message_size;
}

int Crypto::decrypt(const unsigned char *key, int key_size,
  unsigned char *message, long message_size,
  unsigned char *encrypted, int encrypted_size,
  unsigned char *iv, int iv_size)
{
    (void) encrypted_size;

    mbedtls_aes_context context_out;

    // TODO
    memset(iv, 'z', iv_size);

    uint8_t tmpIV[iv_size];
    memcpy(tmpIV, iv, iv_size);

    mbedtls_aes_setkey_dec(&context_out, key, key_size);
    mbedtls_aes_crypt_cbc(&context_out, MBEDTLS_AES_DECRYPT, message_size, (unsigned char *) tmpIV, encrypted, message);

    return encrypted_size;
}

bool Crypto::changeKey(KeyPurpose keyPurpose, unsigned char *new_key, int key_size)
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

int Crypto::checksum(KeyPurpose keyPurpose, Block *blocks, int block_count, uint8_t *digest, int digest_size)
{
    const unsigned char *key = (const unsigned char *) getKey(keyPurpose);
    int key_size = getKeySize(keyPurpose);

    return checksum(key, key_size, blocks, block_count, digest, digest_size);
}

int Crypto::checksum(const unsigned char *key, int key_size, Block *blocks, int block_count, uint8_t *digest,
  int digest_size)
{
    (void) digest_size;

    mbedtls_md_context_t ctx, *mbed_ctx;

    mbed_ctx = &ctx;
    const mbedtls_md_info_t *md_info;

    mbedtls_md_init(mbed_ctx);

    if ((md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256)) == NULL) {
        SD_LOG(LOG_ERR, "failed to get mbedTLS info");
        return -1;
    }

    int rtn;
    rtn = mbedtls_md_setup(mbed_ctx, md_info, 1);
    if (rtn != 0) {
        SD_LOG(LOG_ERR, "failed mbedTLS setup");
        return -1;
    }

    rtn = mbedtls_md_hmac_starts(mbed_ctx, key, key_size / 8); // key length in bytes
    if (rtn != 0) {
        SD_LOG(LOG_ERR, "failed HMAC set key: %d", rtn);
        return -1;
    }

    for (int i = 0; i < block_count; i++) {
        rtn = mbedtls_md_hmac_update(mbed_ctx, blocks[i].block, blocks[i].size);
        if (rtn != 0) {
            SD_LOG(LOG_ERR, "failed HMAC update: %d", rtn);
            return -1;
        }
    }

    rtn = mbedtls_md_hmac_finish(mbed_ctx, digest);
    if (rtn != 0) {
        SD_LOG(LOG_ERR, "failed mbedTLS HMAC final: %d", rtn);
        return -1;
    }

    mbedtls_md_free(mbed_ctx);

    return 0;
}

int Crypto::sha256(const unsigned char *input, int input_size, unsigned char *output, int output_size)
{
    (void) output_size;
    //    if (output_size != 32)
    //        return 0;

    // return non-zero on success
    // 0 here means use the full SHA-256, not the SHA-224 variant
    return mbedtls_sha256(input, input_size, output, 0);
}

#else // if defined(USE_SPM)

#include "crypto_psa.h"

char rsa_private_key[] = {
#include "privateRSA.der.inc"
};

int Crypto::init()
{
    psa_status_t status;

    status = import_key_aes((uint8_t *) encKey, ENC_KEY_BYTES);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = import_key_hmac(0, (uint8_t *) attestKey, ATTEST_KEY_BYTES);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = import_key_hmac(1, (uint8_t *) authKey, AUTH_KEY_BYTES);
    if (status != PSA_SUCCESS) {
        return status;
    }

    // status = import_rsa_sign_key(key_rsa, olen);

    status = import_key_rsa_enc((uint8_t *) rsa_private_key, sizeof(rsa_private_key));
    if (status != PSA_SUCCESS) {
        return status;
    }

    return PSA_SUCCESS;
}

int Crypto::encrypt(unsigned char *message, long message_size,
  unsigned char *ciphertext, int ciphertext_size,
  unsigned char *iv, int iv_size)
{
    getRandomBytes(iv, iv_size);

    uint8_t tmpIV[iv_size];
    memcpy(tmpIV, iv, iv_size);

    int olen;
    psa_status_t status = encrypt_aes_cbc(message, message_size, ciphertext, ciphertext_size, &olen, tmpIV, iv_size);
    if (status != PSA_SUCCESS)
        return -1;

    return olen;
}

int Crypto::decrypt(unsigned char *message, long message_size,
  unsigned char *ciphertext, int ciphertext_size,
  unsigned char *iv, int iv_size)
{
    uint8_t tmpIV[iv_size];

    memcpy(tmpIV, iv, iv_size);

    int olen;
    psa_status_t status = decrypt_aes_cbc(message, message_size, ciphertext, ciphertext_size, &olen, tmpIV, iv_size);
    if (status != PSA_SUCCESS)
        return -1;

    return olen;
}

int Crypto::encrypt(const unsigned char *key, int key_size,
  unsigned char *message, long message_size,
  unsigned char *encrypted, int encrypted_size,
  unsigned char *iv, int iv_size)
{
    (void) encrypted_size;

    // TODO
    //    getRandomBytes(iv, iv_size);
    memset(iv, 'z', iv_size);

    psa_status_t status = import_key_aes((uint8_t *) key, key_size / 8);
    if (status != PSA_SUCCESS)
        return status;

    int olen;
    // TODO: message size should not be used for encrypted_size
    status = encrypt_aes_cbc(message, message_size, encrypted, message_size, &olen, iv, iv_size);
    if (status != PSA_SUCCESS)
        return status;

    return message_size;
}

int Crypto::decrypt(const unsigned char *key, int key_size,
  unsigned char *message, long message_size,
  unsigned char *encrypted, int encrypted_size,
  unsigned char *iv, int iv_size)
{
    (void) encrypted_size;

    // TODO
    memset(iv, 'z', iv_size);

    psa_status_t status = import_key_aes((uint8_t *) key, key_size / 8);
    if (status != PSA_SUCCESS)
        return -2;

    int olen;
    status = decrypt_aes_cbc(message, message_size, encrypted, encrypted_size, &olen, iv, iv_size);
    if (status != PSA_SUCCESS)
        return -1;

    return olen;
}

bool Crypto::changeKey(KeyPurpose keyPurpose, unsigned char *new_key, int key_size)
{
    psa_status_t status = -99;

    switch (keyPurpose) {
    case KEY_ENCRYPTION:
        if (key_size != ENC_KEY_BYTES)
            return -1;

        status = import_key_aes((uint8_t *) new_key, key_size);
        break;
    case KEY_ATTESTATION:
        if (key_size != ATTEST_KEY_BYTES)
            return -1;

        status = import_key_hmac(0, (uint8_t *) new_key, key_size);
        break;
    case KEY_AUTH:
        if (key_size != AUTH_KEY_BYTES)
            return -1;

        status = import_key_hmac(1, (uint8_t *) new_key, key_size);
        break;
    // return import_key_rsa_enc((uint8_t *) new_key, key_size);
    //    status = import_rsa_sign_key(key_rsa, olen);
    default:
        break;
    }
    return status == PSA_SUCCESS;
}

int Crypto::checksum(KeyPurpose keyPurpose, Block *blocks, int block_count, uint8_t *digest, int digest_size)
{
    int olen;
    int signing = (keyPurpose == KEY_AUTH) ? 1 : 0;

    return sign_hmac(signing, blocks, block_count, digest, digest_size, &olen);
}

int Crypto::checksum(const unsigned char *key, int key_size, Block *blocks, int block_count, uint8_t *digest,
  int digest_size)
{
    int olen;

    psa_status_t status = import_key_hmac_jedi((uint8_t *) key, key_size);

    if (status != PSA_SUCCESS) {
        SD_LOG(LOG_ERR, "import_key_hmac_jedi failed! (Error: %d)", status);
        return status;
    }

    // 2 is for JEDI
    return sign_hmac(2, blocks, block_count, digest, digest_size, &olen);
}

int Crypto::sha256(const unsigned char *input, int input_size, unsigned char *output, int output_size)
{
    uint32_t olen;
    psa_status_t status;

    /* Calculate the SHA256 hash */
    status = psa_hash_compute(PSA_ALG_SHA_256, input, input_size, output, output_size, &olen);
    if (status != PSA_SUCCESS) {
        SD_LOG(LOG_ERR, "psa_hash_compute failed! (Error: %d)", status);
        return status;
    }

    return PSA_SUCCESS;
}

#endif // USE_SPM

#else  // PLATFORM_NRF9160

int Crypto::init()
{
    return 0;
}

int Crypto::encrypt(unsigned char *message, long message_size,
  unsigned char *encrypted, int encrypted_size,
  unsigned char *iv, int iv_size)
{
    (void) encrypted_size;

    mbedtls_aes_context context_in;

    getRandomBytes(iv, iv_size);

    uint8_t tmpIV[iv_size];
    memcpy(tmpIV, iv, iv_size);

    mbedtls_aes_setkey_enc(&context_in, (const unsigned char *) encKey, ENC_KEY_SIZE);
    mbedtls_aes_crypt_cbc(&context_in, MBEDTLS_AES_ENCRYPT, message_size, (unsigned char *) tmpIV, message, encrypted);

    return message_size;
}

int Crypto::decrypt(unsigned char *message, long message_size,
  unsigned char *encrypted, int encrypted_size,
  unsigned char *iv, int iv_size)
{
    (void) encrypted_size;

    mbedtls_aes_context context_out;

    uint8_t tmpIV[iv_size];
    memcpy(tmpIV, iv, iv_size);

    mbedtls_aes_setkey_dec(&context_out, (const unsigned char *) encKey, ENC_KEY_SIZE);
    mbedtls_aes_crypt_cbc(&context_out, MBEDTLS_AES_DECRYPT, message_size, (unsigned char *) tmpIV, encrypted, message);

    return 0;
}

int Crypto::encrypt(const unsigned char *key, int key_size,
  unsigned char *message, long message_size,
  unsigned char *encrypted, int encrypted_size,
  unsigned char *iv, int iv_size)
{
    (void) encrypted_size;

    mbedtls_aes_context context_in;

    // TODO
    //    getRandomBytes(iv, iv_size);
    memset(iv, 'z', iv_size);

    uint8_t tmpIV[iv_size];
    memcpy(tmpIV, iv, iv_size);

    mbedtls_aes_setkey_enc(&context_in, key, key_size);
    mbedtls_aes_crypt_cbc(&context_in, MBEDTLS_AES_ENCRYPT, message_size, (unsigned char *) tmpIV, message, encrypted);

    return message_size;
}

int Crypto::decrypt(const unsigned char *key, int key_size,
  unsigned char *message, long message_size,
  unsigned char *encrypted, int encrypted_size,
  unsigned char *iv, int iv_size)
{
    (void) encrypted_size;

    mbedtls_aes_context context_out;

    // TODO
    memset(iv, 'z', iv_size);

    uint8_t tmpIV[iv_size];
    memcpy(tmpIV, iv, iv_size);

    mbedtls_aes_setkey_dec(&context_out, key, key_size);
    mbedtls_aes_crypt_cbc(&context_out, MBEDTLS_AES_DECRYPT, message_size, (unsigned char *) tmpIV, encrypted, message);

    return encrypted_size;
}

int Crypto::checksum(KeyPurpose keyPurpose, Block *blocks, int block_count, uint8_t *digest, int digest_size)
{
    const unsigned char *key = (const unsigned char *) getKey(keyPurpose);
    int key_size = getKeySize(keyPurpose);

    return checksum(key, key_size, blocks, block_count, digest, digest_size);
}

int Crypto::checksum(const unsigned char *key, int key_size, Block *blocks, int block_count, uint8_t *digest,
  int digest_size)
{
    memset(digest, '\0', digest_size);

    mbedtls_md_context_t ctx, *mbed_ctx;

    mbed_ctx = &ctx;
    const mbedtls_md_info_t *md_info;

    mbedtls_md_init(mbed_ctx);

    if ((md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256)) == NULL) {
        SD_LOG(LOG_ERR, "failed to get mbedTLS info");
        return -1;
    }

    int rtn;
    rtn = mbedtls_md_setup(mbed_ctx, md_info, 1);
    if (rtn != 0) {
        SD_LOG(LOG_ERR, "failed mbedTLS setup");
        return -1;
    }

    rtn = mbedtls_md_hmac_starts(mbed_ctx, key, key_size / 8); // key length in bytes
    if (rtn != 0) {
        SD_LOG(LOG_ERR, "failed HMAC set key: %d", rtn);
        return -1;
    }

    for (int i = 0; i < block_count; i++) {
        rtn = mbedtls_md_hmac_update(mbed_ctx, blocks[i].block, blocks[i].size);
        if (rtn != 0) {
            SD_LOG(LOG_ERR, "failed HMAC update: %d", rtn);
            return -1;
        }
    }

    rtn = mbedtls_md_hmac_finish(mbed_ctx, digest);
    if (rtn != 0) {
        SD_LOG(LOG_ERR, "failed mbedTLS HMAC final: %d", rtn);
        return -1;
    }

    mbedtls_md_free(mbed_ctx);

    return 0;
}

int Crypto::sha256(const unsigned char *input, int input_size, unsigned char *output, int output_size)
{
    (void) output_size;
    //    if (output_size != 32)
    //        return 0;

    // return non-zero on success
    // 0 here means use the full SHA-256, not the SHA-224 variant
    return mbedtls_sha256(input, input_size, output, 0);
}

#endif // PLATFORM_NRF9160

void Crypto::getRandomBytes(void *dst, size_t len)
{
#if defined(PLATFORM_GIANT_GECKO) || defined(PLATFORM_NRF9160)
    sys_csrand_get(dst, len);

#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        char *buf = (char *) dst;
        for (size_t i = 0; i < len; i++)
            buf[i] = (char) (rand() & 0xf);
    }
    else {
        read(fd, dst, len);
        close(fd);
    }
#endif // if defined(PLATFORM_GIANT_GECKO) || defined(PLATFORM_NRF9160)
}