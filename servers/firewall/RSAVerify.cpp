/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <filesystem>

const char hn[] = "SHA256";

#include "RSAVerify.hpp"
#include "Log.hpp"

RSAVerify::RSAVerify(const string &verify_key_pem)
{
    if (!filesystem::exists(verify_key_pem)) {
        SD_LOG(LOG_ERR, "verifying key pem file does not exisit: %s", verify_key_pem.c_str());
        exit(EXIT_FAILURE);
    }

    verifyingKey = NULL;
    BIO *bio_public = BIO_new_file(verify_key_pem.c_str(), "r");
    if (bio_public == NULL) {
        SD_LOG(LOG_ERR, "failed to create a new file BIO: %s", verify_key_pem.c_str());
        exit(EXIT_FAILURE);
    }
    
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio_public, &verifyingKey, 0, NULL);
    if (pkey == NULL) {
        SD_LOG(LOG_ERR, "failed to read RSA verifying key pem file: %s", verify_key_pem.c_str());
        exit(EXIT_FAILURE);
    }

    BIO_flush(bio_public);
    BIO_free(bio_public);
}

int RSAVerify::verify_it(const uchar *msg, size_t mlen, const uchar *sig, size_t slen)
{
    /* Returned to caller */
    int result = -1;

    if (!msg || !mlen || !sig || !slen || !verifyingKey) {
        SD_LOG(LOG_ERR, "null signing parameters");
        return -1;
    }

    EVP_MD_CTX *ctx = NULL;

    do {
        ctx = EVP_MD_CTX_new();
        if (ctx == NULL) {
            SD_LOG(LOG_ERR, "EVP_MD_CTX_create failed, error 0x%lx", ERR_get_error());
            break; /* failed */
        }

        const EVP_MD *md = EVP_get_digestbyname(hn);
        if (md == NULL) {
            SD_LOG(LOG_ERR, "EVP_get_digestbyname failed, error 0x%lx", ERR_get_error());
            break; /* failed */
        }

        int rc = EVP_DigestInit_ex(ctx, md, NULL);
        if (rc != 1) {
            SD_LOG(LOG_ERR, "EVP_DigestInit_ex failed, error 0x%lx", ERR_get_error());
            break; /* failed */
        }

        rc = EVP_DigestVerifyInit(ctx, NULL, md, NULL, verifyingKey);
        if (rc != 1) {
            SD_LOG(LOG_ERR, "EVP_DigestVerifyInit failed, error 0x%lx", ERR_get_error());
            break; /* failed */
        }

        rc = EVP_DigestVerifyUpdate(ctx, msg, mlen);
        if (rc != 1) {
            SD_LOG(LOG_ERR, "EVP_DigestVerifyUpdate failed, error 0x%lx", ERR_get_error());
            break; /* failed */
        }

        /* Clear any errors for the call below */
        ERR_clear_error();

        rc = EVP_DigestVerifyFinal(ctx, sig, slen);
        if (rc != 1) {
            SD_LOG(LOG_ERR, "EVP_DigestVerifyFinal failed, error 0x%lx", ERR_get_error());
            break; /* failed */
        }

        result = 0;
    } while (0);

    if (ctx) {
        EVP_MD_CTX_free(ctx);
        ctx = NULL;
    }

    return !!result;
}