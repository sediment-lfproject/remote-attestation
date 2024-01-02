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

#include "RSASign.hpp"
#include "Log.hpp"

const char hn[] = "SHA256";

using std::filesystem::exists;

RSASign::RSASign(const string &signing_key_pem)
{
    if (!filesystem::exists(signing_key_pem)) {
        SD_LOG(LOG_WARNING, "signing key pem file does not exisit: %s", signing_key_pem.c_str());
        exit(EXIT_FAILURE);
    }

    signingKey = NULL;
    BIO *bio_private = BIO_new_file(signing_key_pem.c_str(), "r");
    if (bio_private == NULL) {
        SD_LOG(LOG_ERR, "failed to create a new file BIO: %s", signing_key_pem.c_str());
        exit(EXIT_FAILURE);
    }
    

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio_private, &signingKey, 0, NULL);
    if (pkey == NULL) {
        SD_LOG(LOG_ERR, "failed to read RSA signing key pem file: %s", signing_key_pem.c_str());
        exit(EXIT_FAILURE);
    }

    BIO_flush(bio_private);
    BIO_free(bio_private);
}

int RSASign::sign_it(const uchar *msg, size_t mlen, uchar **sig, size_t *slen)
{
    /* Returned to caller */
    int result = -1;

    if (!msg || !mlen || !sig || !signingKey) {
        SD_LOG(LOG_ERR, "null signing parameters");
        return -1;
    }

    if (*sig)
        OPENSSL_free(*sig);

    *sig  = NULL;
    *slen = 0;

    EVP_MD_CTX *ctx = NULL;

    do {
        ctx = EVP_MD_CTX_create();
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

        rc = EVP_DigestSignInit(ctx, NULL, md, NULL, signingKey);
        if (rc != 1) {
            SD_LOG(LOG_ERR, "EVP_DigestSignInit failed, error 0x%lx", ERR_get_error());
            break; /* failed */
        }

        rc = EVP_DigestSignUpdate(ctx, msg, mlen);
        if (rc != 1) {
            SD_LOG(LOG_ERR, "EVP_DigestSignUpdate failed, error 0x%lx", ERR_get_error());
            break; /* failed */
        }

        size_t req = 0;
        rc = EVP_DigestSignFinal(ctx, NULL, &req);
        if (rc != 1) {
            SD_LOG(LOG_ERR, "EVP_DigestSignFinal failed (1), error 0x%lx", ERR_get_error());
            break; /* failed */
        }

        if (!(req > 0)) {
            SD_LOG(LOG_ERR, "EVP_DigestSignFinal failed (2), error 0x%lx", ERR_get_error());
            break; /* failed */
        }

        *sig = (uchar *) OPENSSL_malloc(req);
        if (*sig == NULL) {
            SD_LOG(LOG_ERR, "OPENSSL_malloc failed, error 0x%lx", ERR_get_error());
            break; /* failed */
        }

        *slen = req;
        rc    = EVP_DigestSignFinal(ctx, *sig, slen);
        if (rc != 1) {
            SD_LOG(LOG_ERR, "EVP_DigestSignFinal failed (3), return code %d, error 0x%lx", rc, ERR_get_error());
            break; /* failed */
        }

        if (rc != 1) {
            SD_LOG(LOG_ERR, "EVP_DigestSignFinal failed, mismatched signature sizes %ld, %ld", req, *slen);
            break; /* failed */
        }
        result = 0;
    } while (0);

    if (ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }

    return !!result;
}
