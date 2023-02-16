/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <filesystem>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

const char hn[] = "SHA256";

#include "CryptoServer.hpp"
#include "Log.hpp"

#define KEY_LENGTH 2048
#define PUB_EXP    65537

using std::filesystem::exists;

CryptoServer::CryptoServer(CommandLine &cli)
{
    string signFile   = cli.getRsaSigningKey();
    string verifyFile = cli.getRsaVerificationKey();

    if (!exists(signFile) || !exists(verifyFile)) {
        SD_LOG(LOG_WARNING, "keys not exists, re-generated: %s, %s", signFile.c_str(), verifyFile.c_str());

        OpenSSL_add_all_algorithms();

        signingKey   = NULL;
        verifyingKey = NULL;

        int rc = make_keys(&signingKey, &verifyingKey);
        if (rc != 0) {
            SD_LOG(LOG_CRIT, "cannot create keys");
            return;
        }

        if (signingKey == NULL) {
            SD_LOG(LOG_CRIT, "null signing key");
            return;
        }

        if (verifyingKey == NULL) {
            SD_LOG(LOG_CRIT, "null verifying key");
            return;
        }

        // write rsa private key to file
        BIO *bio_private = BIO_new_file(signFile.c_str(), "w+");
        rc = PEM_write_bio_PrivateKey(bio_private, signingKey, NULL, NULL, 0, NULL, NULL);
        if (rc != 1) {
            SD_LOG(LOG_CRIT, "cannot write signing key to %s", signFile.c_str());
            return;
        }
        BIO_flush(bio_private);
        BIO_free(bio_private);

        BIO *bio_public = BIO_new_file(verifyFile.c_str(), "w+");
        rc = PEM_write_bio_PUBKEY(bio_public, verifyingKey);
        if (rc != 1) {
            SD_LOG(LOG_CRIT, "cannot write verifying key to %s", verifyFile.c_str());
            return;
        }
        BIO_flush(bio_public);
        BIO_free(bio_public);
    }
    else {
        // read it back
        signingKey = NULL;
        BIO *bio_private = BIO_new_file(signFile.c_str(), "r");
        PEM_read_bio_PrivateKey(bio_private, &signingKey, 0, NULL);
        BIO_flush(bio_private);
        BIO_free(bio_private);

        verifyingKey = NULL;
        BIO *bio_public = BIO_new_file(verifyFile.c_str(), "r");
        PEM_read_bio_PUBKEY(bio_public, &verifyingKey, 0, NULL);
        BIO_flush(bio_public);
        BIO_free(bio_public);
    }
}

int CryptoServer::test()
{
    SD_LOG(LOG_DEBUG, "Testing RSA functions with EVP_DigestSign and EVP_DigestVerify");

    OpenSSL_add_all_algorithms();

    /* Sign and Verify HMAC keys */
    EVP_PKEY *skey = NULL, *vkey = NULL;

    int rc = make_keys(&skey, &vkey);
    if (rc != 0)
        exit(1);

    if (skey == NULL)
        exit(1);

    if (vkey == NULL)
        exit(1);
#if 0
    // write rsa private key to file
    BIO *bio_private = BIO_new_file("private_new.pem", "w+");
    rc = PEM_write_bio_PrivateKey(bio_private, skey, NULL, NULL, 0, NULL, NULL);
    if (rc != 1) {
        exit(1);
    }
    BIO_flush(bio_private);

    // read it back
    skey        = NULL;
    bio_private = BIO_new_file("private_new.pem", "r");
    PEM_read_bio_PrivateKey(bio_private, &skey, 0, NULL);
    BIO_flush(bio_private);


    // write rsa public key to file
    BIO *bio_public = BIO_new_file("public_new.pem", "w+");

    rc = PEM_write_bio_PUBKEY(bio_public, vkey);
    if (rc != 1) {
        exit(1);
    }
    BIO_flush(bio_public);

    // read it back
    vkey       = NULL;
    bio_public = BIO_new_file("public_new.pem", "r");
    PEM_read_bio_PUBKEY(bio_public, &vkey, 0, NULL);
    BIO_flush(bio_public);
#endif // if 0

    const char *message = "Now is the time for all good men to come to the aide of their country";
    const uchar *msg    = reinterpret_cast<const uchar *>(message);
    uchar *sig  = NULL;
    size_t slen = 0;

    /* Using the skey or signing key */
    rc = sign_it((const uchar *) msg, sizeof(msg), &sig, &slen);
    if (rc == 0) {
        SD_LOG(LOG_INFO, "Created signature");
    }
    else {
        SD_LOG(LOG_ERR, "Failed to create signature, return code %d", rc);
        exit(1); /* Should cleanup here */
    }

    SD_LOG(LOG_DEBUG, "Signature: %s", Log::toHex((char *) sig, slen).c_str());

#if 0
    /* Tamper with signature */
    SD_LOG(LOG_ERR, "Tampering with signature");
    sig[0] ^= 0x01;
#endif

#if 0
    /* Tamper with signature */
    SD_LOG(LOG_ERR, "Tampering with signature");
    sig[slen - 1] ^= 0x01;
#endif

    /* Using the vkey or verifying key */
    rc = verify_it(msg, sizeof(msg), sig, slen);
    if (rc == 0) {
        SD_LOG(LOG_INFO, "Verified signature");
    }
    else {
        SD_LOG(LOG_ERR, "Failed to verify signature, return code %d", rc);
    }

    if (sig)
        OPENSSL_free(sig);

    if (skey)
        EVP_PKEY_free(skey);

    if (vkey)
        EVP_PKEY_free(vkey);

    return 0;
}

int CryptoServer::sign_it(const uchar *msg, size_t mlen, uchar **sig, size_t *slen)
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

int CryptoServer::verify_it(const uchar *msg, size_t mlen, const uchar *sig, size_t slen)
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

int CryptoServer::make_keys(EVP_PKEY **skey, EVP_PKEY **vkey)
{
    int result = -1;

    if (!skey || !vkey)
        return -1;

    if (*skey != NULL) {
        EVP_PKEY_free(*skey);
        *skey = NULL;
    }

    if (*vkey != NULL) {
        EVP_PKEY_free(*vkey);
        *vkey = NULL;
    }

    RSA *rsa = NULL;

    do {
        *skey = EVP_PKEY_new();
        if (*skey == NULL) {
            SD_LOG(LOG_ERR, "EVP_PKEY_new failed (1), error 0x%lx", ERR_get_error());
            break; /* failed */
        }

        *vkey = EVP_PKEY_new();
        if (*vkey == NULL) {
            SD_LOG(LOG_ERR, "EVP_PKEY_new failed (2), error 0x%lx", ERR_get_error());
            break; /* failed */
        }

        //        rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
        //        if(rsa == NULL) {
        //            SD_LOG(LOG_ERR, "RSA_generate_key failed, error 0x%lx", ERR_get_error());
        //            break; /* failed */
        //        }

        // RSA *keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);
        // 1. generate rsa key
        BIGNUM *bne = NULL;
        bne = BN_new();
        int ret;
        ret = BN_set_word(bne, PUB_EXP);
        if (ret != 1) {
            SD_LOG(LOG_ERR, "RSA_generate_key failed, error 0x%lx", ERR_get_error());
            break; /* failed */
        }
        rsa = RSA_new();
        ret = RSA_generate_key_ex(rsa, KEY_LENGTH, bne, NULL);
        if (ret != 1) {
            SD_LOG(LOG_ERR, "RSA_generate_key failed, error 0x%lx", ERR_get_error());
            break; /* failed */
        }

        /* Set signing key */
        int rc = EVP_PKEY_assign_RSA(*skey, RSAPrivateKey_dup(rsa));
        if (rc != 1) {
            SD_LOG(LOG_ERR, "EVP_PKEY_assign_RSA (1) failed, error 0x%lx", ERR_get_error());
            break; /* failed */
        }

        /* Sanity check. Verify private exponent is present */
        /* assert(EVP_PKEY_get0_RSA(*skey)->d != NULL); */

        /* Set verifier key */
        rc = EVP_PKEY_assign_RSA(*vkey, RSAPublicKey_dup(rsa));
        if (rc != 1) {
            SD_LOG(LOG_ERR, "EVP_PKEY_assign_RSA (2) failed, error 0x%lx", ERR_get_error());
            break; /* failed */
        }

        /* Sanity check. Verify private exponent is missing */
        /* assert(EVP_PKEY_get0_RSA(*vkey)->d == NULL); */

        result = 0;
    } while (0);

    if (rsa) {
        RSA_free(rsa);
        rsa = NULL;
    }

    return !!result;
}
