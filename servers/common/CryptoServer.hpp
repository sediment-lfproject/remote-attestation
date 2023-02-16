/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include "Crypto.hpp"
#include "CommandLine.hpp"

typedef unsigned char uchar;
#define UNUSED(x) ((void) x)

class CryptoServer : public Crypto
{
private:
    EVP_PKEY *signingKey;
    EVP_PKEY *verifyingKey;

public:
    CryptoServer(CommandLine &cli);

    int sign_it(const uchar *msg, size_t mlen, uchar **sig, size_t *slen);
    int verify_it(const uchar *msg, size_t mlen, const uchar *sig, size_t slen);
    int make_keys(EVP_PKEY **skey, EVP_PKEY **vkey);
    int test();
};
