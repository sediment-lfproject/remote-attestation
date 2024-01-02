/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
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

class RSASign : public Crypto
{
private:
    EVP_PKEY *signingKey;

public:
    RSASign(const string &signing_key_pem);

    int sign_it(const uchar *msg, size_t mlen, uchar **sig, size_t *slen);
};
