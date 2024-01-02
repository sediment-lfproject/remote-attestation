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

class RSAVerify : public Crypto
{
private:
    EVP_PKEY *verifyingKey;

public:
    RSAVerify(const string &verify_key_pem);

    int verify_it(const uchar *msg, size_t mlen, const uchar *sig, size_t slen);
};
