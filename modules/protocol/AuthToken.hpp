/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once
// #include <cstring>

#include "Codec.hpp"
#include "Vector.hpp"

#define NONCE_LEN  2
#define DIGEST_LEN 2

class AuthToken
{
public:
    static const int AUTH_NONCE_LEN  = 32;
    static const int AUTH_DIGEST_LEN = 32;
    static const int AUTH_TOKEN_LEN  = (NONCE_LEN + AUTH_NONCE_LEN + DIGEST_LEN + AUTH_DIGEST_LEN);

private:
    vector<uint8_t> nonce;
    vector<uint8_t> digest;

public:
    AuthToken();

    void decode(Vector &data);
    void encode(Vector &data);

    uint32_t getSize();
    string toString();

    vector<uint8_t> &getDigest()
    {
        return digest;
    }

    void setDigest(const char *src, int len)
    {
        if (src != NULL) {
            digest.assign(src, src + len);
        }
    }

    vector<uint8_t> &getNonce()
    {
        return nonce;
    }
};
