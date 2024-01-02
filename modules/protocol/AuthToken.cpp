/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#include <vector>
#include <random>
#include <climits>
#include <algorithm>
#include <functional>

#include "AuthToken.hpp"
#include "Crypto.hpp"

AuthToken::AuthToken()
{
    nonce.resize(AUTH_NONCE_LEN);
    Crypto::getRandomBytes((char *) &nonce[0], AUTH_NONCE_LEN);

    digest.resize(AUTH_DIGEST_LEN);
}

uint32_t AuthToken::getSize()
{
    //    return NONCE_LEN +
    //           nonce.size() +
    //           DIGEST_LEN +
    //           digest.size();
    return AuthToken::AUTH_TOKEN_LEN;
}

string AuthToken::toString()
{
    return "\nnonce: " + Log::toHex(nonce) +
           "\ndigest: " + Log::toHex(digest);
}

void AuthToken::decode(Vector &data)
{
    int digestLen = Codec::getInt(data, DIGEST_LEN);

    digest.clear();
    Codec::getByteArray(data, digestLen, digest);

    int nonceLen = Codec::getInt(data, NONCE_LEN);
    nonce.clear();
    Codec::getByteArray(data, nonceLen, nonce);
}

void AuthToken::encode(Vector &data)
{
    Codec::putInt(digest.size(), data, DIGEST_LEN);
    Codec::putByteArray(data, digest);

    Codec::putInt(nonce.size(), data, NONCE_LEN);
    Codec::putByteArray(data, nonce);
}
