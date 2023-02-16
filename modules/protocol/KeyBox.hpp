/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once
#include <cstring>

#include "Codec.hpp"
#include "Log.hpp"

#define KEY_PURPOSE_SIZE     1
#define KEY_ENC_TYPE_SIZE    1
#define JEDI_KEY_LEN_SIZE    2
#define ENC_AES_KEY_LEN_SIZE 2

class KeyBox
{
protected:
    KeyPurpose keyPurpose;
    KeyEncType encType = KEY_ENC_TYPE_JEDI; // encryption type of the enclosed key
    vector<uint8_t> encryptedKey;           // key encrypted using JEDI, RSA or other methods

public:
    KeyBox()
    { }

    void decode(Vector &data);
    void encode(Vector &data);
    uint32_t getSize();
    string toString();

    vector<uint8_t> &getEncryptedKey()
    {
        return encryptedKey;
    }

    KeyEncType getEncType() const
    {
        return encType;
    }

    void setEncType(KeyEncType encType = KEY_ENC_TYPE_JEDI)
    {
        this->encType = encType;
    }

    KeyPurpose getKeyPurpose() const
    {
        return keyPurpose;
    }

    void setKeyPurpose(KeyPurpose keyPurpose)
    {
        this->keyPurpose = keyPurpose;
    }
};
