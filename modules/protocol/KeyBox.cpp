/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#include <vector>
#include <random>
#include <climits>
#include <algorithm>
#include <functional>

#include "Enum.hpp"
#include "KeyBox.hpp"

uint32_t KeyBox::getSize()
{
    return KEY_PURPOSE_SIZE
           + KEY_ENC_TYPE_SIZE
           + ENC_AES_KEY_LEN_SIZE
           + encryptedKey.size();
}

string KeyBox::toString()
{
    return SD_TO_STRING(
        "\nkeyPurpose: " + TO_KEY_PURPOSE(keyPurpose)
        + "\nencType: " + TO_KEY_ENC_TYPE(encType)
        + "\naesKey (len): " + to_string(encryptedKey.size())); // +  // Log::toHex((char *)&encryptedKey[0], encryptedKey.size()) +
}

void KeyBox::decode(Vector &data)
{
    int cand = Codec::getInt(data, KEY_PURPOSE_SIZE);

    keyPurpose = DECODE_CHECK(KeyPurpose, cand, MIN_KEY_PURPOSE, MAX_KEY_PURPOSE, "bad key purpose");

    cand    = Codec::getInt(data, KEY_ENC_TYPE_SIZE);
    encType = DECODE_CHECK(KeyEncType, cand, MIN_KEY_ENC_TYPE, MAX_KEY_ENC_TYPE, "bad key enc type");

    if (encType == KEY_ENC_TYPE_NONE || encType == KEY_ENC_TYPE_EC) {
        return;
    }

    int aes_key_size = Codec::getInt(data, ENC_AES_KEY_LEN_SIZE);
    Codec::getByteArray(data, aes_key_size, encryptedKey);
}

void KeyBox::encode(Vector &data)
{
    Codec::putInt(keyPurpose, data, KEY_PURPOSE_SIZE);
    Codec::putInt(encType, data, KEY_ENC_TYPE_SIZE);

    if (encType == KEY_ENC_TYPE_NONE || encType == KEY_ENC_TYPE_EC) {
        SD_LOG(LOG_ERR, "encode: unsupported key encryption type: %d", encType);
        return;
    }

    Codec::putInt(encryptedKey.size(), data, ENC_AES_KEY_LEN_SIZE);
    Codec::putByteArray(data, encryptedKey);
}
