/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#include "Seec.hpp"
#include "Crypto.hpp"
#include "Log.hpp"

#ifdef SEEC_ENABLED
#include "KeyDistJedi.hpp"
#include "KeyDistRSA.hpp"

void Seec::encryptData(Vector &iv, Vector &payload, int message_size, MeasurementList &measList, Board *board,
  string &deviceID, Crypto *crypto, char *plaintext)
{
    KeyEncType keyEncType = config.getKeyDistMethod();

    switch (keyEncType) {
    case KEY_ENC_TYPE_JEDI:
        jedi.encryptData(iv, payload, message_size, measList, board, deviceID, crypto, plaintext);
        break;
    case KEY_ENC_TYPE_RSA:
        rsa.encryptData(iv, payload, message_size, measList, board, deviceID, crypto, plaintext);
        break;
    default:
        SD_LOG(LOG_ERR, "unsupported key encryption type: %s", TO_KEY_ENC_TYPE(keyEncType).c_str());
        break;
    }
}

bool Seec::decryptData(Vector &iv, Vector &payload, Board *board, MeasurementList &measList, string &deviceID, uint32_t &seecSqn)
{
    KeyEncType keyEncType = config.getKeyDistMethod();

    switch (keyEncType) {
    case KEY_ENC_TYPE_JEDI:
        return jedi.decryptData(iv, payload, board, measList, deviceID, seecSqn);
    case KEY_ENC_TYPE_RSA:
        return rsa.decryptData(iv, payload, board, measList, deviceID);
    default:
        SD_LOG(LOG_ERR, "unsupported key encryption type: %s", TO_KEY_ENC_TYPE(keyEncType).c_str());
        return false;
    }
}

void Seec::encryptKey(KeyBox &keyBox, Board *board, MeasurementList &measList, string &deviceID)
{
    KeyEncType keyEncType = config.getKeyDistMethod();

    keyBox.setEncType(keyEncType);

    switch (keyEncType) {
    case KEY_ENC_TYPE_JEDI:
        jedi.encryptKey(keyBox, board, measList, deviceID);
        break;
    case KEY_ENC_TYPE_RSA:
        rsa.encryptKey(keyBox, board, measList, deviceID);
        break;
    default:
        SD_LOG(LOG_ERR, "unsupported key encryption type: %s", TO_KEY_ENC_TYPE(keyEncType).c_str());
        break;
    }
}

void Seec::decryptKey(KeyBox &keyBox)
{
    KeyEncType keyEncType = config.getKeyDistMethod();

    KeyEncType recvKeyEncType = keyBox.getEncType();

    if (recvKeyEncType != config.getKeyDistMethod()) {
        SD_LOG(LOG_ERR, "umatched key encryption type: received %s, expected %s",
          TO_KEY_ENC_TYPE(recvKeyEncType).c_str(), TO_KEY_ENC_TYPE(keyEncType).c_str());
        return;
    }

    switch (keyEncType) {
    case KEY_ENC_TYPE_JEDI:
        jedi.decryptKey(keyBox);
        break;
    case KEY_ENC_TYPE_RSA:
        rsa.decryptKey(keyBox);
        break;
    default:
        SD_LOG(LOG_ERR, "unsupported key encryption type: %s", TO_KEY_ENC_TYPE(keyEncType).c_str());
        break;
    }
}

#endif // ifdef SEEC_ENABLED
