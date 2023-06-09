/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once

#include <string>
#include <vector>

#include "Crypto.hpp"
#include "KeyBox.hpp"
#include "Board.hpp"
#include "MeasurementList.hpp"
#include "Config.hpp"

#ifdef SEEC_ENABLED
#include "KeyDistJedi.hpp"
#include "KeyDistRSA.hpp"
#endif

using namespace std;

class Seec
{
protected:
    Config &config;

    Crypto *crypto;
    uint32_t lastChangeKey; // timestamp at the last key change

#ifdef SEEC_ENABLED
    KeyDistJedi jedi;
    KeyDistRSA rsa;
#endif

public:
    Seec(Config &cfg) :
        config(cfg)
#ifdef SEEC_ENABLED
        ,
        jedi(cfg.getNumCycles(), cfg.getIterations()),
        rsa(cfg.getNumCycles(), cfg.getIterations())
#endif
    {
        this->crypto = new Crypto();
#ifdef SEEC_ENABLED
        jedi.setCrypto(crypto);
        rsa.setCrypto(crypto);
#endif
    }

    void init(int cycles, int iterations)
    {
#ifdef SEEC_ENABLED
        jedi.init(cycles, iterations);
#else
        (void) cycles;
        (void) iterations;
#endif
    }

#ifdef SEEC_ENABLED
    void encryptData(Vector &iv, Vector &payload, int MAX_MESSAGE_SIZE, MeasurementList &measList, 
                     Board *board, string &deviceID, Crypto *crypto, char *plaintext);
    bool decryptData(Vector &iv, Vector &payload, Board *board, MeasurementList &measList, 
                     string &deviceID, uint32_t &seecSqn, bool sigVerifier);
    void encryptKey(KeyBox &keyBox, Board *board, MeasurementList &measList, string &deviceID);
    void decryptKey(KeyBox &keyBox);
#endif

    Crypto * getCrypto()
    {
        return crypto;
    }

    void setCrypto(Crypto *crypto)
    {
        this->crypto = crypto;
    }

    uint32_t getLastChangeKey() const
    {
        return lastChangeKey;
    }

    void setLastChangeKey(uint32_t lastChangeKey)
    {
        this->lastChangeKey = lastChangeKey;
    }
};
