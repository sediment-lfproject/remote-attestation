/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once

#include "Config.hpp"
#include "Board.hpp"

using namespace std;

#define SEDIMENT   "../../../"
#define DATA_DIR   SEDIMENT "data/"
#define CONFIG_DIR SEDIMENT "configs/"

class CommandLine
{
protected:
    string publisherConfig    = CONFIG_DIR "boards/Ubuntu-001"; // data publisher related materials
    string subscriberConfig   = CONFIG_DIR "boards/+";          // data subscriber related materials
    string rsaPublicKey       = DATA_DIR "publicRSA.pem";       // RSA public key in PEM format
    string rsaPrivateKey      = DATA_DIR "privateRSA.pem";      // RSA private key in PEM format
    string rsaSigningKey      = DATA_DIR "sign_key.pem";        // RSA signing key in PEM format
    string rsaVerificationKey = DATA_DIR "verify_key.pem";      // RSA verification key in PEM format
    string database = DATA_DIR "sediment.db";                   // device sqlite database

public:
    CommandLine()
    { }

    void parseCmdline(int argc, char *argv[]);
    void printUsage(char *cmd);

    const string& getPublisherConfig() const
    {
        return publisherConfig;
    }

    void setPublisherConfig(const string &publisherConfig)
    {
        this->publisherConfig = publisherConfig;
    }

    const string& getSubscriberConfig() const
    {
        return subscriberConfig;
    }

    void setSubscriberConfig(const string &subscriberConfig)
    {
        this->subscriberConfig = subscriberConfig;
    }

    const string& getRsaPrivateKey() const
    {
        return rsaPrivateKey;
    }

    void setRsaPrivateKey(const string &rsaPrivateKey)
    {
        this->rsaPrivateKey = rsaPrivateKey;
    }

    const string& getRsaPublicKey() const
    {
        return rsaPublicKey;
    }

    void setRsaPublicKey(const string &rsaPublicKey)
    {
        this->rsaPublicKey = rsaPublicKey;
    }

    const string& getRsaSigningKey() const
    {
        return rsaSigningKey;
    }

    void setRsaSigningKey(const string &rsaSigningKey)
    {
        this->rsaSigningKey = rsaSigningKey;
    }

    const string& getRsaVerificationKey() const
    {
        return rsaVerificationKey;
    }

    void setRsaVerificationKey(const string &rsaVerificationKey)
    {
        this->rsaVerificationKey = rsaVerificationKey;
    }

    const string& getDatabase() const
    {
        return database;
    }
};
