/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once

#include <iostream>

#include "Config.hpp"
#include "Board.hpp"

using namespace std;

#define SEDIMENT       "/opt/local/sediment/"
#define DATA_DIR       "data/"
#define CONFIGS_DIR    "configs/"

#define DFT_PUBLISHER  CONFIGS_DIR "boards/Ubuntu-001" // data publisher related materials
#define DFT_SUBSCRIBER CONFIGS_DIR "boards/+"          // data subscriber related materials
#define DFT_RSA_PKEY   DATA_DIR "publicRSA.pem"        // RSA public key in PEM format
#define DFT_RSA_PRKEY  DATA_DIR "privateRSA.pem"       // RSA private key in PEM format
#define DFT_RSA_SKEY   DATA_DIR "sign_key.pem"         // RSA signing key in PEM format
#define DFT_RSA_VKEY   DATA_DIR "verify_key.pem"       // RSA verification key in PEM format
#define DFT_DATABASE   DATA_DIR "sediment.db"          // device sqlite database

class CommandLine
{
protected:
    // These are overriden if the environment variable SEDIMENT is set.
    // Those set by SEDIMENT variable are in turn overriden by command line arguments.
    string publisherConfig    = SEDIMENT DFT_PUBLISHER;
    string subscriberConfig   = SEDIMENT DFT_SUBSCRIBER;
    string rsaPublicKey       = SEDIMENT DFT_RSA_PKEY;
    string rsaPrivateKey      = SEDIMENT DFT_RSA_PRKEY;
    string rsaSigningKey      = SEDIMENT DFT_RSA_SKEY;
    string rsaVerificationKey = SEDIMENT DFT_RSA_VKEY;
    string database           = SEDIMENT DFT_DATABASE;
    string sediment_home      = SEDIMENT;
    bool sigVerifier          = true;
    bool noGUI                = false;

    void updateHome(const char *env_p) 
    {
        string sediment(env_p);
        if (sediment.back() != '/')
            sediment += "/";

        publisherConfig    = sediment + DFT_PUBLISHER;
        subscriberConfig   = sediment + DFT_SUBSCRIBER;
        rsaPublicKey       = sediment + DFT_RSA_PKEY;
        rsaPrivateKey      = sediment + DFT_RSA_PRKEY;
        rsaSigningKey      = sediment + DFT_RSA_SKEY;
        rsaVerificationKey = sediment + DFT_RSA_VKEY;
        database           = sediment + DFT_DATABASE;
        sediment_home      = sediment;
    }

public:
    CommandLine()
    {
        if (const char *env_p = std::getenv("SEDIMENT")) 
        {
            updateHome(env_p);
            SD_LOG(LOG_INFO, "Environment variable SEDIMENT is %s", sediment_home.c_str());
        }
        else
        {
            SD_LOG(LOG_WARNING, "Environment variable SEDIMENT not set, default to %s", sediment_home.c_str());
        }
    }

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

    const string& getSedimentHome() const
    {
        return sediment_home;
    }

    bool isSigVerifier() const
    {
        return sigVerifier;
    }

    bool isNoGUI() const
    {
        return noGUI;
    }
};
