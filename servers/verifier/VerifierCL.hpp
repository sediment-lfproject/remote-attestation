/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#pragma once

#include "CommandLine.hpp"

using namespace std;

#define DFT_CONFIG    CONFIGS_DIR "boards/RAP_Server" 
#define DFT_SIGN_KEY  DATA_DIR "sign_key.pem"

class VerifierCL : public CommandLine
{
protected:
    uint16_t guiPort  = 8101;
    uint16_t apiPort  = 8102;
    string defConfig  = SEDIMENT DFT_CONFIG;
    bool noGUI        = false;
    string signingKey = SEDIMENT DFT_SIGN_KEY;
    int blockSize     = -1;

    string opstring = "a:b:hg:ns:";
    vector<struct option> options = {
        { "api-port",     required_argument, 0, 'a' },
        { "block-size",   required_argument, 0, 'b' },
        { "gui-port",     required_argument, 0, 'g' },
        { "no-gui",       no_argument,       0, 'n' },
        { "signing-key",  required_argument, 0, 's' },        
        { 0,              0,                 0, 0   }        
    };

    void updateHome(const char *env_p) {
        string sediment(env_p);
        if (sediment.back() != '/')
            sediment += "/";

        config = sediment + DFT_CONFIG;
        signingKey = sediment + DFT_SIGN_KEY;
    }

public:
    VerifierCL() {
        if (const char *env_p = std::getenv("SEDIMENT")) {
            updateHome(env_p);
        }
        options.insert(options.begin(), CommandLine::options.begin(), CommandLine::options.end());
    }

    string toString() {
        return CommandLine::toString() + "\n" +
               "api-port: " + to_string(apiPort) + "\n" +
               "block-size: " + to_string(blockSize) + "\n" +
               "gui-port: " + to_string(guiPort) + "\n" +
               "no-gui: " + BOOL(noGUI) + "\n" +
               "signing-key: " + signingKey;
    }

    void parseCmdline(int argc, char *argv[]);
    void printUsage(char *cmd);
    bool parseOption(int c);

    void setBlocksize(int blockSize) {
        this->blockSize = blockSize;
    }

    int getBlockSize() const {
        return blockSize;
    }

    bool isNoGUI() const {
        return noGUI;
    }

    void setApiPort(uint16_t apiPort) {
        this->apiPort = apiPort;
    }

    int getApiPort() const {
        return apiPort;
    }

    void setGuiPort(uint16_t guiPort) {
        this->guiPort = guiPort;
    }

    int getGuiPort() const {
        return guiPort;
    }

    const string& getSigningKey() const {
        return signingKey;
    }

    void setSigningKey(const string &signingKey) {
        this->signingKey = signingKey;
    }   
};
