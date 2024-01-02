/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#pragma once

#include "CommandLine.hpp"

using namespace std;

#define DFT_CONFIG      CONFIGS_DIR "boards/RA_Manager" 
#define DFT_VERIFY_KEY  DATA_DIR "verify_key.pem"

class FirewallCL : public CommandLine
{
protected:
    string defConfig = SEDIMENT DFT_CONFIG;
    string verifyKey = SEDIMENT DFT_VERIFY_KEY;

    string opstring = "hv:";
    vector<struct option> options = {
        { "verify-key",   required_argument, 0, 'v' },
        { 0,              0,                 0, 0   }        
    };

    void updateHome(const char *env_p) {
        string sediment(env_p);
        if (sediment.back() != '/')
            sediment += "/";

        defConfig = sediment + DFT_CONFIG;
        verifyKey = sediment + DFT_VERIFY_KEY;        
    }

public:
    FirewallCL() {
        if (const char *env_p = std::getenv("SEDIMENT")) {
            updateHome(env_p);
        }
        options.insert(options.begin(), CommandLine::options.begin(), CommandLine::options.end());
    }

    string toString() {
        return CommandLine::toString() + "\n" +
               "verify-key: " + verifyKey;
    }

    void parseCmdline(int argc, char *argv[]);
    void printUsage(char *cmd);
    bool parseOption(int c);

    const string& getVerifyKey() const {
        return verifyKey;
    }
};
