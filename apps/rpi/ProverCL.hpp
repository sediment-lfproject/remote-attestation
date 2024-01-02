/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#pragma once

#include <string>
#include <vector>

#include <getopt.h>

#include "CommandLine.hpp"
#include "Log.hpp"

using namespace std;

#define DFT_CONFIG   CONFIGS_DIR "boards/Ubuntu-001" 

class ProverCL : public CommandLine
{
protected:
    string defConfig = SEDIMENT DFT_CONFIG;

    string opstring = "h";
    vector<struct option> options = {
        { "help",         no_argument,    0, 'h' },         
        { 0,              0,              0, 0   }        
    };

    void updateHome(const char *env_p) {
        string sediment(env_p);
        if (sediment.back() != '/')
            sediment += "/";

        sediment_home        = sediment;
        defConfig = sediment + DFT_CONFIG;
    }

public:
    ProverCL() {
        if (const char *env_p = std::getenv("SEDIMENT")) {
            updateHome(env_p);
        }
        options.insert(options.begin(), CommandLine::options.begin(), CommandLine::options.end());
    }

    void parseCmdline(int argc, char *argv[]);
    void printUsage(char *cmd);
    bool parseOption(int c);
};
