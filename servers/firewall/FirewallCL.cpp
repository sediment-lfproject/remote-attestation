/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */
#include <filesystem>
#include <getopt.h>

#include "FirewallCL.hpp"

using namespace std;

void FirewallCL::printUsage(char *cmd)
{
    CommandLine::printUsage(cmd);
    cout <<
            "--verify-key/-v <pem-key>\n"
            "  RSA verifying key in pem, default to $SEDIMENT/data/verify_key.pem\n\n"
    ;
    exit(0);
}

bool FirewallCL::parseOption(int c)
{
    bool val = true;

    switch (c) {
    case 'v':
        verifyKey = optarg;
        break;       
    default:
        val = false;
        break;
    }
    return val;
}

void FirewallCL::parseCmdline(int argc, char *argv[])
{
    struct option *long_options = &options[0];
    int option_index = 0;
    string plus_base = CommandLine::opstring + opstring;

    int c;
    while ((c = getopt_long(argc, argv, (char *)&plus_base[0], long_options, &option_index)) != -1) {
        if (c == 'h') {
            printUsage(argv[0]);
        }
        else if (c == 0) {
            if (!CommandLine::parseLongOption(longopt))
                printUsage(argv[0]);
        }
        else if (!parseOption(c)) {
            printUsage(argv[0]);
        }
    }
    init(argv[0], defConfig);
    SD_LOG(LOG_DEBUG, "%s", toString().c_str());
}
