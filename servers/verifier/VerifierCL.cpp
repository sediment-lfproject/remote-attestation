/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#include <getopt.h>

#include "VerifierCL.hpp"

using namespace std;

void VerifierCL::printUsage(char *cmd)
{
    CommandLine::printUsage(cmd);
    cout <<
         "--api-port/-a <port>\n"
         "  Listen on the port for connection for service\n\n"

         "--block-size/-b <block-size>\n"
         "  Use the specified block size instead of the full firmware size in RA\n\n"

         "--gui-port/-g <port>\n"
         "  Listen on the port for connection from the GUI\n\n"

         "--no-gui/-n\n"
         "  Run without GUI\n\n"

         "--signing-key/-s <pem-key>\n"
         "  RSA signing key in pem\n\n"
        ;
    exit(0);
}

bool VerifierCL::parseOption(int c)
{
    bool val = true;

    switch (c) {
    case 'a':
        apiPort = atoi(optarg);
        break;        
    case 'b':
        blockSize = atoi(optarg);
        break; 
    case 'g':
        guiPort = atoi(optarg);
        break;
    case 'n':
        noGUI = true;
        break;
    case 's':
        signingKey = optarg;
        break;         
    default:
        val = false;
        break;
    }
    return val;
}

void VerifierCL::parseCmdline(int argc, char *argv[])
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
