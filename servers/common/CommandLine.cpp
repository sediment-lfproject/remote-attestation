/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#include <iostream>
#include <getopt.h>

#include "CommandLine.hpp"
#include "Log.hpp"

using namespace std;

void CommandLine::printUsage(char *cmd)
{
    cout << cmd << endl
         << "  -d/--database <device database>\n\t"
         << "Use the specified device database." << endl
         << "  -p/--wdkibe-pub-key <publisher key file>\n\t"
         << "Read WKD-IBE publisher key material file. Used only by publishers." << endl
         << "  -s/--wdkibe-sub-key <subscriber key file>\n\t"
         << "Read WKD-IBE subscriber key material file. Used only by subscribers" << endl
         << "  -h/--help\n\t"
         << "This help." << endl
    ;
    exit(0);
}

void CommandLine::parseCmdline(int argc, char *argv[])
{
    int c;

    struct option long_options[] = {
        { "database",       required_argument, 0, 'd' },
        { "wdkibe-pub-key", required_argument, 0, 'p' },
        { "wdkibe-sub-key", required_argument, 0, 's' },
        { "help",           no_argument,       0, 'h' },
        { 0,                0,                 0, 0   }
    };

    int option_index = 0;

    while ((c = getopt_long(argc, argv, "hd:p:s:",
      long_options, &option_index)) != -1)
    {
        switch (c) {
        case 'd':
            database = optarg;
            break;
        case 'p':
            publisherConfig = optarg;
            break;
        case 's':
            subscriberConfig = optarg;
            break;
        case 'h':
            printUsage(argv[0]);
            break;
        default:
            printUsage(argv[0]);
            break;
        }
    }
}
