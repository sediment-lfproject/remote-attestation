/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#include <iostream>
#include <filesystem>
#include <getopt.h>

#include "CommandLine.hpp"
#include "Log.hpp"

using namespace std;

void CommandLine::printUsage(char *cmd)
{
    cout << cmd << endl
         << "  -a/--application-server\n\t"
         << "Run as a application server, instead of a signature verifier" << endl
         << "  for SQLite databases\n\t"
         << "  -d/--database <device database>\n\t"
         << "  for MySQL databases\n\t"
         << "  -d/--database <url>,<user>,<pass>,<device database>\n\t"
         << "Use the specified device database." << endl
         << "  -e/--sediment-home <sediment home directory>\n\t"
         << "Set the sediment installation directory." << endl
         << "  -g/--no-gui\n\t"
         << "Run without GUI." << endl
         << "  -p/--publisher <config file>\n\t"
         << "Read publisher configuration file. Used only by publishers." << endl
         << "  -s/--subscriber <config file>\n\t"
         << "Read subscriber configuration file. Used only by subscribers" << endl
         << "  -h/--help\n\t"
         << "This help." << endl
    ;
    exit(0);
}

void CommandLine::parseCmdline(int argc, char *argv[])
{
    int c;

    struct option long_options[] = {
        { "app-server",    no_argument,       0, 'a' },
        { "database",      required_argument, 0, 'd' },
        { "sediment-home", required_argument, 0, 'e' },
        { "no-gui",        required_argument, 0, 'g' },
        { "publisher",     required_argument, 0, 'p' },
        { "subscriber",    required_argument, 0, 's' },
        { "help",          no_argument,       0, 'h' },
        { 0,               0,                 0, 0   }
    };

    int option_index = 0;

    while ((c = getopt_long(argc, argv, "ad:e:ghp:s:",
      long_options, &option_index)) != -1)
    {
        switch (c) {
        case 'a':
            sigVerifier = false;
            break;
        case 'd':
            database = optarg;
            break;
        case 'e':
            if (!filesystem::exists(optarg)) {
                SD_LOG(LOG_ERR, "SEDIMENT home directory does not exist: %s", optarg);
                exit(EXIT_FAILURE);
            }
            updateHome(optarg);
            SD_LOG(LOG_INFO, "SEDIMENT overridden by command line: %s", sediment_home.c_str());
            break;
        case 'g':
            noGUI = true;
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
