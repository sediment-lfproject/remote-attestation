/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#include <iostream>
#include <filesystem>
#include <getopt.h>

#include "CommandLine.hpp"
#include "Log.hpp"

#include "version.hpp"

using namespace std;

void CommandLine::init(char *app, string &def_config) {
    if (config.empty())
        config = def_config;

    auto appName = std::filesystem::path(app).filename().string();
    if (logFile.empty()) {
        logFile = appName + ".log";
    }
    else if (logFile.find('/') != std::string::npos) {
        SD_LOG(LOG_ERR, "log file contains path separator %s", logFile.c_str());
        exit(EXIT_FAILURE);
    }

    if (!filesystem::exists(logDir)) {
        if (!filesystem::create_directories(logDir)) {
            SD_LOG(LOG_ERR, "could not create directory: %s!", logDir.c_str());
            exit(EXIT_FAILURE);
        }
    }

    string logPath = logDir + "/" + logFile;
    Log::initLog(consoleLogLevel, logLevel, logPath, logMaxSize, logMaxFiles);
    appName[0] = toupper(appName[0]);

    SD_LOG(LOG_INFO, "Peraton Labs SEDIMENT %s Version %s", appName.c_str(), PROGRAM_VERSION.c_str());
    SD_LOG(LOG_DEBUG, "%s-%s %s-%s", GIT_BRANCH.c_str(), GIT_HASH.c_str(), GIT_BRANCH_RA.c_str(), GIT_HASH_RA.c_str());
}

void CommandLine::printUsage(char *cmd)
{
    cout << cmd << " -h" << endl
         << 
         "--config <config-file>\n"
         "  Configuration file, default is app dependent.\n\n"

         "--console-log-level [off, trace, debug, info, warning, error, critical]\n"
         "  Console logging level, default to 'debug'\n\n"

         "--database <Argument>\n"
         "  Use the specified device database. <Argument> can be one of \n"
         "    <sqlite database file> for sqlite\n"
         "    <url>,<user>,<pass>,<device database> for MySQL\n"
         "  Default to $SEDIMENT/data/sediment.db\n\n"

         "--database-impl [ sqlite | mysql ]\n"
         "  Database implementation, default to sqlite\n\n"

         "--log-dir <log-dir>\n"      
         "  Write log files to this directory, defaults to '$SEDIMENT/logs'\n\n"

         "--log-file <log file>\n"
         "  Log file name, default to <executable name>.log\n\n"

         "--log-level [off, trace, debug, info, warning, error, critical]\n"
         "  Logging level, default to 'debug'\n\n"

         "--log-max-files <int>\n"
         "  Maximum number of rotating log files, default to 3\n\n"
         
         "--log-max-size <MB>\n"
         "  Maximum log file size, default to 512 MB\n\n"

         "--sediment <sediment home directory>\n"
         "  SEDIMENT installation directory, overriding the envrionment variable SEDIMENT\n\n"

         "--version\n"
         "  Display the version number\n\n"

         "--help/-h\n"
         "  This help.\n\n"
    ;
}

bool CommandLine::parseLongOption(int c)
{
    bool val = true;

    switch (c) {
    case OPT_CONFIG:
        config = optarg;
        break;
    case OPT_SEDIMENT:
        if (!filesystem::exists(optarg)) {
            SD_LOG(LOG_ERR, "SEDIMENT home directory does not exist: %s", optarg);
            exit(EXIT_FAILURE);
        }
        updateHome(optarg);
        break;
    case OPT_LOG_DIR:
        logDir = optarg;
        break;
    case OPT_LOG_FILE:
        logFile = optarg;
        break;
    case OPT_LOG_LEVEL: {
        string arg(optarg);
        logLevel = Log::fromStr(arg);
        }
        break;
    case OPT_CONSOLE_LOG_LEVEL: {
        string arg(optarg);
        consoleLogLevel = Log::fromStr(arg);
        }
        break;
    case OPT_DATABASE:
        database = optarg;
        break;
    case OPT_DATABASE_IMPL:
        databaseType = optarg;
        break;
    case OPT_LOG_MAX_SIZE:
        logMaxSize = strtol(optarg, NULL, 10);
        break;
    case OPT_LOG_MAX_FILES:
        logMaxFiles = strtol(optarg, NULL, 10);
        break;
    case OPT_VERSION:
        std::cout << PROGRAM_VERSION << endl;
        exit(EXIT_SUCCESS);
        break;
    default:
        val = false;
        break;
    }
    return val;
}

