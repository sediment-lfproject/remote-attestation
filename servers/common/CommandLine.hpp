/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#pragma once

#include <iostream>
#include <vector>
#include <getopt.h>

#include "Config.hpp"
#include "Board.hpp"

#define BOOL(x) (x ? "true" : "false")

using namespace std;

#define SEDIMENT                "/opt/local/sediment/"
#define DATA_DIR                "data/"
#define CONFIGS_DIR             "configs/"

#define DFT_DATABASE            DATA_DIR "sediment.db"
#define DFT_LOG_DIR             "logs"

#define OPT_CONFIG              1000
#define OPT_SEDIMENT            1001
#define OPT_LOG_DIR             1002
#define OPT_LOG_FILE            1003
#define OPT_LOG_LEVEL           1004
#define OPT_CONSOLE_LOG_LEVEL   1005
#define OPT_LOG_MAX_SIZE        1006
#define OPT_LOG_MAX_FILES       1007
#define OPT_DATABASE            1008
#define OPT_DATABASE_IMPL       1009
#define OPT_VERSION             1010

class CommandLine
{
protected:
    // These are overriden if the environment variable SEDIMENT is set.
    // Those set by SEDIMENT variable are in turn overriden by command line arguments.
    string config;
    string database             = SEDIMENT DFT_DATABASE;
    string databaseType         = "sqlite";
    string sediment_home        = SEDIMENT;
    string logDir               = SEDIMENT DFT_LOG_DIR;
    string logFile;
    int logLevel                = LOG_DEBUG;
    int consoleLogLevel         = LOG_DEBUG;
    int logMaxSize              = 512;   // in MB
    int logMaxFiles             = 3;

    int longopt = 0;
    string opstring = "h";
    vector<struct option> options = {
        { "config",            required_argument, &longopt, OPT_CONFIG },
        { "console-log-level", required_argument, &longopt, OPT_CONSOLE_LOG_LEVEL },
        { "database",          required_argument, &longopt, OPT_DATABASE },
        { "database-impl",     required_argument, &longopt, OPT_DATABASE_IMPL },
        { "help",              no_argument,       0, 'h' },
        { "log-dir",           required_argument, &longopt, OPT_LOG_DIR },
        { "log-file",          required_argument, &longopt, OPT_LOG_FILE },
        { "log-level",         required_argument, &longopt, OPT_LOG_LEVEL },
        { "log-max-files",     required_argument, &longopt, OPT_LOG_MAX_FILES },
        { "log-max-size",      required_argument, &longopt, OPT_LOG_MAX_SIZE },
        { "sediment",          required_argument, &longopt, OPT_SEDIMENT },
        { "version",           no_argument,       &longopt, OPT_VERSION },
    };

    void updateHome(const char *env_p) {
        string sediment(env_p);
        if (sediment.back() != '/')
            sediment += "/";

        database             = sediment + DFT_DATABASE;
        logDir               = sediment + DFT_LOG_DIR;
        sediment_home        = sediment;
    }

public:
    CommandLine() {
        if (const char *env_p = std::getenv("SEDIMENT")) {
            updateHome(env_p);
        }
    }

    string toString() {
        const char *level_strings[] = {
            "trace", "debug", "info", "warning", "error", "critical", "off"
        };
        return
            "config: " + config + "\n" +
            "console-log-level: " + level_strings[consoleLogLevel] + "\n" +
            "database: " + database + "\n" +
            "database-impl: " + databaseType + "\n" +
            "log-dir: " + logDir + "\n" +
            "log-file: " + logFile + "\n" +
            "log-level: " + level_strings[logLevel] + "\n" +
            "log-max-files: " + to_string(logMaxFiles) + "\n" +
            "log-max-size: " + to_string(logMaxSize) + "\n" +
            "sediment: " + sediment_home
            ;
    }

    void init(char *app, string &def_config);
    virtual void parseCmdline(int argc, char *argv[]) = 0;
    void printUsage(char *cmd);
    bool parseLongOption(int c);
    
    const string& getConfig() const {
        return config;
    }

    void setConfig(const string &config) {
        this->config = config;
    }

    const string& getDatabase() const {
        return database;
    }

    const string& getDatabaseType() const {
        return databaseType;
    }
    const string& getSedimentHome() const {
        return sediment_home;
    }

    const string& getLogDir() const {
        return logDir;
    }

    const string& getLogFile() const {
        return logFile;
    }

    int getLogLevel() const {
        return logLevel;
    }

    int getConsoleLogLevel() const {
        return consoleLogLevel;
    }

    int getLogMaxSize() const {
        return logMaxSize;
    }

    int getLogMaxFiles() const {
        return logMaxFiles;
    }
};
