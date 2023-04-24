/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once

#include "Config.hpp"
#include "Board.hpp"

using namespace std;

class BoardRPI : public Board
{
public:
    BoardRPI(char *executable) :
        executable(executable[0] == '.' ? executable + 1 : executable)
    {
    }

    virtual void sleepSec(uint32_t sec);
    virtual void getOS(char *buf, int len);
    virtual uint32_t getUptime();
    virtual uint64_t getTimeInstant();
    virtual uint32_t getElapsedTime(uint64_t start_time);
    virtual uint32_t getTimestamp();
    virtual uint32_t getTemperature();
    virtual void * getStartingAddr(string &library_keyword, uint32_t *blockSize);
    virtual void saveAttestSqn(uint32_t sqn);
    virtual uint32_t getAttestSqn();
    virtual char* getConfigBlocks(int *len);

    void setConfigFile(string cfg)
    {
        this->configFile = cfg;
    }

    const string& getConfigFile() const
    {
        return configFile;
    }    

private:
    string executable;
    string configFile;
};
