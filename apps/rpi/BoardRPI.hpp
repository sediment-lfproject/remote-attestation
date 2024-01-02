/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
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
    virtual int getAllSensors(uint32_t sqn, char *buf, uint32_t len);
    virtual void * getStartingAddr(string &library_keyword, uint32_t *blockSize);
    virtual void saveAttestSqn(uint32_t sqn);
    virtual uint32_t getAttestSqn();
    virtual void saveSeecSqn(uint32_t sqn);
    virtual uint32_t getSeecSqn();
    virtual void saveRevCheckSqn(uint32_t sqn);
    virtual uint32_t getRevCheckSqn();
    virtual void saveRevAckSqn(uint32_t sqn);
    virtual uint32_t getRevAckSqn();
    virtual char* getConfigBlocks(int *len);
    virtual uint32_t getReportInterval();
    virtual void saveReportInterval(uint32_t interval);  

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
