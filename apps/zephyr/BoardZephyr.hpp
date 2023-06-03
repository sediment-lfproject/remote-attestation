/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once

#include "Config.hpp"
#include "Board.hpp"

using namespace std;

class BoardZephyr : public Board
{
protected:
    uint32_t secSinceReset = 0; // seconds since reset when the first timestamp is received in PassportResponse

public:
    virtual void sleepSec(uint32_t sec);
    virtual void getOS(char *buf, int len);
    virtual uint32_t getUptime();
    virtual uint64_t getTimeInstant();
    virtual uint32_t getElapsedTime(uint64_t start_time);
    virtual uint32_t getTimestamp();
    virtual void setBaseTime(uint32_t bt);
    virtual void * getStartingAddr(string &library_keyword, uint32_t *blockSize);
    virtual void saveAttestSqn(uint32_t sqn);
    virtual uint32_t getAttestSqn();
    virtual void saveSeecSqn(uint32_t sqn);
    virtual uint32_t getSeecSqn();
    virtual uint32_t getReportInterval();    
    virtual char* getConfigBlocks(int *len) ;
};
