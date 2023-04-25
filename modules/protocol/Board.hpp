/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once

#include "Config.hpp"

using namespace std;

class Board
{
protected:
    uint32_t baseTime;
    uint32_t seq = 0; // sensor data sequence number
    string id;        // for file name of RPI SQN

public:
    virtual void getOS(char *buf, int len)
    {
        snprintf(buf, len, "unknown");
    }

    virtual uint32_t getUptime()
    {
        return 0;
    }

    virtual uint32_t getTimestamp()
    {
        return 0;
    }

    virtual uint64_t getTimeInstant(){ return 0; }

    virtual string runUdf(){ return ""; }

    virtual uint32_t getHumidity();
    virtual uint32_t getTemperature();

    /**
     * allocate a memory block to collect the configurations.
     * caller is responsible for freeing the buffer.
     */
    virtual char *getConfigBlocks(int *len)
    {
        (void) len;
        return NULL;
    }

    virtual void sleepSec(uint32_t sec)
    {
        (void) sec;
    }

    virtual uint32_t getElapsedTime(uint64_t start_time)
    {
        (void) start_time;
        return 0;
    }

    virtual void * getStartingAddr(string &library_keyword, uint32_t *blockSize)
    {
        (void) library_keyword;
        (void) blockSize;
        return 0;
    }

    int getSeq()
    {
        return seq;
    }

    void incSeq()
    {
        seq++;
    }

    virtual void setBaseTime(uint32_t bt)
    {
        baseTime = bt;
    }

    virtual void saveAttestSqn(uint32_t sqn)
    {
        (void) sqn;
    }

    virtual uint32_t getAttestSqn()
    {
        return 0;
    }

    const string& getId() const
    {
        return id;
    }

    void setId(const string &id)
    {
        this->id = id;
    }
};
