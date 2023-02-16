/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once

#include "Config.hpp"
#include "Board.hpp"

using namespace std;

class BoardServer : public Board
{
public:
    BoardServer()
    { }

    virtual ~BoardServer()
    { }

    virtual void getOS(char *buf, int len)
    {
        snprintf(buf, len, "server");
    }

    virtual uint32_t getUptime()
    {
        return 0;
    }

    virtual uint32_t getTimestamp();
    virtual uint64_t getTimeInstant();

    virtual uint32_t getHumidity(){ return 0; }

    virtual uint32_t getTemperature(){ return 0; }

    virtual void sleepSec(uint32_t sec)
    {
        sleep(sec);
    }

    virtual uint32_t getElapsedTime(uint64_t start_time);

    virtual void * getStartingAddr(string &library_keyword)
    {
        (void) library_keyword;
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
};
