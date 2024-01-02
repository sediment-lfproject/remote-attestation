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
