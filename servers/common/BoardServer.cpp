/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#include "BoardServer.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sstream>
#include <cmath>

#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "BoardServer.hpp"
#include "Log.hpp"

using namespace std;

uint64_t BoardServer::getTimeInstant()
{
    struct timespec tp;

    clock_gettime(CLOCK_MONOTONIC, &tp);

    uint64_t ts = ((uint64_t) 1000000) * ((uint64_t) tp.tv_sec); // seconds to microseconds
    ts += (tp.tv_nsec / 1000);

    return ts;
}

uint32_t BoardServer::getElapsedTime(uint64_t start_time)
{
    return getTimeInstant() - start_time;
}

uint32_t BoardServer::getTimestamp()
{
    long ms;  // Milliseconds
    time_t s; // Seconds
    struct timespec spec;

    clock_gettime(CLOCK_REALTIME, &spec);

    s  = spec.tv_sec;
    ms = round(spec.tv_nsec / 1.0e6); // Convert nanoseconds to milliseconds
    if (ms > 999) {
        s++;
        ms = 0;
    }
    return s;
}
