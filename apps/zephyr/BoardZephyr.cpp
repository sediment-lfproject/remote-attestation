/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#include <zephyr.h>

#include <fcntl.h>
#include <sys/stat.h>
// #include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "nv_board.h"

#include "BoardZephyr.hpp"
#include "Log.hpp"

using namespace std;

int getAttestSqnNV();
void saveAttestSqnNV(uint32_t sqn);

void BoardZephyr::sleepSec(uint32_t sec)
{
    k_sleep(K_MSEC(sec * 1000));
}

void BoardZephyr::getOS(char *buf, int len)
{
    uint32_t version = sys_kernel_version_get();

    snprintf(buf, len, "Zephyr_%d.%d.%d",
      SYS_KERNEL_VER_MAJOR(version),
      SYS_KERNEL_VER_MINOR(version),
      SYS_KERNEL_VER_PATCHLEVEL(version));
}

uint32_t BoardZephyr::getUptime()
{
    // k_uptime_get() returns the elapsed time since the system booted, in milliseconds (sint64)
    uint32_t uptime = (uint32_t) (k_uptime_get() / 1000);

    return uptime;
}

uint64_t BoardZephyr::getTimeInstant()
{
    return k_cycle_get_32();
}

uint32_t BoardZephyr::getElapsedTime(uint64_t start_time)
{
    /* compute how long the work took (assumes no counter rollover) */
    uint64_t cycles_spent      = k_cycle_get_32() - start_time;
    uint64_t nanoseconds_spent = k_cyc_to_ns_floor64(cycles_spent);

    return nanoseconds_spent / 1000;
}

uint32_t BoardZephyr::getTimestamp()
{
    uint32_t uptime = getUptime();

    return baseTime + (uptime - secSinceReset);
}

void BoardZephyr::setBaseTime(uint32_t bt)
{
    baseTime      = bt;
    secSinceReset = getUptime();
}

void * BoardZephyr::getStartingAddr(string &library_keyword, uint32_t *blockSize)
{
    (void) library_keyword;
    (void) blockSize;

    /*
     * The starting address can be obtained from the zephyr build in
     * zephyrproject/zephyr/build/zephyr/zephyr.lst.
     */
    return (void *) CODE_START_ADDR;
}

void BoardZephyr::saveAttestSqn(uint32_t sqn)
{
    saveAttestSqnNV(sqn);
}

uint32_t BoardZephyr::getAttestSqn()
{
    return getAttestSqnNV();
}
