﻿/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
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
#include "AttestedConfigs.hpp"

using namespace std;

extern "C" 
{
    void save_sqn(SQN_Type sqn_type, uint32_t sqn);
    uint32_t read_sqn(SQN_Type sqn_type);
}

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
    save_sqn(SQN_ATTEST, sqn);
}

uint32_t BoardZephyr::getAttestSqn()
{
    return read_sqn(SQN_ATTEST);
}

void BoardZephyr::saveSeecSqn(uint32_t sqn)
{
    save_sqn(SQN_SEEC, sqn);
}

uint32_t BoardZephyr::getSeecSqn()
{
    return read_sqn(SQN_SEEC);
}

void BoardZephyr::saveRevCheckSqn(uint32_t sqn)
{
    save_sqn(SQN_REV_CHECK, sqn);
}

uint32_t BoardZephyr::getRevCheckSqn()
{
    return read_sqn(SQN_REV_CHECK);
}

void BoardZephyr::saveRevAckSqn(uint32_t sqn)
{
    save_sqn(SQN_REV_ACK, sqn);
}

uint32_t BoardZephyr::getRevAckSqn()
{
    return read_sqn(SQN_REV_ACK);
}

uint32_t BoardZephyr::getReportInterval()
{
    SD_LOG(LOG_ERR, "getReportInterval() not implemented");
    return 0;
//     uint8_t buf[16];

//     if (reload(NV_REPORT_INTVL, sizeof(buf), buf) == 0) {
//         return *(uint32_t *) buf;
//     }

//     SD_LOG(LOG_ERR, "getReportInterval() failed");
//     return 0;
}

bool isVariableLen(string key)
{
    return !(key.compare(NV_PARAMS) &&
             key.compare(NV_SIGNKEY) &&
             key.compare(NV_EURIPATH) &&
             key.compare(NV_SURIPATH) &&
             key.compare(NV_TIMEPATH));
}

/**
 * allocate a memory block to collect the configurations.
 * caller is responsible for freeing the buffer.
*/
char* BoardZephyr::getConfigBlocks(int *size) 
{
#if 0
    int total = 0;
    int num_items = sizeof(attested_items) / sizeof(Item);
    for (int i = 0; i < num_items; i++)
    {
        total += attested_items[i].len;
    }
    *size = total;

    char *pool = (char *) calloc(1, total);  // allocation here
    int read_item(const char *item_name, int buf_len, uint8_t *buf);

    int offset = 0;
    int var_len = 0;
    for (int i = 0; i < num_items; i++)
    {
        Item *item = &attested_items[i];
        if (strcmp(item->name, NV_ATTEST_SQN)) {  // exclude attestation sqn
            if (item->type == NV_TYPE_BOOL) {
                uint8_t xbuf[item->len];
                read_item(item->name, item->len, xbuf);
                pool[offset] = (xbuf[0] == 0) ? 0 : 1;
            }
            else if (isVariableLen(item->name)) 
            {
                read_item(item->name, item->len, (uint8_t *) (pool + offset));
                memset(pool + offset + var_len, '\0', item->len - var_len);  // zero out trailing unused bytes
            }
            else {
                read_item(item->name, item->len, (uint8_t *) (pool + offset));
            }

            if (isVariableLenSize(item->name)) // save the length of the next item
            {
                var_len = *(int *)&pool[offset];
            }
        }
        offset += item->len;
    }
    // dump((const uint8_t *)pool, num_items);
    // dump_hex_ascii((const uint8_t *)pool, total);
    return pool;
#endif
    return NULL;    
}
