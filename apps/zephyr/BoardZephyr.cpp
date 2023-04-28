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
int getSeecSqnNV();
void saveSeecSqnNV(uint32_t sqn);

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

void BoardZephyr::saveSeecSqn(uint32_t sqn)
{
    saveSeecSqnNV(sqn);
}

uint32_t BoardZephyr::getSeecSqn()
{
    return getSeecSqnNV();
}

static Item flash_items[] = {
    { NV_MAGIC,            NV_OFFSET_MAGIC,            NV_LEN_MAGIC,            NV_TYPE_BYTE                },
    { NV_ID,               NV_OFFSET_ID,               NV_LEN_ID,               NV_TYPE_CHAR                },
    { NV_PROTOCOL,         NV_OFFSET_PROTOCOL,         NV_LEN_PROTOCOL,         NV_TYPE_CHAR                },
    { NV_ADDRESS,          NV_OFFSET_ADDRESS,          NV_LEN_ADDRESS,          NV_TYPE_CHAR                },
    { NV_PORT,             NV_OFFSET_PORT,             NV_LEN_PORT,             NV_TYPE_INT                 },
    { NV_KEY_DIST,         NV_OFFSET_KEY_DIST,         NV_LEN_KEY_DIST,         NV_TYPE_CHAR                },
    { NV_KEY_CHG_INTVL,    NV_OFFSET_KEY_CHG_INTVL,    NV_LEN_KEY_CHG_INTVL,    NV_TYPE_INT                 },
    { NV_ENCRYPT,          NV_OFFSET_ENCRYPT,          NV_LEN_ENCRYPT,          NV_TYPE_BOOL                },
    { NV_REPORT_INTVL,     NV_OFFSET_REPORT_INTVL,     NV_LEN_REPORT_INTVL,     NV_TYPE_INT                 },
    { NV_ATTEST,           NV_OFFSET_ATTEST,           NV_LEN_ATTEST,           NV_TYPE_BOOL                },
    { NV_SEEC,             NV_OFFSET_SEEC,             NV_LEN_SEEC,             NV_TYPE_BOOL                },
    { NV_KEY_ENCRYPTION,   NV_OFFSET_KEY_ENCRYPTION,   NV_LEN_KEY_ENCRYPTION,   NV_TYPE_BOOL                },
    { NV_SIGNING,          NV_OFFSET_SIGNING,          NV_LEN_SIGNING,          NV_TYPE_BOOL                },
    { NV_KEY_CHANGE,       NV_OFFSET_KEY_CHANGE,       NV_LEN_KEY_CHANGE,       NV_TYPE_BOOL                },
    { NV_PASSPORT_PERIOD,  NV_OFFSET_PASSPORT_PERIOD,  NV_LEN_PASSPORT_PERIOD,  NV_TYPE_INT                 },
    { NV_PAYLOAD_SIZE,     NV_OFFSET_PAYLOAD_SIZE,     NV_LEN_PAYLOAD_SIZE,     NV_TYPE_INT                 },
    { NV_PASS_THRU,        NV_OFFSET_PASS_THRU,        NV_LEN_PASS_THRU,        NV_TYPE_BOOL                },
    { NV_NUM_CYCLES,       NV_OFFSET_NUM_CYCLES,       NV_LEN_NUM_CYCLES,       NV_TYPE_INT                 },
    { NV_ITERATIONS,       NV_OFFSET_ITERATIONS,       NV_LEN_ITERATIONS,       NV_TYPE_INT                 },
    { NV_AUTHENTICATION,   NV_OFFSET_AUTHENTICATION,   NV_LEN_AUTHENTICATION,   NV_TYPE_BOOL                },

    { NV_ENC_KEY,          NV_OFFSET_ENC_KEY,          NV_LEN_ENC_KEY,          NV_TYPE_BYTE                },
    { NV_ATTEST_KEY,       NV_OFFSET_ATTEST_KEY,       NV_LEN_ATTEST_KEY,       NV_TYPE_BYTE                },
    { NV_AUTH_KEY,         NV_OFFSET_AUTH_KEY,         NV_LEN_AUTH_KEY,         NV_TYPE_BYTE                },
    { NV_ATTEST_SQN,       NV_OFFSET_ATTEST_SQN,       NV_LEN_ATTEST_SQN,       NV_TYPE_INT                 },
 
    { NV_PARAMS_SIZE,      NV_OFFSET_PARAMS_SIZE,      NV_LEN_PARAMS_SIZE,      NV_TYPE_INT                 },
    { NV_PARAMS,           NV_OFFSET_PARAMS,           NV_LEN_PARAMS,           NV_TYPE_BLOCK               },

    { NV_URIPATH_SIZE,     NV_OFFSET_URIPATH_SIZE,     NV_LEN_URIPATH_SIZE,     NV_TYPE_INT                 },
    { NV_URIPATH,          NV_OFFSET_URIPATH,          NV_LEN_URIPATH,          NV_TYPE_BLOCK               },

    { NV_TIMEPATH_SIZE,    NV_OFFSET_TIMEPATH_SIZE,    NV_LEN_TIMEPATH_SIZE,    NV_TYPE_INT                 },
    { NV_TIMEPATH,         NV_OFFSET_TIMEPATH,         NV_LEN_TIMEPATH,         NV_TYPE_BLOCK               },

    { NV_SIGNKEY_SIZE,     NV_OFFSET_SIGNKEY_SIZE,     NV_LEN_SIGNKEY_SIZE,     NV_TYPE_INT                 },
    { NV_SIGNKEY,          NV_OFFSET_SIGNKEY,          NV_LEN_SIGNKEY,          NV_TYPE_BLOCK               },
};

bool isVariableLen(string key)
{
    return !(key.compare(NV_PARAMS) &&
             key.compare(NV_SIGNKEY) &&
             key.compare(NV_URIPATH) &&
             key.compare(NV_TIMEPATH));
}

bool isVariableLenSize(string key)
{
    return !(key.compare(NV_PARAMS_SIZE) &&
             key.compare(NV_URIPATH_SIZE) &&
             key.compare(NV_TIMEPATH_SIZE) &&
             key.compare(NV_SIGNKEY_SIZE));
}

/**
 * allocate a memory block to collect the configurations.
 * caller is responsible for freeing the buffer.
*/
char* BoardZephyr::getConfigBlocks(int *size) 
{
    int total = 0;
    int num_items = 0;
    int i = 0;

    while (true)
    {
        total += flash_items[i].len;
        num_items++;

        if (!strcmp(flash_items[i].name, NV_SIGNKEY)) {
            break;
        } 
        i++;
    }
    *size = total;

    char *pool = (char *) calloc(1, total);  // allocation here
    int read_item(const char *item_name, int buf_len, uint8_t *buf);

    int offset = 0;
    int var_len = 0;
    for (int i = 0; i < num_items; i++)
    {
        Item *item = &flash_items[i];
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
}
