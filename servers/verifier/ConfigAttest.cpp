/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#include <iostream>
#include <getopt.h>
#include <filesystem>

#include "nv.h"

#include "Config.hpp"
#include "Utils.hpp"
#include "Log.hpp"
#include "AttestedConfigs.hpp"

using std::filesystem::exists;

void dump(const uint8_t *data, int num_items)
{
    int offset = 0;
    for (int i = 0; i < num_items; i++)
    {
        int start = offset;
        int end = offset + attested_items[i].len;
        
        printf("%s ", attested_items[i].name);
        for (int j = start; j < end; j++) 
            printf("%c", isprint(data[j]) ? data[j] : '.');
        printf("\n");

        for (int j = start; j < end; j++) 
            printf("%02x", data[j]);
        printf("\n\n");

        offset += attested_items[i].len;
    }
}

void dump_hex_ascii(const uint8_t *data, size_t size)
{
	char ascii[17];
	size_t i, j;

	ascii[16] = '\0';

	printf("\n");
	printf("0  1  2  3  4  5  6  7   8  9  A  B  C  D  E  F\n");

    for (i = 0; i < size; ++i)
    {
        printf("%02X ", ((unsigned char *)data)[i]);

        ascii[i % 16] = isprint(data[i]) ? data[i] : '.';

        if ((i + 1) % 8 == 0 || i + 1 == size)
        {
            printf(" ");
            if ((i + 1) % 16 == 0)
                printf("|  %s\n", ascii);
            else if ((i + 1) == size)
            {
                ascii[(i + 1) % 16] = '\0';

                if ((i + 1) % 16 <= 8)
                    printf(" ");

                for (j = (i + 1) % 16; j < 16; ++j)
                    printf("   ");
                printf("|  %s\n", ascii);
            }
        }
    }
    printf("\n");
}

bool isMultiline(string key)
{
    return !(key.compare(NV_PARAMS) &&
           key.compare(NV_ENCRYPTKEY) &&
           key.compare(NV_SIGNKEY) &&
           key.compare(NV_URIPATH) &&
           key.compare(NV_TIMEPATH));
}

char *gatherConfigBlocks(const string &filename, int *size)
{
    if (!exists(filename)) {
        SD_LOG(LOG_ERR, "file not exists: '%s'", filename.c_str());
        exit(1);
    }

    ifstream fin(filename);

    string line, key, value;

    int total = 0;
    int num_items = sizeof(attested_items) / sizeof(Item);
    for (int i = 0; i < num_items; i++)
    {
        total += attested_items[i].len;
    }
    *size = total;

    char *pool = (char *) calloc(1, total);
    pool[0] = 0x0a;
    pool[1] = 0xce;
    pool[2] = 0xbe;
    pool[3] = 0xef;

    int i = 0;
    int extra = 0;
    while (getline(fin, line)) {
        i = 0;
        Utils::trim(line);
        if (line.size() == 0 || line[0] == '#')
            continue;

        stringstream s(line);
        getline(s, key, ' ');
        getline(s, value, ' ');

        int offset = 0;
        for (i = 0; i < num_items; i++)
        {
            if (key.compare(attested_items[i].name))
                offset += attested_items[i].len;
            else
                break;
        }
        if (i == num_items) {
            // not interested
            continue;
        }

        Item *item = &attested_items[i];
        if (item->type == NV_TYPE_CHAR ||
            item->type == NV_TYPE_LINE) {
            strncpy((char *)(pool + offset), (char *)&value[0], value.length());
        }
        else if (item->type == NV_TYPE_BOOL) {
            pool[offset] = value.compare("true") ? 0 : 1;
        }
        else if (item->type == NV_TYPE_INT) {
            int ival =  strtoul(value.c_str(), NULL, 10);
            int *iptr = (int *) &ival;
            memcpy((char *)(pool + offset), iptr, sizeof(int));
        }
        else if (item->type == NV_TYPE_BYTE) {
            char hex[3] = {'\0'};
            char *ptr = (char *)&value[0];
            for (uint32_t i = 0; i < item->len; i++)
            {
                memcpy(hex, ptr, 2);
                pool[offset + i] = (strtoul(hex, NULL, 16)) & 0xff;
                ptr += 2;
            }
        }
        else if (item->type == NV_TYPE_BLOCK) {
            char hex[3] = {'\0'};
            char *ptr = (char *)&value[0];
            for (size_t i = 0; i < value.length() / 2; i++)
            {
                memcpy(hex, ptr, 2);
                pool[offset + extra + i] = (strtoul(hex, NULL, 16)) & 0xff;
                ptr += 2;
            }
        }
        else {
            SD_LOG(LOG_ERR, "type: %d", item->type);
        }

        if (isMultiline(key))
            extra += (value.length() / 2);
        else
            extra = 0;
    }
    // dump((const uint8_t *)pool, num_items);
    // dump_hex_ascii((const uint8_t *)pool, total);

    return pool;
}
