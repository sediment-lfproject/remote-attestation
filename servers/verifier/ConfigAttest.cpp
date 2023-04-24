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

using std::filesystem::exists;

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

    { NV_RSA_PRIVATE_SIZE, NV_OFFSET_RSA_PRIVATE_SIZE, NV_LEN_RSA_PRIVATE_SIZE, NV_TYPE_INT                 },
    { NV_RSA_PRIVATE,      NV_OFFSET_RSA_PRIVATE,      NV_LEN_RSA_PRIVATE,      NV_TYPE_LINE                },

    { NV_RSA_PUBLIC_SIZE,  NV_OFFSET_RSA_PUBLIC_SIZE,  NV_LEN_RSA_PUBLIC_SIZE,  NV_TYPE_INT                 },
    { NV_RSA_PUBLIC,       NV_OFFSET_RSA_PUBLIC,       NV_LEN_RSA_PUBLIC,       NV_TYPE_LINE                },

    { NV_RSA_SIGN_SIZE,    NV_OFFSET_RSA_SIGN_SIZE,    NV_LEN_RSA_SIGN_SIZE,    NV_TYPE_INT                 },
    { NV_RSA_SIGN,         NV_OFFSET_RSA_SIGN,         NV_LEN_RSA_SIGN,         NV_TYPE_LINE                },

    { NV_RSA_VERIFY_SIZE,  NV_OFFSET_RSA_VERIFY_SIZE,  NV_LEN_RSA_VERIFY_SIZE,  NV_TYPE_INT                 },
    { NV_RSA_VERIFY,       NV_OFFSET_RSA_VERIFY,       NV_LEN_RSA_VERIFY,       NV_TYPE_LINE                },

    { NV_DOWNLOAD,         NV_OFFSET_DOWNLOAD,         NV_LEN_DOWNLOAD,         NV_TYPE_INT                 },
    { NV_DATA_TRANSPORT,   NV_OFFSET_DATA_TRANSPORT,   NV_LEN_DATA_TRANSPORT,   NV_TYPE_CHAR                },
    { NV_LOG_LEVEL,        NV_OFFSET_LOG_LEVEL,        NV_LEN_LOG_LEVEL,        NV_TYPE_INT                 },
};

std::vector<int> vec;

void dump(const uint8_t *data, int num_items)
{
    int offset = 0;
    for (int i = 0; i < num_items; i++)
    {
        int start = offset;
        int end = offset + flash_items[i].len;
        
        printf("%s ", flash_items[i].name);
        for (int j = start; j < end; j++) 
        {
            printf("%c", isprint(data[j]) ? data[j] : '.');
        }
        printf("\n");

        for (int j = start; j < end; j++) 
        {
            printf("%02x", data[j]);
        }
        printf("\n\n");

        offset += flash_items[i].len;
    }
}

void dump_hex_ascii(const uint8_t *data, size_t size)
{
	char ascii[17];
	size_t i, j;

	ascii[16] = '\0';

	printf("\n");
	printf("0  1  2  3  4  5  6  7   8  9  A  B  C  D  E  F\n");

	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char *)data)[i]);

		ascii[i % 16] = isprint(data[i]) ? data[i] : '.';

		if ((i + 1) % 8 == 0 || i + 1 == size) {
			printf(" ");
			if ((i + 1) % 16 == 0) {
				printf("|  %s\n", ascii);
			} else if ((i + 1) == size) {
				ascii[(i + 1) % 16] = '\0';

				if ((i + 1) % 16 <= 8) {
					printf(" ");
				}

				for (j = (i + 1) % 16; j < 16; ++j) {
					printf("   ");
				}
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

bool isNotInterested(string key)
{
    return !(key.compare(NV_ENCRYPTKEY) &&
           key.compare(NV_ENCRYPTKEY_SIZE) &&
           key.compare(NV_FW_SCRIPT) &&
           key.compare(NV_LOG_LEVEL) &&
           key.compare(NV_DATA_TRANSPORT) &&
           key.compare(NV_DOWNLOAD));
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
    int total_items = sizeof(flash_items) / sizeof(Item);
    int num_items = total_items;
    for (int i = 0; i < total_items; i++)
    {
        total += flash_items[i].len;
        if (!strcmp(flash_items[i].name, NV_SIGNKEY)) {
            num_items = i + 1;
            break;
        }
    }
    *size = total;
    // std::cout << " Total Siz = " << *size << std::endl;

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
            if (key.compare(flash_items[i].name))
                offset += flash_items[i].len;
            else
                break;
        }
        if (i == num_items) {
            if (!isNotInterested(key))
                SD_LOG(LOG_ERR, "not found: %s", key.c_str());
            continue;
            // break;
        }
        vec.push_back(offset);
        // printf("%20s %s %d %d\n", key.c_str(), value.c_str(), flash_items[i].len, offset);

        Item *item = &flash_items[i];
        if (item->type == NV_TYPE_CHAR ||
            item->type == NV_TYPE_LINE) {
            strncpy((char *)(pool + offset), (char *)&value[0], value.length());
        }
        else if (item->type == NV_TYPE_BOOL) {
            pool[offset] = strcmp(value.c_str(), "true") ? 0 : 1;
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
    dump((const uint8_t *)pool, num_items);
    dump_hex_ascii((const uint8_t *)pool, total);

    return pool;
}
