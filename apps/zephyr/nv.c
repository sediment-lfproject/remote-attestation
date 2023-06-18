/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>

#include <zephyr.h>
#include <sys/printk.h>
#include <logging/log.h>
#include <drivers/flash.h>
#include <device.h>
#include <soc.h>
#include <stdlib.h>

#include "nv.h"

LOG_MODULE_REGISTER(app);

#define MAX_KEY_SIZE 2048

static const struct device *flash_device = DEVICE_DT_GET_OR_NULL(DT_CHOSEN(zephyr_flash_controller));

static off_t chunk_offset = 0;
static uint8_t rsa_key_buf[MAX_KEY_SIZE];

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
    { NV_MQTT_URL,         NV_OFFSET_MQTT_URL,         NV_LEN_MQTT_URL,         NV_TYPE_CHAR                },
    { NV_MQTT_PUB_TOPIC,   NV_OFFSET_MQTT_PUB_TOPIC,   NV_LEN_MQTT_PUB_TOPIC,   NV_TYPE_CHAR                },
    { NV_MQTT_SUB_TOPIC,   NV_OFFSET_MQTT_SUB_TOPIC,   NV_LEN_MQTT_SUB_TOPIC,   NV_TYPE_CHAR                },

    { NV_ENC_KEY,          NV_OFFSET_ENC_KEY,          NV_LEN_ENC_KEY,          NV_TYPE_BYTE                },
    { NV_ATTEST_KEY,       NV_OFFSET_ATTEST_KEY,       NV_LEN_ATTEST_KEY,       NV_TYPE_BYTE                },
    { NV_AUTH_KEY,         NV_OFFSET_AUTH_KEY,         NV_LEN_AUTH_KEY,         NV_TYPE_BYTE                },
    { NV_ATTEST_SQN,       NV_OFFSET_ATTEST_SQN,       NV_LEN_ATTEST_SQN,       NV_TYPE_INT                 },
    { NV_SEEC_SQN,         NV_OFFSET_SEEC_SQN,         NV_LEN_SEEC_SQN,         NV_TYPE_INT                 },

    { NV_PARAMS_SIZE,      NV_OFFSET_PARAMS_SIZE,      NV_LEN_PARAMS_SIZE,      NV_TYPE_INT                 },
    { NV_PARAMS,           NV_OFFSET_PARAMS,           NV_LEN_PARAMS,           NV_TYPE_BLOCK               },

    { NV_EURIPATH_SIZE,    NV_OFFSET_EURIPATH_SIZE,    NV_LEN_EURIPATH_SIZE,    NV_TYPE_INT                 },
    { NV_EURIPATH,         NV_OFFSET_EURIPATH,         NV_LEN_EURIPATH,         NV_TYPE_BLOCK               },

    { NV_SURIPATH_SIZE,    NV_OFFSET_SURIPATH_SIZE,    NV_LEN_SURIPATH_SIZE,    NV_TYPE_INT                 },
    { NV_SURIPATH,         NV_OFFSET_SURIPATH,         NV_LEN_SURIPATH,         NV_TYPE_BLOCK               },

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

int check_flash_device()
{
    if (flash_device == NULL) {
        printk("Flash device is unknown. Run set_device first.\n");
        return -ENODEV;
    }
    return 0;
}

int do_read(off_t offset, size_t len, uint8_t *buf)
{
    int ret;

    ret = check_flash_device();
    if (ret) {
        printk("null flash_device: %x\n", ret);
        return ret;
    }

    ret = flash_read(flash_device, offset, buf, len);
    if (ret) {
        printk("flash_read error: %d\n", ret);
    }

    return ret;
}

int do_erase(off_t offset, size_t size)
{
    int ret;

    ret = check_flash_device();
    if (ret) {
        printk("null flash_device: %x\n", ret);
        return ret;
    }

    /*
     *  ret = flash_write_protection_set(flash_device, 0);
     *  if (ret) {
     *      printk("Failed to disable flash protection (err: %d).\n", ret);
     *      return ret;
     *  }
     */
    ret = flash_erase(flash_device, offset, size);
    if (ret) {
        printk("flash_erase failed (err:%d).\n", ret);
    }

    return ret;
}

int do_write(off_t offset, size_t len, uint8_t *buf)
{
    int ret;

    ret = check_flash_device();
    if (ret) {
        printk("null flash_device: %x\n", ret);
        return ret;
    }

    //    ret = do_erase(offset, len);
    //    if (ret) {
    //        printk("flash erase failed (err:%d).\n", ret);
    //        return ret;
    //    }

    ret = flash_write(flash_device, offset, buf, len);
    if (ret) {
        printk("flash_write failed (err:%d): %0x %d.\n", ret, (uint32_t) buf, len);
    }

    return ret;
}

Item * get_item(const char *item_name)
{
    for (int i = 0; i < sizeof(flash_items) / sizeof(Item); i++) {
        if (!strcmp(item_name, flash_items[i].name)) {
            return &flash_items[i];
        }
    }
    printk("flash item not found: %s\n", item_name);

    return NULL;
}

static int is_block_start(Item *item)
{
    return (item != NULL &&
           (!strcmp(item->name, NV_PARAMS_SIZE) ||
           !strcmp(item->name, NV_EURIPATH_SIZE) ||
           !strcmp(item->name, NV_SURIPATH_SIZE) ||
           !strcmp(item->name, NV_TIMEPATH_SIZE) ||
           !strcmp(item->name, NV_SIGNKEY_SIZE) ||

           !strcmp(item->name, NV_RSA_PRIVATE_SIZE) ||
           !strcmp(item->name, NV_RSA_PUBLIC_SIZE) ||
           !strcmp(item->name, NV_RSA_SIGN_SIZE) ||
           !strcmp(item->name, NV_RSA_VERIFY_SIZE)
           ));
}

int read_item(const char *item_name, int buf_len, uint8_t *buf)
{
    Item *item = get_item(item_name);

    if (item == NULL) {
        return -1;
    }

    int len    = item->len;
    off_t addr = item->offset;

    if (addr < 0 || len <= 0 || buf_len < len) {
        printk("Offset or len not found or insufficient buffer: %s (%d, %d, %d)\n", item_name, (int) addr, len,
          buf_len);
        return -1;
    }

    int ret = do_read(addr, len, buf);
    if (ret) {
        printk("item read error: %s, %d\n", item_name, ret);
        return -1;
    }

    return 0;
}

int read_item_exact(const char *item_name, int buf_len, uint8_t *buf)
{
    Item *item = get_item(item_name);

    if (item == NULL) {
        return -1;
    }

    off_t addr = item->offset;

    int ret = do_read(addr, buf_len, buf);
    if (ret) {
        printk("item read error: %s, %d\n", item_name, ret);
        return -1;
    }

    return 0;
}

int write_item(char *item_name, int buf_len, uint8_t *buf)
{
    Item *item = get_item(item_name);

    if (item == NULL) {
        return -1;
    }

    char chunk = 0;
    int len    = item->len;
    off_t addr = item->offset;

    if (is_block_start(item)) {
        chunk_offset = 0;
        memset(rsa_key_buf, 0, MAX_KEY_SIZE);
    }
    else if (item->type == NV_TYPE_BLOCK) {
        chunk = 1;
        addr += chunk_offset;
        len   = buf_len;
    }
    else if (item->type == NV_TYPE_LINE) {
        // - GG block size is 4 and the written address needs to be multiples of 4,
        // - but each line of an RSA pem is not 4's multiples, it cannot be written line by line.
        // - zephyr shell cannot accept more than 200 chars.
        // So wait until the entire pem is received before writing to the flash.
        strcat(rsa_key_buf, buf);
        char *end = "-----END";
        if (strncmp(buf, end, strlen(end))) {
            return 0;
        }
        len = strlen(rsa_key_buf);
        if (len % NV_BLOCK_SIZE != 0) {
            int new_len = ((len / NV_BLOCK_SIZE) + 1) * NV_BLOCK_SIZE;
            printk("padded from %d to %d\n", len, new_len);
            len = new_len;
        }
        do_write(addr, len, rsa_key_buf);
        return 0;
    }

    if (addr < 0 || len <= 0 || buf_len < len) {
        printk("Offset or len not found or insufficient buffer: %s (%d, %d, %d, %d)\n",
          item_name, (int) addr, len, buf_len, item->type);
        return -1;
    }

    do_write(addr, buf_len, buf);

    if (chunk)
        chunk_offset += buf_len;

    return 0;
}
