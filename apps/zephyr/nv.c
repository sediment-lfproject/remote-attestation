/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 *
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
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
