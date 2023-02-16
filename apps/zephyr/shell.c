/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 */
#include <logging/log.h>
LOG_MODULE_REGISTER(net_echo_server_sample, LOG_LEVEL_DBG);

#include <zephyr.h>
#include <linker/sections.h>
#include <errno.h>
#include <shell/shell.h>
#include <drivers/flash.h>
#include <sys/reboot.h>

#include <stdlib.h>

// #include "common.h"
#include "nv.h"

#define PR_SHELL(shell, fmt, ...)                \
        shell_fprintf(shell, SHELL_NORMAL, fmt, ## __VA_ARGS__)
#define PR_ERROR(shell, fmt, ...)                \
        shell_fprintf(shell, SHELL_ERROR, fmt, ## __VA_ARGS__)
#define PR_INFO(shell, fmt, ...)                \
        shell_fprintf(shell, SHELL_INFO, fmt, ## __VA_ARGS__)
#define PR_WARNING(shell, fmt, ...)                \
        shell_fprintf(shell, SHELL_WARNING, fmt, ## __VA_ARGS__)

/* Command usage info. */
#define READ_HELP \
        ("[ enc_key | attest_key | ... ] - Read the specified settings.")
#define WRITE_HELP \
        ("[ enc_key | attest_key | ... ] value - Write the specified settings.")

// static void quit(void)
// {
////    k_sem_give(&quit_lock);
// }

static int cmd_reset(const struct shell *shell, size_t argc, char *argv[])
{
    LOG_INF("Resetting device");
    sys_reboot(SYS_REBOOT_COLD);

    return 0;
}

static void flash_dump(Item *item, uint8_t *buf, int buf_size)
{
    if (item->type == NV_TYPE_BYTE) {
        printk("\n%s: ", item->name);
        for (int i = 0; i < buf_size; i++) {
            printk("%02X ", buf[i]);
        }
        printk("\n");
    }
    else if (item->type == NV_TYPE_BLOCK) {
        printk("\n%s: ", item->name);
        for (int i = 0; i < buf_size; i++) {
            printk("%02X ", buf[i]);
        }
        printk("\n");
    }
    else if (item->type == NV_TYPE_CHAR || item->type == NV_TYPE_LINE) {
        printk("\n%s: %s\n", item->name, (char *) buf);
    }
    else if (item->type == NV_TYPE_BOOL) {
        printk("\n%s: %s\n", item->name, *buf == 0 ? "false" : "true");
    }
    else if (item->type == NV_TYPE_INT) {
        int *iptr = (int *) buf;
        printk("\n%s: %d\n", item->name, *iptr);
    }
    else {
        printk("bad NV item type: %d\n", item->type);
    }
}

static int cmd_flash_read(const struct shell *shell, size_t argc, char *argv[])
{
    if (argc < 2) {
        PR_ERROR(shell, "Please specify the key to read.\n");
        return -1;
    }

    Item *item = get_item(argv[1]);
    if (item == NULL)
        return -1;

    int len = item->len;
    uint8_t buf[len];
    int ret = read_item(argv[1], len, buf);
    if (ret) {
        PR_ERROR(shell, "Key read error: %s, %d\n", argv[1], ret);
        return -1;
    }
    flash_dump(item, buf, sizeof(buf));

    return 0;
}

static int cmd_flash_write(const struct shell *shell, size_t argc, char *argv[])
{
    if (argc < 3) {
        PR_ERROR(shell, "Please specify the key type and key to write.\n");
        return -1;
    }

    Item *item = get_item(argv[1]);
    if (item == NULL)
        return -1;

    int len    = item->len;
    int padded = 0;
    if (item->type == NV_TYPE_BLOCK) {
        len = strlen(argv[2]) / 2;
        if ((len % NV_BLOCK_SIZE) != 0) {
            int new_len = ((len / NV_BLOCK_SIZE) + 1) * NV_BLOCK_SIZE;
            padded = new_len - len; // needed to adjust offset in NV_TYPE_LINE
            PR_WARNING(shell, "not multiples of block size: %d; padded to %d\n", len, new_len);
            len = new_len;
        }
    }
    else if (item->type == NV_TYPE_LINE) {
        len = strlen(argv[2]);
    }

    char buf[len];
    if (item->type == NV_TYPE_BYTE) {
        if (strlen(argv[2]) != len * 2) {
            PR_ERROR(shell, "incorrect value length, need %d bytes, got %d\n", len * 2, strlen(argv[2]));
            return -1;
        }
        char hex[3] = { '\0' };
        char *ptr   = argv[2];
        for (int i = 0; i < len; i++) {
            memcpy(hex, ptr, 2);
            buf[i] = (strtoul(hex, NULL, 16)) & 0xff;
            ptr   += 2;
        }
    }
    else if (item->type == NV_TYPE_BLOCK) {
        char hex[3] = { '\0' };
        char *ptr   = argv[2];
        for (int i = 0; i < len; i++) {
            memcpy(hex, ptr, 2);
            buf[i] = (strtoul(hex, NULL, 16)) & 0xff;
            ptr   += 2;
        }
    }
    else if (item->type == NV_TYPE_CHAR || item->type == NV_TYPE_LINE) {
        memset(buf, 0, len);
        strcpy(buf, argv[2]);
    }
    else if (item->type == NV_TYPE_BOOL) {
        buf[0] = strcmp(argv[2], "true") ? 0 : 1;
    }
    else if (item->type == NV_TYPE_INT) {
        int *iptr = (int *) buf;
        *iptr = strtoul(argv[2], NULL, 10);
    }
    else {
        printk("invalid flash item type: %d\n", item->type);
        return -1;
    }
    write_item(argv[1], len, buf);

    return 0;
}

static int cmd_flash_erase(const struct shell *shell, size_t argc, char *argv[])
{
    //    Item *item = get_item(NV_MAGIC);
    //    if (item == NULL)
    //        return -1;

    uint32_t offset = 0;

    if (!strcmp(argv[1], NV_WKD_IBE_PAGE)) {
        offset = NV_FLASH_OFFSET;
    }
    else if (!strcmp(argv[1], NV_RA_PAGE)) {
        offset = NV_RA_OFFSET;
    }
    else if (!strcmp(argv[1], NV_RSA_PAGE)) {
        if (!NV_SPLIT_PAGES) // RSA and RSA2 are in the same page with WKD
            return 0;        // it should have been erased in "erase wkd"

        offset = NV_RSA_OFFSET;
    }
    else if (!strcmp(argv[1], NV_RSA2_PAGE)) {
        if (!NV_SPLIT_PAGES)
            return 0;

        offset = NV_RSA2_OFFSET;
    }
    else {
        PR_ERROR(shell, "unrecognized pages: %s, choose among [%s | %s | %s | %s]\n",
          argv[2], NV_WKD_IBE_PAGE, NV_RA_PAGE, NV_RSA_PAGE, NV_RSA2_PAGE);
        return -1;
    }

    int ret = do_erase(offset, NV_PAGE_SIZE);
    if (ret) {
        PR_ERROR(shell, "erase error: %d\n", ret);
        return -1;
    }

    return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sediment_commands,
  SHELL_CMD_ARG(read, NULL, READ_HELP, cmd_flash_read, 2, 0),
  SHELL_CMD_ARG(write, NULL, WRITE_HELP, cmd_flash_write, 3, 0),
  SHELL_CMD_ARG(erase, NULL, "erase the flash page", cmd_flash_erase, 2, 0),
  SHELL_CMD(reset, NULL, "reset the device", cmd_reset),
  SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(sediment, &sediment_commands, "SEDIMENT commands", NULL);
