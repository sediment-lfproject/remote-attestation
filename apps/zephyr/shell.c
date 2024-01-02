/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 *
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */#include <logging/log.h>
LOG_MODULE_REGISTER(net_echo_server_sample, LOG_LEVEL_DBG);

#include <zephyr.h>
#include <linker/sections.h>
#include <errno.h>
#include <shell/shell.h>
#include <drivers/flash.h>
#include <sys/reboot.h>

#include <stdlib.h>
// #include <unistd.h>
#include <net/socket.h>

#include <net/net_core.h>
#include <net/tls_credentials.h>

#include <pb_encode.h>
#include <pb_decode.h>

#include "provision.pb.h"

#include "nv.h"

static bool dispatch_message(uint8_t *buffer, size_t message_length)
{
	bool status = false;

    // work around the limitation that nanopb does not handle string callbacks for oneof. 
    // add the message tag at the front of the send buffer
    switch(buffer[0]) {
    case provision_ProvisionMessage_sediment_page_tag:
        printk("sediment\n");
        status = erase_and_write(NV_SEDIMENT_PAGE, buffer, message_length);
        break;
    case provision_ProvisionMessage_sqn_page_tag:
        printk("sqn\n");
        status = erase_and_write(NV_SQN_PAGE, buffer, message_length);
        break;
    case provision_ProvisionMessage_wkd_ibe_page1_tag:
        printk("wkd ibe 1\n");
        status = erase_and_write(NV_SEEC_PAGE_1, buffer, message_length);
        break;
    case provision_ProvisionMessage_wkd_ibe_page2_tag:
        printk("wkd ibe 2\n");
        status = erase_and_write(NV_SEEC_PAGE_2, buffer, message_length);
        break;
    case provision_ProvisionMessage_quit_tag:
        printk("quit\n");
        return false;
    default:
        printk("unknown message: %d\n", buffer[0]);
        break;
    }

	return status;
}

static int cmd_provision(const struct shell *shell, size_t argc, char *argv[])
{
    int sock = conn_to_provisioner(argv[1], strtoul(argv[2], NULL, 10));
    if (sock < 0)
        return -1;

    const int MESSAGE_BUF_SIZE = 4096;
    uint8_t buf[MESSAGE_BUF_SIZE];

    int expected = 0;
    int received = 0;
    char *ptr    = (char *) buf;
    int avail    = MESSAGE_BUF_SIZE;

    while (true) {
        int bytesRead = recv(sock, ptr, avail, 0);
        if (bytesRead <= 0) {
            break;
        }
        if (expected == 0 && bytesRead >= 3) {
            expected =  (buf[1] | (buf[2] << 8)) + 3;
        }
        received += bytesRead;
        if (expected == 0 || received < expected) {
            ptr   += bytesRead;
            avail -= bytesRead;
            continue;
        }

        int status = dispatch_message(buf, expected);
        if (!status) {
            close(sock);
            return 0;
        }
        int remain = received - expected;
        memcpy(buf, &buf[received], remain);
        ptr = &buf[remain];
        avail = MESSAGE_BUF_SIZE - remain;
        expected = 0;
        received = remain;
    }
    return 0;
}

static int cmd_log(const struct shell *shell, size_t argc, char *argv[])
{
    int console_log = strtoul(argv[1], NULL, 10);
    if (console_log < 0 || console_log > 6) {
        printk("log level range is [0-6]\n");
        return -1;
    }
    set_log_level(console_log);
    
    return 0;
}

static int cmd_suspend(const struct shell *shell, size_t argc, char *argv[])
{
    bool suspend = strtoul(argv[1], NULL, 10) ? true : false;
    set_suspend(suspend);
    
    return 0;
}

static int cmd_clear_sqn(const struct shell *shell, size_t argc, char *argv[])
{
    save_sqn(SQN_CLEAR, 0);
    return 0;
}

static int cmd_show(const struct shell *shell, size_t argc, char *argv[])
{
    show_flash();
    return 0;
}

static int cmd_reset(const struct shell *shell, size_t argc, char *argv[])
{
    LOG_INF("Resetting device");
    sys_reboot(SYS_REBOOT_COLD);

    return 0;
}

#if defined(SIMULATED_UDP_ATTACK)
static void cmd_attack(const struct shell *shell, size_t argc, char *argv[])
{
    char *addr = argv[1];
    int port = strtoul(argv[2], NULL, 10);
    int count = strtoul(argv[3], NULL, 10);
    int delay = strtoul(argv[4], NULL, 10);
    int payloadSize = strtoul(argv[5], NULL, 10);

	int ret;

	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		printk("Failed to create UDP socket (%s:%d): %d", addr, port, errno);
		return;
	}
    struct sockaddr_in addr4;
    addr4.sin_family = AF_INET;                                                   
    addr4.sin_port = htons(port);                                            
    inet_pton(AF_INET, addr, &addr4.sin_addr); 

    ret = connect(sock, (struct sockaddr *) &addr4, sizeof(addr4));
	if (ret < 0) {
		printk("Cannot connect to UDP remote (%s): %d", addr, errno);
		ret = -errno;
	}

    // const int LEN = 32;
    char data[payloadSize];
    memset(data, '\0', payloadSize);

    int sent_count = 0;
    while (true) {
        ret = send(sock, data, payloadSize, 0);
        sent_count++;
        printk("[%d] Sent %d bytes\n", sent_count, payloadSize);
        if (sent_count >= count && count > 0)
            break;
        k_sleep(K_MSEC(delay));
    }
}
#endif

SHELL_STATIC_SUBCMD_SET_CREATE(sediment_commands,
  SHELL_CMD(show, NULL, "Show configurations", cmd_show),
  SHELL_CMD(clear_sqn, NULL, "reset SQN's to initial values", cmd_clear_sqn),
  SHELL_CMD_ARG(provision, NULL, "<server IP> <server port> - Provision a device.", cmd_provision, 3, 0),
  SHELL_CMD(reset, NULL, "reset the device", cmd_reset),
  SHELL_CMD_ARG(log, NULL, "<log level [0-6]> - Set log level.", cmd_log, 2, 0),
  SHELL_CMD_ARG(suspend, NULL, "[0 | 1] - Suspend(0) or Resume(1).", cmd_suspend, 2, 0),
#if defined(SIMULATED_UDP_ATTACK)
  SHELL_CMD_ARG(attack, NULL, "<server IP> <server port> <count> <delay in ms> <payload in bytes> - Send UDP attack traffic.", cmd_attack, 6, 0),
#endif
  SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(sediment, &sediment_commands, "SEDIMENT commands", NULL);
