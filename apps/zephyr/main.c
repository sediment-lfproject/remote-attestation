/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 *
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */
#include <logging/log.h>
LOG_MODULE_REGISTER(_, LOG_LEVEL_DBG);

#include <zephyr.h>
#include <linker/sections.h>
#include <errno.h>
#include <shell/shell.h>
#include <drivers/flash.h>
#include <sys/reboot.h>

#include <stdlib.h>

#include <net/net_core.h>
#include <net/tls_credentials.h>

#include <net/net_mgmt.h>
#include <net/net_event.h>
#include <net/net_conn_mgr.h>

#include "common.h"

#define APP_BANNER "Peraton Labs SEDIMENT"

static struct k_sem quit_lock;
static struct net_mgmt_event_callback mgmt_cb;
static bool connected;
K_SEM_DEFINE(run_app, 0, 1);
static bool want_to_quit;

#if defined(CONFIG_USERSPACE)
K_APPMEM_PARTITION_DEFINE(app_partition);
struct k_mem_domain app_domain;
#endif

void set_lte_ready();

#define EVENT_MASK (NET_EVENT_L4_CONNECTED | NET_EVENT_L4_DISCONNECTED)

APP_DMEM struct configs conf = {
    .ipv4      = {
        .proto = "IPv4",
    },
    .ipv6      = {
        .proto = "IPv6",
    },
};

void quit(void)
{
    k_sem_give(&quit_lock);
}

#if 0
static void start_udp_and_tcp(void)
{
    LOG_INF("Starting...");

    if (IS_ENABLED(CONFIG_NET_TCP)) {
        start_tcp();
    }

    if (IS_ENABLED(CONFIG_NET_UDP)) {
        start_udp();
    }
}

static void stop_udp_and_tcp(void)
{
    LOG_INF("Stopping...");

    if (IS_ENABLED(CONFIG_NET_UDP)) {
        stop_udp();
    }

    if (IS_ENABLED(CONFIG_NET_TCP)) {
        stop_tcp();
    }
}

#endif /* if 0 */

static void event_handler(struct net_mgmt_event_callback *cb,
  uint32_t mgmt_event, struct net_if *iface)
{
    if ((mgmt_event & EVENT_MASK) != mgmt_event) {
        return;
    }

    if (want_to_quit) {
        k_sem_give(&run_app);
        want_to_quit = false;
    }

    if (is_tunnel(iface)) {
        /* Tunneling is handled separately, so ignore it here */
        return;
    }

    if (mgmt_event == NET_EVENT_L4_CONNECTED) {
        printk("Network connected\n");

        connected = true;
        k_sem_give(&run_app);

        return;
    }

    if (mgmt_event == NET_EVENT_L4_DISCONNECTED) {
        if (connected == false) {
            printk("Waiting network to be connected\n");
        }
        else {
            printk("Network disconnected\n");
            connected = false;
        }

        k_sem_reset(&run_app);

        return;
    }
}

static void init_app(void)
{
#if defined(CONFIG_USERSPACE)
    struct k_mem_partition *parts[] = {
#if Z_LIBC_PARTITION_EXISTS
        &z_libc_partition,
#endif
        &app_partition
    };

    k_mem_domain_init(&app_domain, ARRAY_SIZE(parts), parts);
#endif

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS) || \
    defined(CONFIG_MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
    int err;
#endif

    k_sem_init(&quit_lock, 0, K_SEM_MAX_LIMIT);

    printk("%s\n", APP_BANNER);

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
#if defined(CONFIG_NET_SAMPLE_CERTS_WITH_SC)
    err = tls_credential_add(SERVER_CERTIFICATE_TAG,
        TLS_CREDENTIAL_CA_CERTIFICATE,
        ca_certificate,
        sizeof(ca_certificate));
    if (err < 0) {
        LOG_ERR("Failed to register CA certificate: %d", err);
    }
#endif

    err = tls_credential_add(SERVER_CERTIFICATE_TAG,
        TLS_CREDENTIAL_SERVER_CERTIFICATE,
        server_certificate,
        sizeof(server_certificate));
    if (err < 0) {
        LOG_ERR("Failed to register public certificate: %d", err);
    }


    err = tls_credential_add(SERVER_CERTIFICATE_TAG,
        TLS_CREDENTIAL_PRIVATE_KEY,
        private_key, sizeof(private_key));
    if (err < 0) {
        LOG_ERR("Failed to register private key: %d", err);
    }
#endif /* if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS) */

#if defined(CONFIG_MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
    err = tls_credential_add(PSK_TAG,
        TLS_CREDENTIAL_PSK,
        psk,
        sizeof(psk));
    if (err < 0) {
        LOG_ERR("Failed to register PSK: %d", err);
    }
    err = tls_credential_add(PSK_TAG,
        TLS_CREDENTIAL_PSK_ID,
        psk_id,
        sizeof(psk_id) - 1);
    if (err < 0) {
        LOG_ERR("Failed to register PSK ID: %d", err);
    }
#endif /* if defined(CONFIG_MBEDTLS_KEY_EXCHANGE_PSK_ENABLED) */

    if (IS_ENABLED(CONFIG_NET_CONNECTION_MANAGER)) {
        net_mgmt_init_event_callback(&mgmt_cb, event_handler, EVENT_MASK);
        net_mgmt_add_event_callback(&mgmt_cb);
        net_conn_mgr_resend_status();
    }

    //    init_vlan();
    //    init_tunnel();
}

void main(void)
{
    init_app();

    if (!IS_ENABLED(CONFIG_NET_CONNECTION_MANAGER)) {
        /* If the config library has not been configured to start the
         * app only after we have a connection, then we can start
         * it right away.
         */
        k_sem_give(&run_app);
    }

    /* Wait for the connection. */
    k_sem_take(&run_app, K_FOREVER);

    k_msleep(5000); // wait for DHCP server
    set_lte_ready();

    k_sem_take(&quit_lock, K_FOREVER);

    if (connected) {
        //        stop_udp_and_tcp();
    }
}
