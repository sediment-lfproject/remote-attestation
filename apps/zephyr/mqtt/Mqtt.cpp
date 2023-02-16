/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_mqtt_publisher_sample, LOG_LEVEL_DBG);

#include <zephyr/zephyr.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/random/rand32.h>

#include <string.h>
#include <errno.h>

#include "Mqtt.hpp"
// #include "PahoMqtt.hpp"
#include "StateMachine.hpp"
#include "Log.hpp"

using namespace std;

#define APP_CONNECT_TIMEOUT_MS 2000
#define APP_SLEEP_MSECS        500

#define APP_CONNECT_TRIES      10
#define SERVER_PORT            1883
#define SERVER_ADDR            "10.139.80.148"

#define APP_MQTT_BUFFER_SIZE   128

#define MQTT_CLIENTID          "zephyr_publisher"

#if defined(CONFIG_USERSPACE)
#include <zephyr/app_memory/app_memdomain.h>
K_APPMEM_PARTITION_DEFINE(app_partition);
struct k_mem_domain app_domain;
#define APP_BMEM K_APP_BMEM(app_partition)
#define APP_DMEM K_APP_DMEM(app_partition)
#else
#define APP_BMEM
#define APP_DMEM
#endif

static APP_BMEM struct mqtt_client client_ctx;
static APP_BMEM struct zsock_pollfd fds[1];
static APP_BMEM int nfds;

static APP_BMEM bool connected;
static APP_BMEM struct sockaddr_storage broker;

/* Buffers for MQTT client. */
static APP_BMEM uint8_t rx_buffer[APP_MQTT_BUFFER_SIZE];
static APP_BMEM uint8_t tx_buffer[APP_MQTT_BUFFER_SIZE];

static void prepare_fds(struct mqtt_client *client)
{
    if (client->transport.type == MQTT_TRANSPORT_NON_SECURE) {
        fds[0].fd = client->transport.tcp.sock;
    }
#if defined(CONFIG_MQTT_LIB_TLS)
    else if (client->transport.type == MQTT_TRANSPORT_SECURE) {
        fds[0].fd = client->transport.tls.sock;
    }
#endif

    fds[0].events = ZSOCK_POLLIN;
    nfds = 1;
}

static void clear_fds(void)
{
    nfds = 0;
}

static int wait(int timeout)
{
    int ret = 0;

    if (nfds > 0) {
        ret = zsock_poll(fds, nfds, timeout);
        if (ret < 0) {
            LOG_ERR("poll error: %d", errno);
        }
    }

    return ret;
}

void mqtt_evt_handler(struct mqtt_client *const client,
  const struct mqtt_evt *                       evt)
{
    int err;

    switch (evt->type) {
    case MQTT_EVT_CONNACK:
        if (evt->result != 0) {
            LOG_ERR("MQTT connect failed %d", evt->result);
            break;
        }

        connected = true;
        LOG_INF("MQTT client connected!");

        break;

    case MQTT_EVT_DISCONNECT:
        LOG_INF("MQTT client disconnected %d", evt->result);

        connected = false;
        clear_fds();

        break;

    case MQTT_EVT_PUBACK:
        if (evt->result != 0) {
            LOG_ERR("MQTT PUBACK error %d", evt->result);
            break;
        }

        LOG_INF("PUBACK packet id: %u", evt->param.puback.message_id);

        break;

    case MQTT_EVT_PUBREC:
        if (evt->result != 0) {
            LOG_ERR("MQTT PUBREC error %d", evt->result);
            break;
        }

        LOG_INF("PUBREC packet id: %u", evt->param.pubrec.message_id);

        //        const struct mqtt_pubrel_param rel_param = {
        //            .message_id = evt->param.pubrec.message_id
        //        };
        //
        //        err = mqtt_publish_qos2_release(client, &rel_param);
        if (err != 0) {
            LOG_ERR("Failed to send MQTT PUBREL: %d", err);
        }

        break;

    case MQTT_EVT_PUBCOMP:
        if (evt->result != 0) {
            LOG_ERR("MQTT PUBCOMP error %d", evt->result);
            break;
        }

        LOG_INF("PUBCOMP packet id: %u",
          evt->param.pubcomp.message_id);

        break;

    case MQTT_EVT_PINGRESP:
        LOG_INF("PINGRESP packet");
        break;

    default:
        break;
    }
}

static void broker_init(void)
{
#if defined(CONFIG_NET_IPV6)
    struct sockaddr_in6 *broker6 = (struct sockaddr_in6 *) &broker;

    broker6->sin6_family = AF_INET6;
    broker6->sin6_port   = htons(SERVER_PORT);
    zsock_inet_pton(AF_INET6, SERVER_ADDR, &broker6->sin6_addr);

#if defined(CONFIG_SOCKS)
    struct sockaddr_in6 *proxy6 = (struct sockaddr_in6 *) &socks5_proxy;

    proxy6->sin6_family = AF_INET6;
    proxy6->sin6_port   = htons(SOCKS5_PROXY_PORT);
    zsock_inet_pton(AF_INET6, SOCKS5_PROXY_ADDR, &proxy6->sin6_addr);
#endif
#else // if defined(CONFIG_NET_IPV6)
    struct sockaddr_in *broker4 = (struct sockaddr_in *) &broker;

    broker4->sin_family = AF_INET;
    broker4->sin_port   = htons(SERVER_PORT);
    zsock_inet_pton(AF_INET, SERVER_ADDR, &broker4->sin_addr);
#if defined(CONFIG_SOCKS)
    struct sockaddr_in *proxy4 = (struct sockaddr_in *) &socks5_proxy;

    proxy4->sin_family = AF_INET;
    proxy4->sin_port   = htons(SOCKS5_PROXY_PORT);
    zsock_inet_pton(AF_INET, SOCKS5_PROXY_ADDR, &proxy4->sin_addr);
#endif
#endif // if defined(CONFIG_NET_IPV6)
}

static void client_init(struct mqtt_client *client)
{
    mqtt_client_init(client);

    broker_init();

    /* MQTT client configuration */
    client->broker           = &broker;
    client->evt_cb           = mqtt_evt_handler;
    client->client_id.utf8   = (uint8_t *) MQTT_CLIENTID;
    client->client_id.size   = strlen(MQTT_CLIENTID);
    client->password         = NULL;
    client->user_name        = NULL;
    client->protocol_version = MQTT_VERSION_3_1_1;

    /* MQTT buffers configuration */
    client->rx_buf      = rx_buffer;
    client->rx_buf_size = sizeof(rx_buffer);
    client->tx_buf      = tx_buffer;
    client->tx_buf_size = sizeof(tx_buffer);

    /* MQTT transport configuration */
#if defined(CONFIG_MQTT_LIB_TLS)
#if defined(CONFIG_MQTT_LIB_WEBSOCKET)
    client->transport.type = MQTT_TRANSPORT_SECURE_WEBSOCKET;
#else
    client->transport.type = MQTT_TRANSPORT_SECURE;
#endif

    struct mqtt_sec_config *tls_config = &client->transport.tls.config;

    tls_config->peer_verify   = TLS_PEER_VERIFY_REQUIRED;
    tls_config->cipher_list   = NULL;
    tls_config->sec_tag_list  = m_sec_tags;
    tls_config->sec_tag_count = ARRAY_SIZE(m_sec_tags);
#if defined(MBEDTLS_X509_CRT_PARSE_C) || defined(CONFIG_NET_SOCKETS_OFFLOAD)
    tls_config->hostname = TLS_SNI_HOSTNAME;
#else
    tls_config->hostname = NULL;
#endif

#else // if defined(CONFIG_MQTT_LIB_TLS)
#if defined(CONFIG_MQTT_LIB_WEBSOCKET)
    client->transport.type = MQTT_TRANSPORT_NON_SECURE_WEBSOCKET;
#else
    client->transport.type = MQTT_TRANSPORT_NON_SECURE;
#endif
#endif // if defined(CONFIG_MQTT_LIB_TLS)

#if defined(CONFIG_MQTT_LIB_WEBSOCKET)
    client->transport.websocket.config.host        = SERVER_ADDR;
    client->transport.websocket.config.url         = "/mqtt";
    client->transport.websocket.config.tmp_buf     = temp_ws_rx_buf;
    client->transport.websocket.config.tmp_buf_len =
      sizeof(temp_ws_rx_buf);
    client->transport.websocket.timeout = 5 * MSEC_PER_SEC;
#endif

#if defined(CONFIG_SOCKS)
    mqtt_client_set_proxy(client, &socks5_proxy,
      socks5_proxy.sa_family == AF_INET ?
      sizeof(struct sockaddr_in) :
      sizeof(struct sockaddr_in6));
#endif
}

bool Mqtt::connect(string &url, string &id)
{
    int rc, i = 0;

    while (i++ < APP_CONNECT_TRIES && !connected) {
        printk("mqtt connecting \n");
        client_init(&client_ctx);

        rc = mqtt_connect(&client_ctx);
        if (rc != 0) {
            printk("mqtt_connect failed: %d\n", rc);
            k_sleep(K_MSEC(APP_SLEEP_MSECS));
            continue;
        }
        prepare_fds(&client_ctx);

        if (wait(APP_CONNECT_TIMEOUT_MS)) {
            mqtt_input(&client_ctx);
        }

        if (!connected) {
            mqtt_abort(&client_ctx);
        }
    }

    if (connected) {
        printk("mqtt_connected\n");
        return true;
    }

    return false;
}

void Mqtt::publish(char *message)
{
    struct mqtt_publish_param param;

    param.message.topic.qos        = MQTT_QOS_0_AT_MOST_ONCE;
    param.message.topic.topic.utf8 = (uint8_t *) "sensor";
    param.message.topic.topic.size = strlen((char *) param.message.topic.topic.utf8);
    param.message.payload.data     = (uint8_t *) message;
    param.message.payload.len      = strlen((char *) param.message.payload.data);
    param.message_id  = sys_rand32_get();
    param.dup_flag    = 0U;
    param.retain_flag = 0U;

    mqtt_publish(&client_ctx, &param);

    printk("publish %s\n", message);
}

void Mqtt::disconnect()
{
    int rc = mqtt_disconnect(&client_ctx);

    printk("mqtt_disconnect: %d", rc);
}

void Mqtt::handlePubData(char *data)
{
    machine->handlePubData(data);
}
