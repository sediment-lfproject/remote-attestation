/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#include "Mqtt.hpp"
#include "PahoMqtt.hpp"
#include "StateMachine.hpp"
#include "Log.hpp"

using namespace std;

static mqtt::async_client *cli;
static mqtt::topic *top = NULL;
static callback *cb;
static mqtt::connect_options connOpts;

bool Mqtt::connect(string &url, string &id)
{
    cli = new mqtt::async_client(url, id);

    connOpts.set_clean_session(false);
    connOpts.set_user_name(id);
    connOpts.set_password(id);

    SD_LOG(LOG_INFO, "MQTT connecting %s/%s", id.c_str(), id.c_str());

    // Install the callback(s) before connecting.
    cb = new callback(*cli, connOpts, this);
    cli->set_callback(*cb);

    try {
        // cli->connect()->wait();
        cli->connect(connOpts, nullptr, *cb);

        return true;
    }
    catch (const mqtt::exception& exc) {
        SD_LOG(LOG_ERR, "MQTT::connect(): %s", exc.what());
        return false;
    }
}

void Mqtt::publish(char *message)
{
    try {
        if (!isConnected()) {
            SD_LOG(LOG_ERR, "can't publish to MQTT: not connected");
            return;
        }

        if (cb == NULL || !cb->isOk()) {
            SD_LOG(LOG_ERR, "can't publish to MQTT: null call back or call back not ready");
            return;
        }

        if (top == NULL)
            top = new mqtt::topic(*cli, topicPub, QOS);

        mqtt::token_ptr tok = top->publish(message);
        tok->wait(); // Just wait for the last one to complete.

        // SD_LOG(LOG_DEBUG, "MQTT published %s", message);
        SD_LOG(LOG_DEBUG, "MQTT published len=%d", strlen(message));
    }
    catch (const mqtt::exception& exc) {
        SD_LOG(LOG_ERR, "MQTT::publish(): %s", exc.what());
    }
}

void Mqtt::disconnect()
{
    try {
        cli->disconnect()->wait();
        SD_LOG(LOG_INFO, "MQTT disconnected");
    }
    catch (const mqtt::exception& exc) {
        SD_LOG(LOG_ERR, "MQTT::disconnect(): %s", exc.what());
        return;
    }
}

void Mqtt::handlePubData(char *data)
{
    machine->handlePubData(data);
}
