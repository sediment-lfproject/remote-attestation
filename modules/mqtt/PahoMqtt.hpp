/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once

#include "mqtt/async_client.h"

#include "Log.hpp"
#include "Mqtt.hpp"

const int N_RETRY_ATTEMPTS = 5;
const int QOS = 1;

class action_listener : public virtual mqtt::iaction_listener
{
    std::string name_;

    void on_failure(const mqtt::token& tok) override
    {
        SD_LOG(LOG_ERR, "%s failed for token: [%d]", name_.c_str(), tok.get_message_id());
    }

    void on_success(const mqtt::token& tok) override
    {
        SD_LOG(LOG_DEBUG, "%s succeeded for token: [%d]", name_.c_str(), tok.get_message_id());

        auto top = tok.get_topics();
        if (top && !top->empty())
            SD_LOG(LOG_DEBUG, "topic: %s ", ((*top)[0]).c_str());
    }

public:
    action_listener(const std::string& name) : name_(name)
    { }
};

/**
 * Local callback & listener class for use with the client connection.
 * This is primarily intended to receive messages, but it will also monitor
 * the connection to the broker. If the connection is lost, it will attempt
 * to restore the connection and re-subscribe to the topic.
 */
class callback : public virtual mqtt::callback
    , public virtual mqtt::iaction_listener
{
    int nretry_;                      // Counter for the number of connection retries
    mqtt::async_client& cli_;         // The MQTT client
    mqtt::connect_options& connOpts_; // Options to use if we need to reconnect
    action_listener subListener_;     // An action listener to display the result of actions.
    Mqtt *mqtt;
    bool ok = false;

    // This deomonstrates manually reconnecting to the broker by calling
    // connect() again. This is a possibility for an application that keeps
    // a copy of it's original connect_options, or if the app wants to
    // reconnect with different options.
    // Another way this can be done manually, if using the same options, is
    // to just call the async_client::reconnect() method.
    void reconnect()
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));
        try {
            cli_.connect(connOpts_, nullptr, *this);
        }
        catch (const mqtt::exception& exc) {
            SD_LOG(LOG_ERR, "%s", exc.what());
        }
    }

    void on_failure(const mqtt::token& tok) override
    {
        (void) tok;
        ok = false;
        SD_LOG(LOG_ERR, "MQTT Connection attempt #%d failed", nretry_);

        if (++nretry_ > N_RETRY_ATTEMPTS)
            return;

        reconnect();
    }

    // Either this or connected() can be used for callbacks.
    void on_success(const mqtt::token& tok) override
    {
        (void) tok;
    }

    void connected(const std::string& cause) override
    {
        (void) cause;
        ok = true;

        SD_LOG(LOG_INFO, "MQTT connected");
        if (!mqtt->getTopicPub().empty()) {
            SD_LOG(LOG_INFO, "publish to %s", mqtt->getTopicPub().c_str());
        }

        if (!mqtt->getTopicSub().empty()) {
            cli_.subscribe(mqtt->getTopicSub(), QOS, nullptr, subListener_);
            SD_LOG(LOG_INFO, "subscrib to %s with QOS %d", mqtt->getTopicSub().c_str(), QOS);
        }
    }

    void connection_lost(const std::string& cause) override
    {
        SD_LOG(LOG_ERR, "MQTT connection lost: %s", !cause.empty() ? cause.c_str() : "unknown reason");
        SD_LOG(LOG_DEBUG, "MQTT reconnecting...");

        nretry_ = 0;
        reconnect();
    }

    void message_arrived(mqtt::const_message_ptr msg) override
    {
        // SD_LOG(LOG_DEBUG, "MQTT message: (%s) %s", msg->get_topic().c_str(), msg->to_string().c_str());
        SD_LOG(LOG_DEBUG, "MQTT message: (%s) len=%d", msg->get_topic().c_str(), msg->to_string().size());
        mqtt->handlePubData((char *) msg->to_string().c_str());
    }

    void delivery_complete(mqtt::delivery_token_ptr token) override
    {
        (void) token;
    }

public:
    callback(mqtt::async_client& cli, mqtt::connect_options& connOpts, Mqtt *mqtt)
        : nretry_(0),
        cli_(cli),
        connOpts_(connOpts),
        subListener_("Subscription"),
        mqtt(mqtt)
    { }

    bool isOk()
    {
        return ok;
    }
};
