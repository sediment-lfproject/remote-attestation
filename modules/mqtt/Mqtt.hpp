/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once

#include "Message.hpp"

#include "Vector.hpp"

class StateMachine;

using namespace std;

class Mqtt
{
private:
    string topicPub       = "sensor";
    string topicSub       = "control";
    StateMachine *machine = NULL;

public:
    Mqtt(bool server, StateMachine *machine)
    {
        if (server) {
            topicPub = "control";
            topicSub = "sensor";
        }
        this->machine = machine;
    }

    bool connect(string &url, string &id);
    void publish(char *message);
    void disconnect();
    void handlePubData(char *data);

    string &getTopicSub()
    {
        return topicSub;
    }

    string &getTopicPub()
    {
        return topicPub;
    }
};
