﻿/*
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
    string topicPub;
    string topicSub;
    string topicRev;
    StateMachine *machine = NULL;
    bool connected = false;

public:
    Mqtt(const string &pub, const string &sub, StateMachine *machine)
    {
        topicPub = pub;
        topicSub = sub;
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

    string &getTopicRev()
    {
        return topicRev;
    }

    bool isConnected() {
        return connected;
    }

    void setConnected(bool connected) {
        this->connected = connected;
    }
};
