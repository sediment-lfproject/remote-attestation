/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once

#include "../mqtt/Mqtt.hpp"
#include "Config.hpp"
#include "Board.hpp"
#include "Message.hpp"

using namespace std;

enum Procedure {
    PROC_INIT       = 0,
    PROC_ATTEST     = 1,
    PROC_JOIN       = 2,
    PROC_REPORT     = 3,
    PROC_KEY_CHANGE = 4,
};

class StateMachine
{
protected:
    static const int MAX_TIME_OUT = 3; // # of consecutive message time outs
    Config &config;

    MessageID waitForMessage = MIN_MSG_ID;
    Endpoint endpoint;
    Board *board; // host of device specific functions
    Mqtt mqtt;

    virtual Message * decodeMessage(uint8_t dataArray[], uint32_t len)
    {
        (void) dataArray;
        (void) len;
        return NULL;
    }

    virtual void calAuthToken(Message *message, uint8_t *serialized, uint32_t len) = 0;
    virtual void setTimestamp(Message *message) = 0;

public:
    StateMachine(Config &config, Board *board, bool server) :
        config(config),
        board(board),
        mqtt(server, this)
    {
        board->setId(config.getComponent().getID());
    }

    virtual ~StateMachine()
    { }

    virtual void finalizeAndSend(int peer_sock, Message *message);
    virtual bool sendMessage(int peer_sock, MessageID messageID, uint8_t *serialized, uint32_t msg_len);

    const Endpoint& getEndpoint() const
    {
        return endpoint;
    }

    bool isWellFormed(uint8_t dataArray[], uint32_t len);

    virtual void handlePubData(char *data) = 0;
    virtual void mqttConnect(){ }
};
