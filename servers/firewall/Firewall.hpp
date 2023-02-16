/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once

#include <set>

#include "Config.hpp"
#include "Message.hpp"
#include "Server.hpp"
#include "EndpointSock.hpp"
#include "Log.hpp"

using namespace std;

class Firewall : public Server
{
private:
    Endpoint *appSvrEndpoint;
    unordered_map<string, Action> actions;
    set<string> pendingDevices;

protected:
    Message * decodeMessage(uint8_t dataArray[], uint32_t len);
    Message * handleMessage(Message *message, EndpointSock *src, Device *device, uint8_t *serialized, uint32_t len);
    Message * handleData(Data *data, Device *device, uint8_t *serialized, uint32_t len);
    Message * handleAlert(Alert *alert, Device *device);
    Message * handleKeyChange(KeyChange *keyChange, Device *device, uint8_t *serialized, uint32_t len);
    Message * handlePassportRequest(PassportRequest *passportRequest, Device *device);
    Message * handlePassportCheck(PassportCheck *passport, Device *device);
    Message * handleConfigMessage(ConfigMessage *configMessage, Device *device);

    bool validatePassport(string &deviceID, Passport &passport);
    void carbonCopy(Endpoint &endpoint, Message *message);

    void forward(KeyChange *keyChange, uint8_t *serialized, uint32_t len);
    Acceptance forward(Data *data, Config &config, uint8_t *serialized, uint32_t len);
    bool borderControl(string &deviceID, Action action);

    void reject(string deviceID)
    {
        actions[deviceID] = INCORRECT;
    }

public:
    Firewall(Config &config, Board *board, CommandLine &cli)
        : Server(config, board, cli)
    {
        this->endpoint.copy(*config.getComponent().getIncoming());

        appSvrEndpoint = config.getComponent().getOutgoing();
    }
};
