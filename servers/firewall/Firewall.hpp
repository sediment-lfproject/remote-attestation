/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#pragma once

#include <set>

#include "Config.hpp"
#include "Message.hpp"
#include "Server.hpp"
#include "EndpointSock.hpp"
#include "RSAVerify.hpp"
#include "FirewallCL.hpp"
#include "Log.hpp"
#include "DeviceManager.hpp"

using namespace std;

class Firewall : public Server
{
private:
    Endpoint *appSvrEndpoint;
    unordered_map<string, Action> actions;
    set<string> pendingDevices;
    RSAVerify rsaVerify;

protected:
    Message * decodeMessage(uint8_t dataArray[], uint32_t len);
    Message * handleMessage(DeviceManager &deviceManager, Message *message, EndpointSock *src, Device *device,
      uint8_t *serialized, uint32_t len);
    Message * handleData(Data *data, Device *device, uint8_t *serialized, uint32_t len);
    Message * handleAlert(Alert *alert, Device *device);
    Message * handleKeyChange(KeyChange *keyChange, Device *device, uint8_t *serialized, uint32_t len);
    Message * handlePassportRequest(DeviceManager &deviceManager, PassportRequest *passportRequest, Device *device);
    Message * handlePassportCheck(DeviceManager &deviceManager, PassportCheck *passport, Device *device);
    Message * handleConfigMessage(ConfigMessage *configMessage, Device *device);

    bool validatePassport(string &deviceID, Passport &passport);
    void carbonCopy(DeviceManager &deviceManager, Endpoint &endpoint, Message *message);

    void forward(KeyChange *keyChange, uint8_t *serialized, uint32_t len);
    Acceptance forward(Data *data, Config &config, uint8_t *serialized, uint32_t len);
    bool borderControl(string &deviceID, Action action);

    void reject(string deviceID)
    {
        actions[deviceID] = INCORRECT;
    }

public:
    Firewall(Config &config, Board *board, FirewallCL &cli)
        : Server(config, board, cli),
          rsaVerify(cli.getVerifyKey())
    {
        if (config.getComponent().getIncoming() != NULL)
            this->endpoint.copy(*config.getComponent().getIncoming());
        else {
            SD_LOG(LOG_ERR, "null incoming endpoint");
            exit(1);
        }
        appSvrEndpoint = config.getComponent().getOutgoing();
    }
};
