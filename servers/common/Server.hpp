/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once

#include "StateMachine.hpp"
#include "CryptoServer.hpp"
#include "Seec.hpp"
#include "Device.hpp"
#include "CommandLine.hpp"
#include "EndpointSock.hpp"

using namespace std;

class Server : public StateMachine
{
protected:
    CryptoServer cryptoServer;
    string sediment_home;

    void runProcedure(EndpointSock *epSock);

    virtual void calAuthToken(Message *message, uint8_t *serialized, uint32_t len);
    virtual void setTimestamp(Message *message);
    virtual Device * authenticate(Message *message, uint8_t *serialized, uint32_t len);
    virtual time_t getTimestamp();
    virtual void handlePubData(char *data);

    virtual Message * decodeMessage(uint8_t dataArray[], uint32_t len)
    {
        (void) dataArray;
        (void) len;

        return NULL;
    }

    virtual Message * handleMessage(Message *message, EndpointSock *src, Device *device, uint8_t *serialized,
      uint32_t len)
    {
        (void) message;
        (void) src;
        (void) device;
        (void) serialized;
        (void) len;

        return NULL;
    }

public:
    Server(Config &config, Board *board, CommandLine &cli)
        : StateMachine(config, board),
        cryptoServer(cli),
        sediment_home(cli.getSedimentHome())
    {
        Device::open(cli.getDatabase());
    }

    virtual ~Server(){ }

    Seec * findSeec(string deviceID);

    const CryptoServer& getCryptoServer() const
    {
        return cryptoServer;
    }

    const string& getSedimentHome() const
    {
        return sediment_home;
    }

    void run();
};
