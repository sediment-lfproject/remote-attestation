/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once
#include <iostream>
#include <fstream>

#include "Config.hpp"
#include "Message.hpp"
#include "Device.hpp"
#include "Server.hpp"
#include "EndpointSock.hpp"
#include "Log.hpp"

using namespace std;

class Verifier : public Server
{
private:
    Endpoint *aService;
    Endpoint *alertEndpoint;
    Endpoint *guiEndpoint;

    ofstream statsFile;

protected:
    Message * decodeMessage(uint8_t dataArray[], uint32_t len);
    Message * handleMessage(Message *message, EndpointSock *src, Device *device, uint8_t *serialized, uint32_t len);
    Message * handleAttestationRequest(AttestationRequest *attReq, EndpointSock *src, Device *device);
    Message * handleEvidence(Evidence *evidence, EndpointSock *sr, Device *devicec);
    Message * handlePassportResponse(PassportResponse *passportResponse, Device *device);

    void prepareGrant(Grant *grant);

    bool verifyFullFirmware(EvidenceItem *item, Device *device, EvidenceType type);
    bool verifyOsVersion(EvidenceItem *item, Device *device);
    bool verifyBootTime(EvidenceItem *item, Device *device);
    bool verifyUDF(EvidenceItem *item, Device *device, EvidenceType type);

    string receiveDeviceID(int dev_sock);

    void runService();
    void sendAlert(Reason reason, string deviceID, EndpointSock *src);
    void publish(Evidence *evidence, bool verified);

public:
    Verifier(Config &config, Board *board, CommandLine &cli)
        : Server(config, board, cli),
        aService(config.getComponent().getAService())
    {
        this->endpoint.copy(*config.getComponent().getIncoming());

        alertEndpoint = config.getComponent().getOutgoing();
        guiEndpoint   = config.getComponent().getOutgoing2();

        statsFile.open("ra.csv", ios::out | ios::app);
    }

    static void * serviceControl(void *); // just to have a static method to run the thread
};
