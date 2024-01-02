/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#pragma once
#include <iostream>
#include <fstream>

#include "Config.hpp"
#include "VerifierCL.hpp"
#include "Message.hpp"
#include "Device.hpp"
#include "DeviceManager.hpp"
#include "Server.hpp"
#include "RSASign.hpp"
#include "EndpointSock.hpp"
#include "MeasurementLog.hpp"
#include "Log.hpp"

using namespace std;

class Verifier : public Server
{
private:
    Endpoint *alertEndpoint;
    VerifierCL &cli;
    RSASign rsaSign;
    MeasurementLog measurementLog;

protected:
    Message * decodeMessage(uint8_t dataArray[], uint32_t len);
    Message * handleMessage(DeviceManager &deviceManager, Message *message, EndpointSock *src, Device *device,
                            uint8_t *serialized, uint32_t len);
    Message * handleAttestationRequest(DeviceManager &deviceManager, AttestationRequest *attReq, EndpointSock *src,
                                       Device *device);
    Message * handleEvidence(DeviceManager &deviceManager, Evidence *evidence, EndpointSock *sr, Device *devicec);
    Message * handlePassportResponse(PassportResponse *passportResponse, Device *device);

    void prepareGrant(Grant *grant);

    bool verifyFullFirmware(EvidenceItem *item, Device *device, EvidenceType type);
    bool verifyOsVersion(EvidenceItem *item, Device *device);
    bool verifyBootTime(EvidenceItem *item, Device *device);
    bool verifyConfigs(EvidenceItem *item, Device *device, EvidenceType type);
    bool verifyUDF(EvidenceItem *item, Device *device, EvidenceType type);
    bool verifyHashing(EvidenceItem *item, Device *device, EvidenceType type, unsigned char *bufPtr, int fileSize);

    string receiveDeviceID(int dev_sock);

    void runGuiService();
    void runService();
    void sendAlert(DeviceManager &deviceManager, Reason reason, string deviceID, EndpointSock *src);
    void publish(Evidence *evidence, bool verified);

public:
    Verifier(Config &config, Board *board, VerifierCL &cli)
        : Server(config, board, cli),
          cli(cli),
          rsaSign(cli.getSigningKey()),
          measurementLog(cli.getLogDir(), "ra.csv", cli.getLogMaxSize(), cli.getLogMaxFiles())
    {
        if (config.getComponent().getIncoming() != NULL)
            this->endpoint.copy(*config.getComponent().getIncoming());
        else {
            SD_LOG(LOG_ERR, "null incoming endpoint");
            exit(1);
        }

        alertEndpoint = config.getComponent().getOutgoing();
    }

    static void * serviceControl(void *); // just to have a static method to run the thread
    static void * guiServiceControl(void *p);
};
