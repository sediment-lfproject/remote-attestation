/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once

#include "StateMachine.hpp"
#include "Board.hpp"
#include "Crypto.hpp"
#include "Seec.hpp"

class Prover : public StateMachine
{
protected:
    static const int MAX_CONN_WAIT      = 3600; // max connection wait time in seconds
    static const int MAX_REJECT         = 5;    // # of consecutive rejected data messages
    static const int MAX_ATTEST_RESTART = 5;    // # of times the procedure can restart at AR


    Passport passport;    // passport received from the verifier
    Reason reason = INIT; // reason for starting attestation

    Endpoint rpEndpoint; // saved relying party endpoint
    MessageID expecting = CONFIG;
    int mySock = -1;

    uint32_t rejectCount    = 0; // consecutive times of data being rejected
    uint32_t attestSqn      = 0; // current attestation sequence number
    uint32_t attestRestarts = 0; // amount of restarts from AR

    Seec seec;

    void runProcedure(int sock);
    Message * decodeMessage(uint8_t dataArray[], uint32_t len);

    bool moveTo(MessageID id, Message *received);
    bool handleMessage(Message *message);

    Message * prepareConfig(Message *received);
    bool handleConfig(Message *received);

    Message * preparePassportRequest(Message *received);
    bool handlePassportResponse(Message *message);
    Message * prepareAttestationRequest(Message *received);
    bool handleChallenge(Message *message);
    Message * prepareEvidence(Message *received);
    bool handleGrant(Message *message);
    Message * preparePassportCheck(Message *received);
    bool handlePermission(Message *message);
    Message * prepareKeyChange(Message *received);
    Message * prepareData(Message *received);
    bool handleResult(Message *message);

    void setTimestamp(Message *message);
    void calAuthToken(Message *message, uint8_t *serialized, uint32_t len);
    virtual bool authenticate(Message *message, uint8_t *serialized, uint32_t len);
    void pause(int bad_procs);
    void handlePubData(char *data);

    bool preapreEvidenceBootTime(Challenge *challenge, EvidenceItem *item);
    bool preapreEvidenceOsVersion(Challenge *challenge, EvidenceItem *item);
    bool prepareEvidenceFullFirmware(Challenge *challenge, EvidenceItem *item, uint32_t *elapsed, int *optional,
      bool isUDF);
#ifdef PLATFORM_RPI
    string sediment_home;

    bool preapreEvidenceUDF(Challenge *challenge, EvidenceItem *item, EvidenceType evidenceType);
#endif

    void restartAttestionRequest();
    void resetProcedure(bool proc);
    bool toGiveup(bool msg_success, int *bad_msg_count, bool fullReset);

public:
    Prover(Config &config, Board *board)
        : StateMachine(config, board, false),
        seec(config)
    {
#ifdef PLATFORM_RPI
        // The following are not necessary for non-Linux based devices 
        // since they load configurations from the flash after the prover
        // is constructed and overrides what's done here.
        
        this->endpoint.copy(*config.getComponent().getOutgoing());
        this->rpEndpoint.copy(endpoint);

        Crypto *crypto = seec.getCrypto();

        vector<uint8_t> &enc_key = config.getEncKey();
        crypto->changeKey(KEY_ENCRYPTION, (unsigned char *) &enc_key[0], enc_key.size());

        vector<uint8_t> &attest_key = config.getAttestKey();
        crypto->changeKey(KEY_ATTESTATION, (unsigned char *) &attest_key[0], attest_key.size());

        vector<uint8_t> &auth_key = config.getAuthKey();
        crypto->changeKey(KEY_AUTH, (unsigned char *) &auth_key[0], auth_key.size());
#endif        
    }

    void run();
    void runMqtt();

    Seec &getSeec()
    {
        return seec;
    }

    // invoked when endpoints are loaded from flash
    void reInitEndpoints(Protocol protocol, string addr, int port)
    {
        endpoint.setProtocol(protocol);
        endpoint.setAddress(addr);
        endpoint.setPort(port);

        rpEndpoint.setProtocol(protocol);
        rpEndpoint.setAddress(addr);
        rpEndpoint.setPort(port);
    }

#ifdef PLATFORM_RPI
    const string& getSedimentHome() const
    {
        return sediment_home;
    }

    void setSedimentHome(string home)
    {
        sediment_home = home;
    }
#endif    
};
