/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#pragma once

#include <string>

#include "Endpoint.hpp"
#include "Vector.hpp"
#include "Seec.hpp"
#include "Config.hpp"
#include "Log.hpp"
#include "nlohmann/json.hpp"

using json = nlohmann::json;
using namespace std;

typedef uint32_t TimeStamp;

class Device
{
private:
    string id;
    string firmware;
    string osVersion;
    string configs;
    int firmwareSize = -1; // no longer used
    Endpoint verifierEndpoint;
    Endpoint relyingPartyEndpoint;
    Endpoint proverEndpoint;
    Endpoint revocationEndpoint;

    Vector attestationKey;
    Vector encryptionKey;
    Vector authKey;

    vector<uint8_t> nonce; // saved for ongoing attestation
    Seec seec;
    uint32_t passportExpiryDate = 0; // epoch time

    TimeStamp lastAttestation;
    bool status = false;
    uint32_t sqn;
    uint32_t seecSqn;
    uint32_t revCheckSqn;
    uint32_t revAckSqn;
    vector<uint8_t> evidenceTypes;

public:
    Device(nlohmann::basic_json<> value, Config &config);

    Device(Config &config) :
        seec(config)
    { }

    static void parseEvidenceTypes(string &s, vector<uint8_t> &types);

    string convertEvidenceTypes();


    string toString();

    const string& getFirmware() const
    {
        return firmware;
    }

    const string& getConfigs() const
    {
        return configs;
    }

    const string& getOsVersion() const
    {
        return osVersion;
    }

    const string& getId() const
    {
        return id;
    }

    // obsolete
    int getFirmwareSize() const
    {
        return firmwareSize;
    }

    Vector& getAttestationKey()
    {
        return attestationKey;
    }

    Vector& getEncryptionKey()
    {
        return encryptionKey;
    }

    Vector& getAuthKey()
    {
        return authKey;
    }

    void setKey(KeyPurpose keyPurpose, const vector<uint8_t> &src)
    {
        Vector *key = NULL;

        switch (keyPurpose) {
        case KEY_ENCRYPTION:
            key = &encryptionKey;
            break;
        case KEY_ATTESTATION:
            key = &attestationKey;
            break;
        case KEY_AUTH:
            key = &authKey;
            break;
        default:
            SD_LOG(LOG_ERR, "Device::setKey - unsupported key purpose: %s", TO_KEY_PURPOSE(keyPurpose).c_str());
            return;
        }
        key->resize(src.size());
        memcpy(key->at(0), (char *) &src[0], src.size());
        key->inc(src.size());
    }

    vector<uint8_t> &getNonce()
    {
        return nonce;
    }

    Endpoint &getVerifierEndpoint()
    {
        return verifierEndpoint;
    }

    const Endpoint &getRelyingPartyEndpoint() const
    {
        return relyingPartyEndpoint;
    }

    Seec * getSeec()
    {
        return &seec;
    }

    uint32_t getPassportExpiryDate() const
    {
        return passportExpiryDate;
    }

    void setPassportExpiryDate(uint32_t passportExpiryDate)
    {
        this->passportExpiryDate = passportExpiryDate;
    }

    void setId(string id)
    {
        this->id = id;
    }

    //    void setAttestationKey(const Vector &attestationKey) {
    //        this->attestationKey = attestationKey;
    //    }

    //    void setEncryptionKey(const Vector &encryptionKey) {
    //        this->encryptionKey = encryptionKey;
    //    }

    void setFirmware(string firmware)
    {
        this->firmware = firmware;
    }

    void setFirmwareSize(int firmwareSize = -1)
    {
        this->firmwareSize = firmwareSize;
    }

    void setConfigs(string configs)
    {
        this->configs = configs;
    }

    void setOsVersion(string osVersion)
    {
        this->osVersion = osVersion;
    }

    void setRelyingPartyEndpoint(Endpoint &relyingPartyEndpoint)
    {
        this->relyingPartyEndpoint.copy(relyingPartyEndpoint);
    }

    //    void setSigningKey(const Vector &signingKey) {
    //        this->signingKey = signingKey;
    //    }

    void setVerifierEndpoint(Endpoint &verifierEndpoint)
    {
        this->verifierEndpoint.copy(verifierEndpoint);
    }

    TimeStamp getLastAttestation() const
    {
        return lastAttestation;
    }

    void setLastAttestation(TimeStamp lastAttestation)
    {
        this->lastAttestation = lastAttestation;
    }

    bool getStatus() const
    {
        return status;
    }

    void setStatus(bool status)
    {
        this->status = status;
    }

    uint32_t getSqn() const
    {
        return sqn;
    }

    void setSqn(uint32_t sqn)
    {
        this->sqn = sqn;
    }

    uint32_t getSeecSqn() const
    {
        return seecSqn;
    }

    void setSeecSqn(uint32_t sqn)
    {
        this->seecSqn = sqn;
    }

    uint32_t getRevCheckSqn() const
    {
        return revCheckSqn;
    }

    void setRevCheckSqn(uint32_t sqn)
    {
        this->revCheckSqn = sqn;
    }

    uint32_t getRevAckSqn() const
    {
        return revAckSqn;
    }

    void setRevAckSqn(uint32_t sqn)
    {
        this->revAckSqn = sqn;
    }

    Endpoint& getProverEndpoint()
    {
        return proverEndpoint;
    }

    void setProverEndpoint(const Endpoint &proverEndpoint)
    {
        this->proverEndpoint.copy(proverEndpoint);
    }

    Endpoint& getRevocationEndpoint()
    {
        return revocationEndpoint;
    }

    void setRevocationEndpoint(const Endpoint &revocationEndpoint)
    {
        this->revocationEndpoint.copy(revocationEndpoint);
    }

    vector<uint8_t> &getEvidenceTypes()
    {
        return evidenceTypes;
    }

    void copyNonce(vector<uint8_t> &src)
    {
        nonce = src;
    }
};
