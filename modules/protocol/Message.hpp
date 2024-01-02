/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#pragma once

#include <cstring>

#include "Codec.hpp"
#include "Crypto.hpp"
#include "Log.hpp"
#include "Enum.hpp"
#include "AuthToken.hpp"
#include "KeyBox.hpp"
#include "Vector.hpp"
#include "MeasurementList.hpp"

#define TOTAL_SIZE_LEN        2
#define MESSAGE_ID_LEN        1
#define AUTH_TOKEN_OFFSET     (TOTAL_SIZE_LEN)
#define TIMESTAMP_LEN         sizeof(TimeStamp)
#define DEVICE_ID_LEN         1

#define MESSAGE_ID_OFFSET     (TOTAL_SIZE_LEN + AuthToken::AUTH_TOKEN_LEN)

#define MIN_MSG_LEN \
                              (TOTAL_SIZE_LEN + MESSAGE_ID_LEN + AuthToken::AUTH_TOKEN_LEN + TIMESTAMP_LEN \
        + DEVICE_ID_LEN)
#define MAX_MSG_LEN           32768

#define REASON_LEN            1

#define CONFIGS_LEN           4
#define PORT_LEN              2
#define COUNTER_LEN           4

#define BLOCK_SIZE_LEN        4
#define BLOCK_COUNT_LEN       4

#define NUM_EVIDENCE_LEN      1
#define EVIDENCE_TYPE_LEN     1

#define EVIDENCE_ENCODING_LEN 1
#define EVIDENCE_SIZE_LEN     2

#define ELAPSED_TIME_LEN      4

#define PROVER_ID_LEN         1
#define VERIFIER_ID_LEN       1

#define SIGNATURE_LEN_LEN     2

#define ADMITTANCE_LEN        1
#define CAUSE_LEN             1

#define IV_LEN                1
#define PAYLOAD_SIZE_LEN      2
#define DATA_CHECKSUM_LEN     1

#define ACCEPTANCE_LEN        1

using namespace std;

typedef uint32_t TimeStamp;

class Message
{
protected:
    MessageID id;
    TimeStamp timestamp;
    string deviceID;
    AuthToken authToken;

public:
    Message()
    { }

    Message(MessageID id)
    {
        this->id = id;
        deviceID = "";
    }

    virtual ~Message(){ }

    virtual void decode(Vector &data);
    virtual void encode(Vector &data);
    virtual uint32_t getSize()
    {
        return TOTAL_SIZE_LEN
               + MESSAGE_ID_LEN
               + TIMESTAMP_LEN
               + DEVICE_ID_LEN
               + deviceID.length()
               + authToken.getSize();
    }

    virtual string toString()
    {
        return
              "id: " + idToString()
            + "\ntimestamp: " + to_string(timestamp)
            + "\ndeviceID: " + deviceID
            + authToken.toString();
    }

    string idToString();

    uint8_t * serialize(uint32_t *len);

    int getPayloadOffset()
    {
        return AUTH_TOKEN_OFFSET + DIGEST_LEN + AuthToken::AUTH_DIGEST_LEN;
    }

    MessageID getId() const
    {
        return id;
    }

    void setId(MessageID id)
    {
        this->id = id;
    }

    string &getDeviceID()
    {
        return deviceID;
    }

    void setDeviceID(string deviceID)
    {
        this->deviceID = deviceID;
    }

    uint32_t getTimestamp() const
    {
        return timestamp;
    }

    void setTimestamp(uint32_t timestamp)
    {
        this->timestamp = timestamp;
    }

    AuthToken& getAuthToken()
    {
        return authToken;
    }
};

class ConfigMessage : public Message
{
protected:
    Vector configs;

public:
    ConfigMessage()
        : Message(CONFIG)
    { }

    virtual ~ConfigMessage(){ }

    void decode(Vector &data);
    void encode(Vector &data);

    uint32_t getSize()
    {
        return Message::getSize()
               + CONFIGS_LEN
               + configs.size();
    }

    string toString()
    {
        const char *ptr = (configs.size() > 0) ? (char *) configs.at(0) : "";
        string cfg(ptr);

        cfg.resize(configs.size());

        return
              Message::toString()
            + "\nconfigs:" + cfg;
    }

    Vector& getConfigs()
    {
        return configs;
    }

    void setConfigs(string &cfg)
    {
        configs.resize(cfg.size() + 1); // 1 for \0
        configs.reset();
        configs.put((uint8_t *) &cfg[0], cfg.size() + 1);
    }
};

class PassportRequest : public Message
{
protected:
    Reason reason;

public:
    PassportRequest()
        : Message(PASSPORT_REQUEST)
    { }

    PassportRequest(Reason reason)
        : Message(PASSPORT_REQUEST)
    {
        this->reason = reason;
    }

    virtual ~PassportRequest(){ }

    void decode(Vector &data);
    void encode(Vector &data);

    uint32_t getSize()
    {
        return Message::getSize()
               + REASON_LEN;
    }

    string toString()
    {
        return
              Message::toString()
            + "\nreason: " + TO_REASON(reason);
    }

    Reason getReason() const
    {
        return reason;
    }

    void setReason(Reason reason)
    {
        this->reason = reason;
    }
};

class PassportResponse : public Message
{
protected:
    Endpoint endpoint;
    KeyBox attKeyBox;
    MeasurementList measurementList;

public:
    PassportResponse()
        : Message(PASSPORT_RESPONSE)
    { }

    virtual ~PassportResponse(){ }

    void decode(Vector &data);
    void encode(Vector &data);

    uint32_t getSize()
    {
        return Message::getSize()
               + endpoint.getSize()
               + attKeyBox.getSize()
               + measurementList.getSize();
    }

    string toString()
    {
        return
              Message::toString()
            + endpoint.toString()
            + attKeyBox.toString()
            + measurementList.toString();
    }

    KeyBox& getAttKeyBox()
    {
        return attKeyBox;
    }

    Endpoint& getEndpoint()
    {
        return endpoint;
    }

    void setEndpoint(const Endpoint &endpoint)
    {
        this->endpoint.copy(endpoint);
    }

    MeasurementList& getMeasurementList()
    {
        return measurementList;
    }
};

class AttestationRequest : public Message
{
protected:
    int port         = 0; // port the prover is waiting for on-demand RA request
    uint32_t counter = 0;

public:
    AttestationRequest()
        : Message(ATTESTATION_REQUEST)
    { }

    virtual ~AttestationRequest(){ }

    void decode(Vector &data);
    void encode(Vector &data);

    uint32_t getSize()
    {
        return Message::getSize()
               + PORT_LEN
               + COUNTER_LEN;
    }

    string toString()
    {
        return
              Message::toString()
            + "\ncounter: " + to_string(counter)
            + "\nport: " + to_string(port);
    }

    int getPort() const
    {
        return port;
    }

    void setPort(int port)
    {
        this->port = port;
    }

    uint32_t getCounter() const
    {
        return counter;
    }

    void setCounter(int counter)
    {
        this->counter = counter;
    }
};

class Challenge : public Message
{
protected:
    Vector evidenceTypes;

    uint32_t blockSize;
    uint32_t blockCount;
    uint32_t counter = 0;
    vector<uint8_t> nonce;

public:
    Challenge()
        : Message(CHALLENGE),
        evidenceTypes(MAX_EVIDENCE_TYPE)
    {
        nonce.resize(AuthToken::AUTH_NONCE_LEN);
        Crypto::getRandomBytes((char *) &nonce[0], AuthToken::AUTH_NONCE_LEN);
    }

    virtual ~Challenge(){ }

    void decode(Vector &data);
    void encode(Vector &data);

    uint32_t getSize()
    {
        return Message::getSize()
               + NUM_EVIDENCE_LEN
               + evidenceTypes.size() * EVIDENCE_TYPE_LEN
               + BLOCK_SIZE_LEN
               + BLOCK_COUNT_LEN
               + COUNTER_LEN
               + NONCE_LEN
               + nonce.size();
    }

    string toString()
    {
        return Message::toString()
                 + "\ncounter:" + to_string(counter)
                 + "\nevidenceTypes: " + Log::toHex(evidenceTypes)
                 + "\nblockSize: " + to_string(blockSize)
                 + "\nblockCount: " + to_string(blockCount)
                 + "\nchallenge nonce: " + Log::toHex(nonce);
    }

    uint32_t getBlockCount() const
    {
        return blockCount;
    }

    void setBlockCount(uint32_t blockCount)
    {
        this->blockCount = blockCount;
    }

    uint32_t getBlockSize() const
    {
        return blockSize;
    }

    void setBlockSize(uint32_t blockSize)
    {
        this->blockSize = blockSize;
    }

    Vector &getEvidenceTypes()
    {
        return evidenceTypes;
    }

    uint32_t getCounter() const
    {
        return counter;
    }

    void setCounter(int counter)
    {
        this->counter = counter;
    }

    vector<uint8_t> &getNonce()
    {
        return nonce;
    }
};

class EvidenceItem
{
protected:
    EvidenceType type;
    EvidenceEncoding encoding;
    Vector evidence;

public:
    EvidenceItem()
    {
        this->type     = type;
        this->encoding = encoding;
    }

    EvidenceItem(EvidenceType type, EvidenceEncoding encoding)
    {
        this->type     = type;
        this->encoding = encoding;
    }

    EvidenceItem(const EvidenceItem &src) : evidence(src.evidence)
    {
        this->type     = src.type;
        this->encoding = src.encoding;
    }

    void decode(Vector &data);
    void encode(Vector &data);

    uint32_t getSize()
    {
        return EVIDENCE_TYPE_LEN
               + EVIDENCE_ENCODING_LEN
               + EVIDENCE_SIZE_LEN
               + evidence.size();
    }

    string toString()
    {
        return
              "\ntype: " + TO_EVIDENCETYPE(type)
            + "\nencoding: " + TO_EVIDENCEENCODING(encoding)
            + "\nevidence: " + Log::toHex(evidence);
    }

    EvidenceEncoding getEncoding() const
    {
        return encoding;
    }

    void setEncoding(EvidenceEncoding encoding)
    {
        this->encoding = encoding;
    }

    Vector &getEvidence()
    {
        return evidence;
    }

    EvidenceType getType() const
    {
        return type;
    }

    void setType(EvidenceType type)
    {
        this->type = type;
    }
};

class Evidence : public Message
{
protected:
    Measurement measurement;
    vector<EvidenceItem> evidenceItems;
    uint32_t counter = 0;

public:
    Evidence()
        : Message(EVIDENCE)
    { }

    virtual ~Evidence(){ }

    void decode(Vector &data);
    void encode(Vector &data);

    uint32_t getSize()
    {
        int sizeofEvidence = 0;

        for (uint32_t i = 0; i < evidenceItems.size(); i++) {
            sizeofEvidence += evidenceItems[i].getSize();
        }

        return Message::getSize()
               + measurement.getSize()
               + NUM_EVIDENCE_LEN
               + COUNTER_LEN
               + sizeofEvidence;
    }

    string toString()
    {
#ifndef LOG_NONE
        string evidenceString;
        for (uint32_t i = 0; i < evidenceItems.size(); i++) {
            evidenceString += "\n[" + to_string(i) + "]:" + evidenceItems[i].toString();
        }
#endif
        return
              Message::toString()
            + "\ncounter:" + to_string(counter)
            + measurement.toString()
            + evidenceString;
    }

    vector<EvidenceItem> &getEvidenceItems()
    {
        return evidenceItems;
    }

    void setEvidenceItems(vector<EvidenceItem> items)
    {
        for (uint32_t i = 0; i < items.size(); i++) {
            EvidenceItem newItem(items[i]);
            evidenceItems.push_back(newItem);
        }
    }

    Measurement &getMeasurement()
    {
        return measurement;
    }

    void setMeasurement(MeasurementType type, uint32_t elapsedTime, int optional)
    {
        measurement.setType(type);
        measurement.setElapsedTime(elapsedTime);
        measurement.setOptional(optional);
    }

    uint32_t getCounter() const
    {
        return counter;
    }

    void setCounter(int counter)
    {
        this->counter = counter;
    }
};

class Passport
{
private:
    string proverID;
    string verifierID;
    uint32_t issueDate;
    uint32_t expireDate;
    Vector signature;

public:
    Passport()
    { }

    Passport(const Passport &src) : signature(src.signature)
    {
        copy(src);
    }

    void decode(Vector &data);
    void encode(Vector &data);

    uint32_t getSize()
    {
        return PROVER_ID_LEN
               + proverID.length()
               + VERIFIER_ID_LEN
               + verifierID.length()
               + sizeof(uint32_t)
               + sizeof(uint32_t)
               + SIGNATURE_LEN_LEN
               + signature.size();

        ;
    }

    string toString()
    {
        return
              "\nproverID: " + proverID
            + "\nverifierID: " + verifierID
            + "\nissueDate: " + to_string(issueDate)
            + "\nexpireDate: " + to_string(expireDate)
            + "\nsignature: " + Log::toHex(signature);
    }

    void copy(const Passport &src)
    {
        this->proverID   = src.proverID;
        this->verifierID = src.verifierID;
        this->issueDate  = src.issueDate;
        this->expireDate = src.expireDate;

        this->signature.copy(src.signature);
    }

    uint32_t getExpireDate() const
    {
        return expireDate;
    }

    uint32_t getIssueDate() const
    {
        return issueDate;
    }

    string &getProverId()
    {
        return proverID;
    }

    void setExpireDate(uint32_t expireDate)
    {
        this->expireDate = expireDate;
    }

    void setIssueDate(uint32_t issueDate)
    {
        this->issueDate = issueDate;
    }

    void setProverId(string proverId)
    {
        proverID = proverId;
    }

    void setVerifierId(string &verifierId)
    {
        verifierID = verifierId;
    }

    Vector &getSignature()
    {
        return signature;
    }
};

class Grant : public Message
{
protected:
    Passport passport;

public:
    Grant()
        : Message(GRANT)
    { }

    virtual ~Grant(){ }

    void decode(Vector &data);
    void encode(Vector &data);

    uint32_t getSize()
    {
        return Message::getSize()
               + passport.getSize();
    }

    string toString()
    {
        return
              Message::toString()
            + passport.toString();
    }

    Passport &getPassport()
    {
        return passport;
    }
};

class PassportCheck : public Message
{
protected:
    Passport passport;

public:
    PassportCheck()
    { }

    PassportCheck(Passport pport)
        : Message(PASSPORT_CHECK),
        passport(pport)
    { }

    virtual ~PassportCheck(){ }

    void decode(Vector &data);
    void encode(Vector &data);

    uint32_t getSize()
    {
        return Message::getSize()
               + passport.getSize();
    }

    string toString()
    {
        return
              Message::toString()
            + passport.toString();
    }

    Passport &getPassport()
    {
        return passport;
    }
};

class Permission : public Message
{
protected:
    Admittance admittance;
    Cause cause;
    Endpoint endpoint;

public:
    Permission()
        : Message(PERMISSION)
    { }

    virtual ~Permission(){ }

    void decode(Vector &data);
    void encode(Vector &data);

    uint32_t getSize()
    {
        return Message::getSize()
               + ADMITTANCE_LEN
               + CAUSE_LEN
               + endpoint.getSize();
    }

    string toString()
    {
        return
              Message::toString()
            + "\nadmittance " + TO_ADMITTANCE(admittance)
            + "\ncause: " + TO_CAUSE(cause)
            + endpoint.toString();
    }

    Admittance getAdmittance() const
    {
        return admittance;
    }

    void setAdmittance(Admittance admittance)
    {
        this->admittance = admittance;
    }

    Cause getCause() const
    {
        return cause;
    }

    void setCause(Cause cause)
    {
        this->cause = cause;
    }

    Endpoint& getEndpoint()
    {
        return endpoint;
    }

    void setEndpoint(const Endpoint &endpoint)
    {
        this->endpoint.copy(endpoint);
    }
};

class KeyChange : public Message
{
protected:
    KeyBox encKeyBox;
    KeyBox signKeyBox;
    MeasurementList measurementList;

public:
    KeyChange(KeyEncType keyEncType)
        : Message(KEY_CHANGE)
    {
        encKeyBox.setEncType(keyEncType);
        signKeyBox.setEncType(keyEncType);
    }

    virtual ~KeyChange(){ }

    void decode(Vector &data);
    void encode(Vector &data);

    uint32_t getSize()
    {
        return Message::getSize()
               + encKeyBox.getSize()
               + signKeyBox.getSize()
               + measurementList.getSize();
    }

    string toString()
    {
        return
              Message::toString()
            + encKeyBox.toString()
            + signKeyBox.toString()
            + measurementList.toString();
    }

    KeyBox& getEncKeyBox()
    {
        return encKeyBox;
    }

    KeyBox& getSignKeyBox()
    {
        return signKeyBox;
    }

    MeasurementList& getMeasurementList()
    {
        return measurementList;
    }
};

class Data : public Message
{
protected:
    MeasurementList measurementList;
    Vector iv;
    Vector payload;
    Vector checksum;

public:
    Data()
        : Message(DATA)
    {
        iv.resize(Crypto::IV_SIZE);
    }

    virtual ~Data(){ }

    void decode(Vector &data);
    void encode(Vector &data);

    uint32_t getSize()
    {
        return Message::getSize()
               + measurementList.getSize()
               + IV_LEN
               + iv.size()
               + PAYLOAD_SIZE_LEN
               + payload.size()
               + DATA_CHECKSUM_LEN
               + checksum.size();
    }

    string toString()
    {
        return
              Message::toString()
            + measurementList.toString()
            + "\niv: " + Log::toHex(iv)
            + "\npayload: " + Log::toHex(payload)
            + "\nchecksum: " + Log::toHex(checksum);
    }

    Vector &getPayload()
    {
        return payload;
    }

    MeasurementList &getMeasurementList()
    {
        return measurementList;
    }

    Vector &getChecksum()
    {
        return checksum;
    }

    Vector &getIv()
    {
        return iv;
    }
};

class Result : public Message
{
protected:
    Acceptance acceptance;

public:
    Result()
        : Message(RESULT)
    { }

    virtual ~Result(){ }

    void decode(Vector &data);
    void encode(Vector &data);

    uint32_t getSize()
    {
        return Message::getSize()
               + ACCEPTANCE_LEN;
    }

    string toString()
    {
        return
              Message::toString()
            + "\nacceptance: " + TO_ACCEPTANCE(acceptance);
    }

    Acceptance getAcceptance() const
    {
        return acceptance;
    }

    void setAcceptance(Acceptance acceptance)
    {
        this->acceptance = acceptance;
    }
};

class Alert : public Message
{
protected:
    string verifierID;
    Reason reason = INIT;
    Vector signature;

    // the device ID is in the common message header
    Endpoint endpoint; // device end point

public:
    Alert()
        : Message(ALERT)
    { }

    virtual ~Alert(){ }

    void decode(Vector &data);
    void encode(Vector &data);

    uint32_t getSize()
    {
        return Message::getSize()
               + VERIFIER_ID_LEN
               + verifierID.length()
               + REASON_LEN
               + SIGNATURE_LEN_LEN
               + signature.size()
               + endpoint.getSize();
    }

    string toString()
    {
        return
              Message::toString()
            + "\nverifierID: " + verifierID
            + "\nreason: " + TO_REASON(reason)
            + "\nsignature: " + Log::toHex(signature)
            + endpoint.toString();
    }

    uint32_t getSigCoverage(Vector &signature, uint32_t *total)
    {
        // exclude the total len (2), auth token size, signature_size(2) and signature(256) in the signing;
        int excluded = AUTH_TOKEN_OFFSET + authToken.getSize() + +MESSAGE_ID_LEN + TIMESTAMP_LEN;

        *total = *total - (excluded + SIGNATURE_LEN_LEN + signature.size());

        return excluded;
    }

    Reason getReason() const
    {
        return reason;
    }

    void setReason(Reason reason)
    {
        this->reason = reason;
    }

    Vector &getSignature()
    {
        return signature;
    }

    void setVerifierId(string verifierId)
    {
        verifierID = verifierId;
    }

    Endpoint& getEndpoint()
    {
        return endpoint;
    }

    void setEndpoint(const Endpoint &endpoint)
    {
        this->endpoint.copy(endpoint);
    }
};

class Revocation : public Message
{
protected:
    Vector payload;
    Vector checksum;

public:
    Revocation()
        : Message(REVOCATION)
    { }

    virtual ~Revocation(){ }

    void decode(Vector &data);
    void encode(Vector &data);

    uint32_t getSize()
    {
        return Message::getSize()
            + PAYLOAD_SIZE_LEN
            + payload.size()
            + DATA_CHECKSUM_LEN
            + checksum.size();
    }

    string toString()
    {
       return
            Message::toString()
            + "\npayload: " + Log::toHex(payload)
            + "\nchecksum: " + Log::toHex(checksum);
    }

    Vector &getPayload()
    {
        return payload;
    }

    Vector &getChecksum()
    {
        return checksum;
    }

};
