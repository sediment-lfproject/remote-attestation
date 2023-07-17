/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once

#include <fstream>
#include <sqlite3.h>
#include <memory>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>

#include "Seec.hpp"
#include "Crypto.hpp"
#include "Config.hpp"
#include "Log.hpp"

#include "nlohmann/json.hpp"

using json = nlohmann::json;
using namespace std;

#define COL_TYPE_CHAR        0
#define COL_TYPE_TEXT        1
#define COL_TYPE_INT         2
#define COL_TYPE_BLOB        3

#define COL_ID               "id"
#define COL_FIRMWARE         "firmware"
#define COL_FIRMWARE_SIZE    "firmwareSize"
#define COL_CONFIGS          "configs"
#define COL_OS_VERSION       "osVersion"
#define COL_VERIFIER_EP      "verifierEndpoint"
#define COL_RELYINGPARTY_EP  "relyingPartyEndpoint"
#define COL_PROVER_EP        "proverEndpoint"
#define COL_ENCRYPTION_KEY   "encryptionKey"
#define COL_ATTESTATION_KEY  "attestationKey"
#define COL_AUTH_KEY         "authKey"
#define COL_NONCE            "nonce"
#define COL_PASSPORT_EXPIRY  "passportExpiryDate"

#define COL_LAST_ATTESTATION "lastAttestation"
#define COL_STATUS           "status"
#define COL_SQN              "sqn"
#define COL_SEEC_SQN         "seec_sqn"
#define COL_EVIDENCE_TYPES   "evidenceTypes"

typedef uint32_t TimeStamp;

typedef struct _col {
    const char *name;
    char        type;
} Col;


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
    vector<uint8_t> evidenceTypes;

public:
    Device(nlohmann::basic_json<> value, Config &config);

    Device(Config &config) :
        seec(config)
    { }

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

    Endpoint& getProverEndpoint()
    {
        return proverEndpoint;
    }

    void setProverEndpoint(const Endpoint &proverEndpoint)
    {
        this->proverEndpoint.copy(proverEndpoint);
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

class SQLiteDeviceManager
{
private:
    map<string, Device *> devices;
    sqlite3 *deviceDB;
public:
    SQLiteDeviceManager(const string &dbName);
    ~SQLiteDeviceManager();

    // DeviceManagers should not be copied
    void operator = (SQLiteDeviceManager const &)    = delete;
    SQLiteDeviceManager(SQLiteDeviceManager const &) = delete;

    Device * findDevice(string &serial);
    Device * findDeviceByIP(string &ip);
    void deleteDevice(Device *device);
    void insertDevice(Device *device);
    void insertDevice(string device);
    Device * selectDevice(string col, string &value);
    void createDeviceTable();
    string getCol(Device *device, string col);
    void update(Device *device, string col, string value);
};

class MySQLDeviceManager
{
private:
    map<string, Device *> devices;
    std::unique_ptr<sql::Connection> conn;

    void populateDevice(Device *device, std::unique_ptr<sql::ResultSet> res);
public:
    MySQLDeviceManager(const string &dbName);

    // DeviceManagers should not be copied
    void operator = (const MySQLDeviceManager &other)   = delete;
    MySQLDeviceManager(const MySQLDeviceManager &other) = delete;

    Device * findDevice(string &serial);
    Device * findDeviceByIP(string &ip);
    void deleteDevice(Device *device);
    void insertDevice(Device *device);
    void insertDevice(string device);
    Device * selectDevice(string col, string &value);
    void createDeviceTable();
    string getCol(Device *device, string col);
    void update(Device *device, string col, string value);
};

typedef MySQLDeviceManager DeviceManager;
