/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#pragma once

#include <string>

#include "Device.hpp"

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
#define COL_REVOCATION_EP    "revocationEndpoint"
#define COL_ENCRYPTION_KEY   "encryptionKey"
#define COL_ATTESTATION_KEY  "attestationKey"
#define COL_AUTH_KEY         "authKey"
#define COL_NONCE            "nonce"
#define COL_PASSPORT_EXPIRY  "passportExpiryDate"

#define COL_LAST_ATTESTATION "lastAttestation"
#define COL_STATUS           "status"
#define COL_SQN              "sqn"
#define COL_SEEC_SQN         "seec_sqn"
#define COL_REV_CHECK_SQN    "rev_check_sqn"
#define COL_REV_ACK_SQN      "rev_ack_sqn"
#define COL_EVIDENCE_TYPES   "evidenceTypes"

typedef struct _col {
    const char *name;
    char        type;
} Col;

class DeviceStorage
{
public:
    virtual ~DeviceStorage() {};
    virtual Device *findDevice(string &serial) = 0;
    virtual Device *findDeviceByIP(string &ip) = 0;
    virtual void deleteDevice(Device *device) = 0;
    virtual void insertDevice(Device *device) = 0;
    virtual void insertDevice(string device) = 0;

    virtual string getCol(Device *device, string col) = 0;
    virtual void update(Device *device, string col, string value) = 0;
    virtual bool isConnected() = 0;
    virtual void close() = 0;
};
