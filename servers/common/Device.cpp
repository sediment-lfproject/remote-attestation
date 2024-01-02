/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#include "Device.hpp"
#include "DeviceStorage.hpp"
#include "Enum.hpp"
#include "Utils.hpp"
#include "Log.hpp"

static void toEndpoint(Endpoint &endpoint, nlohmann::basic_json<> value)
{
    for (auto &el : value.items()) {
        string key = el.key();

        if (!key.compare(NV_PROTOCOL)) {
            string val = el.value().get<string>();
            endpoint.setProtocol(Endpoint::toProtocol(val));
        }
        else if (!key.compare(NV_ADDRESS)) {
            endpoint.setAddress(el.value().get<string>());
        }
        else if (!key.compare(NV_PORT)) {
            endpoint.setPort(el.value().get<int>());
        }
        else if (!key.compare("comments")) { }
        else {
            SD_LOG(LOG_ERR, "unrecognized key %s", key.c_str());
        }
    }
}

void Device::parseEvidenceTypes(string &s, vector<uint8_t> &types)
{
    std::string delimiter = ":";

    size_t pos = 0;
    std::string token;

    while ((pos = s.find(delimiter)) != std::string::npos) {
        token = s.substr(0, pos);
        types.push_back(stol(token));

        s.erase(0, pos + delimiter.length());
    }
    types.push_back(stol(s));
}

Device::Device(nlohmann::basic_json<> value, Config &config) :
    seec(config)
{
    for (auto &el : value.items()) {
        string key = el.key();

        if (!key.compare(COL_ID)) {
            id = el.value().get<string>();
        }
        else if (!key.compare(COL_FIRMWARE)) {
            firmware = el.value().get<string>();
        }
        else if (!key.compare(COL_FIRMWARE_SIZE)) {
            firmwareSize = el.value().get<int>();
        }
        else if (!key.compare(COL_CONFIGS)) {
            configs = el.value().get<string>();
        }
        else if (!key.compare(COL_OS_VERSION)) {
            osVersion = el.value().get<string>();
        }
        else if (!key.compare(COL_VERIFIER_EP)) {
            toEndpoint(verifierEndpoint, el.value());
        }
        else if (!key.compare(COL_RELYINGPARTY_EP)) {
            toEndpoint(relyingPartyEndpoint, el.value());
        }
        else if (!key.compare(COL_PROVER_EP)) {
            toEndpoint(proverEndpoint, el.value());
        }
        else if (!key.compare(COL_REVOCATION_EP)) {
            toEndpoint(revocationEndpoint, el.value());
        }
        else if (!key.compare(COL_ENCRYPTION_KEY)) {
            string src = el.value().get<string>();
            vector<uint8_t> vec;
            Utils::readHex(vec, src, src.size() / 2);

            setKey(KEY_ENCRYPTION, vec);
        }
        else if (!key.compare(COL_ATTESTATION_KEY)) {
            string src = el.value().get<string>();
            vector<uint8_t> vec;
            Utils::readHex(vec, src, src.size() / 2);

            setKey(KEY_ATTESTATION, vec);
        }
        else if (!key.compare(COL_AUTH_KEY)) {
            string src = el.value().get<string>();
            vector<uint8_t> vec;
            Utils::readHex(vec, src, src.size() / 2);

            setKey(KEY_AUTH, vec);
        }
        else if (!key.compare(COL_NONCE)) {
            string src = el.value().get<string>();
            vector<uint8_t> vec;
            Utils::readHex(vec, src, src.size() / 2);

            nonce.resize(vec.size());
            memcpy(&nonce[0], (char *) &vec[0], vec.size());
        }
        else if (!key.compare(COL_PASSPORT_EXPIRY)) {
            passportExpiryDate = el.value().get<int>();
        }
        else if (!key.compare(COL_LAST_ATTESTATION)) {
            lastAttestation = el.value().get<int>();
        }
        else if (!key.compare(COL_STATUS)) {
            status = el.value().get<bool>();
        }
        else if (!key.compare(COL_SQN)) {
            sqn = el.value().get<int>();
        }
        else if (!key.compare(COL_SEEC_SQN)) {
            seecSqn = el.value().get<int>();
        }
        else if (!key.compare(COL_REV_CHECK_SQN)) {
            revCheckSqn = el.value().get<int>();
        }
        else if (!key.compare(COL_REV_ACK_SQN)) {
            revAckSqn = el.value().get<int>();
        }
        else if (!key.compare(COL_EVIDENCE_TYPES)) {
            string src = el.value().get<string>();
            parseEvidenceTypes(src, evidenceTypes);
        }
        else {
            SD_LOG(LOG_ERR, "unrecognized key %s", key.c_str());
        }
    }
}
