/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#include <iostream>
#include <getopt.h>
#include <filesystem>

#include "nv.h"

#include "Config.hpp"
#include "Utils.hpp"
#include "Log.hpp"

#ifdef SEEC_ENABLED
#include "Publish.hpp"
#include "Subscribe.hpp"
#include "../../../servers/revocation/RevServerPreload.hpp"
#endif

using std::filesystem::exists;

DataTransport Config::toDataTransport(string transport)
{
    std::transform(transport.begin(), transport.end(), transport.begin(), [](unsigned char c){
        return std::tolower(c);
    });
    
    if (transport.compare("mqtt") == 0) {
        return TRANSPORT_MQTT;
    }
    else if (transport.compare("sediment") == 0) {
        return TRANSPORT_SEDIMENT;
    }
    else if (transport.compare("sediment_mqtt") == 0) {
        return TRANSPORT_SEDIMENT_MQTT;
    }
    else {
        SD_LOG(LOG_ERR, "unrecognized data transport %s", transport.c_str());
    }
    return TRANSPORT_SEDIMENT;
}

inline bool stob(string value)
{
    return (!value.compare("true") ? true : false);
}

Endpoint *Config::parseEndpoint(string &value, bool *incoming)
{
    string delimiter = ":";

    size_t colon1 = value.find(delimiter);
    string token  = value.substr(0, colon1);
    std::transform(token.begin(), token.end(), token.begin(), [](unsigned char c){ return std::tolower(c); });
    if (token == "incoming")
        *incoming = true;
    else if (token == "outgoing")
        *incoming = false;
    else {
        SD_LOG(LOG_ERR, "bad endpoint: %s", value.c_str());
        return NULL;
    }

    value = value.substr(colon1 + 1);
    Endpoint *ep = new Endpoint(value);

    return ep;
}

bool Config::parseTopLevel(bool isProver, string &key, string &value)
{
    bool processed = true;

    if (key == NV_LOG_LEVEL) {
        log_level = stoi(value);
    }
    else if (key == NV_FIXED_DELAY) {
        fixed_delay = stoi(value);
    }    
    else if (key == NV_PASS_THRU) {
        pass_thru_enabled = stob(value);
    }
    else if (key == NV_REPORT_INTVL) {
        report_interval = stoi(value);
    }
    else if (key == NV_PASSPORT_PERIOD) {
        passport_period = stoi(value);
    }
    else if (key == NV_PAYLOAD_SIZE) {
        payload_size = stoi(value);
    }
    else if (key == NV_ATTEST) {
        attest_enabled = stob(value);
    }
    else if (key == NV_SEEC) {
        seec_enabled = stob(value);
    }
    else if (key == NV_AUTHENTICATION) {
        auth_enabled = stob(value);
    }
    else if (key == NV_ENCRYPT) {
        enc_enabled = stob(value);
    }
    else if (key == NV_SIGNING) {
        sign_enabled = stob(value);
    }
    else if (key == NV_DATA_TRANSPORT) {
        transport = toDataTransport(value);
    }
    else if (key == NV_NUM_CYCLES) {
        num_cycles = stoi(value);
    }
    else if (key == NV_ITERATIONS) {
        iterations = stoi(value);
    }
    else if (key == NV_DOWNLOAD) {
        download = stob(value);
    }
    else if (key == NV_FW_SCRIPT) {
        fwScript = value;
    }
    else if (key == NV_MQTT_URL) {
        mqttUrl = value;
    }
    else if (key == NV_MQTT_PUB_TOPIC) {
        topicPub = value;
    }
    else if (key == NV_MQTT_SUB_TOPIC) {
        topicSub = value;
    }
    else if (key == NV_ENC_KEY) {
        Utils::readHex(enc_key, value, value.size() / 2);
    }
    else if (key == NV_ATTEST_KEY) {
        Utils::readHex(attest_key, value, value.size() / 2);
    }
    else if (key == NV_ATTEST_SQN) {
    }
    else if (key == NV_SEEC_SQN) {
    }
    else if (key == NV_REV_CHECK_SQN) {
    }
    else if (key == NV_REV_ACK_SQN) {
    }
    else if (key == NV_AUTH_KEY) {
        Utils::readHex(auth_key, value, value.size() / 2);
    }
#ifdef SEEC_ENABLED
    else if (key == NV_PARAMS) {
        if (isProver) {
            Utils::readHex(Publish::getParams(), value, value.size() / 2);
        }
        else {
            Utils::readHex(Subscribe::getParams(), value, value.size() / 2);
            Utils::readHex(RevServerPreload::getParams(), value, value.size() / 2);
        }
    }
    else if (key == NV_EURIPATH) {
        if (isProver)
            Utils::readHex(Publish::getEncryptUripath(), value, value.size() / 2);
        else
            Utils::readHex(Subscribe::getEncryptUripath(), value, value.size() / 2);
    }
    else if (key == NV_SURIPATH) {
        if (isProver)
            Utils::readHex(Publish::getSignUripath(), value, value.size() / 2);
        else
            Utils::readHex(Subscribe::getSignUripath(), value, value.size() / 2);
    }
    else if (key == NV_RURIPATH) {
        if (!isProver)
            Utils::readHex(Subscribe::getRevocationUripath(), value, value.size() / 2);
    }
    else if (key == NV_TIMEPATH) {
        if (isProver)
            Utils::readHex(Publish::getTimepath(), value, value.size() / 2);
        else
            Utils::readHex(Subscribe::getTimepath(), value, value.size() / 2);
    }
    else if (key == NV_SIGNKEY) {
        if (isProver)
            Utils::readHex(Publish::getSigningKey(), value, value.size() / 2);
    }
    else if (key == NV_REVKEY) {
        if (!isProver)
            Utils::readHex(Subscribe::getRevocationKey(), value, value.size() / 2);
    }
    else if (key == NV_ENCRYPTKEY) {
        // SD_LOG(LOG_WARNING, "NV item ignored: %s", key.c_str());
        if (!isProver)
            Utils::readHex(Subscribe::getEncryptKey(), value, value.size() / 2);
    }
    else if (key == NV_MQTT_REV_TOPIC) {
        topicRev = value;
    }
#endif // ifdef SEEC_ENABLED
    else if (key == NV_PROVER || 
             key == NV_VERIFIER ||
             key == NV_FIREWALL ||
             key == NV_APP_SERVER ||
             key == NV_REV_SERVER) {
        if (component == key) {
            size_t colon1 = value.find(":");
            string token  = value.substr(0, colon1);
            std::transform(token.begin(), token.end(), token.begin(), [](unsigned char c){ return std::tolower(c); });
            if (token == NV_ID) {
                configComponent.setID(value.substr(colon1 + 1));
            }
            else {
                bool incoming;
                Endpoint *ep = parseEndpoint(value, &incoming);
                if (incoming) {
                    if (key == NV_PROVER)
                        SD_LOG(LOG_ERR, "prover should not have incoming endpoint: %s", ep->toStringOneline().c_str());
                    else
                        configComponent.setIncoming(ep);
                }
                else {
                    configComponent.setOutgoing(ep);  
                }
            }
        }
    }
    else if (key == NV_REVOCATION) {
        if (component == NV_PROVER) {  // only prover has config for the rev server endpoint
             Endpoint *ep = new Endpoint(value);
             configComponent.setRevServer(ep); 
        }
    }
    else {
        // SD_LOG(LOG_ERR, "unrecognized parameter: %s", item.c_str());
        processed = false;
    }

    return processed;
}

void Config::update(string &lines)
{
    std::istringstream f(lines);
    string line;
    string key, value;

    while (std::getline(f, line)) {
        stringstream s(line);
        getline(s, key, ' ');
        getline(s, value, ' ');

        parseTopLevel(true, key, value);
    }
}

void Config::parseFile(const string &filename)
{
    if (!exists(filename)) {
        SD_LOG(LOG_ERR, "file not exists: '%s'", filename.c_str());
        exit(1);
    }

    ifstream fin(filename);

    string line, key, value;
    bool isProver = !component.compare(NV_PROVER);

    while (getline(fin, line)) {
        Utils::trim(line);
        if (line.size() == 0 || line[0] == '#')
            continue;

        stringstream s(line);
        getline(s, key, ' ');
        getline(s, value, ' ');

        parseTopLevel(isProver, key, value);
    }
}
