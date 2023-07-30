/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
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

KeyEncType Config::toKeyEncType(string method)
{
    if (method.compare("jedi") == 0) {
        return KEY_ENC_TYPE_JEDI;
    }
    else if (method.compare("rsa") == 0) {
        return KEY_ENC_TYPE_RSA;
    }
    else if (method.compare("ec") == 0) {
        return KEY_ENC_TYPE_EC;
    }
    else if (method.compare("none") == 0) {
        return KEY_ENC_TYPE_NONE;
    }
    else {
        SD_LOG(LOG_ERR, "unrecognized key encryption method %s", method.c_str());
    }
    return MIN_KEY_ENC_TYPE;
}

DataTransport Config::toDataTransport(string transport)
{
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

bool Config::parseTopLevel(bool isProver, string &key, string &value)
{
    bool processed = true;

    if (!key.compare(NV_LOG_LEVEL)) {
        log_level = stoi(value);
    }
    else if (!key.compare(NV_PASS_THRU)) {
        pass_thru_enabled = stob(value);
    }
    else if (!key.compare(NV_KEY_DIST)) {
        key_dist = toKeyEncType(value);
    }
    else if (!key.compare(NV_REPORT_INTVL)) {
        report_interval = stoi(value);
    }
    else if (!key.compare(NV_KEY_CHG_INTVL)) {
        key_change_interval = stoi(value);
    }
    else if (!key.compare(NV_KEY_CHANGE)) {
        key_change_enabled = stob(value);
    }
    else if (!key.compare(NV_KEY_ENCRYPTION)) {
        key_enc_enabled = stob(value);
    }
    else if (!key.compare(NV_PASSPORT_PERIOD)) {
        passport_period = stoi(value);
    }
    else if (!key.compare(NV_PAYLOAD_SIZE)) {
        payload_size = stoi(value);
    }
    else if (!key.compare(NV_ATTEST)) {
        attest_enabled = stob(value);
    }
    else if (!key.compare(NV_SEEC)) {
        seec_enabled = stob(value);
    }
    else if (!key.compare(NV_AUTHENTICATION)) {
        auth_enabled = stob(value);
    }
    else if (!key.compare(NV_ENCRYPT)) {
        enc_enabled = stob(value);
    }
    else if (!key.compare(NV_SIGNING)) {
        sign_enabled = stob(value);
    }
    else if (!key.compare(NV_DATA_TRANSPORT)) {
        transport = toDataTransport(value);
    }
    else if (!key.compare(NV_NUM_CYCLES)) {
        num_cycles = stoi(value);
    }
    else if (!key.compare(NV_ITERATIONS)) {
        iterations = stoi(value);
    }
    else if (!key.compare(NV_DOWNLOAD)) {
        download = stob(value);
    }
    else if (!key.compare(NV_FW_SCRIPT)) {
        fwScript = value;
    }
    else if (!key.compare(NV_MQTT_URL)) {
        mqttUrl = value;
    }
    else if (!key.compare(NV_MQTT_PUB_TOPIC)) {
        topicPub = value;
    }
    else if (!key.compare(NV_MQTT_SUB_TOPIC)) {
        topicSub = value;
    }
    else if (!key.compare(NV_ENC_KEY)) {
        Utils::readHex(enc_key, value, value.size() / 2);
    }
    else if (!key.compare(NV_ATTEST_KEY)) {
        Utils::readHex(attest_key, value, value.size() / 2);
    }
    else if (!key.compare(NV_ATTEST_SQN)) { }
    else if (!key.compare(NV_SEEC_SQN)) { }
    else if (!key.compare(NV_REV_CHECK_SQN)) { }
    else if (!key.compare(NV_REV_ACK_SQN)) { }
    else if (!key.compare(NV_AUTH_KEY)) {
        Utils::readHex(auth_key, value, value.size() / 2);
    }
    else if (!key.compare(NV_PARAMS_SIZE)) {
        // size = stoi(value);
    }
#ifdef SEEC_ENABLED
    else if (!key.compare(NV_PARAMS)) {
        if (isProver) {
            Utils::readHex(Publish::getParams(), value, value.size() / 2);
        }
        else {
            Utils::readHex(Subscribe::getParams(), value, value.size() / 2);
            Utils::readHex(RevServerPreload::getParams(), value, value.size() / 2);
        }
    }
    else if (!key.compare(NV_EURIPATH_SIZE)) {
        // size = stoi(value);
    }
    else if (!key.compare(NV_EURIPATH)) {
        if (isProver)
            Utils::readHex(Publish::getEncryptUripath(), value, value.size() / 2);
        else
            Utils::readHex(Subscribe::getEncryptUripath(), value, value.size() / 2);
    }
    else if (!key.compare(NV_SURIPATH_SIZE)) {
        // size = stoi(value);
    }
    else if (!key.compare(NV_SURIPATH)) {
        if (isProver)
            Utils::readHex(Publish::getSignUripath(), value, value.size() / 2);
        else
            Utils::readHex(Subscribe::getSignUripath(), value, value.size() / 2);
    }
    else if (!key.compare(NV_RURIPATH_SIZE)) {
        // size = stoi(value);
    }
    else if (!key.compare(NV_RURIPATH)) {
        if (!isProver)
            Utils::readHex(Subscribe::getRevocationUripath(), value, value.size() / 2);
    }
    else if (!key.compare(NV_TIMEPATH_SIZE)) {
        // size = stoi(value);
    }
    else if (!key.compare(NV_TIMEPATH)) {
        if (isProver)
            Utils::readHex(Publish::getTimepath(), value, value.size() / 2);
        else
            Utils::readHex(Subscribe::getTimepath(), value, value.size() / 2);
    }
    else if (!key.compare(NV_SIGNKEY_SIZE)) {
        // size = stoi(value);
    }
    else if (!key.compare(NV_SIGNKEY)) {
        if (isProver)
            Utils::readHex(Publish::getSigningKey(), value, value.size() / 2);
    }
    else if (!key.compare(NV_REVKEY_SIZE)) {
        // size = stoi(value);
    }
    else if (!key.compare(NV_REVKEY)) {
        if (!isProver)
            Utils::readHex(Subscribe::getRevocationKey(), value, value.size() / 2);
    }
    else if (!key.compare(NV_ENCRYPTKEY_SIZE)) { }
    else if (!key.compare(NV_ENCRYPTKEY)) {
        // SD_LOG(LOG_WARNING, "NV item ignored: %s", key.c_str());
        if (!isProver)
            Utils::readHex(Subscribe::getEncryptKey(), value, value.size() / 2);
    }
    else if (!key.compare(NV_MQTT_REV_TOPIC)) {
        topicRev = value;
    }
#endif // ifdef SEEC_ENABLED
    else if (isProver) {
        if (!key.compare(NV_ID)) {
            getComponent().setID(value);
        }
        else if (!key.compare(NV_PROTOCOL)) {
            Endpoint *endpoint = configComponent.getOutgoing();
            if (endpoint == NULL) {
                endpoint = new Endpoint();
                configComponent.setOutgoing(endpoint);
            }
            endpoint->setProtocol(Endpoint::toProtocol(value));
        }
        else if (!key.compare(NV_ADDRESS)) {
            Endpoint *endpoint = configComponent.getOutgoing();
            if (endpoint == NULL) {
                endpoint = new Endpoint();
                configComponent.setOutgoing(endpoint);
            }
            endpoint->setAddress(value);
        }
        else if (!key.compare(NV_PORT)) {
            Endpoint *endpoint = configComponent.getOutgoing();
            if (endpoint == NULL) {
                endpoint = new Endpoint();
                configComponent.setOutgoing(endpoint);
            }
            endpoint->setPort(stoi(value));
        }
#ifdef SEEC_ENABLED
        else if (!key.compare(NV_REV_PROTOCOL)) {
            Endpoint *endpoint = configComponent.getRevServer();
            if (endpoint == NULL) {
                endpoint = new Endpoint();
                configComponent.setRevServer(endpoint);
            }
            endpoint->setProtocol(Endpoint::toProtocol(value));
        }
        else if (!key.compare(NV_REV_ADDRESS)) {
            Endpoint *endpoint = configComponent.getRevServer();
            if (endpoint == NULL) {
                endpoint = new Endpoint();
                configComponent.setRevServer(endpoint);
            }
            endpoint->setAddress(value);
        }
        else if (!key.compare(NV_REV_PORT)) {
            Endpoint *endpoint = configComponent.getRevServer();
            if (endpoint == NULL) {
                endpoint = new Endpoint();
                configComponent.setRevServer(endpoint);
            }
            endpoint->setPort(stoi(value));
        }
#endif // ifdef SEEC_ENABLED
        else {
            SD_LOG(LOG_ERR, "unrecognized parameter: %s", key.c_str());
            processed = false;
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

bool isOtherComponent(string key)
{
    return !(key.compare(NV_COMMENT) &&
           key.compare(NV_VERIFIER) &&
           key.compare(NV_PROVER) &&
           key.compare(NV_FIREWALL) &&
           key.compare(NV_APP_SERVER) &&
           key.compare(NV_REV_SERVER));
}

bool isOptional(string key)
{
    return !(key.compare(NV_PARAMS) &&
           key.compare(NV_ENCRYPTKEY_SIZE) &&
           key.compare(NV_ENCRYPTKEY) &&
           key.compare(NV_SIGNKEY) &&
           key.compare(NV_SIGNKEY_SIZE) &&
           key.compare(NV_REVKEY) &&
           key.compare(NV_REVKEY_SIZE) &&
           key.compare(NV_EURIPATH) &&
           key.compare(NV_EURIPATH_SIZE) &&
           key.compare(NV_SURIPATH) &&
           key.compare(NV_SURIPATH_SIZE) &&
           key.compare(NV_RURIPATH) &&
           key.compare(NV_RURIPATH_SIZE) &&
           key.compare(NV_TIMEPATH) &&
           key.compare(NV_TIMEPATH_SIZE) &&
           key.compare(NV_MQTT_REV_TOPIC) &&
           key.compare(NV_REV_PROTOCOL) &&
           key.compare(NV_REV_ADDRESS) &&
           key.compare(NV_REV_PORT));
}

void Config::parseFile(const string &filename)
{
    if (!exists(filename)) {
        SD_LOG(LOG_ERR, "file not exists: '%s'", filename.c_str());
        exit(1);
    }

    ifstream fin(filename);

    string line, key, value;
    bool inComp        = false;
    bool skipping      = false;
    Endpoint *endpoint = NULL;

    bool isProver = !component.compare(NV_PROVER);

    while (getline(fin, line)) {
        Utils::trim(line);
        if (line.size() == 0 || line[0] == '#')
            continue;

        stringstream s(line);
        getline(s, key, ' ');
        getline(s, value, ' ');

        if (skipping) {
            if (!key.compare("end"))
                skipping = false;
            continue;
        }
        if (!inComp) {
            if (parseTopLevel(isProver, key, value)) {
                continue;
            }
        }
        if (inComp) {
            if (!key.compare(NV_ID)) {
                configComponent.setID(value);
            }
            else if (!key.compare("incoming")) {
                endpoint = new Endpoint();
                configComponent.setIncoming(endpoint);
            }
            else if (!key.compare("outgoing")) {
                endpoint = new Endpoint();
                configComponent.setOutgoing(endpoint);
            }
            else if (!key.compare("outgoing2")) {
                endpoint = new Endpoint();
                configComponent.setOutgoing2(endpoint);
            }
            else if (!key.compare("aService")) {
                endpoint = new Endpoint();
                configComponent.setAService(endpoint);
            }
            else if (!key.compare(NV_PROTOCOL)) {
                endpoint->setProtocol(Endpoint::toProtocol(value));
            }
            else if (!key.compare(NV_ADDRESS)) {
                endpoint->setAddress(value);
            }
            else if (!key.compare(NV_PORT)) {
                endpoint->setPort(stoi(value));
            }
            else if (!key.compare("end")) {
                inComp = false;
            }
        }
        else if (!key.compare(component)) {
            inComp = true;
        }
        else if (isOtherComponent(key)) {
            skipping = true;
        }
        else if (!isOptional(key)) {
            SD_LOG(LOG_ERR, "unrecognized key %s", key.c_str());
        }
    }
}
