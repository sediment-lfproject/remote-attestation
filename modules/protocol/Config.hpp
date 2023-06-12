/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once

#include <fstream>

#include "nv.h"

#include "Enum.hpp"
#include "ConfigComponent.hpp"
#include "Endpoint.hpp"
#include "Log.hpp"

class Config
{
protected:
    int log_level       = 8;
    KeyEncType key_dist = KEY_ENC_TYPE_JEDI;

    uint32_t report_interval     = 5;   // device reporting interval
    uint32_t key_change_interval = 600; // in seconds
    bool enc_enabled        = true;     // whether to encrypt sensor data
    bool auth_enabled       = true;
    bool attest_enabled     = true;
    bool seec_enabled       = true;
    bool sign_enabled       = true;
    bool key_change_enabled = true;
    bool key_enc_enabled    = true;

    uint32_t passport_period = 10 * 24 * 60 * 60; // in seconds
    bool pass_thru_enabled   = false;             // for easier testing and debugging

    uint32_t payload_size = 32; // sensor data payload, (minimum is

    string component;
    ConfigComponent configComponent;

    string jstr;
    bool download = false; // whether to download config to the device

    int num_cycles = 5;  // number of cycles in the WKD-IBE case
    int iterations = 10; // number of iterations in each cycle

    // temporary buffers to hold key data loaded from flash/file for provers
    vector<uint8_t> enc_key;
    vector<uint8_t> attest_key;
    vector<uint8_t> auth_key;

    DataTransport transport = TRANSPORT_SEDIMENT;

    string fwScript; // firewall script to run on Alert message bby Firewall

    string mqttUrl = "127.0.0.1";
    string topicPub;
    string topicSub;

public:
    Config()
    { }

    Config(string component)
    {
        this->component = component;
    }

    vector<string> parse_cmdline(int argc, char *argv[]);
    void print_usage(char *cmd);
    bool parseTopLevel(bool isProver, string &key, string &value);
    void parseFile(const string &filename);
    void update(string &lines);

    static KeyEncType toKeyEncType(string method);
    static DataTransport toDataTransport(string transport);

    string toString()
    {
        return SD_TO_STRING(
            NV_KEY_DIST        ": " + TO_KEY_ENC_TYPE(key_dist) + "\n"
            + NV_REPORT_INTVL    ": " + to_string(report_interval) + "\n"
            + NV_KEY_CHG_INTVL   ": " + to_string(key_change_interval) + "\n"
            + NV_ENCRYPT         ": " + (enc_enabled ? "true" : "false") + "\n"
            + NV_AUTHENTICATION  ": " + (auth_enabled ? "true" : "false") + "\n"
            + NV_ATTEST          ": " + (attest_enabled ? "true" : "false") + "\n"
            + NV_PASSPORT_PERIOD ": " + to_string(passport_period) + "\n"
            + NV_PASS_THRU       ": " + (pass_thru_enabled ? "true" : "false") + "\n"
            + NV_PAYLOAD_SIZE    ": " + to_string(payload_size) + "\n"
            + NV_LOG_LEVEL       ": " + to_string(log_level) + "\n" +

            "Component: " + configComponent.toString());
    }

    int getLogLevel() const
    {
        return log_level;
    }

    void setLogLevel(int logLevel = 8)
    {
        this->log_level = logLevel;
    }

    bool isPassThru() const
    {
        return pass_thru_enabled;
    }

    void setPassThru(bool passThru = false)
    {
        this->pass_thru_enabled = passThru;
    }

    KeyEncType getKeyDistMethod() const
    {
        return key_dist;
    }

    void setKeyDistMethod(KeyEncType keyDistMethod = KEY_ENC_TYPE_JEDI)
    {
        this->key_dist = keyDistMethod;
    }

    uint32_t getReportInterval() const
    {
        return report_interval;
    }

    void setReportInterval(uint32_t reportInterval = 5)
    {
        this->report_interval = reportInterval;
    }

    uint32_t getKeyChangeInterval() const
    {
        return key_change_interval;
    }

    void setKeyChangeInterval(uint32_t keyChangeInterval = 600)
    {
        this->key_change_interval = keyChangeInterval;
    }

    uint32_t getPassportPeriod() const
    {
        return passport_period;
    }

    void setPassportPeriod(uint32_t passportPeriod = 10 * 24 * 60 * 60)
    {
        this->passport_period = passportPeriod;
    }

    bool isEncryptionEnabled() const
    {
        return enc_enabled;
    }

    void setEncryptionEnabled(bool encryptionEnabled = true)
    {
        this->enc_enabled = encryptionEnabled;
    }

    bool isAuthenticationEnabled() const
    {
        return auth_enabled;
    }

    void setAuthenticationEnabled(bool authenticationEnabled = true)
    {
        this->auth_enabled = authenticationEnabled;
    }

    bool isAttestationEnabled() const
    {
        return attest_enabled;
    }

    void setAttestationEnabled(bool attestationEnabled = true)
    {
        this->attest_enabled = attestationEnabled;
    }

    ConfigComponent& getComponent()
    {
        return configComponent;
    }

    void setComponent(const ConfigComponent &configComponent)
    {
        this->configComponent = configComponent;
    }

    bool isSigningEnabled() const
    {
        return sign_enabled;
    }

    void setSigningEnabled(bool signingEnabled = true)
    {
        this->sign_enabled = signingEnabled;
    }

    bool isKeyChangeEnabled() const
    {
        return key_change_enabled;
    }

    void setKeyChangeEnabled(bool keyChangeEnabled = true)
    {
        this->key_change_enabled = keyChangeEnabled;
    }

    uint32_t getPayloadSize() const
    {
        return payload_size;
    }

    void setPayloadSize(uint32_t payloadSize = 32)
    {
        this->payload_size = payloadSize;
    }

    bool isSeecEnabled() const
    {
        return seec_enabled;
    }

    void setSeecEnabled(bool seecEnabled = true)
    {
        this->seec_enabled = seecEnabled;
    }

    bool isKeyEncryptionEnabled() const
    {
        return key_enc_enabled;
    }

    void setKeyEncryptionEnabled(bool keyEncryptionEnabled = true)
    {
        this->key_enc_enabled = keyEncryptionEnabled;
    }

    string& getJstr()
    {
        return jstr;
    }

    int getIterations() const
    {
        return iterations;
    }

    void setIterations(int iterations = 120)
    {
        this->iterations = iterations;
    }

    int getNumCycles() const
    {
        return num_cycles;
    }

    void setNumCycles(int numCycles = 10)
    {
        this->num_cycles = numCycles;
    }

    bool isDownload() const
    {
        return download;
    }

    void setDownload(bool download = false)
    {
        this->download = download;
    }

    vector<uint8_t>& getAttestKey()
    {
        return attest_key;
    }

    vector<uint8_t>& getAuthKey()
    {
        return auth_key;
    }

    vector<uint8_t>& getEncKey()
    {
        return enc_key;
    }

    DataTransport getTransport() const
    {
        return transport;
    }

    void setTransport(DataTransport transport = TRANSPORT_SEDIMENT)
    {
        this->transport = transport;
    }

    const string& getFwScript() const
    {
        return fwScript;
    }
    
    const string& getMqttUrl()
    {
        return mqttUrl;
    }

    void setMqttUrl(string &mqttUrl)
    {
        this->mqttUrl = mqttUrl;
    }

    const string& getTopicPub()
    {
        return topicPub;
    }

    void setTopicPub(string &topicPub)
    {
        this->topicPub = topicPub;
    }    

    const string& getTopicSub()
    {
        return topicSub;
    }

    void setTopicSub(string &topicSub)
    {
        this->topicSub = topicSub;
    }   
};
