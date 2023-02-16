/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#include <unistd.h>
#include <ctime>

#include "Device.hpp"
#include "Log.hpp"
#include "CryptoServer.hpp"
#include "Comm.hpp"
#include "Message.hpp"
#include "Config.hpp"
#include "CryptoServer.hpp"
#include "Firewall.hpp"

using namespace std;

Message * Firewall::decodeMessage(uint8_t dataArray[], uint32_t len)
{
    Vector data(dataArray, len);

    if (!isWellFormed(dataArray, len))
        return NULL;

    Message *message = NULL;
    MessageID id     = (MessageID) * data.at(MESSAGE_ID_OFFSET);

    switch (id) {
    case CONFIG:
        message = new ConfigMessage();
        break;
    case PASSPORT_REQUEST:
        message = new PassportRequest();
        break;
    case PASSPORT_CHECK:
        message = new PassportCheck();
        break;
    case DATA:
        message = new Data();
        break;
    case ALERT:
        message = new Alert();
        break;
    case KEY_CHANGE:
        message = new KeyChange(KEY_ENC_TYPE_JEDI); // the key enc type will be overriden after decoding
        break;
    default:
        SD_LOG(LOG_ERR, "firewall decodeMessage: unhandled message: %s", TO_MESSAGE_ID(id).c_str());
        break;
    }
    if (message != NULL) {
        try {
            message->decode(data);
        }
        catch (...) {
            SD_LOG(LOG_ERR, "decodeMessage: message decode failed");
            message = NULL;
        }
    }
    return message;
}

Message * Firewall::handleMessage(Message *message, EndpointSock *src, Device *device, uint8_t *serialized,
  uint32_t len)
{
    (void) src;

    MessageID id = message->getId();

    Message *response = NULL;
    switch (id) {
    case CONFIG:
        response = handleConfigMessage((ConfigMessage *) message, device);
        break;
    case PASSPORT_REQUEST:
        response = handlePassportRequest((PassportRequest *) message, device);
        break;
    case PASSPORT_CHECK:
        response = handlePassportCheck((PassportCheck *) message, device);
        break;
    case DATA:
        response = handleData((Data *) message, device, serialized, len);
        break;
    case ALERT:
        response = handleAlert((Alert *) message, device);
        break;
    case KEY_CHANGE:
        response = handleKeyChange((KeyChange *) message, device, serialized, len);
        break;
    default:
        SD_LOG(LOG_ERR, "unexpected message: %d", id);
    }

    return response;
}

Message * Firewall::handleConfigMessage(ConfigMessage *configRequest, Device *device)
{
    (void) device;

    if (config.isDownload()) {
        ConfigMessage *configResponse = new ConfigMessage();
        configResponse->setConfigs(config.getJstr());
        configResponse->setDeviceID(configRequest->getDeviceID());

        return configResponse;
    }
    else {
        // not downloading, return a dummy response
        Message *message = new Message(DUMMY);
        message->setDeviceID(configRequest->getDeviceID());

        return message;
    }
}

Message * Firewall::handleData(Data *data, Device *device, uint8_t *serialized, uint32_t len)
{
    if (device == NULL) {
        SD_LOG(LOG_ERR, "null device");
        return NULL;
    }

    Acceptance accept;
    string &deviceID = data->getDeviceID();

    set<std::string>::iterator it = pendingDevices.find(deviceID);
    if (it != pendingDevices.end()) {
        accept = ATTEST;
        pendingDevices.erase(deviceID);
    }
    else {
        const time_t expired = (time_t) device->getPassportExpiryDate();
        if (expired < getTimestamp()) {
            if (!config.isAttestationEnabled()) {
                borderControl(deviceID, CORRECT);
                accept = forward(data, config, serialized, len);
            }
            else {
                SD_LOG(LOG_ERR, "passport expired: %s", asctime(localtime(&expired)));
                borderControl(deviceID, INCORRECT);
                accept = REJECT;
            }
        }
        else {
            // forwarder will determine drop/pass
            accept = forward(data, config, serialized, len);
        }
    }
    Result *result = new Result();
    result->setAcceptance(accept);
    result->setDeviceID(data->getDeviceID());

    return result;
}

Message * Firewall::handleAlert(Alert *alert, Device *device)
{
    (void) device;
    Vector &signature = alert->getSignature();
    size_t slen       = signature.size();

    uint32_t total;
    uint8_t *result = alert->serialize(&total);
    if (result == NULL) {
        SD_LOG(LOG_ERR, "failed to serialize result");
        return NULL;
    }
    int excluded = alert->getSigCoverage(signature, &total);

    int rc = cryptoServer.verify_it((const uchar *) &result[excluded], total, (uchar *) signature.at(0), slen);
    free(result);

    if (rc != 0) {
        SD_LOG(LOG_ERR, "failed to verify alert signatured");
        return NULL;
    }
    SD_LOG(LOG_INFO, "alert signature verified");

    Endpoint ep = alert->getEndpoint();

    string &deviceID = alert->getDeviceID();
    Reason reason    = alert->getReason();

    if (reason == PASS) {
        string fw = config.getFwScript() + " " + deviceID + " " + ep.getAddress() + " " + Log::toReason(reason);
        SD_LOG(LOG_INFO, "%s", fw.c_str());
        system(fw.c_str());
    }
    else if (reason == FAILED_ATTEST) {
        SD_LOG(LOG_ERR, "failed attestation");
        if (!config.isPassThru()) {
            reject(deviceID);
            pendingDevices.erase(deviceID);

            string fw = config.getFwScript() + " " + deviceID + " " + ep.getAddress() + " " + Log::toReason(reason);
            SD_LOG(LOG_INFO, "%s", fw.c_str());
            system(fw.c_str());
        }
    }
    else if (reason == USER_REJECT) {
        SD_LOG(LOG_ERR, "data rejected on user's request");

        reject(deviceID);
        pendingDevices.erase(deviceID);
    }
    else if (reason == REQUESTED) {
        pendingDevices.insert(deviceID);
    }

    return NULL;
}

Message * Firewall::handleKeyChange(KeyChange *keyChange, Device *device, uint8_t *serialized, uint32_t len)
{
    (void) device;

    if (!config.isAttestationEnabled())
        borderControl(keyChange->getDeviceID(), CORRECT);  // forwarder will pass
    forward(keyChange, serialized, len);

    return NULL;
}

Message * Firewall::handlePassportRequest(PassportRequest *passportRequest, Device *device)
{
    if (device == NULL) {
        SD_LOG(LOG_ERR, "null device");
        return NULL;
    }

    string &deviceID     = passportRequest->getDeviceID();
    Endpoint &verifierEp = device->getVerifierEndpoint();
    PassportResponse *passportResponse = new PassportResponse();

    passportResponse->setEndpoint(verifierEp);
    passportResponse->setDeviceID(deviceID);

    if (config.isKeyChangeEnabled()) {
        KeyBox &keyBox = passportResponse->getAttKeyBox();
        keyBox.setKeyPurpose(KEY_ATTESTATION);
#ifdef SEEC_ENABLED
        Seec *seec = device->getSeec();
        if (seec == NULL) {
            SD_LOG(LOG_ERR, "seec not found for device %s", deviceID.c_str());
            return NULL;
        }
        seec->encryptKey(keyBox, board, passportResponse->getMeasurementList(), deviceID);
        seec->setLastChangeKey(getTimestamp());
#endif
        carbonCopy(verifierEp, passportResponse);
    }
    else {
        KeyBox &keyBox = passportResponse->getAttKeyBox();
        keyBox.setKeyPurpose(KEY_ATTESTATION);
    }

    return passportResponse;
}

Message * Firewall::handlePassportCheck(PassportCheck *passportCheck, Device *device)
{
    if (device == NULL) {
        SD_LOG(LOG_ERR, "null device");
        return NULL;
    }

    string &deviceID     = passportCheck->getDeviceID();
    Passport &passport   = passportCheck->getPassport();
    const time_t expired = (time_t) passport.getExpireDate();
    if (expired < getTimestamp()) {
        SD_LOG(LOG_ERR, "passport expired: %s", asctime(localtime(&expired)));
        return NULL;
    }

    bool ok = validatePassport(deviceID, passport);
    borderControl(deviceID, ok ? CORRECT : INCORRECT);
    if (!ok) {
        return NULL;
    }

    device->update(COL_PASSPORT_EXPIRY, to_string(expired));
    device->setPassportExpiryDate(expired);

    const Endpoint relyingParty = device->getRelyingPartyEndpoint();
    Permission *permission      = new Permission();
    permission->setDeviceID(passportCheck->getDeviceID());

    permission->setAdmittance(GRANTED);
    permission->setCause(NONE);
    permission->setEndpoint(relyingParty);

    return permission;
}

bool Firewall::validatePassport(string &deviceID, Passport &passport)
{
    uint32_t size = passport.getSize();

    Vector data(size);

    passport.encode(data);

    Vector &signature = passport.getSignature();
    size_t slen       = signature.size();

    size -= (SIGNATURE_LEN_LEN + slen); // exclude the signature in the verification

    int rc = cryptoServer.verify_it((const uchar *) data.at(0), size, (uchar *) signature.at(0), slen);
    if (rc != 0) {
        SD_LOG(LOG_ERR, "%s invalid passport signature", deviceID.c_str());
        return false;
    }
    SD_LOG(LOG_INFO, "%s passport signature verified", deviceID.c_str());

    if (deviceID.compare(passport.getProverId()) != 0) {
        SD_LOG(LOG_ERR, "invalid passport owner: %s v.s. %s", deviceID.c_str(), passport.getProverId().c_str());
        return false;
    }
    SD_LOG(LOG_INFO, "%s passport prover ID verified", deviceID.c_str());

    time_t exp = passport.getExpireDate();
    char *tm   = asctime(localtime(&exp));
    tm[strlen(tm) - 1] = '\0'; // remove the \n
    if (exp < getTimestamp()) {
        SD_LOG(LOG_ERR, "%s passport expired on %s ", deviceID.c_str(), tm);
        return false;
    }
    SD_LOG(LOG_INFO, "%s passport valid until %s ", deviceID.c_str(), tm);

    return true;
}

void Firewall::carbonCopy(Endpoint &endpoint, Message *message)
{
    const int MAX_ATTEMPTS = 3;

    int sock = 0;
    int i    = 0;

    while (1) {
        sock = Comm::connectTcp((Endpoint *) &endpoint);
        if (sock > 0)
            break;
        i++;
        if (i >= MAX_ATTEMPTS) {
            SD_LOG(LOG_ERR, "cannot connect to %s", endpoint.toString().c_str());
            return;
        }
        sleep(1);
    }

    finalizeAndSend(sock, message);

    char buf[32];
    recv(sock, buf, 32, 0); // ack; content irrelevant
    close(sock);
}

Acceptance Firewall::forward(Data *data, Config &config, uint8_t *serialized, uint32_t len)
{
    string &deviceID = data->getDeviceID();
    auto map         = actions.find(deviceID);
    Acceptance accept;
    Vector &payload = data->getPayload();

    if (map == actions.end()) {
        SD_LOG(LOG_ERR, "device not found: %s", deviceID.c_str());
    }
    else if (map->second != CORRECT) {
        SD_LOG(LOG_WARNING, "device attestion is incorrect or no longer valid: %s", deviceID.c_str());
    }

    string payloadStr((const char *) payload.at(0));
    if (config.isEncryptionEnabled())
        payloadStr = Log::toHex(payload).c_str();
    if (map == actions.end() || map->second != CORRECT) {
        Log::plain(COLOR_RED, "DROP %11s %s", deviceID.c_str(), payloadStr.c_str());
        accept = REJECT;
    }
    else {
        Log::plain(COLOR_GREEN, "PASS %11s %s", deviceID.c_str(), payloadStr.c_str());

        int sock = Comm::connectTcp(appSvrEndpoint);
        if (sock < 0) {
            SD_LOG(LOG_ERR, "failed to connect: %s", appSvrEndpoint->toStringOneline().c_str());
            accept = REJECT;
        }
        else {
            bool sent = sendMessage(sock, DATA, serialized, len);
            close(sock);
            if (sent) {
                SD_LOG(LOG_DEBUG, "sent alert.........");
                accept = ACCEPT;
            }
            else {
                accept = REJECT;
            }
        }
    }
    return accept;
}

void Firewall::forward(KeyChange *keyChange, uint8_t *serialized, uint32_t len)
{
    string &deviceID = keyChange->getDeviceID();
    const char *id   = deviceID.c_str();
    auto map         = actions.find(deviceID);

    if (map == actions.end())
        SD_LOG(LOG_ERR, "device not found for key change: %s", id);
    else if (map->second != CORRECT) {
        SD_LOG(LOG_WARNING, "device attestion is incorrect or no longer valid: %s", id);
    }

    if (map == actions.end() || map->second != CORRECT) {
        SD_LOG(LOG_ERR, "device not passed attestation, key change dropped: %s", id);
    }
    else {
        int sock = Comm::connectTcp(appSvrEndpoint);
        if (sock < 0) {
            SD_LOG(LOG_ERR, "failed to connect: %s", appSvrEndpoint->toStringOneline().c_str());
        }
        else {
            bool sent = sendMessage(sock, KEY_CHANGE, serialized, len);
            close(sock);
            if (sent) {
                SD_LOG(LOG_DEBUG, "sent key change.........");
            }
        }
    }
}

bool Firewall::borderControl(string &deviceID, Action action)
{
    actions[deviceID] = action;

    return true;
}
