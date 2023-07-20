/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <ctime>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "Comm.hpp"
#include "Seec.hpp"
#include "Utils.hpp"
#include "Verifier.hpp"
#include "CryptoServer.hpp"

using namespace std;

int getFirmwareSize(const string &filename)
{
    int fd = open(filename.c_str(), O_RDONLY);

    if (fd < 0) {
        SD_LOG(LOG_ERR, "cannot open file: %s", filename.c_str());
        return 0;
    }

    // Obtain the filesize.
    struct stat sb;
    if (fstat(fd, &sb) == -1) {
        SD_LOG(LOG_ERR, "fstat error: %s", filename);
        close(fd);
        return 0;
    }
    close(fd);

    return (int) sb.st_size;
}

Message * Verifier::decodeMessage(uint8_t dataArray[], uint32_t len)
{
    Vector data(dataArray, len);

    if (!isWellFormed(dataArray, len))
        return NULL;

    Message *message = NULL;
    MessageID id     = (MessageID) * data.at(MESSAGE_ID_OFFSET);

    switch (id) {
    case ATTESTATION_REQUEST:
        message = new AttestationRequest();
        break;
    case EVIDENCE:
        message = new Evidence();
        break;
    case PASSPORT_RESPONSE:
        message = new PassportResponse();
        break;
    default:
        SD_LOG(LOG_ERR, "verifier decodeMessage: unhandled message:  %s", TO_MESSAGE_ID(id).c_str());
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

Message * Verifier::handleMessage(DeviceManager &deviceManager, Message *message, EndpointSock *src, Device *device,
  uint8_t *serialized,
  uint32_t len)
{
    // TODO
    (void) serialized;
    (void) len;
    Message *response = NULL;
    MessageID id      = message->getId();

    switch (id) {
    case ATTESTATION_REQUEST:
        response = handleAttestationRequest(deviceManager, (AttestationRequest *) message, src, device);
        break;
    case EVIDENCE:
        response = handleEvidence(deviceManager, (Evidence *) message, src, device);
        break;
    case PASSPORT_RESPONSE:
        response = handlePassportResponse((PassportResponse *) message, device);
        break;
    default:
        SD_LOG(LOG_WARNING, "unexpected message: %s", message->idToString().c_str());
    }

    return response;
}

void normalizeEvidenceTypes(vector<uint8_t> &types)
{
    EvidenceType udfs[] = {
        EVIDENCE_UDF1,
        EVIDENCE_UDF2,
        EVIDENCE_UDF3,
    };

    bool hasUdf = false;

    for (uint32_t i = 0; i < sizeof(udfs) / sizeof(EvidenceType); i++) {
        if (std::find(types.begin(), types.end(), udfs[i]) != types.end()) {
            hasUdf = true;
        }
    }
    if (!hasUdf)
        return;

    if (std::find(types.begin(), types.end(), EVIDENCE_UDF_LIB) == types.end()) {
        types.push_back(EVIDENCE_UDF_LIB);
    }
}

Message * Verifier::handleAttestationRequest(DeviceManager &deviceManager, AttestationRequest *attReq,
  EndpointSock *srcEp, Device *device)
{
    if (device == NULL) {
        SD_LOG(LOG_ERR, "null device");
        return NULL;
    }

    uint32_t cp = attReq->getCounter();
    uint32_t cv = stoi(deviceManager.getCol(device, COL_SQN));
    if (cp <= cv) {
        SD_LOG(LOG_ERR, "out of date Attestation Request SQN: Cv=%d, Cp=%d", cv, cp);
        return NULL;
    }

    Challenge *challenge = new Challenge();
    challenge->setDeviceID(attReq->getDeviceID());
    challenge->setBlockSize(getFirmwareSize(getSedimentHome() + device->getFirmware()));
    challenge->setBlockCount(1);

    vector<uint8_t> &types = device->getEvidenceTypes();
    normalizeEvidenceTypes(types);
    challenge->getEvidenceTypes().put(&types[0], types.size());

    deviceManager.update(device, COL_SQN, to_string(cp));

    int saved = srcEp->getPort();
    srcEp->setPort(attReq->getPort());
    deviceManager.update(device, COL_PROVER_EP, srcEp->toStringOneline());
    srcEp->setPort(saved);

    challenge->setCounter(cp);

    vector<uint8_t> &nonce = challenge->getNonce();
    device->copyNonce(nonce); // save it for verification

    return challenge;
}

Message * Verifier::handleEvidence(DeviceManager &deviceManager, Evidence *evidence, EndpointSock *src, Device *device)
{
    if (device == NULL) {
        SD_LOG(LOG_ERR, "null device");
        return NULL;
    }

    const time_t ts = (time_t) evidence->getTimestamp();
    string tss      = asctime(localtime(&ts));
    tss.pop_back();
    statsFile << tss << ","
              << ts << ","
              << evidence->getDeviceID() << ","
              << TO_MEAS_TYPE(evidence->getMeasurement().getType()) << ","
              << evidence->getMeasurement().getElapsedTime() << ","
              << evidence->getMeasurement().getOptional() << ","
              << endl;

    string &deviceID = evidence->getDeviceID();
    uint32_t counter = stoi(deviceManager.getCol(device, COL_SQN));
    if (counter != evidence->getCounter()) {
        SD_LOG(LOG_ERR, "unexpected SQN: %d (Verifier) v.s. %d (Prover)", counter, evidence->getCounter());
        return NULL;
    }

    vector<EvidenceItem> items = evidence->getEvidenceItems();
    uint8_t numEvidence        = items.size();
    vector<uint8_t> &types     = device->getEvidenceTypes();
    normalizeEvidenceTypes(types);

    bool verified = true;
    if (numEvidence < types.size()) {
        verified = false;
        SD_LOG(LOG_ERR, "insufficient #evidence: %d expected, %d received", types.size(), numEvidence);
    }
    else {
        vector<uint8_t> presented;
        for (int i = 0; i < numEvidence; i++) {
            EvidenceType type = items[i].getType();

            if (std::find(types.begin(), types.end(), type) != types.end()) {
                presented.push_back(type);
            }
            else {
                SD_LOG(LOG_WARNING, "unrequested evidence type: %s", Log::toEvidencetype(type).c_str());
            }

            switch (type) {
            case EVIDENCE_FULL_FIRMWARE:
            case EVIDENCE_UDF_LIB:
                verified &= verifyFullFirmware(&items[i], device, type);
                break;
            case EVIDENCE_OS_VERSION:
                verified &= verifyOsVersion(&items[i], device);
                break;
            case EVIDENCE_BOOT_TIME:
                verified &= verifyBootTime(&items[i], device);
                break;
            case EVIDENCE_CONFIGS:
                verified &= verifyConfigs(&items[i], device, type);
                break;
            case EVIDENCE_UDF1:
            case EVIDENCE_UDF2:
            case EVIDENCE_UDF3:
                verified &= verifyUDF(&items[i], device, type);
                break;
            case EVIDENCE_SPARSE_FIRMWARE:
            case EVIDENCE_APP_FIRMWARE_VERSION:
            case EVIDENCE_BIOS_VERSION:
            case EVIDENCE_LOCATION:
            default:
                verified = false;
                SD_LOG(LOG_ERR, "unsupported evidence type: %d", type);
                break;
            }
            if (!verified)
                break;
        }
        if (verified && presented.size() != types.size()) {
            SD_LOG(LOG_ERR, "requested evidence not presetned");
            verified = false;
        }
    }
    deviceManager.update(device, COL_LAST_ATTESTATION, to_string(getTimestamp()));
    deviceManager.update(device, COL_STATUS, to_string(verified));

    sendAlert(deviceManager, verified ? PASS : FAILED_ATTEST, device->getId(), src);

    if (!verified) {
        SD_LOG(LOG_ERR, "device %s not verified", deviceID.c_str());
        if (!config.isPassThru()) {
            publish(evidence, verified);
            return NULL;
        }
    }
    SD_LOG(LOG_INFO, "all evidence verified for device %s", deviceID.c_str());

    publish(evidence, verified);

    Grant *grant = new Grant();
    grant->setDeviceID(deviceID);
    prepareGrant(grant);

    return grant;
}

/**
 * Firewall cc verifier the passport response it sends to a prover.
 */
Message * Verifier::handlePassportResponse(PassportResponse *passportResponse, Device *device)
{
    if (device == NULL) {
        SD_LOG(LOG_ERR, "null device");
        return NULL;
    }

#ifdef SEEC_ENABLED
    Seec *seec = device->getSeec();
    if (seec == NULL)
        return NULL;

    KeyBox &keyBox = passportResponse->getAttKeyBox();
    if (keyBox.getEncType() == KEY_ENC_TYPE_JEDI ||
      keyBox.getEncType() == KEY_ENC_TYPE_RSA)
    {
        seec->decryptKey(keyBox);
    }
#endif // ifdef SEEC_ENABLED
    // ack; content irrelevant
    Message *dummy = new Message(DUMMY);
    dummy->setDeviceID(passportResponse->getDeviceID());

    return dummy;
}

void Verifier::prepareGrant(Grant *grant)
{
    setTimestamp(grant);
    uint32_t issueDate = grant->getTimestamp();
    Passport &passport = grant->getPassport();
    passport.setIssueDate(issueDate);
    passport.setExpireDate(issueDate + config.getPassportPeriod());
    passport.setProverId(grant->getDeviceID());
    passport.setVerifierId(config.getComponent().getID());

    // exclude the signature
    Vector &signature = passport.getSignature();

    // serialize the passport into an array
    uint32_t size = passport.getSize();

    Vector data(size);

    passport.encode(data);
    size -= (SIGNATURE_LEN_LEN + signature.size()); // exclude the signature in the verification

    // sign the serialized passport
    uchar *sig  = NULL;
    size_t slen = 0;
    cryptoServer.sign_it((const unsigned char *) data.at(0), size, &sig, &slen);
    // TODO: free sig
    signature.resize(slen);
    signature.put(sig, slen);
}

bool Verifier::verifyFullFirmware(EvidenceItem *item, Device *device, EvidenceType type)
{
    string filename = (type == EVIDENCE_UDF_LIB) ? "lib/sediment_udf.so" : device->getFirmware();
    filename = getSedimentHome() + filename;
    int fileSize = getFirmwareSize(filename);

    int fd = open(filename.c_str(), O_RDONLY);
    if (fd < 0) {
        SD_LOG(LOG_ERR, "cannot open file: %s", filename.c_str());
        return false;
    }

    unsigned char *bufPtr = (unsigned char *) mmap(0, fileSize, PROT_READ, MAP_SHARED, fd, 0);
    if (bufPtr == 0) {
        SD_LOG(LOG_ERR, "mmap error: %s", filename.c_str());
        close(fd);
        return false;
    }
    return verifyHashing(item, device, type, bufPtr, fileSize, -1);
}

bool Verifier::verifyConfigs(EvidenceItem *item, Device *device, EvidenceType type)
{
    string filename = getSedimentHome() + device->getConfigs();
    int fileSize;

    char * gatherConfigBlocks(const string &filename, int *size, int **report_interval);
    int *dummy;
    unsigned char *bufPtr = (unsigned char *) gatherConfigBlocks(filename, &fileSize, &dummy);
    if (bufPtr == 0) {
        SD_LOG(LOG_ERR, "config error: %s", filename.c_str());
        return false;
    }
    bool val = verifyHashing(item, device, type, bufPtr, fileSize, -1);
    free(bufPtr);

    return val;
}

bool Verifier::verifyHashing(EvidenceItem *item, Device *device, EvidenceType type, unsigned char *bufPtr, int fileSize,
  int fd)
{
    EvidenceEncoding encoding = item->getEncoding();
    if (encoding != ENCODING_HMAC_SHA256) {
        SD_LOG(LOG_ERR, "%s envidence must be encoded as HMAC_SHA256", Log::toEvidencetype(type).c_str());
        return false;
    }

    vector<uint8_t> nonce = device->getNonce();
    Block blocks[]        = {
        { .block = &nonce[0], .size    = (int) nonce.size() },
        { .block = bufPtr,    .size    = fileSize           }
    };
    uint8_t digest[Crypto::FW_DIGEST_LEN];

    Seec *seec     = device->getSeec();
    Crypto *crypto = seec->getCrypto();
    if (crypto == NULL) {
        SD_LOG(LOG_ERR, "null crypto: %s");
        if (fd > 0)
            close(fd);
        return false;
    }
    crypto->checksum(KEY_ATTESTATION, blocks, sizeof(blocks) / sizeof(Block), digest, Crypto::FW_DIGEST_LEN);

    Vector &vecEvidence = item->getEvidence();
    int memcpy_resp     = memcmp((char *) vecEvidence.at(0), digest, vecEvidence.size());
    if (memcpy_resp != 0) {
        SD_LOG(LOG_ERR, "%s checksum is incorrect", Log::toEvidencetype(type).c_str());
        SD_LOG(LOG_INFO, "Expected: %s", Log::toHex((char *) digest, vecEvidence.size()).c_str());
        if (fd > 0)
            close(fd);
        return false;
    }
    if (fd > 0)
        close(fd);
    SD_LOG(LOG_INFO, "%s checksum is correct", Log::toEvidencetype(type).c_str());

    return true;
}

bool Verifier::verifyOsVersion(EvidenceItem *item, Device *device)
{
    const string &expected = device->getOsVersion();
    Vector &received       = item->getEvidence();

    bool correct = false;
    EvidenceEncoding encoding = item->getEncoding();

    if (encoding == ENCODING_HMAC_SHA256) {
        SD_LOG(LOG_ERR, "HMAC_SHA256 is not supported for OS version, yet");
    }
    else if (encoding == ENCODING_ENCRYPTED) {
        Seec *seec     = device->getSeec();
        Crypto *crypto = seec->getCrypto();
        if (crypto == NULL) {
            SD_LOG(LOG_ERR, "null crypto");
        }
        else {
            int len      = received.size(); // include leading IV
            int dec_size = len - Crypto::IV_SIZE;
            char decrypted[dec_size + 1];
            decrypted[dec_size] = '\0';
            crypto->decrypt((unsigned char *) decrypted, len,
              (unsigned char *) received.at(Crypto::IV_SIZE), dec_size,
              (unsigned char *) received.at(0), Crypto::IV_SIZE);
            int memcpy_resp = memcmp((char *) decrypted, (char *) &expected[0], expected.size());
            if (memcpy_resp != 0) {
                SD_LOG(LOG_ERR, "unexpected OS version, %s v.s. %s", expected.c_str(), decrypted);
            }
            else {
                SD_LOG(LOG_INFO, "OS version is correct: %s", expected.c_str());
                correct = true;
            }
        }
    }
    return correct;
}

bool Verifier::verifyBootTime(EvidenceItem *item, Device *device)
{
    (void) device;

    Vector &vecEvidence = item->getEvidence();
    uint32_t boot_time  = ntohl(*(int *) vecEvidence.at(0));

    uint32_t days = boot_time / 86400;
    uint32_t rem  = boot_time % 86400;

    uint32_t hours = rem / 3600;
    rem = rem % 3600;

    uint32_t min = (rem / 60);
    uint32_t sec = rem % 60;

    SD_LOG(LOG_INFO, "boot time was %d day(s) %02d:%02d:%02d ago", days, hours, min, sec);
    return true;
}

bool Verifier::verifyUDF(EvidenceItem *item, Device *device, EvidenceType type)
{
    EvidenceEncoding encoding = item->getEncoding();

    if (encoding != ENCODING_ENCRYPTED) {
        SD_LOG(LOG_ERR, "UDF evidence needs to be encrypted");
        return false;
    }

    Seec *seec     = device->getSeec();
    Crypto *crypto = seec->getCrypto();
    if (crypto == NULL) {
        SD_LOG(LOG_ERR, "null crypto");
        return false;
    }

    Vector &received = item->getEvidence();
    int len      = received.size(); // include leading IV
    int dec_size = len - Crypto::IV_SIZE;
    char decrypted[dec_size + 1];
    decrypted[dec_size] = '\0';

    crypto->decrypt((unsigned char *) decrypted, len,
      (unsigned char *) received.at(Crypto::IV_SIZE), dec_size,
      (unsigned char *) received.at(0), Crypto::IV_SIZE);

    char expects[] = " OK"; // TODO
    if (strstr(decrypted, expects) == NULL) {
        SD_LOG(LOG_ERR, "%s failed: %s", Log::toEvidencetype(type).c_str(), decrypted);
        return false;
    }

    SD_LOG(LOG_INFO, "%s is correct: %s", Log::toEvidencetype(type).c_str(), decrypted);
    return true;
}

void * Verifier::serviceControl(void *p)
{
    Verifier *verifier = (Verifier *) p;

    verifier->runService();

    return NULL;
}

string Verifier::receiveDeviceID(int ctrl_sock)
{
    const int SERIAL_SIZE = 64;
    char serial[SERIAL_SIZE];

    int bytesRead = read(ctrl_sock, serial, SERIAL_SIZE);

    if (bytesRead < 0) {
        SD_LOG(LOG_ERR, "could not read serial# from the client.");
        close(ctrl_sock);
        return "";
    }
    int eos = (bytesRead < SERIAL_SIZE) ? bytesRead : (SERIAL_SIZE - 1);
    serial[eos] = '\0';

    string deviceID(serial);

    return deviceID;
}

void Verifier::runService()
{
    int cport = aService->getPort();
    DeviceManager deviceManager(dbName);

    int service_sock;
    struct sockaddr_in client;

    int server_fd = Comm::setup(cport);

    if (server_fd < 0) {
        SD_LOG(LOG_ERR, "control: socket cannot be created.");
        return;
    }

    while (1) {
        socklen_t client_len = sizeof(client);
        service_sock = accept(server_fd, (struct sockaddr *) &client, &client_len);
        if (service_sock == -1) {
            SD_LOG(LOG_ERR, "control: accept error");
            continue;
        }

        string line = receiveDeviceID(service_sock);
        Utils::trim(line);
        int space      = line.find(" ");
        Device *device = NULL;
        string type    = line.substr(0, space);
        if (!type.compare("ip")) {
            string addr = line.substr(space + 1);
            string ep   = "TCP:" + addr + ":8899";
            device = deviceManager.findDeviceByIP(ep);
        }
        else if (!type.compare("id")) {
            int secondSpace = line.substr(space + 1).find(" ") + type.length();
            string deviceID = line.substr(space + 1, secondSpace - space);
            device = deviceManager.findDevice(deviceID);
            sendAlert(deviceManager, Reason::REQUESTED, deviceID, NULL);
        }

        if (device == NULL) {
            SD_LOG(LOG_ERR, "unknown device: %s", line.c_str());
        }
        else {
            SD_LOG(LOG_INFO, "attestation requested");
        }
        close(service_sock);
    }
    close(server_fd);
    SD_LOG(LOG_DEBUG, "control: server closed");
}

void Verifier::sendAlert(DeviceManager &deviceManager, Reason reason, string deviceID, EndpointSock *src)
{
    Alert alert;

    alert.setReason(reason);
    alert.setVerifierId(config.getComponent().getID());
    alert.setDeviceID(deviceID);
    if (src != NULL) {
        alert.setEndpoint(*src);
    }

    Vector &signature = alert.getSignature();

    uint32_t total;
    uint8_t *result = alert.serialize(&total);
    if (result == NULL) {
        SD_LOG(LOG_ERR, "failed to serialize result");
        return;
    }
    // finalizeAndSend() below will change timestamp; exclude it in signature
    int excluded = alert.getSigCoverage(signature, &total);

    uchar *sig  = NULL;
    size_t slen = 0;
    cryptoServer.sign_it((const unsigned char *) &result[excluded], total, &sig, &slen);
    // TODO: free sig
    signature.resize(slen);
    signature.put(sig, slen);

    free(result);

    int alert_sock = Comm::connectTcp(alertEndpoint);
    if (alert_sock < 0) {
        SD_LOG(LOG_WARNING, "alert not sent");
    }
    else {
        finalizeAndSend(deviceManager, alert_sock, &alert);
        close(alert_sock);
        SD_LOG(LOG_DEBUG, "sent alert.........");
    }
}

void Verifier::publish(Evidence *evidence, bool verified)
{
    if (noGUI)
        return;

    int pub_sock = Comm::connectTcp(guiEndpoint);

    if (pub_sock < 0) {
        SD_LOG(LOG_WARNING, "verification result not published");
        return;
    }
    string &deviceID = evidence->getDeviceID();

    char rsp[64];
    int us = evidence->getMeasurement().getElapsedTime();
    sprintf(rsp, "%s,%s,%1.6f", deviceID.c_str(), verified ? "correct" : "incorrect", us / (double) 1e6);
    send(pub_sock, (const char *) rsp, strlen(rsp), 0);

    close(pub_sock);

    Log::plain(COLOR_NONE, "publish %s", rsp);
}
