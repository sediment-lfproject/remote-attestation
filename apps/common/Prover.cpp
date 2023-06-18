/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#include <vector>
#include <random>
#include <climits>
#include <algorithm>
#include <functional>

#include "Prover.hpp"

#include "KeyBox.hpp"
#include "sediment.h"

#include "Enum.hpp"
#include "Comm.hpp"
#include "Board.hpp"
#include "Log.hpp"

using namespace std;

#define MESSAGE_BUF_SIZE 2048
#define MAX_FAILURES     3
#define MAX_DELAY        1024
#define RA_PORT          8899 // TODO: on-deman RA

static bool isAttestation(MessageID id);

static int full_reset_count = 0;
static bool proc_completed  = false;

void Prover::run()
{
    attestSqn = board->getAttestSqn();
    seecSqn = board->getSeecSqn();

    if (config.getTransport() == TRANSPORT_SEDIMENT_MQTT) {
        string url = config.getMqttUrl();
        bool ok    = mqtt.connect(url, config.getComponent().getID());
        if (!ok)
            return;
    }

    int proc_fail_count = 0;
    while (true) {
        Endpoint *ep;
        if (isAttestation(expecting)) {
            ep = &endpoint;
        }
        else {
            ep = &rpEndpoint;
        }

        mySock = Comm::connectTcp(ep);
        if (mySock < 0) {
            toGiveup(false, &proc_fail_count, true);
        }
        else {
            proc_completed = true;
            runProcedure(mySock);
            toGiveup(proc_completed, &proc_fail_count, true);

            close(mySock);
            SD_LOG(LOG_DEBUG, "closed socket");
        }
        pause(proc_fail_count);
    }
    mqtt.disconnect();
}

void Prover::runProcedure(int peer_sock)
{
    uint8_t buf[MESSAGE_BUF_SIZE];
    int expected = 0;
    int received = 0;
    char *ptr    = (char *) buf;
    int avail    = MESSAGE_BUF_SIZE;

    bool towait = moveTo(expecting, NULL);

    if (!towait)
        return;

    int bad_msg_count = 0;
    while (true) {
        int bytesRead = recv(peer_sock, ptr, avail, 0);
        if (bytesRead <= 0) {
            if (toGiveup(false, &bad_msg_count, false))
                break;
            else
                continue;
        }
        if (expected == 0 && bytesRead >= TOTAL_SIZE_LEN) {
            uint16_t *si = (uint16_t *) buf;
            expected = ntohs(*si);
        }
        received += bytesRead;
        if (expected == 0 || received < expected) {
            ptr   += bytesRead;
            avail -= bytesRead;
            continue;
        }

        Message *response = decodeMessage(buf, expected);
        if (response == NULL) {
            if (toGiveup(false, &bad_msg_count, false))
                break;
            else
                continue;
        }
        SD_LOG(LOG_DEBUG, "received.....%s", response->toString().c_str());

        if (authenticate(response, buf, expected)) {
            bool msg_success = handleMessage(response);
            delete response;
            if (toGiveup(msg_success, &bad_msg_count, false))
                break;
        }
        else {
            delete response;
        }
        received = 0;
        expected = 0;
        ptr      = (char *) buf;
        avail    = MESSAGE_BUF_SIZE;
    }
}

void Prover::pause(int bad_proc_count)
{
    int delay = 0;

    if (expecting == DATA) {
        if (cause == CAUSE_PERIODIC) {
            // delay = config.getReportInterval();
            delay = board->getReportInterval();  // for demo purposes, the interval is reloaded each time
        }
    }
    else if (expecting == PASSPORT_REQUEST) {
        if (cause == CAUSE_PERIODIC) {
            delay = passport.getExpireDate() - board->getTimestamp();
            SD_LOG(LOG_WARNING, "passport expired in %d seconds", delay);
        }
        else if (cause == CAUSE_INVALID_PASSPORT) {
            delay = board->getReportInterval();  // for demo purposes, the interval is reloaded each time
        }
    }

    if (bad_proc_count > 0) {
        delay = (1 << ((full_reset_count * MAX_FAILURES + bad_proc_count - 1) / MAX_FAILURES));
        delay = (delay > MAX_DELAY) ? MAX_DELAY : delay;
    }

    if (delay > 0)
        board->sleepSec(delay);
}

/**
 * Decode a byte array into a Message object and return a pointer to it.
 * Caller is responsible for deleting the object.
 */
Message * Prover::decodeMessage(uint8_t dataArray[], uint32_t len)
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
    case PASSPORT_RESPONSE:
        message = new PassportResponse();
        break;
    case CHALLENGE:
        message = new Challenge();
        break;
    case GRANT:
        message = new Grant();
        break;
    case PERMISSION:
        message = new Permission();
        break;
    case RESULT:
        message = new Result();
        break;
    case DUMMY:
        message = new Message();
        break;
    default:
        SD_LOG(LOG_ERR, "decodeMessage: unhandled message: %d", id);
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

bool Prover::moveTo(MessageID id, Message *received)
{
    Message *to_send = NULL;
    bool towait      = true;

    switch (id) {
    case CONFIG:
        to_send   = prepareConfig(received);
        expecting = CONFIG;
        break;
    case PASSPORT_REQUEST:
        to_send   = preparePassportRequest(received);
        expecting = PASSPORT_RESPONSE;
        break;
    case ATTESTATION_REQUEST:
        to_send   = prepareAttestationRequest(received);
        expecting = CHALLENGE;
        break;
    case EVIDENCE:
        to_send   = prepareEvidence(received);
        expecting = GRANT;
        break;
    case PASSPORT_CHECK:
        to_send   = preparePassportCheck(received);
        expecting = PERMISSION;
        break;
    case KEY_CHANGE:
        to_send   = prepareKeyChange(received);
#if defined(SEEC_ENABLED)
        expecting = REVOCATION_CHECK; // if SEEC is enabled, check for Revocation(s) before preparing data
#else
        expecting = DATA; // no response, just move to the next procedure
#endif
        towait    = false;
        break;
    case REVOCATION_CHECK:
        SD_LOG(LOG_DEBUG, "REVOCATION_CHECK NOT implemented yet!");
        expecting = REVOCATION_ACK;
        towait = false;
        break;
    case REVOCATION_ACK:
        SD_LOG(LOG_DEBUG, "REVOCATION_ACK NOT implemented yet!");
        expecting = DATA;  // no response, just move to the next procedure
        towait = false;
        break;
    case DATA:
        to_send = prepareData(received);

        if (config.getTransport() == TRANSPORT_SEDIMENT_MQTT) {
#if defined(SEEC_ENABLED)
            expecting = REVOCATION_CHECK; // if SEEC is enabled, check for Revocation(s) before preparing data next time
#endif
            towait = false;
            cause = CAUSE_PERIODIC;
        }
        else {
            expecting = RESULT;
        }
        break;
    default:
        if (received != NULL)
            SD_LOG(LOG_ERR, "state not changed: unexpected dst %s ", TO_MESSAGE_ID(id).c_str());
        towait = false;
    }

    if (to_send != NULL) {
        to_send->setDeviceID(config.getComponent().getID());
        finalizeAndSend(mySock, to_send);
        delete to_send;
    }
    return towait;
}

bool Prover::handleMessage(Message *message)
{
    if (message->getDeviceID().compare(config.getComponent().getID()) != 0) {
        SD_LOG(LOG_ERR, "unexpected message: %s", message->idToString().c_str());
        return false;
    }

    switch (expecting) {
    case CONFIG:
        return handleConfig(message);

    case PASSPORT_RESPONSE:
        return handlePassportResponse(message);

    case CHALLENGE:
        return handleChallenge(message);

    case GRANT:
        return handleGrant(message);

    case PERMISSION:
        return handlePermission(message);

    case RESULT:
        return handleResult(message);

    default:
        SD_LOG(LOG_ERR, "unexpected message received %s", message->toString().c_str());
    }
    return false;
}

Message * Prover::prepareConfig(Message *received)
{
    (void) received;
    ConfigMessage *configReq = new ConfigMessage();

    //    Vector& cfg = configReq->getConfigs();
    //    cfg.resize(0);
    return configReq;
}

bool Prover::authenticate(Message *received, uint8_t *serialized, uint32_t len)
{
    if (!config.isAuthenticationEnabled()) {
        SD_LOG(LOG_WARNING, "authentication disabled");
        return true;

        ;
    }

    if (received == NULL) {
        SD_LOG(LOG_ERR, "null message, cannot authenticate");
        return false;
    }

    Crypto *crypto = seec.getCrypto();
    if (crypto == NULL) {
        SD_LOG(LOG_ERR, "null crypto,  cannot authenticate");
        return false;
    }

    return crypto->authenticate(received->getAuthToken(), serialized, len, received->getPayloadOffset());
}

bool Prover::handleConfig(Message *received)
{
    MessageID id = received->getId();

    if (id == CONFIG) { // if the server does not return a config message, just move on.
        ConfigMessage *configReq = (ConfigMessage *) received;

        Vector configs = configReq->getConfigs();
        string configStr((char *) configs.at(0));
        configStr.resize(configs.size());

        int oldCycles     = config.getNumCycles();
        int oldIterations = config.getIterations();

        config.update(configStr);

        int newCycles     = config.getNumCycles();
        int newIterations = config.getIterations();

        if (oldCycles != newCycles || oldIterations != newIterations) {
            seec.init(newCycles, newIterations);
            SD_LOG(LOG_WARNING, "cycles: %d, iterations: %d", newCycles, newIterations);
        }
    }

    if (board != NULL)
        board->setBaseTime(received->getTimestamp());

    if (!config.isAttestationEnabled()) {
        transit(DATA, CAUSE_POWER_ON);
    }
    else {
        transit(PASSPORT_REQUEST, CAUSE_INIT);
    }
    return true;
}

Message * Prover::preparePassportRequest(Message *received)
{
    (void) received;
    PassportRequest *passReq = new PassportRequest();
    passReq->setReason(reason);

    return passReq;
}

bool Prover::handlePassportResponse(Message *received)
{
    MessageID id = received->getId();

    if (id != PASSPORT_RESPONSE) {
        SD_LOG(LOG_ERR, "expecting PASSPORT_RESPONSE, received %s", received->toString().c_str());
        return false;
    }

    if (board != NULL) {
        board->setBaseTime(received->getTimestamp());
        attestSqn++;
        board->saveAttestSqn(attestSqn);
    }

    PassportResponse *passportResponse = (PassportResponse *) received;
    endpoint.copy(passportResponse->getEndpoint());

    if (config.isKeyChangeEnabled()) {
#ifdef SEEC_ENABLED
        KeyBox &keyBox = passportResponse->getAttKeyBox();
        seec.decryptKey(keyBox);
#endif
    }

    expecting = ATTESTATION_REQUEST;
    return true;
}

Message * Prover::prepareAttestationRequest(Message *received)
{
    (void) received;
    AttestationRequest *attReq = new AttestationRequest();
    attReq->setPort(RA_PORT);
    attReq->setCounter(attestSqn);

    return attReq;
}

bool Prover::handleChallenge(Message *received)
{
    MessageID id = received->getId();

    if (id != CHALLENGE) {
        SD_LOG(LOG_ERR, "expecting CHALLENGE, recevied %s", received->toString().c_str());
        return false;
    }
    Challenge *challenge = (Challenge *) received;

    Crypto *crypto = seec.getCrypto();
    if (crypto == NULL) {
        SD_LOG(LOG_ERR, "null crypto");
        return false;
    }
    else {
        uint32_t verifierSqn = challenge->getCounter();
        if (attestSqn > verifierSqn) {
            SD_LOG(LOG_ERR, "out of date verifier SQN (%d), prover (%d)", verifierSqn, attestSqn);
            return false;
        }
        else if (attestSqn < verifierSqn) {
            SD_LOG(LOG_ERR, "suspicious verifier SQN (%d), prover (%d)", verifierSqn, attestSqn);
            attestSqn = verifierSqn + 1;
            board->saveAttestSqn(attestSqn);
            restartAttestionRequest();
            return false;
        }
        board->saveAttestSqn(attestSqn);
    }
    proc_completed = false;
    moveTo(EVIDENCE, challenge);
    return true;
}

Message * Prover::prepareEvidence(Message *received)
{
    MessageID id = received->getId();

    if (id != CHALLENGE) {
        SD_LOG(LOG_ERR, "expecting CHALLENGE, received %s", received->idToString().c_str());
        return NULL;
    }

    Challenge *challenge = (Challenge *) received;
    Evidence *evidence   = new Evidence();

    Vector &evidenceTypes = challenge->getEvidenceTypes();
    int numEvidenceType   = evidenceTypes.size();
    vector<EvidenceItem> items(numEvidenceType);
    bool ok   = true;
    int count = 0;
    uint32_t elapsed;
    int optional;
    evidence->setCounter(attestSqn);

    for (int i = 0; i < numEvidenceType; i++) {
        bool itemOk       = true;
        EvidenceType type = DECODE_CHECK(EvidenceType, *evidenceTypes.at(i),
            MIN_EVEIDENCE_TYPE, MAX_EVIDENCE_TYPE, "BAD_EVDIENCE_TYPE");
        switch (type) {
        case EVIDENCE_FULL_FIRMWARE:
            itemOk = prepareEvidenceFullFirmware(challenge, &items[count], &elapsed, &optional);
            count++;
            break;
        case EVIDENCE_OS_VERSION:
            itemOk = preapreEvidenceOsVersion(challenge, &items[count]);
            count++;
            break;
        case EVIDENCE_BOOT_TIME:
            itemOk = preapreEvidenceBootTime(challenge, &items[count]);
            count++;
            break;
        case EVIDENCE_CONFIGS:
            itemOk = prepareEvidenceConfigs(challenge, &items[count], &elapsed, &optional);
            count++;       
            break;
        case EVIDENCE_UDF_LIB:
#ifdef PLATFORM_RPI        
            itemOk = prepareEvidenceUDFLib(challenge, &items[count], &elapsed, &optional);
            count++;
#else
            SD_LOG(LOG_ERR, "UDF lib not supported for non-Linux based devices");
            itemOk = false;
#endif            
            break;
        case EVIDENCE_UDF1:
        case EVIDENCE_UDF2:
        case EVIDENCE_UDF3:
#ifdef PLATFORM_RPI
            itemOk = preapreEvidenceUDF(challenge, &items[count], type);
            count++;
#else
            SD_LOG(LOG_ERR, "UDF not supported for non-Linux based devices");
            itemOk = false;
#endif
            break;
        default:
            SD_LOG(LOG_ERR, "unhandled evidence type: %s", TO_EVIDENCETYPE(type).c_str());
            // TODO
            //            itemOk = false;
            break;
        }
        ok &= itemOk;
    }
    if (!ok)
        return NULL;

    evidence->setDeviceID(config.getComponent().getID());
    evidence->setMeasurement(MEAS_ATTESTATION, elapsed, optional);
    items.resize(count);
    evidence->setEvidenceItems(items);

    return evidence;
}

bool Prover::handleGrant(Message *received)
{
    MessageID id = received->getId();

    if (id != GRANT) {
        SD_LOG(LOG_ERR, "expecting GRANT, received %s", received->idToString().c_str());
        return false;
    }

    Grant *grant = (Grant *) received;
    passport.copy(grant->getPassport());

#if !defined(SEEC_ENABLED)
    transit(PASSPORT_REQUEST, CAUSE_PERIODIC);
#else
    if (config.isSeecEnabled())
        expecting = PASSPORT_CHECK;
    else {
        expecting = ATTESTATION_REQUEST;
    }
#endif
    proc_completed   = true;
    full_reset_count = 0;

    return true;
}

Message * Prover::preparePassportCheck(Message *received)
{
    (void) received;
    return new PassportCheck(passport);
}

bool Prover::handlePermission(Message *received)
{
    MessageID id = received->getId();

    if (id != PERMISSION) {
        SD_LOG(LOG_ERR, "expecting PERMISSION, received %s", received->toString().c_str());
        return false;
    }

    endpoint.copy(((Permission *) received)->getEndpoint());

    transit(DATA, cause);

    return true;
}

Message * Prover::prepareKeyChange(Message *received)
{
    (void) received;
#ifdef SEEC_ENABLED
    KeyChange *keyChange  = new KeyChange(config.getKeyDistMethod());
    KeyEncType keyEncType = config.getKeyDistMethod();

    KeyBox &encKeyBox = keyChange->getEncKeyBox();
    encKeyBox.setKeyPurpose(KEY_ENCRYPTION);
    encKeyBox.setEncType(keyEncType);

    KeyBox &signKeyBox = keyChange->getSignKeyBox();
    signKeyBox.setKeyPurpose(KEY_AUTH);
    signKeyBox.setEncType(keyEncType);

    if (keyEncType == KEY_ENC_TYPE_JEDI) {
        MeasurementList &list = keyChange->getMeasurementList();
        seec.encryptKey(encKeyBox, board, list, config.getComponent().getID());
    }
    else if (keyEncType == KEY_ENC_TYPE_RSA) {
        MeasurementList &list = keyChange->getMeasurementList();
        seec.encryptKey(encKeyBox, board, list, config.getComponent().getID());
        seec.encryptKey(signKeyBox, board, list, config.getComponent().getID());
    }
    else if (keyEncType == KEY_ENC_TYPE_EC) {
        SD_LOG(LOG_ERR, "EC key change not implemened");
    }
    seec.setLastChangeKey(board->getTimestamp());

    return keyChange;

#else // ifdef SEEC_ENABLED
    SD_LOG(LOG_ERR, "KEY CHANGE disabled");
    return NULL;

#endif // ifdef SEEC_ENABLED
}

Message * Prover::prepareData(Message *received)
{
    (void) received;
#ifdef SEEC_ENABLED
    Data *data = new Data();

    uint32_t temp  = 0;
    uint32_t humid = 0;

    if (board == NULL) {
        SD_LOG(LOG_ERR, "Prover: null board");
        return NULL;
    }
    temp  = board->getTemperature();
    humid = board->getHumidity();

    seecSqn++;
    board->saveSeecSqn(seecSqn);

    Crypto *crypto = seec.getCrypto();
    if (crypto == NULL) {
        SD_LOG(LOG_ERR, "null crypto");
        return NULL;
    }

    const int message_size = config.getPayloadSize();
    char message[message_size];
    memset(message, '_', message_size); // pad the buffer
    int n = snprintf(message, message_size, "%d,%d,%d", seecSqn, temp, humid);
    message[message_size - 1] = '\0';
    message[n] = '_';
    Vector &payload = data->getPayload();
    MeasurementList &measList = data->getMeasurementList();
    if (config.isEncryptionEnabled()) {
        if (config.isSeecEnabled()) {
            seec.encryptData(data->getIv(), data->getPayload(), message_size, measList, board,
              config.getComponent().getID(), crypto, message);
        }
        else {
            int payloadSize = message_size;
            payload.resize(payloadSize);

            Vector &iv = data->getIv();
            iv.inc(Crypto::IV_SIZE);

            uint64_t start_time = board->getTimeInstant();
            crypto->encrypt((unsigned char *) message, message_size,
              (unsigned char *) payload.at(0), payloadSize,
              (unsigned char *) iv.at(0), Crypto::IV_SIZE);
            uint32_t elapsed = board->getElapsedTime(start_time);
            measList.add(MEAS_AES_ENCRYPTION, elapsed, payloadSize);

            payload.inc(payloadSize);
        }
    }
    else {
        payload.resize(message_size);
        uint64_t start_time = board->getTimeInstant();
        memcpy(payload.at(0), message, message_size);
        uint32_t elapsed = board->getElapsedTime(start_time);
        measList.add(MEAS_PLAINTEXT_COPY, elapsed, message_size);
        payload.inc(message_size);
    }

    Vector &cksum = data->getChecksum();
    if (config.isSigningEnabled()) {
        cksum.resize(Crypto::DATA_CHECKSUM_BYTES);
        Block blocks[] = {
            { .block = payload.at(0), .size = (int) payload.size() },
        };
        uint64_t start_time = board->getTimeInstant();
        crypto->checksum(KEY_AUTH, blocks, sizeof(blocks) / sizeof(Block), cksum.at(0), Crypto::DATA_CHECKSUM_BYTES);
        uint32_t elapsed = board->getElapsedTime(start_time);
        measList.add(MEAS_HMAC_SIGNING, elapsed, payload.size());
        cksum.inc(Crypto::DATA_CHECKSUM_BYTES);
    }
    else {
        cksum.resize(0);
    }

    return data;

#else // ifdef SEEC_ENABLED
    SD_LOG(LOG_ERR, "DATA disabled");
    return NULL;

#endif // ifdef SEEC_ENABLED
}

bool Prover::handleResult(Message *received)
{
    MessageID id = received->getId();

    if (id != RESULT) {
        SD_LOG(LOG_ERR, "expecting RESULT, received %s", received->idToString().c_str());
        return false;
    }

    expecting = DATA;

    Result *result = (Result *) received;
    Acceptance acceptance = result->getAcceptance();
    if (acceptance == REJECT || acceptance == NO_COMM) {
        rejectCount++;
        if (rejectCount >= MAX_REJECT) {
            rejectCount = 0;
            transit(PASSPORT_REQUEST, CAUSE_DATA_REJECTED);
        }
    }
    else if (acceptance == ATTEST) {
        rejectCount = 0;
        transit(PASSPORT_REQUEST, CAUSE_REQUESTED);
    }
    else if (isPassportExipred()) {
        transit(PASSPORT_REQUEST, CAUSE_INVALID_PASSPORT);
    }
    else if (acceptance == ACCEPT) {
        rejectCount = 0;
        transit(DATA, CAUSE_PERIODIC);
    }
    return true;
}

bool Prover::preapreEvidenceBootTime(Challenge *challenge, EvidenceItem *item)
{
    (void) challenge;
    item->setType(EVIDENCE_BOOT_TIME);
    item->setEncoding(ENCODING_CLEAR);

    uint32_t uptime = board->getUptime();

    Vector &evidence = item->getEvidence();
    evidence.resize(sizeof(uptime));

    uint32_t si = htonl(uptime);
    memcpy((char *) evidence.at(0), (char *) &si, sizeof(uptime));
    evidence.inc(sizeof(uptime));

    return true;
}

#ifdef PLATFORM_RPI
#include <dlfcn.h>
#include "sediment_udf.hpp"

string run_udf(EvidenceType evidenceType, string library)
{
    void *sediment = dlopen(library.c_str(), RTLD_LAZY);

    if (!sediment) {
        SD_LOG(LOG_ERR, "Cannot load library: %s", dlerror());
        return "FAILED";
    }

    dlerror(); // reset errors

    char symbol[128];
    int i = evidenceType - EVIDENCE_UDF1 + 1;
    sprintf(symbol, "create_udf%d", i);

    create_t *create_udf    = (create_t *) dlsym(sediment, symbol);
    const char *dlsym_error = dlerror();
    if (dlsym_error) {
        SD_LOG(LOG_ERR, "Cannot load symbol create: %s", dlsym_error);
        return "FAILED";
    }

    SedimentUDF *udf = create_udf();
    string result    = udf->attest();

    sprintf(symbol, "destroy_udf%d", i);
    destroy_t *destroy_udf = (destroy_t *) dlsym(sediment, symbol);
    dlsym_error = dlerror();
    if (dlsym_error) {
        SD_LOG(LOG_ERR, "Cannot load symbol destroy: %s", dlsym_error);
        return "FAILED";
    }

    destroy_udf(udf);
    dlclose(sediment);

    return result;
}

bool Prover::preapreEvidenceUDF(Challenge *challenge, EvidenceItem *item, EvidenceType evidenceType)
{
    (void) challenge;
    item->setType(evidenceType);
    item->setEncoding(ENCODING_ENCRYPTED);

    string library = sediment_home + "lib/sediment_udf.so";
    string udf = run_udf(evidenceType, library);
    int udflen = udf.size(); // strlen(udf);

    // Each block is 16 byte. If the clear-text is multiple of block size,
    // a whole new block is needed for padding.
    int payloadSize = (udflen / 16 + 1) * 16;

    unsigned char message[payloadSize] = { '0' };
    memcpy(message, (const char *) &udf[0], udflen);

    Vector &evidence = item->getEvidence();
    evidence.resize(Crypto::IV_SIZE + payloadSize); // put the IV at the beginning

    Crypto *crypto = seec.getCrypto();
    if (crypto == NULL) {
        SD_LOG(LOG_ERR, "null crypto");
        return false;
    }

    crypto->encrypt((unsigned char *) message, payloadSize,
      (unsigned char *) evidence.at(Crypto::IV_SIZE), payloadSize,
      (unsigned char *) evidence.at(0), Crypto::IV_SIZE);
    evidence.inc(Crypto::IV_SIZE + payloadSize);

    return true;
}

bool Prover::prepareEvidenceUDFLib(Challenge *challenge, EvidenceItem *item, uint32_t *elapsed, int *optional)
{
    uint32_t blockSize      = challenge->getBlockSize();
    string lib              = sediment_home + "lib/sediment_udf.so";
    const uint8_t *starting = (const uint8_t *) board->getStartingAddr(lib, &blockSize);

    SD_LOG(LOG_INFO, "attest firmware starting address: %0x", starting);

    return prepareEvidenceHashing(challenge, item, elapsed, optional, EVIDENCE_UDF_LIB, starting, blockSize);
}

#endif // ifdef PLATFORM_RPI

bool Prover::preapreEvidenceOsVersion(Challenge *challenge, EvidenceItem *item)
{
    (void) challenge;
    item->setType(EVIDENCE_OS_VERSION);
    item->setEncoding(ENCODING_ENCRYPTED); // TODO?

    char os[32] = { '0' }; // init to stop valgrind complaint about unintialized string
    board->getOS(os, 32);
    int oslen = strlen(os);

    // Each block is 16 byte. If the clear-text is multiple of block size,
    // a whole new block is needed for padding.
    int payloadSize = (oslen / 16 + 1) * 16;

    unsigned char message[payloadSize] = { '0' };
    memcpy(message, (const char *) &os[0], oslen);

    Vector &evidence = item->getEvidence();
    evidence.resize(Crypto::IV_SIZE + payloadSize); // put the IV at the beginning

    Crypto *crypto = seec.getCrypto();
    if (crypto == NULL) {
        SD_LOG(LOG_ERR, "null crypto");
        return false;
    }

    crypto->encrypt((unsigned char *) message, payloadSize,
      (unsigned char *) evidence.at(Crypto::IV_SIZE), payloadSize,
      (unsigned char *) evidence.at(0), Crypto::IV_SIZE);
    evidence.inc(Crypto::IV_SIZE + payloadSize);

    return true;
}

void Prover::restartAttestionRequest()
{
    if (attestRestarts++ >= MAX_ATTEST_RESTART) {
        SD_LOG(LOG_ERR, "Verifier failure");
        attestRestarts = 0;
        // XXX: Send message to other server
        cause = CAUSE_RESET;
        moveTo(PASSPORT_REQUEST, NULL);
        return;
    }
    moveTo(ATTESTATION_REQUEST, NULL);
}

bool Prover::prepareEvidenceFullFirmware(Challenge *challenge, EvidenceItem *item, uint32_t *elapsed, int *optional)
{
    uint32_t blockSize      = challenge->getBlockSize();
    string lib              = "sediment";
    const uint8_t *starting = (const uint8_t *) board->getStartingAddr(lib, &blockSize);

    SD_LOG(LOG_INFO, "attest firmware starting address: %0x", starting);

    return prepareEvidenceHashing(challenge, item, elapsed, optional, EVIDENCE_FULL_FIRMWARE, starting, blockSize);
}

bool Prover::prepareEvidenceConfigs(Challenge *challenge, EvidenceItem *item, uint32_t *elapsed, int *optional)
{
    uint32_t blockSize;
    char *starting = board->getConfigBlocks((int *)&blockSize);   // memoery allocation

    bool val = prepareEvidenceHashing(challenge, item, elapsed, optional, EVIDENCE_CONFIGS, (const uint8_t *)starting, blockSize);
    free(starting);

    return val;
}

bool Prover::prepareEvidenceHashing(Challenge *challenge, EvidenceItem *item, uint32_t *elapsed, 
    int *optional, EvidenceType evidenceType, const uint8_t *starting, uint32_t blockSize)
{
    vector<uint8_t> &nonce = challenge->getNonce();

    Block blocks[] = {
        { .block = &nonce[0], .size  = (int) nonce.size() },
        { .block = starting,  .size  = (int) blockSize    }
    };
    *optional = nonce.size() + blockSize;

    Vector &evidence = item->getEvidence();
    evidence.resize(Crypto::FW_DIGEST_LEN);

    Crypto *crypto = seec.getCrypto();
    if (crypto == NULL) {
        SD_LOG(LOG_ERR, "null crypto");
        return false;
    }

    uint64_t start_time = board->getTimeInstant();
    crypto->checksum(KEY_ATTESTATION, blocks, sizeof(blocks) / sizeof(Block), evidence.at(0), Crypto::FW_DIGEST_LEN);
    *elapsed = board->getElapsedTime(start_time);
    evidence.inc(Crypto::FW_DIGEST_LEN);

    item->setType(evidenceType);
    item->setEncoding(ENCODING_HMAC_SHA256);

    return true;    
}

void Prover::setTimestamp(Message *message)
{
    uint32_t ts = (board != NULL) ? board->getTimestamp() : 0;

    message->setTimestamp(ts);
}

void Prover::calAuthToken(Message *message, uint8_t *serialized, uint32_t len)
{
    Crypto *crypto = seec.getCrypto();

    if (crypto == NULL) {
        SD_LOG(LOG_ERR, "null crypto");
        return;
    }
    AuthToken &authToken = message->getAuthToken();
    crypto->calDigest(authToken, serialized, len, message->getPayloadOffset());
}

static bool isAttestation(MessageID id)
{
    switch (id) {
    case ATTESTATION_REQUEST:
    case CHALLENGE:
    case EVIDENCE:
    case GRANT:
        return true;

    default:
        return false;
    }
}

void Prover::resetProcedure(bool fullReset)
{
    if (fullReset) {
        transit(PASSPORT_REQUEST, CAUSE_RESET);
        full_reset_count++;
        return;
    }

    switch (expecting) {
    case PASSPORT_REQUEST:
    case PASSPORT_RESPONSE:
        transit(PASSPORT_REQUEST, CAUSE_RESET);
        break;
    case ATTESTATION_REQUEST:
    case CHALLENGE:
    case EVIDENCE:
    case GRANT:
        expecting = ATTESTATION_REQUEST;
        break;
    case REVOCATION_CHECK:
    case REVOCATION_ACK:
        expecting = REVOCATION_CHECK;
        break;
    case DATA:
    case RESULT:
        expecting = DATA;
        break;
    case PASSPORT_CHECK:
    case PERMISSION:
        expecting = PASSPORT_CHECK;
        break;
    default:
        // no change
        break;
    }
}

bool Prover::toGiveup(bool success, int *bad_count, bool fullReset)
{
    if (success) {
        *bad_count = 0;
        if (proc_completed)
            return true;
    }
    else {
        *bad_count = *bad_count + 1;
        if (*bad_count >= MAX_FAILURES) {
            proc_completed = false;
            resetProcedure(fullReset);
            SD_LOG(LOG_ERR, "giving up after %d %s failures",
              MAX_FAILURES, fullReset ? "procedure" : "message");
            return true;
        }
    }
    return false;
}

bool Prover::isPassportExipred()
{
    return (passport.getExpireDate() - board->getTimestamp()) < config.getReportInterval();
}

void Prover::handlePubData(char *data)
{
    (void) data;
}
