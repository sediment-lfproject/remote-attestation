/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#include "iostream"

#include "Vector.hpp"
#include "Message.hpp"

using namespace std;

string Message::idToString()
{
    return TO_MESSAGE_ID(id);
}

uint8_t * Message::serialize(uint32_t *len)
{
    uint32_t size = getSize();

    Vector data(size);

    encode(data);

    uint8_t *result = (uint8_t *) malloc(size);
    if (result == NULL) {
        SD_LOG(LOG_ERR, "failed to allocate");
        return NULL;
    }
    uint8_t *buf = data.at(0);
    memcpy(result, buf, size);

    *len = size;

    return result;
}

void Message::decode(Vector &data)
{
    Codec::getInt(data, TOTAL_SIZE_LEN); // total size
    authToken.decode(data);

    int cand = Codec::getInt(data, MESSAGE_ID_LEN);
    id = DECODE_CHECK(MessageID, cand, MIN_MSG_ID, MAX_MSG_ID, "bad message ID");

    timestamp = Codec::getInt(data, TIMESTAMP_LEN);

    int deviceIdLen = Codec::getInt(data, DEVICE_ID_LEN);
    Codec::getString(data, deviceIdLen, deviceID);
}

void Message::encode(Vector &data)
{
    int totalSize = data.getCapacity();

    Codec::putInt(totalSize, data, TOTAL_SIZE_LEN);
    authToken.encode(data);

    Codec::putInt(id, data, MESSAGE_ID_LEN);
    Codec::putInt(timestamp, data, TIMESTAMP_LEN);

    int deviceIdLen = deviceID.length();
    Codec::putInt(deviceIdLen, data, DEVICE_ID_LEN);
    Codec::putString(data, deviceID);
}

void ConfigMessage::decode(Vector &data)
{
    Message::decode(data);

    int configsLen = Codec::getInt(data, CONFIGS_LEN);
    Codec::getByteArray(data, configsLen, configs);
}

void ConfigMessage::encode(Vector &data)
{
    Message::encode(data);

    Codec::putInt(configs.size(), data, CONFIGS_LEN);
    Codec::putByteArray(data, configs);
}

void PassportRequest::decode(Vector &data)
{
    Message::decode(data);

    int cand = Codec::getInt(data, REASON_LEN);
    reason = DECODE_CHECK(Reason, cand, MIN_REASON, MAX_REASON, "bad reason");
}

void PassportRequest::encode(Vector &data)
{
    Message::encode(data);

    Codec::putInt(reason, data, REASON_LEN);
}

void PassportResponse::decode(Vector &data)
{
    Message::decode(data);

    endpoint.decode(data);
    attKeyBox.decode(data);
    measurementList.decode(data);
}

void PassportResponse::encode(Vector &data)
{
    Message::encode(data);

    endpoint.encode(data);
    attKeyBox.encode(data);
    measurementList.encode(data);
}

void AttestationRequest::decode(Vector &data)
{
    Message::decode(data);
    port    = Codec::getInt(data, PORT_LEN);
    counter = Codec::getInt(data, COUNTER_LEN);
}

void AttestationRequest::encode(Vector &data)
{
    Message::encode(data);
    Codec::putInt(port, data, PORT_LEN);
    Codec::putInt(counter, data, COUNTER_LEN);
}

void Challenge::decode(Vector &data)
{
    Message::decode(data);

    int evidenceLen = Codec::getInt(data, NUM_EVIDENCE_LEN);
    Codec::getByteArray(data, evidenceLen, evidenceTypes);

    blockSize  = Codec::getInt(data, BLOCK_SIZE_LEN);
    blockCount = Codec::getInt(data, BLOCK_COUNT_LEN);
    counter    = Codec::getInt(data, COUNTER_LEN);

    int nonceLen = Codec::getInt(data, NONCE_LEN);
    nonce.clear();
    Codec::getByteArray(data, nonceLen, nonce);
}

void Challenge::encode(Vector &data)
{
    Message::encode(data);

    Codec::putInt(evidenceTypes.size(), data, NUM_EVIDENCE_LEN);
    Codec::putByteArray(data, evidenceTypes);

    Codec::putInt(blockSize, data, BLOCK_SIZE_LEN);
    Codec::putInt(blockCount, data, BLOCK_COUNT_LEN);
    Codec::putInt(counter, data, COUNTER_LEN);

    Codec::putInt(nonce.size(), data, NONCE_LEN);
    Codec::putByteArray(data, nonce);
}

void EvidenceItem::decode(Vector &data)
{
    int cand = Codec::getInt(data, EVIDENCE_TYPE_LEN);

    type = DECODE_CHECK(EvidenceType, cand, MIN_EVEIDENCE_TYPE, MAX_EVIDENCE_TYPE, "bad evidence type");

    cand     = Codec::getInt(data, EVIDENCE_ENCODING_LEN);
    encoding = DECODE_CHECK(EvidenceEncoding, cand, MIN_EVIDENCE_ENCODING, MAX_EVIDENCE_ENCODING,
        "bad evidence encoding");

    int evidenceLen = Codec::getInt(data, EVIDENCE_SIZE_LEN);
    Codec::getByteArray(data, evidenceLen, evidence);
}

void EvidenceItem::encode(Vector &data)
{
    Codec::putInt(type, data, EVIDENCE_TYPE_LEN);
    Codec::putInt(encoding, data, EVIDENCE_ENCODING_LEN);

    Codec::putInt(evidence.size(), data, EVIDENCE_SIZE_LEN);
    Codec::putByteArray(data, evidence);
}

void Evidence::decode(Vector &data)
{
    Message::decode(data);

    measurement.decode(data);
    counter = Codec::getInt(data, COUNTER_LEN);

    int numEvidence = Codec::getInt(data, NUM_EVIDENCE_LEN);
    evidenceItems.resize(numEvidence);
    for (int i = 0; i < numEvidence; i++) {
        evidenceItems[i].decode(data);
    }
}

void Evidence::encode(Vector &data)
{
    Message::encode(data);

    measurement.encode(data);
    Codec::putInt(counter, data, COUNTER_LEN);

    Codec::putInt(evidenceItems.size(), data, NUM_EVIDENCE_LEN);
    for (uint32_t i = 0; i < evidenceItems.size(); i++) {
        evidenceItems[i].encode(data);
    }
}

void Passport::decode(Vector &data)
{
    int proverIDLen = Codec::getInt(data, PROVER_ID_LEN);

    Codec::getString(data, proverIDLen, proverID);

    int verifierIDLen = Codec::getInt(data, VERIFIER_ID_LEN);
    Codec::getString(data, verifierIDLen, verifierID);

    issueDate  = Codec::getInt(data, TIMESTAMP_LEN);
    expireDate = Codec::getInt(data, TIMESTAMP_LEN);

    int signatureLen = Codec::getInt(data, SIGNATURE_LEN_LEN);
    Codec::getByteArray(data, signatureLen, signature);
}

void Passport::encode(Vector &data)
{
    int proverIDLen = proverID.length();

    Codec::putInt(proverIDLen, data, PROVER_ID_LEN);
    Codec::putString(data, proverID);

    int verifierIDLen = verifierID.length();
    Codec::putInt(verifierIDLen, data, VERIFIER_ID_LEN);
    Codec::putString(data, verifierID);

    Codec::putInt(issueDate, data, TIMESTAMP_LEN);
    Codec::putInt(expireDate, data, TIMESTAMP_LEN);

    Codec::putInt(signature.size(), data, SIGNATURE_LEN_LEN);
    Codec::putByteArray(data, signature);
}

void Grant::decode(Vector &data)
{
    Message::decode(data);

    passportLen = Codec::getInt(data, PASSPORT_LEN);
    passport.decode(data);
}

void Grant::encode(Vector &data)
{
    Message::encode(data);

    Codec::putInt(passportLen, data, PASSPORT_LEN);
    passport.encode(data);
}

void PassportCheck::decode(Vector &data)
{
    Message::decode(data);

    passport.decode(data);
}

void PassportCheck::encode(Vector &data)
{
    Message::encode(data);

    passport.encode(data);
}

void Permission::decode(Vector &data)
{
    Message::decode(data);

    int cand = Codec::getInt(data, ADMITTANCE_LEN);
    admittance = DECODE_CHECK(Admittance, cand, MIN_ADMIT, MAX_ADMIT, "bad admittance");

    cand  = Codec::getInt(data, CAUSE_LEN);
    cause = DECODE_CHECK(Cause, cand, MIN_CAUSE, MAX_CAUSE, "bad cause");

    endpoint.decode(data);
}

void Permission::encode(Vector &data)
{
    Message::encode(data);

    Codec::putInt(admittance, data, ADMITTANCE_LEN);
    Codec::putInt(cause, data, CAUSE_LEN);

    endpoint.encode(data);
}

void KeyChange::decode(Vector &data)
{
    Message::decode(data);
    encKeyBox.decode(data);
    signKeyBox.decode(data);
    measurementList.decode(data);
}

void KeyChange::encode(Vector &data)
{
    Message::encode(data);
    encKeyBox.encode(data);
    signKeyBox.encode(data);
    measurementList.encode(data);
}

void Data::decode(Vector &data)
{
    Message::decode(data);

    measurementList.decode(data);

    int iv_size = Codec::getInt(data, IV_LEN);
    Codec::getByteArray(data, iv_size, iv);

    int payload_size = Codec::getInt(data, PAYLOAD_SIZE_LEN);
    Codec::getByteArray(data, payload_size, payload);

    int checksum_size = Codec::getInt(data, DATA_CHECKSUM_LEN);
    Codec::getByteArray(data, checksum_size, checksum);
}

void Data::encode(Vector &data)
{
    Message::encode(data);

    measurementList.encode(data);

    Codec::putInt(iv.size(), data, IV_LEN);
    Codec::putByteArray(data, iv);

    Codec::putInt(payload.size(), data, PAYLOAD_SIZE_LEN);
    Codec::putByteArray(data, payload);

    Codec::putInt(checksum.size(), data, DATA_CHECKSUM_LEN);
    Codec::putByteArray(data, checksum);
}

void Result::decode(Vector &data)
{
    Message::decode(data);

    int cand = Codec::getInt(data, ACCEPTANCE_LEN);
    acceptance = DECODE_CHECK(Acceptance, cand, MIN_ACCEPT, MAX_ACCEPT, "bad acceptance");
}

void Result::encode(Vector &data)
{
    Message::encode(data);

    Codec::putInt(acceptance, data, ACCEPTANCE_LEN);
}

void Alert::decode(Vector &data)
{
    Message::decode(data);

    int verifierIdLen = Codec::getInt(data, VERIFIER_ID_LEN);
    Codec::getString(data, verifierIdLen, verifierID);

    int cand = Codec::getInt(data, REASON_LEN);
    reason = DECODE_CHECK(Reason, cand, MIN_REASON, MAX_REASON, "bad reason");

    endpoint.decode(data);

    int signatureLen = Codec::getInt(data, SIGNATURE_LEN_LEN);
    Codec::getByteArray(data, signatureLen, signature);
}

void Alert::encode(Vector &data)
{
    Message::encode(data);

    int verifierIdLen = verifierID.length();
    Codec::putInt(verifierIdLen, data, VERIFIER_ID_LEN);
    Codec::putString(data, verifierID);

    Codec::putInt(reason, data, REASON_LEN);

    endpoint.encode(data);

    Codec::putInt(signature.size(), data, SIGNATURE_LEN_LEN);
    Codec::putByteArray(data, signature);
}

void Revocation::decode(Vector &data)
{
    Message::decode(data);

    int payload_size = Codec::getInt(data, PAYLOAD_SIZE_LEN);
    Codec::getByteArray(data, payload_size, payload);

    int checksum_size = Codec::getInt(data, DATA_CHECKSUM_LEN);
    Codec::getByteArray(data, checksum_size, checksum);
}

void Revocation::encode(Vector &data)
{
    Message::encode(data);

    Codec::putInt(payload.size(), data, PAYLOAD_SIZE_LEN);
    Codec::putByteArray(data, payload);

    Codec::putInt(checksum.size(), data, DATA_CHECKSUM_LEN);
    Codec::putByteArray(data, checksum);
}
