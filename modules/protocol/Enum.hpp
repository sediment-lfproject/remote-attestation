/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once

#define DECODE_CHECK(type, x, min, max, excp) (type) x
// exception disabled to reduce code size
// (x <= min || x >= max) ? throw new FailToDecodeException(excp) : (type)x

enum MessageID {
    MIN_MSG_ID          = 0,

    PASSPORT_REQUEST    = 1,
    PASSPORT_RESPONSE   = 2,

    ATTESTATION_REQUEST = 3,
    CHALLENGE           = 4,
    EVIDENCE            = 5,
    GRANT               = 6,

    ALERT               = 7,

    PASSPORT_CHECK      = 8,
    PERMISSION          = 9,

    DATA                = 10,
    RESULT              = 11,

    KEY_CHANGE          = 12,

    DUMMY               = 13,

    CONFIG              = 14,

    MAX_MSG_ID          = 15,
};

enum Reason {
    MIN_REASON      = 0,

    INIT            = 1,
    EXPIRATION      = 2,
    TIME_OUT        = 3,
    REQUESTED       = 4,
    SQN_OUT_OF_SYNC = 5,
    FAILED_AUTH     = 6,
    FAILED_ATTEST   = 7,
    USER_REJECT     = 8,
    PASS            = 9,

    MAX_REASON      = 10,
};

enum Admittance {
    MIN_ADMIT = 0,

    DENIED    = 1,
    GRANTED   = 2,

    MAX_ADMIT = 3,
};

enum Acceptance {
    MIN_ACCEPT = 0,

    ACCEPT     = 1,
    REJECT     = 2,
    ATTEST     = 3,
    NO_COMM    = 4,

    MAX_ACCEPT = 5,
};

enum Protocol {
    MIN_PROTOCOL = 0,

    TCP          = 1,
    UDP          = 2,
    BLUETOOTH    = 3,

    MAX_PROTOCOL = 4,
};

enum Cause {
    MIN_CAUSE        = 0,

    NONE             = 1,
    INVALID_PASSPORT = 2,

    MAX_CAUSE        = 3,
};

enum EvidenceType {
    MIN_EVEIDENCE_TYPE            = -1,

    EVIDENCE_FULL_FIRMWARE        = 0,
    EVIDENCE_SPARSE_FIRMWARE      = 1,
    EVIDENCE_APP_FIRMWARE_VERSION = 2,
    EVIDENCE_OS_VERSION           = 3,
    EVIDENCE_BIOS_VERSION         = 4,
    EVIDENCE_BOOT_TIME            = 5,
    EVIDENCE_LOCATION             = 6,

    EVIDENCE_UDF_LIB              = 0x40,
    EVIDENCE_UDF1                 = 0x41,
    EVIDENCE_UDF2                 = 0x42,
    EVIDENCE_UDF3                 = 0x43,

    MAX_EVIDENCE_TYPE             = 0x43,
};

enum EvidenceEncoding {
    MIN_EVIDENCE_ENCODING = -1,

    ENCODING_CLEAR        = 0,
    ENCODING_HMAC_SHA256  = 1,
    ENCODING_ENCRYPTED    = 2,

    MAX_EVIDENCE_ENCODING = 3,
};

enum Action {
    FAILED    = 0,
    INCORRECT = 1,
    CORRECT   = 2,
    UNKNOWN   = 3,
};

enum KeyEncType {
    MIN_KEY_ENC_TYPE  = -1,

    KEY_ENC_TYPE_JEDI = 0,
    KEY_ENC_TYPE_RSA  = 1,
    KEY_ENC_TYPE_EC   = 2,
    KEY_ENC_TYPE_NONE = 3,

    MAX_KEY_ENC_TYPE  = 4
};

enum KeyPurpose {
    MIN_KEY_PURPOSE = -1,

    KEY_ENCRYPTION  = 0,
    KEY_ATTESTATION = 1,
    KEY_AUTH        = 2,

    MAX_KEY_PURPOSE = 3,
};

enum MeasurementType {
    MIN_MEASUREMENT             = -1,

    MEAS_AES_ENCRYPTION         = 0,
    MEAS_ATTESTATION            = 1,
    MEAS_HMAC_SIGNING           = 2,

    MEAS_RSA_SIGNING            = 3,
    MEAS_RSA_VERIFYING          = 4,
    MEAS_RSA_ENCRYPTION         = 5,

    MEAS_JEDI_ENCRYPT           = 6,
    MEAS_JEDI_SETUP             = 7,
    MEAS_JEDI_KEYGEN            = 8,
    MEAS_JEDI_PRECOMPUTE        = 9,
    MEAS_JEDI_SIGN              = 10,
    MEAS_JEDI_QUALIFY_KEY       = 11,
    MEAS_JEDI_ADJUST_PRECOMPUTE = 12,

    MEAS_PLAINTEXT_COPY         = 13,
    MEAS_WKD_INIT               = 14,
    MEAS_CYCLE_INIT             = 15,
    MEAS_REGENERATE_STATE       = 16,
    MEAS_PUB_AUTH               = 17,

    MAX_MEASUREMENT             = 18,
};

enum DataTransport {
    TRANSPORT_MQTT          = 0,
    TRANSPORT_SEDIMENT      = 1,
    TRANSPORT_SEDIMENT_MQTT = 2,
};
