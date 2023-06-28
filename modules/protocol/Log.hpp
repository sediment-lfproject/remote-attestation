/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once

#include <vector>

#include "Enum.hpp"
#include "Vector.hpp"

using namespace std;

#if defined(LOG_NONE)

#define SD_LOG(level, fmt, ...)
#define SD_TO_STRING(str)      ""

#define TO_MESSAGE_ID(x)       to_string(x)
#define TO_REASON(x)           to_string(x)
#define TO_ADMITTANCE(x)       to_string(x)
#define TO_ACCEPTANCE(x)       to_string(x)
#define TO_PROTOCOL(x)         to_string(x)
#define TO_CAUSE(x)            to_string(x)
#define TO_EVIDENCETYPE(x)     to_string(x)
#define TO_EVIDENCEENCODING(x) to_string(x)
#define TO_KEY_ENC_TYPE(x)     to_string(x)
#define TO_KEY_PURPOSE(x)      to_string(x)
#define TO_MEAS_TYPE(x)        to_string(x)
#define TO_DATA_TRANSPORT(x)   to_string(x)
#else // if defined(LOG_NONE)

#define SD_LOG(fmt, ...)       Log::print(fmt, ## __VA_ARGS__)
#define SD_TO_STRING(str)      str

#define TO_MESSAGE_ID(x)       Log::toMessageID(x)
#define TO_REASON(x)           Log::toReason(x)
#define TO_ADMITTANCE(x)       Log::toAdmittance(x)
#define TO_ACCEPTANCE(x)       Log::toAcceptance(x)
#define TO_PROTOCOL(x)         Log::toProtocol(x)
#define TO_CAUSE(x)            Log::toCause(x)
#define TO_EVIDENCETYPE(x)     Log::toEvidencetype(x)
#define TO_EVIDENCEENCODING(x) Log::toEvidenceEncoding(x)
#define TO_KEY_ENC_TYPE(x)     Log::toKeyEncType(x)
#define TO_KEY_PURPOSE(x)      Log::toKeyPurpose(x)
#define TO_MEAS_TYPE(x)        Log::toMeasurementType(x)
#define TO_DATA_TRANSPORT(x)   Log::toDataTransport(x)
#endif // if defined(LOG_NONE)

#if defined(PLATFORM_GIANT_GECKO)
#define printf printk
#endif

enum LogLevel {
    LOG_EMERG   = 0, /* system is unusable */
    LOG_ALERT   = 1, /* action must be taken immediately */
    LOG_CRIT    = 2, /* critical conditions */
    LOG_ERR     = 3, /* error conditions */
    LOG_WARNING = 4, /* warning conditions */
    LOG_NOTICE  = 5, /* normal but significant condition */
    LOG_INFO    = 6, /* informational */
    LOG_DEBUG   = 7, /* debug-level messages */
    LOG_TRACE   = 8
};

enum Color {
    COLOR_NONE  = 0,
    COLOR_GREEN = 1,
    COLOR_RED   = 2,
};

class Log
{
#if !defined(LOG_NONE)

private:
    static const int DEBUG_BUF_SIZE = 4096;
    static int loglevel;

    static bool useColor;

public:
    static void print(LogLevel level, const char *fmt, ...);
    static void plain(Color color, const char *fmt, ...);

    static string toHex(char *unprintable, int len);
    static string toHex(vector<uint8_t> &buf);
    static string toHex(Vector &buf);
    static string toHexNoLimit(char *unprintable, int len);

    static void log_line(LogLevel level, const char *buf);

    static char * get_timestamp(struct timeval *new_time, char *timestamp, int len);
    static void isUseColor(bool use)
    {
        useColor = use;
    }

    static string toMessageID(MessageID id);
    static string toReason(Reason reason);
    static string toAdmittance(Admittance admittance);
    static string toAcceptance(Acceptance acceptance);
    static string toProtocol(Protocol acceptance);
    static string toCause(Cause cause);
    static string toEvidencetype(EvidenceType evidenceType);
    static string toEvidenceEncoding(EvidenceEncoding evidenceEncoding);
    static string toKeyEncType(KeyEncType type);
    static string toKeyPurpose(KeyPurpose purpose);
    static string toMeasurementType(MeasurementType measurementType);
    static string toDataTransport(DataTransport dataTransport);

    static int getLoglevel()
    {
        return loglevel;
    }

    static void setLoglevel(int level)
    {
        loglevel = level;
    }

#endif // if !defined(LOG_NONE)
};
