/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#pragma once

#include <vector>

#include "Enum.hpp"
#include "Vector.hpp"

using namespace std;

#define FMT_HEADER_ONLY
#define SD_LOG(fmt, ...)       Log::print(fmt, ## __VA_ARGS__)

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

#if defined(PLATFORM_GIANT_GECKO)
#define printf printk
#endif

enum LogLevel {
    LOG_OFF     = 6,
    LOG_CRIT    = 5, /* critical conditions */
    LOG_ERR     = 4, /* error conditions */
    LOG_WARNING = 3, /* warning conditions */
    LOG_INFO    = 2, /* informational */
    LOG_DEBUG   = 1, /* debug-level messages */
    LOG_TRACE   = 0
};

enum Color {
    COLOR_NONE  = 0,
    COLOR_GREEN = 1,
    COLOR_RED   = 2,
};

class Log
{
private:
    static const int DEBUG_BUF_SIZE = 4096;
    static int loglevel;

public:
    static void initLog(int consoleLogLevel, int level, string &logPath, int logMaxSize, int logMaxFiles);
    static void print(LogLevel level, const char *fmt, ...);
    static void plain(Color color, const char *fmt, ...);
    
    static int fromStr(string &level);

    static string toHex(char *unprintable, int len);
    static string toHex(vector<uint8_t> &buf);
    static string toHex(Vector &buf);
    static string toHexNoLimit(char *unprintable, int len);

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

    static int getLoglevel() {
        return loglevel;
    }

    static void setLoglevel(int level) {
        loglevel = level;
    }
};
