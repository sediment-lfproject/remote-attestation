/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <mutex>

#include "sediment.h"

#include "Log.hpp"

int Log::loglevel  = LOG_DEBUG;

/***********  Use spdlog *********************/
#if defined(SPDLOG_ENABLED)
#include <iostream>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/rotating_file_sink.h"

#define MULTI_SINK    "multi_sink"

std::shared_ptr<spdlog::logger> sedimentLogger;

static std::shared_ptr<spdlog::logger> getLogger()
{
    auto logger = spdlog::get(MULTI_SINK);
    if (logger == nullptr) {
        std::cout << "spdlog not initialized" << std::endl;
        exit(1);
    }
    return logger;
}

void Log::initLog(int consoleLogLevel, int level, string &logPath, int logMaxSize, int logMaxFiles)
{
    Log::loglevel = level;

    auto color_both_p = "%^%Y-%m-%d %T.%e [%l] %v%$";
    auto max_size = 1048576 * logMaxSize;

    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    console_sink->set_level((spdlog::level::level_enum) consoleLogLevel);
    console_sink->set_pattern(color_both_p);

    auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(logPath, max_size, logMaxFiles);
    file_sink->set_level((spdlog::level::level_enum) level);
    file_sink->set_pattern(color_both_p);

    std::vector<spdlog::sink_ptr> sinks{console_sink, file_sink};
    auto logger = std::make_shared<spdlog::logger>(MULTI_SINK, sinks.begin(), sinks.end());
    logger->set_level(spdlog::level::trace);
    logger->flush_on(spdlog::level::info);   // auto flush
    spdlog::flush_every(std::chrono::seconds(3));
    spdlog::register_logger(logger); //if it would be used in some other place

    console_sink->set_color(spdlog::level::trace,    "\033[97m");
    console_sink->set_color(spdlog::level::debug,    "\033[97m");
    console_sink->set_color(spdlog::level::info,     "\033[92m");
    console_sink->set_color(spdlog::level::warn,     "\033[93m");
    console_sink->set_color(spdlog::level::err,      "\033[91m");
    console_sink->set_color(spdlog::level::critical, "\033[91m");
}

int Log::fromStr(string &level)
{
    return spdlog::level::from_str(level);
}

void Log::print(LogLevel level, const char *fmt, ...)
{
    auto logger = getLogger();
    
    char buf[DEBUG_BUF_SIZE];
    va_list va;

    memset(buf, '\0', DEBUG_BUF_SIZE);

    va_start(va, fmt);
    vsnprintf(buf, DEBUG_BUF_SIZE, fmt, va);
    va_end(va);

    switch (level) {
    case LOG_CRIT:
        logger->critical(buf);
        break;
    case LOG_ERR:
        logger->error(buf);
        break;
    case LOG_WARNING:
        logger->warn(buf);
        break;
    case LOG_INFO:
        logger->info(buf);
        break;
    case LOG_DEBUG:
        logger->debug(buf);
        break;
    case LOG_TRACE:
        logger->trace(buf);
        break;
    case LOG_OFF:
        break;
    }
}
#elif defined(PLATFORM_ZEPHYR)
///////////// Use Zephyr Logging //////////////////////////////////////
#include <logging/log.h>
LOG_MODULE_DECLARE(_, LOG_LEVEL_DBG);

void Log::initLog(int consoleLogLevel, int level, string &logPath, int logMaxSize, int logMaxFiles)
{
    Log::loglevel = level;
}

int Log::fromStr(string &level)
{
    return 0;
}

void Log::print(LogLevel level, const char *fmt, ...)
{
    char buf[DEBUG_BUF_SIZE];
    va_list va;

    memset(buf, '\0', DEBUG_BUF_SIZE);

    va_start(va, fmt);
    vsnprintf(buf, DEBUG_BUF_SIZE, fmt, va);
    va_end(va);

    switch (level) {
    case LOG_CRIT:
        LOG_ERR("%s", buf);
        break;
    case LOG_ERR:
        LOG_ERR("%s", buf);
        break;
    case LOG_WARNING:
        LOG_WRN("%s", buf);
        break;
    case LOG_INFO:
        LOG_INF("%s", buf);
        break;
    case LOG_DEBUG:
        LOG_DBG("%s", buf);
        break;
    case LOG_TRACE:
        LOG_DBG("%s", buf);
        break;
    case LOG_OFF:
        break;
    }
}
#else
/*************** Use printf **************/
#include <algorithm>
#include <fstream>

static LogLevel consoleLogLevel = LogLevel::LOG_DEBUG;

#if !defined(PLATFORM_GIANT_GECKO) && !defined(PLATFORM_NRF9160)
static std::mutex mtx;
static std::ofstream theLogFile;
static LogLevel logLevel = LogLevel::LOG_DEBUG;
#endif

static char * get_timestamp(struct timeval *new_time, char *timestamp, int len)
{
#if defined(PLATFORM_GIANT_GECKO) || defined(PLATFORM_NRF9160)
    (void)new_time;
    snprintf(timestamp, len, "0000-00-00 00:00:00.000");
#else
    struct tm *ptm;

    ptm = localtime(&new_time->tv_sec);
    int ts_len        = strftime(timestamp, len, "%Y-%m-%d %H:%M:%S", ptm);
    long milliseconds = new_time->tv_usec / 1000;

    snprintf(timestamp + ts_len, len - ts_len, ".%03ld", milliseconds);
#endif
    return timestamp;
}

void Log::initLog(int clevel, int level, string &logPath, int logMaxSize, int logMaxFiles)
{
    (void) level;
    (void) logMaxSize;
    (void) logMaxFiles;

    consoleLogLevel = (LogLevel) clevel;

#if !defined(PLATFORM_GIANT_GECKO) && !defined(PLATFORM_NRF9160)
    theLogFile.open(logPath, ios::out | ios::app);
    logLevel = (LogLevel) level;
#endif
}

static void log_line(LogLevel level, const char *buf)
{
    struct timeval now = { 0, 0 };
#if !defined(PLATFORM_GIANT_GECKO) && !defined(PLATFORM_NRF9160)
    gettimeofday(&now, NULL);
#endif
    char timestamp[40];

    const char *color_pfx = "", *color_sfx = "";
    // const char *time_pfx = "", *time_sfx = color_sfx;
    const char *level_strings[] = {
        "trace", "debug", "info", "warning", "error", "critical", "off"
    };
    const char *tag = level_strings[level];

    color_pfx = "";
    color_sfx = "\33[0m";
    // time_pfx  = "\e[0;96m";
    // time_sfx  = color_sfx;

    switch (level) {
    case LOG_CRIT:
        color_pfx = "\e[1;91m"; /* bright + Red */
        break;
    case LOG_ERR:
        color_pfx = "\e[0;91m"; /* bright + Red */
        break;
    case LOG_WARNING:
        color_pfx = "\e[0;93m"; /* Purple */
        break;
    case LOG_INFO:
        color_pfx = "\e[0;92m"; /* Green */
        break;
    case LOG_DEBUG:
        // color_pfx = "\e[1;92m"; /* White */
        break;
    case LOG_TRACE:
    case LOG_OFF:
        break;
    }
    get_timestamp(&now, timestamp, 40);

    if (level >= consoleLogLevel) {
        fprintf(stdout, "%s%s [%s] %s%s\n", color_pfx, timestamp, tag, buf, color_sfx);
        fflush(stdout);
    }
#if !defined(PLATFORM_GIANT_GECKO) && !defined(PLATFORM_NRF9160)
    if (level >= logLevel)
        theLogFile << timestamp << " [" << tag << "] " << buf << endl;
#endif
}

int Log::fromStr(string &level)
{
    std::transform(level.begin(), level.end(), level.begin(), [](unsigned char c){
        return std::tolower(c);
    });

    if (level == "trace")
        return LOG_TRACE;
    else if (level == "debug")
        return LOG_DEBUG;
    else if (level == "info")
        return LOG_INFO;
    else if (level == "warn")
        return LOG_WARNING;
    else if (level == "error")
        return LOG_ERR;
    else if (level == "critical")
        return LOG_CRIT;
    else if (level == "off")
        return LOG_OFF;
    else
        return LOG_OFF;
}

void Log::print(LogLevel level, const char *fmt, ...)
{
    char buf[DEBUG_BUF_SIZE];
    va_list va;

    memset(buf, '\0', DEBUG_BUF_SIZE);

    va_start(va, fmt);
    vsnprintf(buf, DEBUG_BUF_SIZE, fmt, va);
    va_end(va);

#if defined(PLATFORM_GIANT_GECKO) || defined(PLATFORM_NRF9160)
    log_line(level, buf);
#else
    mtx.lock();
    log_line(level, buf);
    mtx.unlock();
#endif
}

#endif

string Log::toMessageID(MessageID id)
{
    switch (id) {
    case PASSPORT_REQUEST:
        return "PASSPORT_REQUEST";

    case PASSPORT_RESPONSE:
        return "PASSPORT_RESPONSE";

    case ATTESTATION_REQUEST:
        return "ATTESTATION_REQUEST";

    case CHALLENGE:
        return "CHALLENGE";

    case EVIDENCE:
        return "EVIDENCE";

    case GRANT:
        return "GRANT";

    case ALERT:
        return "ALERT";

    case PASSPORT_CHECK:
        return "PASSPORT_CHECK";

    case PERMISSION:
        return "PERMISSION";

    case DATA:
        return "DATA";

    case RESULT:
        return "RESULT";

    case KEY_CHANGE:
        return "KEY CHANGE";

    case DUMMY:
        return "DUMMY";

    case CONFIG:
        return "CONFIG";

    case REVOCATION:
        return "REVOCATION";

    case REVOCATION_CHECK:
        return "REVOCATION_CHECK";

    case REVOCATION_ACK:
        return "REVOCATION_ACK";

    default:
        return "BAD MESSAGE ID";
    }
}

string Log::toReason(Reason reason)
{
    switch (reason) {
    case INIT:
        return "INIT";

    case EXPIRATION:
        return "EXPIRATION";

    case TIME_OUT:
        return "TIME_OUT";

    case REQUESTED:
        return "REQUESTED";

    case SQN_OUT_OF_SYNC:
        return "SQN_OUT_OF_SYNC";

    case FAILED_AUTH:
        return "FAILED_AUTH";

    case FAILED_ATTEST:
        return "FAILED_ATTEST";

    case USER_REJECT:
        return "USER_REJECT";

    case PASS:
        return "PASS";

    default:
        return "Bad Reason";
    }
}

string Log::toAdmittance(Admittance admittance)
{
    switch (admittance) {
    case DENIED:
        return "DENIED";

    case GRANTED:
        return "GRANTED";

    default:
        return "Bad Admittance";
    }
}

string Log::toAcceptance(Acceptance acceptance)
{
    switch (acceptance) {
    case ACCEPT:
        return "ACCEPT";

    case REJECT:
        return "REJECT";

    case TIME_OUT:
        return "TIME_OUT";

    case NO_COMM:
        return "NO_COMM";

    default:
        return "Bad Acceptance";
    }
}

string Log::toProtocol(Protocol acceptance)
{
    switch (acceptance) {
    case TCP:
        return "TCP";

    case UDP:
        return "UDP";

    case BLUETOOTH:
        return "BLUETOOTH";

    default:
        return "Bad Protocol";
    }
}

string Log::toCause(Cause cause)
{
    switch (cause) {
    case CAUSE_POWER_ON:
        return "POWER_ON";

    case CAUSE_INVALID_PASSPORT:
        return "INVALID_PASSPORT";

    case CAUSE_INIT:
        return "INIT";
        
    case CAUSE_RESET:
        return "RESET";
        
    case CAUSE_PERIODIC:
        return "PERIODIC";
        
    case CAUSE_REQUESTED:
        return "REQUESTED";
        
    case CAUSE_DATA_REJECTED:
        return "DATA_REJECTED";

    default:
        return "Bad Cause";
    }
}

string Log::toEvidencetype(EvidenceType evidenceType)
{
    switch (evidenceType) {
    case EVIDENCE_FULL_FIRMWARE:
        return "FULL_FIRMWARE";

    case EVIDENCE_SPARSE_FIRMWARE:
        return "SPARSE_FIRMWARE";

    case EVIDENCE_APP_FIRMWARE_VERSION:
        return "APP_FIRMWARE_VERSION";

    case EVIDENCE_OS_VERSION:
        return "OS_VERSION";

    case EVIDENCE_BIOS_VERSION:
        return "BIOS_VERSION";

    case EVIDENCE_BOOT_TIME:
        return "BOOT_TIME";

    case EVIDENCE_LOCATION:
        return "LOCATION";

    case EVIDENCE_CONFIGS:
        return "CONFIGS";        

    case EVIDENCE_UDF_LIB:
        return "UDF_LIB";

    case EVIDENCE_UDF1:
        return "UDF1";

    case EVIDENCE_UDF2:
        return "UDF2";

    case EVIDENCE_UDF3:
        return "UDF3";

    default:
        SD_LOG(LOG_ERR, "Bad EvidenceType: %d", evidenceType);
        return "Bad EvidenceType";
    }
}

string Log::toEvidenceEncoding(EvidenceEncoding evidenceEncoding)
{
    switch (evidenceEncoding) {
    case ENCODING_CLEAR:
        return "CLEAR";

    case ENCODING_HMAC_SHA256:
        return "HMAC_SHA256";

    case ENCODING_ENCRYPTED:
        return "ENCRYPTED";

    default:
        return "Bad EvidenceEncoding";
    }
}

string Log::toKeyEncType(KeyEncType type)
{
    switch (type) {
    case KEY_ENC_TYPE_JEDI:
        return "JEDI";

    case KEY_ENC_TYPE_RSA:
        return "RSA";

    case KEY_ENC_TYPE_EC:
        return "EC";

    case KEY_ENC_TYPE_NONE:
        return "None";

    default:
        return "Bad KeyEncType";
    }
}

string Log::toKeyPurpose(KeyPurpose purpose)
{
    switch (purpose) {
    case KEY_ENCRYPTION:
        return "AES Encryption";

    case KEY_ATTESTATION:
        return "Attestation";

    case KEY_AUTH:
        return "HMAC Authentication";

    default:
        return "Bad Key Purpose";
    }
}

string Log::toMeasurementType(MeasurementType measurementType)
{
    switch (measurementType) {
    case MEAS_AES_ENCRYPTION:
        return "AES_ENCRYPTION";

    case MEAS_ATTESTATION:
        return "ATTESTATION";

    case MEAS_HMAC_SIGNING:
        return "HMAC_SIGNING";

    case MEAS_RSA_SIGNING:
        return "RSA_SIGNING";

    case MEAS_RSA_VERIFYING:
        return "RSA_VERIFYING";

    case MEAS_RSA_ENCRYPTION:
        return "RSA_ENCRYPTION";

    case MEAS_JEDI_ENCRYPT:
        return "JEDI_ENCRYPT";

    case MEAS_JEDI_SETUP:
        return "JEDI_SETUP";

    case MEAS_JEDI_KEYGEN:
        return "JEDI_KEYGEN";

    case MEAS_JEDI_PRECOMPUTE:
        return "JEDI_PRECOMPUTE";

    case MEAS_JEDI_SIGN:
        return "JEDI_SIGN";

    case MEAS_JEDI_QUALIFY_KEY:
        return "JEDI_QUALIFY_KEY";

    case MEAS_JEDI_ADJUST_PRECOMPUTE:
        return "JEDI_ADJUST_PRECOMPUTE";

    case MEAS_PLAINTEXT_COPY:
        return "PLAINTEXT_COPY";

    case MEAS_WKD_INIT:
        return "WKD_INIT";

    case MEAS_CYCLE_INIT:
        return "CYCLE_INIT";

    case MEAS_REGENERATE_STATE:
        return "REGENERATE_STATE";

    case MEAS_PUB_AUTH:
        return "PUB_AUTH";

    case MEAS_REV_AES_ENCRYPTION:
        return "REV_AES_ENCRYPTION";

    case MEAS_REV_AES_DECRYPTION:
        return "REV_AES_DECRYPTION";

    case MEAS_REV_CYCLE_INIT:
        return "REV_CYCLE_INIT";

    case MEAS_REV_JEDI_ADJUST_PRECOMPUTE:
        return "REV_JEDI_ADJUST_PRECOMPUTE";

    case MEAS_REV_JEDI_ENCRYPT:
        return "REV_JEDI_ENCRYPT";

    case MEAS_REV_JEDI_QUALIFY_KEY:
        return "REV_JEDI_QUALIFY_KEY";

    case MEAS_REV_JEDI_SIGN:
        return "REV_JEDI_SIGN";

    default:
        return "Bad Measurement Type";
    }
}

string Log::toDataTransport(DataTransport dataTransport)
{
    switch (dataTransport) {
    case TRANSPORT_SEDIMENT:
        return "sediment";
    case TRANSPORT_MQTT:
        return "mqtt";
    case TRANSPORT_SEDIMENT_MQTT:
        return "sediment_mqtt";
    default:
        return "unknown transport";
    }
}

string Log::toHex(char *unprintable, int len)
{
    const int MAX_LEN         = 32;
    static const char *digits = "0123456789ABCDEF";
    string ellipsis = "";

    if (len > MAX_LEN) {
        len      = MAX_LEN + 3;
        ellipsis = "...";
    }
    string rc(len * 2, '0');

    for (int i = 0, j = 0; i < len; ++i, j += 2) {
        char c = unprintable[i];
        rc[j]     = digits[(c >> 4) & 0x0f];
        rc[j + 1] = digits[c & 0x0f];
    }
    return rc + ellipsis;
}

string Log::toHexNoLimit(char *unprintable, int len)
{
    static const char *digits = "0123456789ABCDEF";

    string rc(len * 2, '0');

    for (int i = 0, j = 0; i < len; ++i, j += 2) {
        char c = unprintable[i];
        rc[j]     = digits[(c >> 4) & 0x0f];
        rc[j + 1] = digits[c & 0x0f];
    }
    return rc;
}

string Log::toHex(vector<uint8_t> &vec)
{
    return toHex((char *) &vec[0], vec.size());
}

string Log::toHex(Vector &vec)
{
    return toHex((char *) vec.at(0), vec.size());
}
