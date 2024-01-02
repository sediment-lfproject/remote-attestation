/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */
#include "sediment.h"

#include "MeasurementLog.hpp"
#include "Log.hpp"

/***********  Use spdlog *********************/
#if defined(SPDLOG_ENABLED)
#include <iostream>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/sinks/rotating_file_sink.h"

MeasurementLog::MeasurementLog(const string &logDir, const string &logFile, int logMaxSize, int logMaxFiles)
{
    try  {
        loggerHandle = logFile;

        auto max_size = 1048576 * logMaxSize;
        string logPath = logDir + "/" + logFile;

        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(logPath, max_size, logMaxFiles);
        file_sink->set_level((spdlog::level::level_enum) spdlog::level::trace);
        file_sink->set_pattern("%v");

        std::vector<spdlog::sink_ptr> sinks{file_sink};
        auto logger = std::make_shared<spdlog::logger>(loggerHandle, sinks.begin(), sinks.end());
        logger->set_level(spdlog::level::trace);
        logger->flush_on(spdlog::level::info);   // auto flush
        spdlog::register_logger(logger); //if it would be used in some other place
    }
    catch (const spdlog::spdlog_ex &ex) {
        std::cout << "Log init failed: " << ex.what() << std::endl;
    }
}

/*************** Use printf **************/
#else  // SPDLOG_ENABLED

#include <fstream>
#include <mutex>

#if !defined(PLATFORM_GIANT_GECKO) && !defined(PLATFORM_NRF9160)
static std::mutex mtx;
#endif

MeasurementLog::MeasurementLog(const string &logDir, const string &logFile, int logMaxSize, int logMaxFiles)
{
    (void) logMaxSize;
    (void) logMaxFiles;
    string logPath = logDir + "/" + logFile;
    theLogFile.open(logPath, ios::out | ios::app);
}

#endif

void MeasurementLog::print(uint32_t timestamp, string &deviceID, Measurement &measurement)
{
    const time_t ts = (time_t) timestamp;
    string tss      = asctime(localtime(&ts));
    tss.pop_back();

    string line = tss + ","
                + to_string(ts) + ","
                + deviceID + ","
                + TO_MEAS_TYPE(measurement.getType()) + ","
                + to_string(measurement.getElapsedTime()) + ","
                + to_string(measurement.getOptional()) + ","
                ;

#if defined(SPDLOG_ENABLED)
    auto logger = spdlog::get(loggerHandle);
    if (logger == nullptr) {
        std::cout << "spdlog measurement log not initialized" << std::endl;
        exit(1);
    }
    logger->info(line);
#elif defined(PLATFORM_GIANT_GECKO) || defined(PLATFORM_NRF9160)
    theLogFile << line << endl;
#else
    mtx.lock();
    theLogFile << line << endl;
    mtx.unlock();
#endif
}

void MeasurementLog::print(uint32_t timestamp, string &deviceID, MeasurementList &measurementList)
{
    vector<Measurement> &list = measurementList.getList();
    for (uint32_t i = 0; i < list.size(); i++) {
        print(timestamp, deviceID, list[i]);
    }
}
