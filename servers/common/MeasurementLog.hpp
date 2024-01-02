/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#pragma once

#include <vector>
#include <string>
#include <fstream>

#include "Measurement.hpp"
#include "MeasurementList.hpp"

using namespace std;

#if defined(PLATFORM_GIANT_GECKO)
#define printf printk
#endif

class MeasurementLog
{
private:

#if defined(SPDLOG_ENABLED)
    string loggerHandle;
#else
    std::ofstream theLogFile;
#endif

public:
    MeasurementLog(const string &logPath, const string &logFile, int logMaxSize, int logMaxFiles);
    void print(uint32_t timestamp, string &deviceID, Measurement &measurement);
    void print(uint32_t timestamp, string &deviceID, MeasurementList &measurementList);
};
