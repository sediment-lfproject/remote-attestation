/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#pragma once

#include <string>
#include <map>
#include <mutex>
#include <memory>
#include <sqlite3.h>

#include "Device.hpp"
#include "DeviceStorage.hpp"

using namespace std;

class DeviceStorageSqlite: public DeviceStorage
{
private:
    static map<string, Device *> devices;
    static std::mutex devicesLock; 
    sqlite3 *deviceDB;
        
    Device *selectDevice(string col, string &value);
    void createDeviceTable();

public:
    DeviceStorageSqlite(const string &dbName);
    virtual ~DeviceStorageSqlite() {
        close();
    }

    // DeviceManagers should not be copied
    void operator = (DeviceStorageSqlite const &)    = delete;
    DeviceStorageSqlite(DeviceStorageSqlite const &) = delete;

    Device *findDevice(string &serial);
    Device *findDeviceByIP(string &ip);
    void deleteDevice(Device *device);
    void insertDevice(Device *device);
    void insertDevice(string device);

    string getCol(Device *device, string col);
    void update(Device *device, string col, string value);
    void close() {
        sqlite3_close(deviceDB);
    }
    bool isConnected() { return true; }
};
