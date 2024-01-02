/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#pragma once

#include <memory>

#include "Device.hpp"
#include "DeviceStorage.hpp"
#include "DeviceStorageSqlite.hpp"

#ifdef MYSQL_ENABLED
#include "DeviceStorageMySQL.hpp"
#endif

using namespace std;

class DeviceManager
{
private:
    std::unique_ptr<DeviceStorage> deviceStorage;

public:
    DeviceManager(const string &dbType, const string &dbName) {
        if (dbType == "mysql") {
#ifdef MYSQL_ENABLED        
            deviceStorage = std::make_unique<DeviceStorageMySQL>(dbName);
#else            
            SD_LOG(LOG_ERR, "MySQL is not enabled. Please rebuild with -DMYSQL_ENABLED=ON");
            exit(1);
#endif            
        }
        else if (dbType == "sqlite")
            deviceStorage = std::make_unique<DeviceStorageSqlite>(dbName);
        else {
            SD_LOG(LOG_ERR, "bad device storage type: %s, valid types: sqlite, mysql", dbType.c_str());
            exit(1);
        }
    }

    virtual ~DeviceManager() {
    }

    // DeviceManagers should not be copied
    void operator=(const DeviceManager &other) = delete;
    DeviceManager(const DeviceManager &other) = delete;

    Device *findDevice(string &serial) {
        return deviceStorage->findDevice(serial);
    }

    Device *findDeviceByIP(string &ip) {
        return deviceStorage->findDeviceByIP(ip);
    }

    void deleteDevice(Device *device) {
        deviceStorage->deleteDevice(device);
    }

    void insertDevice(Device *device) {
        deviceStorage->insertDevice(device);
    }

    void insertDevice(string device) {
        deviceStorage->insertDevice(device);
    }

    string getCol(Device *device, string col) {
        return deviceStorage->getCol(device, col);
    }

    void update(Device *device, string col, string value) {
        deviceStorage->update(device, col, value);
    }

    bool isConnected() {
        return deviceStorage->isConnected();
    }

    void close() {
        return deviceStorage->close();
    }
};