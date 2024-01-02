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
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>

#include "Device.hpp"
#include "DeviceStorage.hpp"

using namespace std;

class DeviceStorageMySQL: public DeviceStorage
{
private:
    static map<string, Device *> devices;
    static std::mutex devicesLock;
    std::unique_ptr<sql::Connection> conn;

    void populateDevice(Device *device, std::unique_ptr<sql::ResultSet> res);
    Device *selectDevice(string col, string &value);
    void createDeviceTable();
    
public:
    DeviceStorageMySQL(const string &dbName);
    virtual ~DeviceStorageMySQL() {
        close();
    }

    // DeviceManagers should not be copied
    void operator = (const DeviceStorageMySQL &other)   = delete;
    DeviceStorageMySQL(const DeviceStorageMySQL &other) = delete;

    Device *findDevice(string &serial);
    Device *findDeviceByIP(string &ip);
    void insertDevice(Device *device);
    void insertDevice(string device);

    string getCol(Device *device, string col);
    void update(Device *device, string col, string value);
    
    void deleteDevice(Device *device) {
        (void) device;
    }

    bool isConnected() { 
        return conn != nullptr; 
    }

    void close() {
        try {
            this->conn->close();
        }
        catch(sql::SQLException &e) {
            SD_LOG(LOG_ERR, "MySQL close error: %s", e.what());
        }
    }
};