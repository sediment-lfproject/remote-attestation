/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */
#include <chrono>
#include <thread>
#include <filesystem>

#include "DeviceStorageSqlite.hpp"
#include "Utils.hpp"
#include "Log.hpp"

using namespace std;

static Config tmpConfig;

Col cols[] = {
    { COL_ID,               COL_TYPE_TEXT },
    { COL_FIRMWARE,         COL_TYPE_TEXT },
    { COL_FIRMWARE_SIZE,    COL_TYPE_INT  },
    { COL_CONFIGS,          COL_TYPE_TEXT },
    { COL_OS_VERSION,       COL_TYPE_TEXT },
    { COL_VERIFIER_EP,      COL_TYPE_TEXT },
    { COL_RELYINGPARTY_EP,  COL_TYPE_TEXT },
    { COL_PROVER_EP,        COL_TYPE_TEXT },
    { COL_REVOCATION_EP,    COL_TYPE_TEXT },
    { COL_ENCRYPTION_KEY,   COL_TYPE_BLOB },
    { COL_ATTESTATION_KEY,  COL_TYPE_BLOB },
    { COL_AUTH_KEY,         COL_TYPE_BLOB },
    { COL_NONCE,            COL_TYPE_BLOB },
    { COL_PASSPORT_EXPIRY,  COL_TYPE_INT  },
    { COL_LAST_ATTESTATION, COL_TYPE_INT  },
    { COL_STATUS,           COL_TYPE_INT  },
    { COL_SQN,              COL_TYPE_INT  },
    { COL_SEEC_SQN,         COL_TYPE_INT  },
    { COL_REV_CHECK_SQN,    COL_TYPE_INT  },
    { COL_REV_ACK_SQN,      COL_TYPE_INT  },
    { COL_EVIDENCE_TYPES,   COL_TYPE_TEXT },
};

map<string, Device *> DeviceStorageSqlite::devices;
std::mutex DeviceStorageSqlite::devicesLock;

static int getColumnType(string &col)
{
    int i;
    const char *col_c = (const char *)&col[0];
    for (i = 0; i < (int) (sizeof(cols) / sizeof(Col)); i++) {
        if (!strcmp(cols[i].name, col_c)) {
            return cols[i].type;
        }
    }
    return -1;
}

inline static string quote(string &col, string &val)
{
    return (getColumnType(col) == COL_TYPE_TEXT) ? "'" + val + "'" : val;
}

DeviceStorageSqlite::DeviceStorageSqlite(const string &dbName)
{
    auto p = std::filesystem::weakly_canonical(dbName);
    try {
        filesystem::create_directories(p.parent_path());
    }
    catch (...) {
        SD_LOG(LOG_ERR, "failed to create db directory: %s", dbName.c_str());
        exit(EXIT_FAILURE);
    }

    if (!filesystem::exists(p)) {
        SD_LOG(LOG_WARNING, "sqlite file does not exisit: %s", dbName.c_str());
        // exit(EXIT_FAILURE);
    }

    int rc = sqlite3_open(dbName.c_str(), &deviceDB);
    if (rc) {
        SD_LOG(LOG_ERR, "can't open database: %s\n", sqlite3_errmsg(deviceDB));
        exit(EXIT_FAILURE);
    }
    createDeviceTable();
}

void DeviceStorageSqlite::deleteDevice(Device *device)
{
    string sql = "DELETE FROM Device WHERE ID = '" + device->getId() + "';";

    char *msg;
    int rc = sqlite3_exec(deviceDB, sql.c_str(), NULL, 0, &msg);

    if (rc != SQLITE_OK) {
        SD_LOG(LOG_ERR, "failed to delete device: %s", device->getId().c_str());
        sqlite3_free(msg);
    }
}

void DeviceStorageSqlite::insertDevice(Device *device)
{
    insertDevice(device->toString());
}

void DeviceStorageSqlite::insertDevice(string device)
{
    string sql("INSERT OR REPLACE INTO Device VALUES(" + device + ");");

    char *msg;
    int rc = sqlite3_exec(deviceDB, sql.c_str(), NULL, 0, &msg);

    if (rc != SQLITE_OK) {
        SD_LOG(LOG_ERR, "failed to insert device: %s\n%s", msg, sql.c_str());
        sqlite3_free(msg);
    }
    else {
        string id = device.substr(0, device.find(","));
        id = id.substr(1, id.find("'", 1) - 1); // remove quotes
        SD_LOG(LOG_DEBUG, "device %s", id.c_str());
    }
}

static int populateDeviceSqlite(Device *device, sqlite3_stmt *statement)
{
    int i;

    for (i = 0; i < (int) (sizeof(cols) / sizeof(Col)); i++) {
        const char *name = cols[i].name;

        if (cols[i].type == COL_TYPE_TEXT) {
            char *text = (char *) sqlite3_column_text(statement, i);
            string value(text);
            Utils::trim(value);

            if (!strcmp(name, COL_ID))
                device->setId(value);
            else if (!strcmp(name, COL_FIRMWARE))
                device->setFirmware(value);
            else if (!strcmp(name, COL_CONFIGS))
                device->setConfigs(value);
            else if (!strcmp(name, COL_OS_VERSION))
                device->setOsVersion(value);
            else if (!strcmp(name, COL_VERIFIER_EP)) {
                Endpoint ep(value);
                device->setVerifierEndpoint(ep);
            }
            else if (!strcmp(name, COL_RELYINGPARTY_EP)) {
                Endpoint ep(value);
                device->setRelyingPartyEndpoint(ep);
            }
            else if (!strcmp(name, COL_PROVER_EP)) {
                Endpoint ep(value);
                device->setProverEndpoint(ep);
            }
            else if (!strcmp(name, COL_REVOCATION_EP)) {
                Endpoint ep(value);
                device->setRevocationEndpoint(ep);
            }
            else if (!strcmp(name, COL_EVIDENCE_TYPES)) {
                Device::parseEvidenceTypes(value, device->getEvidenceTypes());
            }
        }
        else if (cols[i].type == COL_TYPE_INT) {
            int value = sqlite3_column_int(statement, i);

            if (!strcmp(name, COL_FIRMWARE_SIZE))
                device->setFirmwareSize(value);
            else if (!strcmp(name, COL_PASSPORT_EXPIRY))
                device->setPassportExpiryDate(value);
            else if (!strcmp(name, COL_LAST_ATTESTATION))
                device->setLastAttestation(value);
            else if (!strcmp(name, COL_STATUS))
                device->setStatus((bool) value);
            else if (!strcmp(name, COL_SQN))
                device->setSqn(value);
            else if (!strcmp(name, COL_SEEC_SQN))
                device->setSeecSqn(value);
            else if (!strcmp(name, COL_REV_CHECK_SQN))
                device->setRevCheckSqn(value);
            else if (!strcmp(name, COL_REV_ACK_SQN))
                device->setRevAckSqn(value);
            else {
                SD_LOG(LOG_ERR, "char column not recogized: %s", cols[i].name);
            }
        }
        else if (cols[i].type == COL_TYPE_BLOB) {
            int size = sqlite3_column_bytes(statement, i);
            unsigned char *data = (unsigned char *) sqlite3_column_blob(statement, i);

            Seec *seec     = device->getSeec();
            Crypto *crypto = seec->getCrypto();
            if (crypto == NULL) {
                SD_LOG(LOG_ERR, "null crypto");
                continue;
            }
            if (!strcmp(name, COL_ATTESTATION_KEY))
                crypto->changeKey(KEY_ATTESTATION, data, size);
            else if (!strcmp(name, COL_ENCRYPTION_KEY))
                crypto->changeKey(KEY_ENCRYPTION, data, size);
            else if (!strcmp(name, COL_AUTH_KEY)) {
                crypto->changeKey(KEY_AUTH, data, size);
            }
            else if (!strcmp(name, COL_NONCE)) {
                vector<uint8_t> &nonce = device->getNonce();
                nonce.resize(size);
                memcpy(&nonce[0], data, size);
            }
            else
                SD_LOG(LOG_ERR, "char column not recogized: %s", cols[i].name);
        }
    }
    return 0;
}

Device *DeviceStorageSqlite::selectDevice(string col, string &value)
{
    int result;
    Device *device = new Device(tmpConfig);

    string sqlplus("SELECT * FROM Device WHERE " + col + " = '" + value + "';");

    sqlite3_stmt *statement;
    const char *sql = (const char *) &sqlplus[0];

    if (sqlite3_prepare_v2(deviceDB, sql, strlen(sql), &statement, 0) != SQLITE_OK) {
        SD_LOG(LOG_ERR, "selectDevice: sqlite3_prepare_v2 failed for device: %s", sql);
        goto err;
    }

    result = sqlite3_step(statement);
    if (result != SQLITE_ROW) {
        SD_LOG(LOG_ERR, "no such device: %s=%s", col.c_str(), value.c_str());
        goto err;
    }
    populateDeviceSqlite(device, statement);

    sqlite3_finalize(statement);

    return device;

err:
    delete device;
    return NULL;
}

void DeviceStorageSqlite::update(Device *device, string col, string value)
{
    string id  = device->getId();
    string sql = "UPDATE Device SET " + col + " = " + quote(col, value) + " WHERE id = '" + id + "'";
    char *msg;
    int rc = sqlite3_exec(deviceDB, sql.c_str(), NULL, 0, &msg);

    if (rc != SQLITE_OK) {
        SD_LOG(LOG_ERR, "sql %s", sql.c_str());
        SD_LOG(LOG_ERR, "failed to update device %s %s: %s", id.c_str(), col.c_str(), msg);
        sqlite3_free(msg);
    }
}

string DeviceStorageSqlite::getCol(Device *device, string col)
{
    string id = device->getId();
    string sqlplus("SELECT " + col + " FROM Device " + " WHERE ID = '" + id + "'");

    sqlite3_stmt *statement;
    const char *sql = (const char *) &sqlplus[0];

    if (sqlite3_prepare_v2(deviceDB, sql, strlen(sql), &statement, 0) != SQLITE_OK) {
        SD_LOG(LOG_ERR, "getCol: %s", sql);
        return "ERR";
    }
    int count = 0;
    while (true) {
        int result = sqlite3_step(statement);
        if (result == SQLITE_ROW)
            break;
        if (result == SQLITE_BUSY) {
            count++;
            if (count <= 3) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
        }
        SD_LOG(LOG_ERR, "(%d) for device: %s", result, id.c_str());
        return "ERR";
    }
    char *text = (char *) sqlite3_column_text(statement, 0);
    string value(text);
    Utils::trim(value);

    sqlite3_finalize(statement);

    return value;
}

void DeviceStorageSqlite::createDeviceTable()
{
    string sql = "CREATE TABLE IF NOT EXISTS Device("
      COL_ID               " TEXT PRIMARY KEY     NOT NULL, "
      COL_FIRMWARE         " TEXT NOT NULL, "
      COL_FIRMWARE_SIZE    " INT  NOT NULL, "
      COL_CONFIGS          " TEXT NOT NULL, "
      COL_OS_VERSION       " TEXT NOT NULL, "
      COL_VERIFIER_EP      " TEXT  NOT NULL, "
      COL_RELYINGPARTY_EP  " TEXT  NOT NULL, "
      COL_PROVER_EP        " TEXT  NOT NULL, "
      COL_REVOCATION_EP    " TEXT  NOT NULL, "
      COL_ENCRYPTION_KEY   " BLOB, "
      COL_ATTESTATION_KEY  " BLOB, "
      COL_AUTH_KEY         " BLOB, "
      COL_NONCE            " BLOB, "
      COL_PASSPORT_EXPIRY  " INT, "
      COL_LAST_ATTESTATION " INT, "
      COL_STATUS           " INT, "
      COL_SQN              " INT, "
      COL_SEEC_SQN         " INT, "
      COL_REV_CHECK_SQN    " INT, "
      COL_REV_ACK_SQN      " INT, "
      COL_EVIDENCE_TYPES   " TEXT);";

    char *msg;
    int count = 0;
    int rc = sqlite3_exec(deviceDB, sql.c_str(), NULL, 0, &msg);
    while (rc != SQLITE_OK) {
        if (rc == SQLITE_BUSY) {
            count++;
            if (count > 3) {
                sqlite3_free(msg);
                break;
            }
            else {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
        }
        SD_LOG(LOG_ERR, "failed to create table: %s (%d)", msg, rc);
        sqlite3_free(msg);
    }
}

string Device::convertEvidenceTypes()
{
    string et  = "";
    bool first = true;

    for (auto i: evidenceTypes) {
        if (!first)
            et += ":";
        et   += to_string(i);
        first = false;
    }
    return et;
}

string Device::toString()
{
    return "'" + id + "', "
           + "'" + firmware + "', "
           + to_string(firmwareSize) + ", "
           + "'" + configs + "', "
           + "'" + osVersion + "', '"
           + verifierEndpoint.toStringOneline() + "', '"
           + relyingPartyEndpoint.toStringOneline() + "', '"
           + proverEndpoint.toStringOneline() + "', '"
           + revocationEndpoint.toStringOneline() + "', "
           + "X'" + Log::toHex(encryptionKey) + "', "
           + "X'" + Log::toHex(attestationKey) + "', "
           + "X'" + Log::toHex(authKey) + "', "
           + "X'" + Log::toHex(nonce) + "', "
           + to_string(passportExpiryDate) + ", "
           + to_string(lastAttestation) + ", "
           + to_string(status) + ", "
           + to_string(sqn) + ", "
           + to_string(seecSqn) + ", "
           + to_string(revCheckSqn) + ", "
           + to_string(revAckSqn) + ", "
           + "'" + convertEvidenceTypes() + "'";
}

Device *DeviceStorageSqlite::findDevice(string &deviceID)
{
    Device *device = NULL;
    devicesLock.lock();
    map<string, Device *>::const_iterator it = devices.find(deviceID);
    if (it != devices.end()) {
        device = (Device *) it->second;
        devicesLock.unlock();
        return (Device *) it->second;
    }
    devicesLock.unlock();
    device = selectDevice(COL_ID, deviceID);
    devicesLock.lock();
    if (device != NULL) {
        devices[device->getId()] = device;
    }
    devicesLock.unlock();
    return device;
}

Device *DeviceStorageSqlite::findDeviceByIP(string &ip)
{
    Device *device = selectDevice(COL_PROVER_EP, ip);

    devicesLock.lock();
    if (device != NULL) {
        devices[device->getId()] = device;
    }
    devicesLock.unlock();
    return device;
}
