/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#include <sys/stat.h>
#include <iostream>
#include <sstream>
#include <memory>

#include "Device.hpp"
#include "Enum.hpp"
#include "Utils.hpp"
#include "Log.hpp"

using json = nlohmann::json;
using namespace std;


static Config tmpConfig;

Col cols[] = {
    { COL_ID,               COL_TYPE_TEXT               },
    { COL_FIRMWARE,         COL_TYPE_TEXT               },
    { COL_FIRMWARE_SIZE,    COL_TYPE_INT                },
    { COL_CONFIGS,          COL_TYPE_TEXT               },
    { COL_OS_VERSION,       COL_TYPE_TEXT               },
    { COL_VERIFIER_EP,      COL_TYPE_TEXT               },
    { COL_RELYINGPARTY_EP,  COL_TYPE_TEXT               },
    { COL_PROVER_EP,        COL_TYPE_TEXT               },
    { COL_ENCRYPTION_KEY,   COL_TYPE_BLOB               },
    { COL_ATTESTATION_KEY,  COL_TYPE_BLOB               },
    { COL_AUTH_KEY,         COL_TYPE_BLOB               },
    { COL_NONCE,            COL_TYPE_BLOB               },
    { COL_PASSPORT_EXPIRY,  COL_TYPE_INT                },
    { COL_LAST_ATTESTATION, COL_TYPE_INT                },
    { COL_STATUS,           COL_TYPE_INT                },
    { COL_SQN,              COL_TYPE_INT                },
    { COL_SEEC_SQN,         COL_TYPE_INT                },
    { COL_EVIDENCE_TYPES,   COL_TYPE_TEXT               },
};

void toEndpoint(Endpoint &endpoint, nlohmann::basic_json<> value)
{
    for (auto &el : value.items()) {
        string key = el.key();

        if (!key.compare(NV_PROTOCOL)) {
            string val = el.value().get<string>();
            endpoint.setProtocol(Endpoint::toProtocol(val));
        }
        else if (!key.compare(NV_ADDRESS)) {
            endpoint.setAddress(el.value().get<string>());
        }
        else if (!key.compare(NV_PORT)) {
            endpoint.setPort(el.value().get<int>());
        }
        else if (!key.compare("comments")) { }
        else {
            SD_LOG(LOG_ERR, "unrecognized key %s", key.c_str());
        }
    }
}

static void parseEvidenceTypes(string &s, vector<uint8_t> &types)
{
    std::string delimiter = ":";

    size_t pos = 0;
    std::string token;

    while ((pos = s.find(delimiter)) != std::string::npos) {
        token = s.substr(0, pos);
        types.push_back(stol(token));

        s.erase(0, pos + delimiter.length());
    }
    types.push_back(stol(s));
}

Device::Device(nlohmann::basic_json<> value, Config &config) :
    seec(config)
{
    for (auto &el : value.items()) {
        string key = el.key();

        if (!key.compare(COL_ID)) {
            id = el.value().get<string>();
        }
        else if (!key.compare(COL_FIRMWARE)) {
            firmware = el.value().get<string>();
        }
        else if (!key.compare(COL_FIRMWARE_SIZE)) {
            firmwareSize = el.value().get<int>();
        }
        else if (!key.compare(COL_CONFIGS)) {
            configs = el.value().get<string>();
        }
        else if (!key.compare(COL_OS_VERSION)) {
            osVersion = el.value().get<string>();
        }
        else if (!key.compare(COL_VERIFIER_EP)) {
            toEndpoint(verifierEndpoint, el.value());
        }
        else if (!key.compare(COL_RELYINGPARTY_EP)) {
            toEndpoint(relyingPartyEndpoint, el.value());
        }
        else if (!key.compare(COL_PROVER_EP)) {
            toEndpoint(proverEndpoint, el.value());
        }
        else if (!key.compare(COL_ENCRYPTION_KEY)) {
            string src = el.value().get<string>();
            vector<uint8_t> vec;
            Utils::readHex(vec, src, src.size() / 2);

            setKey(KEY_ENCRYPTION, vec);
        }
        else if (!key.compare(COL_ATTESTATION_KEY)) {
            string src = el.value().get<string>();
            vector<uint8_t> vec;
            Utils::readHex(vec, src, src.size() / 2);

            setKey(KEY_ATTESTATION, vec);
        }
        else if (!key.compare(COL_AUTH_KEY)) {
            string src = el.value().get<string>();
            vector<uint8_t> vec;
            Utils::readHex(vec, src, src.size() / 2);

            setKey(KEY_AUTH, vec);
        }
        else if (!key.compare(COL_NONCE)) {
            string src = el.value().get<string>();
            vector<uint8_t> vec;
            Utils::readHex(vec, src, src.size() / 2);

            nonce.resize(vec.size());
            memcpy(&nonce[0], (char *) &vec[0], vec.size());
        }
        else if (!key.compare(COL_PASSPORT_EXPIRY)) {
            passportExpiryDate = el.value().get<int>();
        }
        else if (!key.compare(COL_LAST_ATTESTATION)) {
            lastAttestation = el.value().get<int>();
        }
        else if (!key.compare(COL_STATUS)) {
            status = el.value().get<bool>();
        }
        else if (!key.compare(COL_SQN)) {
            sqn = el.value().get<int>();
        }
        else if (!key.compare(COL_SEEC_SQN)) {
            seecSqn = el.value().get<int>();
        }
        else if (!key.compare(COL_EVIDENCE_TYPES)) {
            string src = el.value().get<string>();
            parseEvidenceTypes(src, evidenceTypes);
        }
        else {
            SD_LOG(LOG_ERR, "unrecognized key %s", key.c_str());
        }
    }
}

void SQLiteDeviceManager::deleteDevice(Device *device)
{
    string sql = "DELETE FROM Device WHERE ID = '" + device->getId() + "';";

    char *msg;
    int rc = sqlite3_exec(deviceDB, sql.c_str(), NULL, 0, &msg);

    if (rc != SQLITE_OK) {
        SD_LOG(LOG_ERR, "failed to delete device: %s", device->getId().c_str());
        sqlite3_free(msg);
    }
}

void SQLiteDeviceManager::insertDevice(Device *device)
{
    insertDevice(device->toString());
}

void SQLiteDeviceManager::insertDevice(string device)
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

int populateDeviceSqlite(Device *device, sqlite3_stmt *statement)
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
            else if (!strcmp(name, COL_EVIDENCE_TYPES)) {
                parseEvidenceTypes(value, device->getEvidenceTypes());
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

Device * SQLiteDeviceManager::selectDevice(string col, string &value)
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

void SQLiteDeviceManager::update(Device *device, string col, string value)
{
    string id  = device->getId();
    string sql = "UPDATE Device SET " + col + " = " + value + " WHERE id = '" + id + "'";

    char *msg;
    int rc = sqlite3_exec(deviceDB, sql.c_str(), NULL, 0, &msg);

    if (rc != SQLITE_OK) {
        SD_LOG(LOG_ERR, "failed to update device %s %s: %s", id.c_str(), col.c_str(), msg);
        sqlite3_free(msg);
    }
}

string SQLiteDeviceManager::getCol(Device *device, string col)
{
    string id = device->getId();
    string sqlplus("SELECT " + col + " FROM Device " + " WHERE ID = '" + id + "'");

    sqlite3_stmt *statement;
    const char *sql = (const char *) &sqlplus[0];

    if (sqlite3_prepare_v2(deviceDB, sql, strlen(sql), &statement, 0) != SQLITE_OK) {
        SD_LOG(LOG_ERR, "getCol: %s", sql);
        return "ERR1";
    }

    int result = sqlite3_step(statement);
    if (result != SQLITE_ROW) {
        SD_LOG(LOG_ERR, "no such device: %s", id.c_str());
        return "ERR2";
    }
    char *text = (char *) sqlite3_column_text(statement, 0);
    string value(text);
    Utils::trim(value);

    sqlite3_finalize(statement);

    return value;
}

void SQLiteDeviceManager::createDeviceTable()
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
      COL_ENCRYPTION_KEY   " BLOB, "
      COL_ATTESTATION_KEY  " BLOB, "
      COL_AUTH_KEY         " BLOB, "
      COL_NONCE            " BLOB, "
      COL_PASSPORT_EXPIRY  " INT, "
      COL_LAST_ATTESTATION " INT, "
      COL_STATUS           " INT, "
      COL_SQN              " INT, "
      COL_SEEC_SQN         " INT, "
      COL_EVIDENCE_TYPES   " TEXT);";

    char *msg;
    int rc = sqlite3_exec(deviceDB, sql.c_str(), NULL, 0, &msg);

    if (rc != SQLITE_OK) {
        SD_LOG(LOG_ERR, "failed to create table: %s, %s", msg, sql.c_str());
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
           + proverEndpoint.toStringOneline() + "', "
           + "X'" + Log::toHex(encryptionKey) + "', "
           + "X'" + Log::toHex(attestationKey) + "', "
           + "X'" + Log::toHex(authKey) + "', "
           + "X'" + Log::toHex(nonce) + "', "
           + to_string(passportExpiryDate) + ", "
           + to_string(lastAttestation) + ", "
           + to_string(status) + ", "
           + to_string(sqn) + ", "
           + to_string(seecSqn) + ", "
           + "'" + convertEvidenceTypes() + "'";
}

SQLiteDeviceManager::SQLiteDeviceManager(const string &dbName)
{
    //    tmpConfig = config;
    //    string &database = config.getDatabase();

    //    struct stat buffer;
    //    if (stat(database.c_str(), &buffer) < 0) {
    //        SD_LOG(LOG_ERR, "database %s specified in config.json does not exist.\n"
    //                "Please specify another db or create it and import devices using the -i option.", database.c_str());
    //        exit(1);
    //    }

    int rc = sqlite3_open(dbName.c_str(), &deviceDB);

    if (rc) {
        SD_LOG(LOG_ERR, "can't open database: %s\n", sqlite3_errmsg(deviceDB));
        return;
    }

    createDeviceTable();
}

SQLiteDeviceManager::~SQLiteDeviceManager()
{
    sqlite3_close(deviceDB);
}

Device * SQLiteDeviceManager::findDevice(string &deviceID)
{
    map<string, Device *>::const_iterator it = SQLiteDeviceManager::devices.find(deviceID);

    if (it != devices.end()) {
        return (Device *) it->second;
    }

    Device *device = selectDevice(COL_ID, deviceID);
    if (device != NULL) {
        devices[device->getId()] = device;
    }
    return device;
}

Device * SQLiteDeviceManager::findDeviceByIP(string &ip)
{
    Device *device = selectDevice(COL_PROVER_EP, ip);

    if (device != NULL) {
        devices[device->getId()] = device;
    }
    return device;
}

struct DBInfo {
    string url, user, pass, db;
    DBInfo(string url, string user, string pass, string db) : url(url), user(user), pass(pass), db(db){ }
};

static DBInfo parse_dbinfo(const string& input)
{
    string inp = input;

    string delimiter = ",";
    size_t comma1    = inp.find(delimiter);
    string url       = inp.substr(0, comma1);

    inp = inp.substr(comma1 + 1);
    size_t comma2 = inp.find(delimiter);
    string user   = inp.substr(0, comma2);

    inp = inp.substr(comma2 + 1);
    size_t comma3 = inp.find(delimiter);
    string pass   = inp.substr(0, comma3);

    string db = inp.substr(comma3 + 1);
    return DBInfo(url, user, pass, db);
}

static std::unique_ptr<sql::Connection> init_conn(DBInfo info)
{
    sql::Driver *driver = get_driver_instance();

    return std::unique_ptr<sql::Connection>(driver->connect(info.url, info.user, info.pass));
}

MySQLDeviceManager::MySQLDeviceManager(const string &inp) : conn(init_conn(parse_dbinfo(inp)))
{
    DBInfo info = parse_dbinfo(inp);
    conn->setSchema(info.db);
    createDeviceTable();
}

void MySQLDeviceManager::createDeviceTable()
{
    std::unique_ptr<sql::Statement> stmt(conn->createStatement());
    string sql = "CREATE TABLE IF NOT EXISTS Device("
      COL_ID               " VARCHAR(200) PRIMARY KEY     NOT NULL, "
      COL_FIRMWARE         " TEXT NOT NULL, "
      COL_FIRMWARE_SIZE    " INT  NOT NULL, "
      COL_CONFIGS          " TEXT NOT NULL, "
      COL_OS_VERSION       " TEXT NOT NULL, "
      COL_VERIFIER_EP      " TEXT  NOT NULL, "
      COL_RELYINGPARTY_EP  " TEXT  NOT NULL, "
      COL_PROVER_EP        " TEXT  NOT NULL, "
      COL_ENCRYPTION_KEY   " BLOB, "
      COL_ATTESTATION_KEY  " BLOB, "
      COL_AUTH_KEY         " BLOB, "
      COL_NONCE            " BLOB, "
      COL_PASSPORT_EXPIRY  " INT, "
      COL_LAST_ATTESTATION " INT, "
      COL_STATUS           " INT, "
      COL_SQN              " INT, "
      COL_SEEC_SQN         " INT, "
      COL_EVIDENCE_TYPES   " TEXT);";
    stmt->execute(sql);
}

void MySQLDeviceManager::populateDevice(Device *device, std::unique_ptr<sql::ResultSet> res)
{
    if (!res->first()) {
        SD_LOG(LOG_ERR, "Could not get result from database");
        return;
    }
    device->setId(res->getString(COL_ID));
    device->setFirmware(res->getString(COL_FIRMWARE));
    device->setFirmwareSize(res->getInt(COL_FIRMWARE_SIZE));
    device->setConfigs(res->getString(COL_CONFIGS));
    device->setOsVersion(res->getString(COL_OS_VERSION));

    Endpoint vep(res->getString(COL_VERIFIER_EP));
    Endpoint rep(res->getString(COL_RELYINGPARTY_EP));
    Endpoint pep(res->getString(COL_PROVER_EP));
    device->setVerifierEndpoint(vep);
    device->setRelyingPartyEndpoint(rep);
    device->setProverEndpoint(pep);

    Seec *seec     = device->getSeec();
    Crypto *crypto = seec->getCrypto();

    string encryptionKey  = res->getString(COL_ENCRYPTION_KEY);
    string attestationKey = res->getString(COL_ATTESTATION_KEY);
    string authKey        = res->getString(COL_AUTH_KEY);
    crypto->changeKey(KEY_ENCRYPTION, (unsigned char *) (encryptionKey.c_str()), encryptionKey.length());
    crypto->changeKey(KEY_ATTESTATION, (unsigned char *) (attestationKey.c_str()), attestationKey.length());
    crypto->changeKey(KEY_AUTH, (unsigned char *) (authKey.c_str()), authKey.length());

    string nonceStr        = res->getString(COL_NONCE);
    vector<uint8_t> &nonce = device->getNonce();
    nonce.resize(nonceStr.length());
    memcpy(&nonce[0], nonceStr.c_str(), nonceStr.length());

    device->setPassportExpiryDate(res->getInt(COL_PASSPORT_EXPIRY));
    device->setLastAttestation(res->getInt(COL_LAST_ATTESTATION));
    device->setStatus((bool) res->getInt(COL_STATUS));
    device->setSqn(res->getInt(COL_SQN));
    device->setSeecSqn(res->getInt(COL_SEEC_SQN));

    string evidenceTypes(res->getString(COL_EVIDENCE_TYPES));
    parseEvidenceTypes(evidenceTypes, device->getEvidenceTypes());
}

Device * MySQLDeviceManager::selectDevice(string col, string &value)
{
    Device *device = new Device(tmpConfig);

    std::unique_ptr<sql::PreparedStatement> stmt(conn->prepareStatement("SELECT * FROM Device WHERE " + col + " = ?"));
    stmt->setString(1, value);
    std::unique_ptr<sql::ResultSet> res(stmt->executeQuery());

    MySQLDeviceManager::populateDevice(device, std::move(res));

    return device;
}

Device * MySQLDeviceManager::findDevice(string &deviceID)
{
    map<string, Device *>::const_iterator it = devices.find(deviceID);

    if (it != devices.end()) {
        return (Device *) it->second;
    }

    Device *device = selectDevice(COL_ID, deviceID);
    if (device != NULL) {
        devices[device->getId()] = device;
    }
    return device;
}

Device * MySQLDeviceManager::findDeviceByIP(string &ip)
{
    Device *device = selectDevice(COL_PROVER_EP, ip);

    if (device != NULL) {
        devices[device->getId()] = device;
    }
    return device;
}

void MySQLDeviceManager::insertDevice(string device)
{
    std::unique_ptr<sql::PreparedStatement> stmt(conn->prepareStatement("INSERT OR REPLACE INTO Device VALUES(?)"));
    stmt->setString(1, device);
    stmt->execute();
}

void MySQLDeviceManager::insertDevice(Device *device)
{
    insertDevice(device->toString());
}

void MySQLDeviceManager::update(Device *device, string col, string value)
{
    std::unique_ptr<sql::PreparedStatement> stmt(conn->prepareStatement(
          "UPDATE Device SET " + col + " = (?) WHERE id = ?"));
    stmt->setString(1, value);
    stmt->setString(2, device->getId());
    stmt->execute();
}

string MySQLDeviceManager::getCol(Device *device, string col)
{
    std::unique_ptr<sql::PreparedStatement> stmt(conn->prepareStatement("SELECT " + col + " FROM Device WHERE id = ?"));
    stmt->setString(1, device->getId());
    std::unique_ptr<sql::ResultSet> res(stmt->executeQuery());

    if (!res->first()) {
        SD_LOG(LOG_ERR, "Could not fetch result from database");
    }
    return res->getString(col);
}
