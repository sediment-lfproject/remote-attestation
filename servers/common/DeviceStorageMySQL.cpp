/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */
#ifdef MYSQL_ENABLED

#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>

#include "DeviceStorageMySQL.hpp"
#include "Utils.hpp"
#include "Log.hpp"

using namespace std;

static Config tmpConfig;

struct DBInfo {
    string url, user, pass, db;
    DBInfo(string url, string user, string pass, string db) : url(url), user(user), pass(pass), db(db){ }
};

static DBInfo parse_dbinfo(const string& input)
{
    string inp = input;

    string delimiter = ",";
    size_t comma1    = inp.find(delimiter);
    if (comma1 == string::npos) {
        SD_LOG(LOG_ERR, "Expecting <url>,<user>,<password>,<database>. No delimter found: %s", input.c_str());
        exit(1);
    }
    string url = inp.substr(0, comma1);

    inp = inp.substr(comma1 + 1);
    size_t comma2 = inp.find(delimiter);
    if (comma2 == string::npos) {
        SD_LOG(LOG_ERR, "Expecting <url>,<user>,<password>,<database>. 1 delimter found: %s", input.c_str());
        exit(1);
    }
    string user   = inp.substr(0, comma2);

    inp = inp.substr(comma2 + 1);
    size_t comma3 = inp.find(delimiter);
    if (comma3 == string::npos) {
        SD_LOG(LOG_ERR, "Expecting <url>,<user>,<password>,<database>. 2 delimters found: %s", input.c_str());
        exit(1);
    }    
    string pass   = inp.substr(0, comma3);

    string db = inp.substr(comma3 + 1);

    return DBInfo(url, user, pass, db);
}

static std::unique_ptr<sql::Connection> init_conn(DBInfo info)
{
    for (int i = 0; i < 3; i++) {
        try {
            sql::Driver *driver = get_driver_instance();
            return std::unique_ptr<sql::Connection>(driver->connect(info.url, info.user, info.pass));
        }
        catch(sql::SQLException &e) {
            if (i >= 2) {
                SD_LOG(LOG_ERR, "MySQL connection error: %s", e.what());
                return std::unique_ptr<sql::Connection>(nullptr);
            }
        }
    }
    return std::unique_ptr<sql::Connection>(nullptr);
}

map<string, Device *> DeviceStorageMySQL::devices;
std::mutex DeviceStorageMySQL::devicesLock;

DeviceStorageMySQL::DeviceStorageMySQL(const string &inp) : conn(init_conn(parse_dbinfo(inp)))
{
    if (conn) {
        DBInfo info = parse_dbinfo(inp);
        conn->setSchema(info.db);
        createDeviceTable();
    }
    // if connection failed, the caller (server) will catch it and close the socket.
    // The client will then try again.
    // Connection will fail sometimes with more than a few (e.g. 10) publishers, with the following error
    // "Lost connection to MySQL server at 'reading initial communication packet'"
    // The root cause is not known yet. It's not remote connection or (non-sediment) firewall issue.
}

void DeviceStorageMySQL::createDeviceTable()
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
    stmt->execute(sql);
}

void DeviceStorageMySQL::populateDevice(Device *device, std::unique_ptr<sql::ResultSet> res)
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
    Endpoint revep(res->getString(COL_REVOCATION_EP));
    device->setVerifierEndpoint(vep);
    device->setRelyingPartyEndpoint(rep);
    device->setProverEndpoint(pep);
    device->setRevocationEndpoint(revep);

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
    device->setRevCheckSqn(res->getInt(COL_REV_CHECK_SQN));
    device->setRevAckSqn(res->getInt(COL_REV_ACK_SQN));

    string evidenceTypes(res->getString(COL_EVIDENCE_TYPES));
    Device::parseEvidenceTypes(evidenceTypes, device->getEvidenceTypes());
}

Device * DeviceStorageMySQL::selectDevice(string col, string &value)
{
    Device *device = new Device(tmpConfig);

    std::unique_ptr<sql::PreparedStatement> stmt(conn->prepareStatement("SELECT * FROM Device WHERE " + col + " = ?"));
    stmt->setString(1, value);

    sql::ResultSet *rs = stmt->executeQuery();
    if (!rs->next()) {
        return NULL;
    }
    std::unique_ptr<sql::ResultSet> res(rs);
    DeviceStorageMySQL::populateDevice(device, std::move(res));

    return device;
}

Device * DeviceStorageMySQL::findDevice(string &deviceID)
{
    Device *device = NULL;
    devicesLock.lock();
    map<string, Device *>::const_iterator it = devices.find(deviceID);
    if (it != devices.end()) {
        device = (Device *) it->second; 
        devicesLock.unlock();
        return device;
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

Device * DeviceStorageMySQL::findDeviceByIP(string &ip)
{
    Device *device = selectDevice(COL_PROVER_EP, ip);

    if (device != NULL) {
        devices[device->getId()] = device;
    }
    return device;
}

void DeviceStorageMySQL::insertDevice(string device)
{
    std::unique_ptr<sql::PreparedStatement> stmt(conn->prepareStatement("INSERT OR REPLACE INTO Device VALUES (?)"));
    stmt->setString(1, device);
    stmt->execute();
}

void DeviceStorageMySQL::insertDevice(Device *device)
{
    insertDevice(device->toString());
}

void DeviceStorageMySQL::update(Device *device, string col, string value)
{
    std::unique_ptr<sql::PreparedStatement> stmt(conn->prepareStatement(
          "UPDATE Device SET " + col + " = (?) WHERE id = ?"));
    stmt->setString(1, value);
    stmt->setString(2, device->getId());
    stmt->execute();
}

string DeviceStorageMySQL::getCol(Device *device, string col)
{
    std::unique_ptr<sql::PreparedStatement> stmt(conn->prepareStatement("SELECT " + col + " FROM Device WHERE id = ?"));
    stmt->setString(1, device->getId());
    std::unique_ptr<sql::ResultSet> res(stmt->executeQuery());

    if (!res->first()) {
        SD_LOG(LOG_ERR, "Could not fetch result from database");
    }
    return res->getString(col);
}

#endif