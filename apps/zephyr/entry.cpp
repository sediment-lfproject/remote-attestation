/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#include <zephyr.h>
#include <drivers/flash.h>
#include <device.h>
#include <soc.h>
#include <string.h>

#include "nv.h"

#include "BoardZephyr.hpp"
#include "Prover.hpp"
#include "Log.hpp"

Endpoint endpoint;
Config config(NV_PROVER);
BoardZephyr board;

extern "C" {
int reload(const char *item_name, int size, uint8_t *buf)
{
    memset(buf, 0, size);
    int ret = read_item(item_name, size, buf);
    if (ret != 0) {
        SD_LOG(LOG_ERR, "cannot read item %s from flash", item_name);
        return -1;
    }
    return 0;
}

static int reload_to_vec(const char *item_name, vector<uint8_t> &vec, int size)
{
    uint8_t buf[size];

    memset(buf, 0, size);
    int ret = read_item_exact(item_name, size, buf);
    if (ret != 0) {
        SD_LOG(LOG_ERR, "cannot read item %s from flash", item_name);
        return -1;
    }
    vec.clear();
    for (int i = 0; i < size; i++)
        vec.push_back(buf[i]);

    return 0;
}

static void reload_endpoint(Prover &prover, uint8_t *buf, int size)
{
    if (reload(NV_PROTOCOL, size, buf) != 0)
        return;

    string prot((char *) buf);
    Protocol protocol = Endpoint::toProtocol(prot);

    if (reload(NV_PORT, size, buf) != 0)
        return;

    int port = *(int *) buf;

    if (reload(NV_ADDRESS, size, buf) != 0)
        return;

    SD_LOG(LOG_INFO, "endpoint in flash: %d:%s:%d", protocol, buf, port);
    string address((char *) buf);

    prover.reInitEndpoints(protocol, address, port);
}

static void reload_rev_endpoint(Prover &prover, uint8_t *buf, int size)
{
    if (reload(NV_REV_PROTOCOL, size, buf) != 0)
        return;

    string prot((char *) buf);
    Protocol protocol = Endpoint::toProtocol(prot);

    if (reload(NV_REV_PORT, size, buf) != 0)
        return;

    int port = *(int *) buf;

    if (reload(NV_REV_ADDRESS, size, buf) != 0)
        return;

    SD_LOG(LOG_INFO, "Revocation endpoint in flash: %d:%s:%d", protocol, buf, port);
    string address((char *) buf);

    prover.reInitRevEndpoint(protocol, address, port);
}

static void reload_flash(Prover &prover)
{
    uint8_t buf[32];
    int ret = read_item(NV_MAGIC, 4, buf);

    if (ret != 0 || buf[0] != 0x0a || buf[1] != 0xce) {
        SD_LOG(LOG_WARNING, "MAGIC not found");
        return;
    }
    SD_LOG(LOG_INFO, "MAGIC found");

    if (reload(NV_ID, sizeof(buf), buf) == 0) {
        string newId((char *) buf);
        config.getComponent().setID(newId);
    }

    reload_endpoint(prover, buf, sizeof(buf));

    if (reload(NV_KEY_DIST, sizeof(buf), buf) == 0) {
        string newKeyDist((char *) buf);
        KeyEncType keyDist = Config::toKeyEncType(newKeyDist);
        config.setKeyDistMethod(keyDist);
    }

    if (reload(NV_KEY_CHG_INTVL, sizeof(buf), buf) == 0) {
        config.setKeyChangeInterval(*(uint32_t *) buf);
    }

    if (reload(NV_ENCRYPT, sizeof(buf), buf) == 0) {
        config.setEncryptionEnabled(*(uint8_t *) buf != 0);
    }

    if (reload(NV_REPORT_INTVL, sizeof(buf), buf) == 0) {
        config.setReportInterval(*(uint8_t *) buf);
    }

    if (reload(NV_ATTEST, sizeof(buf), buf) == 0) {
        config.setAttestationEnabled(*(uint8_t *) buf != 0);
    }

    if (reload(NV_SEEC, sizeof(buf), buf) == 0) {
        config.setSeecEnabled(*(uint8_t *) buf != 0);
    }

    if (reload(NV_KEY_ENCRYPTION, sizeof(buf), buf) == 0) {
        config.setKeyEncryptionEnabled(*(uint8_t *) buf != 0);
    }

    if (reload(NV_SIGNING, sizeof(buf), buf) == 0) {
        config.setSigningEnabled(*(uint8_t *) buf != 0);
    }

    if (reload(NV_KEY_CHANGE, sizeof(buf), buf) == 0) {
        config.setKeyChangeEnabled(*(uint8_t *) buf != 0);
    }

    if (reload(NV_PASSPORT_PERIOD, sizeof(buf), buf) == 0) {
        config.setPassportPeriod(*(uint32_t *) buf);
    }

    if (reload(NV_PAYLOAD_SIZE, sizeof(buf), buf) == 0) {
        config.setPayloadSize(*(uint32_t *) buf);
    }

    if (reload(NV_PASS_THRU, sizeof(buf), buf) == 0) {
        config.setPassThru(*(uint8_t *) buf != 0);
    }

    if (reload(NV_NUM_CYCLES, sizeof(buf), buf) == 0) {
        config.setNumCycles(*(uint32_t *) buf);
    }

    if (reload(NV_ITERATIONS, sizeof(buf), buf) == 0) {
        config.setIterations(*(uint32_t *) buf);
    }

    if (reload(NV_AUTHENTICATION, sizeof(buf), buf) == 0) {
        config.setAuthenticationEnabled(*(uint8_t *) buf != 0);
    }

    if (reload(NV_DATA_TRANSPORT, sizeof(buf), buf) == 0) {
        string tx((char *) buf);
        DataTransport dataTx = Config::toDataTransport(tx);
        config.setTransport(dataTx);
    }

    if (reload(NV_MQTT_URL, sizeof(buf), buf) == 0) {
        string url((char *) buf);
        config.setMqttUrl(url);
    }

    if (reload(NV_MQTT_PUB_TOPIC, sizeof(buf), buf) == 0) {
        string pub((char *) buf);
        config.setTopicPub(pub);
    }

    if (reload(NV_MQTT_SUB_TOPIC, sizeof(buf), buf) == 0) {
        string sub((char *) buf);
        config.setTopicSub(pub);
    }

    uint8_t enckey[Crypto::ENC_KEY_BYTES];
    if (reload(NV_ENC_KEY, sizeof(enckey), enckey) == 0) {
        Seec &seec     = prover.getSeec();
        Crypto *crypto = seec.getCrypto();
        if (crypto == NULL) {
            SD_LOG(LOG_ERR, "null crypto");
        }
        else
            crypto->changeKey(KEY_ENCRYPTION, (unsigned char *) enckey, sizeof(enckey));
    }

    uint8_t attestkey[Crypto::ATTEST_KEY_BYTES];
    if (reload(NV_ATTEST_KEY, sizeof(attestkey), attestkey) == 0) {
        Seec &seec     = prover.getSeec();
        Crypto *crypto = seec.getCrypto();
        if (crypto == NULL) {
            SD_LOG(LOG_ERR, "null crypto");
        }
        else
            crypto->changeKey(KEY_ATTESTATION, (unsigned char *) attestkey, sizeof(attestkey));
    }

    uint8_t authkey[Crypto::AUTH_KEY_BYTES];
    if (reload(NV_AUTH_KEY, sizeof(authkey), authkey) == 0) {
        Seec &seec     = prover.getSeec();
        Crypto *crypto = seec.getCrypto();
        if (crypto == NULL) {
            SD_LOG(LOG_ERR, "null crypto");
        }
        else
            crypto->changeKey(KEY_AUTH, (unsigned char *) authkey, sizeof(authkey));
    }
#ifdef SEEC_ENABLED
    reload_rev_endpoint(prover, buf, sizeof(buf));

    int size = 0;
    if (reload(NV_PARAMS_SIZE, sizeof(int), (uint8_t *) &size) != 0)
        return;

    if (reload_to_vec(NV_PARAMS, Publish::getParams(), size) != 0)
        return;

    if (reload(NV_EURIPATH_SIZE, sizeof(int), (uint8_t *) &size) != 0)
        return;

    if (reload_to_vec(NV_EURIPATH, Publish::getEncryptUripath(), size) != 0)
        return;

    if (reload(NV_SURIPATH_SIZE, sizeof(int), (uint8_t *) &size) != 0)
        return;

    if (reload_to_vec(NV_SURIPATH, Publish::getSignUripath(), size) != 0)
        return;

    if (reload(NV_TIMEPATH_SIZE, sizeof(int), (uint8_t *) &size) != 0)
        return;

    if (reload_to_vec(NV_TIMEPATH, Publish::getTimepath(), size) != 0)
        return;

    if (reload(NV_SIGNKEY_SIZE, sizeof(int), (uint8_t *) &size) != 0)
        return;

    if (reload_to_vec(NV_SIGNKEY, Publish::getSigningKey(), size) != 0)
        return;

#endif // ifdef SEEC_ENABLED
}

void set_lte_ready()
{
    ConfigComponent &proverConfig = config.getComponent();

    // create a dummy endpoint; will be overriden below in reload_flash().
    // TODO: should eliminate the need of a dummy endpoint
    proverConfig.setOutgoing(new Endpoint());

    Prover prover(config, &board);
    reload_flash(prover);
    printk("\n%s\n", config.toString().c_str());

    if (config.getTransport() == TRANSPORT_MQTT) {
        prover.runMqtt();
    }
    else
        prover.run();
}
} // extern "C"
