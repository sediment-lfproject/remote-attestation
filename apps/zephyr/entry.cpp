/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#include <zephyr.h>
#include <drivers/flash.h>
#include <device.h>
#include <soc.h>
#include <string.h>

#include <pb_encode.h>
#include <pb_decode.h>
#include "provision.pb.h"

#include "nv.h"

#include "BoardZephyr.hpp"
#include "Prover.hpp"
#include "Log.hpp"
#include "Comm.hpp"

Endpoint endpoint;
Config config(NV_PROVER);
BoardZephyr board;
string protocol;
string address;
string enc_key(Crypto::ENC_KEY_BYTES, 'x');
string attest_key(Crypto::ATTEST_KEY_BYTES, 'x');
string auth_key(Crypto::AUTH_KEY_BYTES, 'x');

extern "C" {

int conn_to_provisioner(char *addr, int port)
{
    Endpoint ep(Protocol::TCP, addr, port);
    return Comm::connectTcp(&ep);
}

void set_log_level(int log_level)
{
    string dummy;
    Log::initLog(log_level, log_level, dummy, -1, -1);
}

void set_suspend(bool suspend)
{
    Prover::suspend = suspend;
}

/**
 * The first byte of each flash page is the page type tag (sediment, sqn, etc, see provision.proto).
 * The next two bytes are the size of the encoded protobuf message.
 * This is to work around the limitation that nanopb does not handle string callbacks for oneof. 
 */
static int16_t read_used_size(off_t offset)
{
    uint8_t buf[5];
    memset(buf, '\0', sizeof(buf));
    int ret = do_read(offset, 4, buf);
    if (ret) {
        printk("used size read error: %d\n", ret);
        return -1;
    }
    int val = buf[1] | (buf[2] << 8);

    return val + NUM_PREFIX_BYTES;
}

static int16_t pad_to_block(int size)
{
    int16_t padded_size = size;
    if ((size % NV_BLOCK_SIZE) != 0) {
        padded_size = ((size / NV_BLOCK_SIZE) + 1) * NV_BLOCK_SIZE;
        // printk("not multiples of block size: %d; padded to %d\n", size, padded_size);
    }
    return padded_size;
}

bool erase_and_write(int32_t offset, uint8_t *buffer, uint32_t len)
{
    len = pad_to_block(len);
    if (len > NV_PAGE_SIZE) {
        printk("flash page size exceeded: %d v.s. %d", len, NV_PAGE_SIZE);
        return false;
    }
    
    int ret = do_erase(offset, NV_PAGE_SIZE);
    if (ret) {
        printk("erase error: %d\n", ret);
        return false;
    }

    ret = do_write(offset, len, buffer);
    if (ret) {
        printk("write error: %d\n", ret);
        return false; 
    }

    return true;
}

static int reload_to_vec(vector<uint8_t> &vec, uint8_t *buf, int size)
{
    vec.clear();
    for (int i = 0; i < size; i++)
        vec.push_back(buf[i]);

    return 0;
}

static bool print_string(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
    uint8_t buffer[1024] = {0};
    
    if (stream->bytes_left > sizeof(buffer) - 1)
        return false;
    
    if (!pb_read(stream, buffer, stream->bytes_left))
        return false;
    
    printf((char*)*arg, buffer);
    return true;
}

static void print_int(char *field, int32_t value)
{
    printk("%s: %d\n", field, value);
}

static void print_bool(char *field, bool value)
{
    printk("%s: %s\n", field, value ? "true" : "false");
}

static bool print_hex(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
    // 2800 is chosen to be slightly higher than
    // maximum WKD-IBE params size of 2535 when url levels is 32.
    uint8_t buffer[2800] = {0};
    
    if (stream->bytes_left > sizeof(buffer) - 1)
        return false;
    
    int field_len = stream->bytes_left;

    if (!pb_read(stream, buffer, stream->bytes_left))
        return false;
    
    printk("%s (%d):\n", (char *)*arg, field_len);
    for (int i = 0; i < field_len; i++) {
        printk("%02x ", buffer[i]);
        if (i % 20 == 19)
            printk("\n");
    }
    printk("\n");
    return true;
}

static bool get_string(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
    // 2800 is chosen to be slightly higher than
    // maximum WKD-IBE params size of 2535 when url levels is 32.
    uint8_t buf[2800] = {0}; 
                            
    /* We could read block-by-block to avoid the large buffer... */
    if (stream->bytes_left > sizeof(buf) - 1)
        return false;

    int field_len = stream->bytes_left;

    if (!pb_read(stream, buf, stream->bytes_left))
        return false;
    
    if (!strcmp(NV_ID, (char *) *arg)) {
        string newId((char *) buf);
        config.getComponent().setID(newId);
    }
    else if (!strcmp(NV_PROTOCOL, (char *) *arg)) {
        protocol = (char *)buf;  // init endpoint after all three (protocol, addr, port) are read
    }
    else if (!strcmp(NV_ADDRESS, (char *) *arg)) {
        address = (char *)buf;  // init endpoint after all three (protocol, addr, port) are read
    }
    else if (!strcmp(NV_DATA_TRANSPORT, (char *) *arg)) {
        string tx((char *) buf);
        DataTransport dataTx = Config::toDataTransport(tx);
        config.setTransport(dataTx);
    }
    else if (!strcmp(NV_MQTT_URL, (char *) *arg)) {
        string url((char *) buf);
        config.setMqttUrl(url);
    }
    else if (!strcmp(NV_MQTT_PUB_TOPIC, (char *) *arg)) {
        string pub((char *) buf);
        config.setTopicPub(pub);
    }
    else if (!strcmp(NV_MQTT_SUB_TOPIC, (char *) *arg)) {
        string sub((char *) buf);
        config.setTopicSub(sub);
    }
    else if (!strcmp(NV_MQTT_REV_TOPIC, (char *) *arg)) {
    }
    else if (!strcmp(NV_ENC_KEY, (char *) *arg)) {
        memcpy((char *)&enc_key[0], (char *) buf, field_len);
    }    
    else if (!strcmp(NV_ATTEST_KEY, (char *) *arg)) {
        memcpy((char *)&attest_key[0], (char *) buf, field_len);
    }
    else if (!strcmp(NV_AUTH_KEY, (char *) *arg)) {
        memcpy((char *)&auth_key[0], (char *) buf, field_len);
    }
    else if (!strcmp(NV_EURIPATH, (char *) *arg)) {
        vector<uint8_t> &vec = Publish::getEncryptUripath();
        reload_to_vec(vec, buf, field_len);
    }
    else if (!strcmp(NV_SURIPATH, (char *) *arg)) {
        vector<uint8_t> &vec = Publish::getSignUripath();
        reload_to_vec(vec, buf, field_len);
    }
    else if (!strcmp(NV_RURIPATH, (char *) *arg)) {
        vector<uint8_t> &vec = Subscribe::getRevocationUripath();
        reload_to_vec(vec, buf, field_len);
    }
    else if (!strcmp(NV_TIMEPATH, (char *) *arg)) {
        vector<uint8_t> &vec = Publish::getTimepath();
        reload_to_vec(vec, buf, field_len);
    }
    else if (!strcmp(NV_ENCRYPTKEY, (char *) *arg)) {
        vector<uint8_t> &vec =  Subscribe::getEncryptKey();
        reload_to_vec(vec, buf, field_len);
    }
    else if (!strcmp(NV_SIGNKEY, (char *) *arg)) {
        vector<uint8_t> &vec =  Publish::getSigningKey();
        reload_to_vec(vec, buf, field_len);
    }
    else if (!strcmp(NV_REVKEY, (char *) *arg)) {
        vector<uint8_t> &vec =  Subscribe::getRevocationKey();
        reload_to_vec(vec, buf, field_len);
    }
    else if (!strcmp(NV_REV_PROTOCOL, (char *) *arg)) {
        protocol = (char *)buf;  // init endpoint after all three (protocol, addr, port) are read
    }
    else if (!strcmp(NV_REV_ADDRESS, (char *) *arg)) {
        address = (char *)buf;  // init endpoint after all three (protocol, addr, port) are read
    }
    else if (!strcmp(NV_PARAMS, (char *) *arg)) {
        vector<uint8_t> &vec = Publish::getParams();
        reload_to_vec(vec, buf, field_len);
    }
    return true;
}

static bool load_sqn(provision_SqnPage *sqn_page)
{
    int16_t size = read_used_size(NV_SQN_PAGE);
    int16_t padded_size = pad_to_block(size);

    uint8_t buf[padded_size];
    memset(buf, '\0', sizeof(padded_size));
    int ret = do_read(NV_SQN_PAGE, padded_size, buf);
    if (ret) {
        printk("load_sqn error: %d\n", ret);
        return false;
    }

    *sqn_page = provision_SqnPage_init_zero;
    pb_istream_t stream = pb_istream_from_buffer(&buf[NUM_PREFIX_BYTES], size - NUM_PREFIX_BYTES);

    bool status = pb_decode(&stream, provision_SqnPage_fields, sqn_page);
    if (!status) {
        printk("load_sqn decode failed\n");
    }
    return status;
}
    
uint32_t read_sqn(SQN_Type sqn_type)
{
    provision_SqnPage sqn_page = provision_SqnPage_init_zero;
    bool ok = load_sqn(&sqn_page);
    if (!ok)
        return -1;

    switch(sqn_type) {
    case SQN_ATTEST:
        return sqn_page.attest_sqn;
    case SQN_SEEC:
        return sqn_page.seec_sqn;
    case SQN_REV_CHECK:
        return sqn_page.rev_check_sqn;
    case SQN_REV_ACK:
        return sqn_page.rev_ack_sqn;
    default:
        printk("invalide sqn type %d\n", sqn_type);
        return -1;
    }
}

void save_sqn(SQN_Type sqn_type, uint32_t sqn)
{
    uint8_t buf[64];
    pb_ostream_t stream;

    stream = pb_ostream_from_buffer(&buf[NUM_PREFIX_BYTES], 64);
    
    provision_SqnPage sqn_page;
    load_sqn(&sqn_page);  // load old sqn page

    switch(sqn_type) {
    case SQN_ATTEST:
        sqn_page.attest_sqn = sqn;
        break;
    case SQN_SEEC:
        sqn_page.seec_sqn = sqn;
        break;
    case SQN_REV_CHECK:
        sqn_page.rev_check_sqn = sqn;
            break;
    case SQN_REV_ACK:
        sqn_page.rev_ack_sqn = sqn;
        break;
    case SQN_CLEAR:
        sqn_page.attest_sqn = 1;
        sqn_page.seec_sqn = 0;
        sqn_page.rev_check_sqn = 0;
        sqn_page.rev_ack_sqn = 0;    
        break;
    default:
        printk("invalide sqn type %d\n", sqn_type);
        return;
    }
    
    if (!pb_encode(&stream, provision_SqnPage_fields, &sqn_page)) {
        SD_LOG(LOG_ERR, "sqn encoding error");
        return;
    }
    
    uint32_t msg_len = stream.bytes_written;
    buf[0] = (uint8_t) provision_ProvisionMessage_sqn_page_tag;
    buf[1] = (uint8_t) (msg_len & 0xff);
    buf[2] = (uint8_t) ((msg_len >> 8) & 0xff);
    
    erase_and_write(NV_SQN_PAGE, buf, msg_len + NUM_PREFIX_BYTES);
}

static void reload_sediment(Prover &prover)
{
    int16_t size = read_used_size(NV_SEDIMENT_PAGE);
    int16_t padded_size = pad_to_block(size);

    uint8_t buf[padded_size];
    memset(buf, '\0', sizeof(padded_size));
    int ret = do_read(NV_SEDIMENT_PAGE, padded_size, buf);
    if (ret) {
        printk("reload_sediment error: %d\n", ret);
        return;
    }

    provision_SedimentPage sediment = provision_SedimentPage_init_zero;
    pb_istream_t stream = pb_istream_from_buffer(&buf[NUM_PREFIX_BYTES], size - NUM_PREFIX_BYTES);
    
    sediment.id.funcs.decode = &get_string;
    sediment.id.arg = (void *)NV_ID;

    sediment.protocol.funcs.decode = &get_string;
    sediment.protocol.arg = (void *)NV_PROTOCOL;

    sediment.address.funcs.decode = &get_string;
    sediment.address.arg = (void *)NV_ADDRESS;

    sediment.transport.funcs.decode = &get_string;
    sediment.transport.arg = (void *)NV_DATA_TRANSPORT;

    sediment.mqtt_url.funcs.decode = &get_string;
    sediment.mqtt_url.arg = (void *)NV_MQTT_URL; 

    sediment.mqtt_pub_topic.funcs.decode = &get_string;
    sediment.mqtt_pub_topic.arg = (void *)NV_MQTT_PUB_TOPIC;

    sediment.mqtt_sub_topic.funcs.decode = &get_string;
    sediment.mqtt_sub_topic.arg = (void *)NV_MQTT_SUB_TOPIC;

    sediment.mqtt_rev_topic.funcs.decode = &get_string;
    sediment.mqtt_rev_topic.arg = (void *)NV_MQTT_REV_TOPIC;

    sediment.enc_key.funcs.decode = &get_string;
    sediment.enc_key.arg = (void *)NV_ENC_KEY;

    sediment.attest_key.funcs.decode = &get_string;
    sediment.attest_key.arg = (void *)NV_ATTEST_KEY;

    sediment.auth_key.funcs.decode = &get_string;
    sediment.auth_key.arg = (void *)NV_AUTH_KEY;

    bool status = pb_decode(&stream, provision_SedimentPage_fields, &sediment);
    if (status) {
        std::transform(protocol.begin(), protocol.end(), protocol.begin(), [](unsigned char c){ return std::tolower(c); });
        prover.reInitEndpoints(Endpoint::toProtocol(protocol), address, sediment.port);
        config.setEncryptionEnabled(sediment.enc_enabled);
        config.setAttestationEnabled(sediment.attest_enabled);
        config.setSeecEnabled(sediment.seec_enabled);
        config.setSigningEnabled(sediment.sign_enabled);
        config.setPassThru(sediment.pass_thru_enabled);
        config.setAuthenticationEnabled(sediment.auth_enabled);
        config.setDownload(sediment.download);
        config.setFixedDelay(sediment.fixed_delay);
        
        config.setPassportPeriod(sediment.passport_period);
        config.setPayloadSize(sediment.payload_size);
        config.setReportInterval(sediment.report_interval);
        config.setLogLevel(sediment.log_level);

        Seec &seec = prover.getSeec();
        Crypto *crypto = seec.getCrypto();
        if (crypto == NULL) {
            SD_LOG(LOG_ERR, "null crypto");
        }
        else {
            crypto->changeKey(KEY_ENCRYPTION, (unsigned char *) &enc_key[0], enc_key.size());
            crypto->changeKey(KEY_ATTESTATION, (unsigned char *) &attest_key[0], attest_key.size());
            crypto->changeKey(KEY_AUTH, (unsigned char *) &auth_key[0], auth_key.size());
        }
    }
    else {
        printk("reload_sediment decode failed\n");
    }
}

static void reload_wkd_ibe_1(Prover &prover)
{
    int16_t size = read_used_size(NV_SEEC_PAGE_1);
    int16_t padded_size = pad_to_block(size);

    uint8_t buf[padded_size];
    memset(buf, '\0', sizeof(padded_size));
    int ret = do_read(NV_SEEC_PAGE_1, padded_size, buf);
    if (ret) {
        printk("reload_wkd_ibe_1 error: %d\n", ret);
        return;
    }
 
    provision_WkdIbePage1 wkd_ibe = provision_WkdIbePage1_init_zero;
    pb_istream_t stream = pb_istream_from_buffer(&buf[NUM_PREFIX_BYTES], size - NUM_PREFIX_BYTES);
    
    wkd_ibe.euripath.funcs.decode = &get_string;
    wkd_ibe.euripath.arg = (void *)NV_EURIPATH;

    wkd_ibe.suripath.funcs.decode = &get_string;
    wkd_ibe.suripath.arg = (void *)NV_SURIPATH;

    wkd_ibe.ruripath.funcs.decode = &get_string;
    wkd_ibe.ruripath.arg = (void *)NV_RURIPATH;

    wkd_ibe.timepath.funcs.decode = &get_string;
    wkd_ibe.timepath.arg = (void *)NV_TIMEPATH;

    wkd_ibe.encryptkey.funcs.decode = &get_string;
    wkd_ibe.encryptkey.arg = (void *)NV_ENCRYPTKEY; 

    wkd_ibe.signkey.funcs.decode = &get_string;
    wkd_ibe.signkey.arg = (void *)NV_SIGNKEY;

    wkd_ibe.revkey.funcs.decode = &get_string;
    wkd_ibe.revkey.arg = (void *)NV_REVKEY;

    wkd_ibe.rev_protocol.funcs.decode = &get_string;
    wkd_ibe.rev_protocol.arg = (void *)NV_REV_PROTOCOL;

    wkd_ibe.rev_address.funcs.decode = &get_string;
    wkd_ibe.rev_address.arg = (void *)NV_REV_ADDRESS;

    bool status = pb_decode(&stream, provision_WkdIbePage1_fields, &wkd_ibe);
    if (status) {
        std::transform(protocol.begin(), protocol.end(), protocol.begin(), [](unsigned char c){ return std::tolower(c); });
        prover.reInitRevEndpoint(Endpoint::toProtocol(protocol), address, wkd_ibe.rev_port);
     
        config.setNumCycles(wkd_ibe.num_cycles);
        config.setIterations(wkd_ibe.iterations);
    }
    else {
        printk("reload_wkd_ibe_1 decode failed\n");
    }
}

static void reload_wkd_ibe_2(Prover &prover)
{
    int16_t size = read_used_size(NV_SEEC_PAGE_2);
    int16_t padded_size = pad_to_block(size);

    uint8_t buf[padded_size];
    memset(buf, '\0', sizeof(padded_size));
    int ret = do_read(NV_SEEC_PAGE_2, padded_size, buf);
    if (ret) {
        printk("reload_wkd_ibe_2 error: %d\n", ret);
        return;
    }
 
    provision_WkdIbePage2 wkd_ibe = provision_WkdIbePage2_init_zero;
    pb_istream_t stream = pb_istream_from_buffer(&buf[NUM_PREFIX_BYTES], size - NUM_PREFIX_BYTES);
    
    wkd_ibe.params.funcs.decode = &get_string;
    wkd_ibe.params.arg = (void *)NV_PARAMS;

    bool status = pb_decode(&stream, provision_WkdIbePage2_fields, &wkd_ibe);
    if (!status) {
        printk("reload_wkd_ibe_2 decode failed\n");
    }
}

static void reload_flash(Prover &prover)
{
    read_sqn(SQN_ATTEST);
    reload_sediment(prover);
    reload_wkd_ibe_1(prover);
    reload_wkd_ibe_2(prover);
}

static void show_sediment()
{
    int16_t size = read_used_size(NV_SEDIMENT_PAGE);
    int16_t padded_size = pad_to_block(size);

    uint8_t buf[padded_size];
    memset(buf, '\0', sizeof(padded_size));
    int ret = do_read(NV_SEDIMENT_PAGE, padded_size, buf);
    if (ret) {
        printk("show_sediment error: %d\n", ret);
        return;
    }

    provision_SedimentPage sediment = provision_SedimentPage_init_zero;
    pb_istream_t stream = pb_istream_from_buffer(&buf[NUM_PREFIX_BYTES], size - NUM_PREFIX_BYTES);
    
    sediment.id.funcs.decode = &print_string;
    sediment.id.arg = (void *)"id: %s\n";

    sediment.protocol.funcs.decode = &print_string;
    sediment.protocol.arg = (void *)"protocol: %s\n";

    sediment.address.funcs.decode = &print_string;
    sediment.address.arg = (void *)"address: %s\n";

    sediment.transport.funcs.decode = &print_string;
    sediment.transport.arg = (void *)"transport: %s\n";

    sediment.mqtt_url.funcs.decode = &print_string;
    sediment.mqtt_url.arg = (void *)"mqtt_url: %s\n";

    sediment.mqtt_pub_topic.funcs.decode = &print_string;
    sediment.mqtt_pub_topic.arg = (void *)"mqtt_pub_topic: %s\n";

    sediment.mqtt_sub_topic.funcs.decode = &print_string;
    sediment.mqtt_sub_topic.arg = (void *)"mqtt_sub_topic: %s\n";

    sediment.mqtt_rev_topic.funcs.decode = &print_string;
    sediment.mqtt_rev_topic.arg = (void *)"mqtt_rev_topic: %s\n";

    sediment.enc_key.funcs.decode = &print_hex;
    sediment.enc_key.arg = (void *)NV_ENC_KEY;

    sediment.attest_key.funcs.decode = &print_hex;
    sediment.attest_key.arg = (void *)NV_ATTEST_KEY;

    sediment.auth_key.funcs.decode = &print_hex;
    sediment.auth_key.arg = (void *)NV_AUTH_KEY;

    bool status = pb_decode(&stream, provision_SedimentPage_fields, &sediment);
    if (status) {
        print_bool((char *)NV_ENCRYPT, sediment.enc_enabled);
        print_bool((char *)NV_ATTEST, sediment.attest_enabled);
        print_bool((char *)NV_SEEC, sediment.seec_enabled);
        print_bool((char *)NV_SIGNING, sediment.sign_enabled);
        print_bool((char *)NV_PASS_THRU, sediment.pass_thru_enabled);
        print_bool((char *)NV_AUTHENTICATION, sediment.auth_enabled);
        print_bool((char *)NV_DOWNLOAD, sediment.download);
        
        print_int((char *)NV_PORT, sediment.port);        
        print_int((char *)NV_PASSPORT_PERIOD, sediment.passport_period);
        print_int((char *)NV_PAYLOAD_SIZE, sediment.payload_size);
        print_int((char *)NV_REPORT_INTVL, sediment.report_interval);
        print_int((char *)NV_LOG_LEVEL, sediment.log_level);
        print_int((char *)NV_FIXED_DELAY, sediment.fixed_delay);
    }
    else {
        printk("show_sediment decode failed\n");
    }
}

static void show_wkd_ibe_1()
{
    int16_t size = read_used_size(NV_SEEC_PAGE_1);
    int16_t padded_size = pad_to_block(size);

    uint8_t buf[padded_size];
    memset(buf, '\0', sizeof(padded_size));
    int ret = do_read(NV_SEEC_PAGE_1, padded_size, buf);
    if (ret) {
        printk("show_wkd_ibe_1 error: %d\n", ret);
        return;
    }
 
    provision_WkdIbePage1 wkd_ibe = provision_WkdIbePage1_init_zero;
    pb_istream_t stream = pb_istream_from_buffer(&buf[NUM_PREFIX_BYTES], size - NUM_PREFIX_BYTES);
    
    wkd_ibe.euripath.funcs.decode = &print_hex;
    wkd_ibe.euripath.arg = (void *)NV_EURIPATH;

    wkd_ibe.suripath.funcs.decode = &print_hex;
    wkd_ibe.suripath.arg = (void *)NV_SURIPATH;

    wkd_ibe.ruripath.funcs.decode = &print_hex;
    wkd_ibe.ruripath.arg = (void *)NV_RURIPATH;

    wkd_ibe.timepath.funcs.decode = &print_hex;
    wkd_ibe.timepath.arg = (void *)NV_TIMEPATH;

    wkd_ibe.encryptkey.funcs.decode = &print_hex;
    wkd_ibe.encryptkey.arg = (void *)NV_ENCRYPTKEY; 

    wkd_ibe.signkey.funcs.decode = &print_hex;
    wkd_ibe.signkey.arg = (void *)NV_SIGNKEY;

    wkd_ibe.revkey.funcs.decode = &print_hex;
    wkd_ibe.revkey.arg = (void *)NV_REVKEY;

    wkd_ibe.rev_protocol.funcs.decode = &print_string;
    wkd_ibe.rev_protocol.arg = (void *)"rev_protocol: %s\n";

    wkd_ibe.rev_address.funcs.decode = &print_string;
    wkd_ibe.rev_address.arg = (void *)"rev_address: %s\n";

    bool status = pb_decode(&stream, provision_WkdIbePage1_fields, &wkd_ibe);
    if (status) {
        print_int((char *)NV_REV_PORT, wkd_ibe.rev_port);
        print_int((char *)NV_NUM_CYCLES, wkd_ibe.num_cycles);
        print_int((char *)NV_ITERATIONS, wkd_ibe.iterations);
    }
    else {
        printk("show_wkd_ibe_1 decode failed\n");
    }
}

static void show_wkd_ibe_2()
{
    int16_t size = read_used_size(NV_SEEC_PAGE_2);
    int16_t padded_size = pad_to_block(size);

    uint8_t buf[padded_size];
    memset(buf, '\0', sizeof(padded_size));
    int ret = do_read(NV_SEEC_PAGE_2, padded_size, buf);
    if (ret) {
        printk("show_wkd_ibe_2 error: %d\n", ret);
        return;
    }
 
    provision_WkdIbePage2 wkd_ibe = provision_WkdIbePage2_init_zero;
    pb_istream_t stream = pb_istream_from_buffer(&buf[NUM_PREFIX_BYTES], size - NUM_PREFIX_BYTES);
    
    wkd_ibe.params.funcs.decode = &print_hex;
    wkd_ibe.params.arg = (void *)NV_PARAMS;

    bool status = pb_decode(&stream, provision_WkdIbePage2_fields, &wkd_ibe);
    if (!status) {
        printk("show_wkd_ibe_2 decode failed\n");
    }
}

static void show_sqn()
{
    provision_SqnPage sqn_page;
    load_sqn(&sqn_page);

    printk("%s: %d\n", NV_ATTEST_SQN, sqn_page.attest_sqn);
    printk("%s: %d\n", NV_SEEC_SQN, sqn_page.seec_sqn);
    printk("%s: %d\n", NV_REV_CHECK_SQN, sqn_page.rev_check_sqn);
    printk("%s: %d\n", NV_REV_ACK_SQN, sqn_page.rev_ack_sqn);            
}

void show_flash()
{
    show_sediment();
    printk("\n");

    show_wkd_ibe_1();
    show_wkd_ibe_2();
    printk("\n");
    
    show_sqn();
}

void set_lte_ready()
{
    ConfigComponent &proverConfig = config.getComponent();

    // create a dummy endpoint; will be overriden below in reload_flash().
    // TODO: should eliminate the need of a dummy endpoint
    proverConfig.setOutgoing(new Endpoint());

    Prover prover(config, &board);
    reload_flash(prover);

    const string &topic = config.getTopicPub();
    prover.setTopicPub(topic);
    // printk("\n%s\n", config.toString().c_str());

    if (config.getTransport() == TRANSPORT_MQTT) {
        prover.runMqtt();
    }
    else
        prover.run();
}
} // extern "C"
