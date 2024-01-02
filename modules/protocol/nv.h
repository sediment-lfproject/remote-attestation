/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

/*
 * See doc/flash_pages.txt for flash page layout of the Giant Gecko.
 *
 * Each page is 4KB.
 * Each write must be of multiple blocks, each block is 4 byte.
 * An entire page must be erased before any block can be properly written.
 * 1's can be changed to 0's, but not 0's to 1s.
 */
#pragma once

#ifndef __FLASH__
#define __FLASH__

#ifdef __cplusplus
extern "C" {
#endif

#include "nv_board.h"

#define NUM_PREFIX_BYTES          3

// sediment page
#define NV_ID                     "id"
#define NV_PROTOCOL               "protocol"
#define NV_ADDRESS                "address"
#define NV_PORT                   "port"
#define NV_ENC_KEY                "enc_key"
#define NV_ATTEST_KEY             "attest_key"
#define NV_AUTH_KEY               "auth_key"
#define NV_DATA_TRANSPORT         "transport"
#define NV_MQTT_URL               "mqtt_url"
#define NV_MQTT_PUB_TOPIC         "mqtt_pub_topic"
#define NV_MQTT_SUB_TOPIC         "mqtt_sub_topic"
#define NV_MQTT_REV_TOPIC         "mqtt_rev_topic"
#define NV_ENCRYPT                "enc_enabled"
#define NV_AUTHENTICATION         "auth_enabled"
#define NV_ATTEST                 "attest_enabled"
#define NV_SEEC                   "seec_enabled"
#define NV_SIGNING                "sign_enabled"
#define NV_PASS_THRU              "pass_thru_enabled"
#define NV_DOWNLOAD               "download"
#define NV_PASSPORT_PERIOD        "passport_period"
#define NV_PAYLOAD_SIZE           "payload_size"
#define NV_REPORT_INTVL           "report_interval"
#define NV_LOG_LEVEL              "log_level"
#define NV_FIXED_DELAY            "fixed_delay"

// WKD-IBE page 1
#define NV_NUM_CYCLES             "num_cycles"
#define NV_ITERATIONS             "iterations"

#define NV_REVOCATION             "revocation"
#define NV_REV_PROTOCOL           "rev_protocol"
#define NV_REV_ADDRESS            "rev_address"
#define NV_REV_PORT               "rev_port"

#define NV_EURIPATH               "euripath"
#define NV_SURIPATH               "suripath"
#define NV_RURIPATH               "ruripath"
#define NV_TIMEPATH               "timepath"
#define NV_SIGNKEY                "signkey"
#define NV_REVKEY                 "revkey"
#define NV_ENCRYPTKEY             "encryptkey"

// WKD-IBE page 2
// the WKD-IBE params can be big, .e.g when the attribute length is 32, it is 2353.
// keep it at its own page
#define NV_PARAMS                 "params"

// SQN's page
#define NV_ATTEST_SQN             "attest_sqn"
#define NV_SEEC_SQN               "seec_sqn"
#define NV_REV_CHECK_SQN          "rev_check_sqn"
#define NV_REV_ACK_SQN            "rev_ack_sqn"

// RSA page 1 (Smart Warehouse)
#define NV_RSA_PRIVATE_SIZE       "rsa_private_size"
#define NV_RSA_PRIVATE            "rsa_private"
#define NV_RSA_PUBLIC_SIZE        "rsa_public_size"
#define NV_RSA_PUBLIC             "rsa_public"

// RSA pages 2 (Smart Warehouse)
#define NV_RSA_SIGN               "rsa_sign"
#define NV_RSA_VERIFY             "rsa_verify"

// misc items not saved
#define NV_PROVER                 "prover"
#define NV_VERIFIER               "verifier"
#define NV_FIREWALL               "firewall"
#define NV_APP_SERVER             "appServer"
#define NV_REV_SERVER             "revServer"
#define NV_COMMENT                "comment"
#define NV_FW_SCRIPT              "fwScript"

typedef enum _SQN_TYPE { 
    SQN_ATTEST = 0, 
    SQN_SEEC = 1,
    SQN_REV_CHECK = 2,
    SQN_REV_ACK = 3,
    SQN_CLEAR = 4   // reset to initial values for all SQN's
} SQN_Type;

void save_sqn(SQN_Type sqn_type, uint32_t sqn);
uint32_t read_sqn(SQN_Type sqn_type);
bool erase_and_write(int32_t offset, uint8_t *buffer, uint32_t len);
void show_flash();
int conn_to_provisioner(char *addr, int port);
void set_log_level(int log_level);
void set_suspend(bool sus);

int check_flash_device();
int do_read(off_t offset, size_t len, uint8_t *buf);
int do_erase(off_t offset, size_t size);
int do_write(off_t offset, size_t len, uint8_t *buf);

#ifdef __cplusplus
}
#endif

#endif // ifndef __FLASH__
