/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
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

#define NV_TYPE_CHAR    0
#define NV_TYPE_BYTE    1
#define NV_TYPE_BOOL    2
#define NV_TYPE_INT     3
#define NV_TYPE_BLOCK   4 // multi-chunk data in hex
#define NV_TYPE_LINE    5 // multi-chunk data in chars

#define NV_WKD_IBE_PAGE "wkd"
#define NV_RA_PAGE      "ra"
#define NV_RSA_PAGE     "rsa"
#define NV_RSA2_PAGE    "rsa2"

// Maintain the order of the following macros since the offsets are relatively defined

// The following are assumed to be static. Changes to them requires a reboot for them to take effect
#define NV_MAGIC                  "magic"
#define NV_LEN_MAGIC              4
#define NV_OFFSET_MAGIC           NV_FLASH_OFFSET

#define NV_ID                     "id"
#define NV_LEN_ID                 32
#define NV_OFFSET_ID              (NV_OFFSET_MAGIC + NV_LEN_MAGIC)

#define NV_PROTOCOL               "protocol"
#define NV_LEN_PROTOCOL           8
#define NV_OFFSET_PROTOCOL        (NV_OFFSET_ID + NV_LEN_ID)

#define NV_ADDRESS                "address"
#define NV_LEN_ADDRESS            32
#define NV_OFFSET_ADDRESS         (NV_OFFSET_PROTOCOL + NV_LEN_PROTOCOL)

#define NV_PORT                   "port"
#define NV_LEN_PORT               4
#define NV_OFFSET_PORT            (NV_OFFSET_ADDRESS + NV_LEN_ADDRESS)

#define NV_KEY_DIST               "key_dist"
#define NV_LEN_KEY_DIST           8
#define NV_OFFSET_KEY_DIST        (NV_OFFSET_PORT + NV_LEN_PORT)

#define NV_KEY_CHG_INTVL          "key_change_interval"
#define NV_LEN_KEY_CHG_INTVL      4
#define NV_OFFSET_KEY_CHG_INTVL   (NV_OFFSET_KEY_DIST + NV_LEN_KEY_DIST)

#define NV_ENCRYPT                "enc_enabled"
#define NV_LEN_ENCRYPT            4
#define NV_OFFSET_ENCRYPT         (NV_OFFSET_KEY_CHG_INTVL + NV_LEN_KEY_CHG_INTVL)

#define NV_REPORT_INTVL           "report_interval"
#define NV_LEN_REPORT_INTVL       4
#define NV_OFFSET_REPORT_INTVL    (NV_OFFSET_ENCRYPT + NV_LEN_ENCRYPT)

#define NV_ATTEST                 "attest_enabled"
#define NV_LEN_ATTEST             4
#define NV_OFFSET_ATTEST          (NV_OFFSET_REPORT_INTVL + NV_LEN_REPORT_INTVL)

#define NV_SEEC                   "seec_enabled"
#define NV_LEN_SEEC               4
#define NV_OFFSET_SEEC            (NV_OFFSET_ATTEST + NV_LEN_ATTEST)

#define NV_KEY_ENCRYPTION         "key_enc_enabled"
#define NV_LEN_KEY_ENCRYPTION     4
#define NV_OFFSET_KEY_ENCRYPTION  (NV_OFFSET_SEEC + NV_LEN_SEEC)

#define NV_SIGNING                "sign_enabled"
#define NV_LEN_SIGNING            4
#define NV_OFFSET_SIGNING         (NV_OFFSET_KEY_ENCRYPTION + NV_LEN_KEY_ENCRYPTION)

#define NV_KEY_CHANGE             "key_change_enabled"
#define NV_LEN_KEY_CHANGE         4
#define NV_OFFSET_KEY_CHANGE      (NV_OFFSET_SIGNING + NV_LEN_SIGNING)

#define NV_PASSPORT_PERIOD        "passport_period"
#define NV_LEN_PASSPORT_PERIOD    4
#define NV_OFFSET_PASSPORT_PERIOD (NV_OFFSET_KEY_CHANGE + NV_LEN_KEY_CHANGE)

#define NV_PAYLOAD_SIZE           "payload_size"
#define NV_LEN_PAYLOAD_SIZE       4
#define NV_OFFSET_PAYLOAD_SIZE    (NV_OFFSET_PASSPORT_PERIOD + NV_LEN_PASSPORT_PERIOD)

#define NV_PASS_THRU              "pass_thru_enabled"
#define NV_LEN_PASS_THRU          4
#define NV_OFFSET_PASS_THRU       (NV_OFFSET_PAYLOAD_SIZE + NV_LEN_PAYLOAD_SIZE)

#define NV_NUM_CYCLES             "num_cycles"
#define NV_LEN_NUM_CYCLES         4
#define NV_OFFSET_NUM_CYCLES      (NV_OFFSET_PASS_THRU + NV_LEN_PASS_THRU)

#define NV_ITERATIONS             "iterations"
#define NV_LEN_ITERATIONS         4
#define NV_OFFSET_ITERATIONS      (NV_OFFSET_NUM_CYCLES + NV_LEN_NUM_CYCLES)

#define NV_AUTHENTICATION         "auth_enabled"
#define NV_LEN_AUTHENTICATION     4
#define NV_OFFSET_AUTHENTICATION  (NV_OFFSET_ITERATIONS + NV_LEN_ITERATIONS)

#define NV_DATA_TRANSPORT         "transport"
#define NV_LEN_DATA_TRANSPORT     32
#define NV_OFFSET_DATA_TRANSPORT  (NV_OFFSET_AUTHENTICATION + NV_LEN_AUTHENTICATION)

#define NV_LOG_LEVEL              "log_level"
#define NV_LEN_LOG_LEVEL          4
#define NV_OFFSET_LOG_LEVEL       (NV_OFFSET_DATA_TRANSPORT + NV_LEN_DATA_TRANSPORT)

#define NV_DOWNLOAD               "download"
#define NV_LEN_DOWNLOAD           4
#define NV_OFFSET_DOWNLOAD        (NV_OFFSET_LOG_LEVEL + NV_LEN_LOG_LEVEL)

// The following are expected to be changed during device operation
#define NV_ENC_KEY              "enc_key"
#define NV_LEN_ENC_KEY          32
#define NV_OFFSET_ENC_KEY       (NV_OFFSET_DOWNLOAD + NV_LEN_DOWNLOAD)

#define NV_ATTEST_KEY           "attest_key"
#define NV_LEN_ATTEST_KEY       32
#define NV_OFFSET_ATTEST_KEY    (NV_OFFSET_ENC_KEY + NV_LEN_ENC_KEY)

#define NV_PARAMS_SIZE          "params_size" // actual size of the params data
#define NV_LEN_PARAMS_SIZE      4
#define NV_OFFSET_PARAMS_SIZE   (NV_OFFSET_ATTEST_KEY + NV_LEN_ATTEST_KEY)

#define NV_PARAMS               "params"
#define NV_LEN_PARAMS           1024
#define NV_OFFSET_PARAMS        (NV_OFFSET_PARAMS_SIZE + NV_LEN_PARAMS_SIZE)

#define NV_URIPATH_SIZE         "uripath_size"
#define NV_LEN_URIPATH_SIZE     4
#define NV_OFFSET_URIPATH_SIZE  (NV_OFFSET_PARAMS + NV_LEN_PARAMS)

#define NV_URIPATH              "uripath"
#define NV_LEN_URIPATH          64
#define NV_OFFSET_URIPATH       (NV_OFFSET_URIPATH_SIZE + NV_LEN_URIPATH_SIZE)

#define NV_TIMEPATH_SIZE        "timepath_size"
#define NV_LEN_TIMEPATH_SIZE    4
#define NV_OFFSET_TIMEPATH_SIZE (NV_OFFSET_URIPATH + NV_LEN_URIPATH)

#define NV_TIMEPATH             "timepath"
#define NV_LEN_TIMEPATH         16
#define NV_OFFSET_TIMEPATH      (NV_OFFSET_TIMEPATH_SIZE + NV_LEN_TIMEPATH_SIZE)

#define NV_SIGNKEY_SIZE         "signkey_size"
#define NV_LEN_SIGNKEY_SIZE     4
#define NV_OFFSET_SIGNKEY_SIZE  (NV_OFFSET_TIMEPATH + NV_LEN_TIMEPATH)

#define NV_SIGNKEY              "signkey"
#define NV_LEN_SIGNKEY          1024
#define NV_OFFSET_SIGNKEY       (NV_OFFSET_SIGNKEY_SIZE + NV_LEN_SIGNKEY_SIZE)

#define NV_AUTH_KEY             "auth_key"
#define NV_LEN_AUTH_KEY         32
#define NV_OFFSET_AUTH_KEY      (NV_OFFSET_SIGNKEY + NV_LEN_SIGNKEY)

#define NV_PROVER               "prover"
#define NV_VERIFIER             "verifier"
#define NV_FIREWALL             "firewall"
#define NV_APP_SERVER           "appServer"
#define NV_COMMENT              "comment"
#define NV_FW_SCRIPT            "fwScript"

// These are used by the subscribers (in a file)
#define NV_ENCRYPTKEY_SIZE      "encryptkey_size"
#define NV_ENCRYPTKEY           "encryptkey"

// RSA keys starts at a different offset (e.g. a different page for GG, which has 4k pages)
#define NV_RSA_PRIVATE_SIZE        "rsa_private_size"
#define NV_LEN_RSA_PRIVATE_SIZE    4
#define NV_OFFSET_RSA_PRIVATE_SIZE (NV_RSA_OFFSET)

#define NV_RSA_PRIVATE             "rsa_private"
#define NV_LEN_RSA_PRIVATE         2048
#define NV_OFFSET_RSA_PRIVATE      (NV_OFFSET_RSA_PRIVATE_SIZE + NV_LEN_RSA_PRIVATE_SIZE)

#define NV_RSA_PUBLIC_SIZE         "rsa_public_size"
#define NV_LEN_RSA_PUBLIC_SIZE     4
#define NV_OFFSET_RSA_PUBLIC_SIZE  (NV_OFFSET_RSA_PRIVATE + NV_LEN_RSA_PRIVATE)

#define NV_RSA_PUBLIC              "rsa_public"
#define NV_LEN_RSA_PUBLIC          1024
#define NV_OFFSET_RSA_PUBLIC       (NV_OFFSET_RSA_PUBLIC_SIZE + NV_LEN_RSA_PUBLIC_SIZE)

// RSA keys starts at a different offset (e.g. a different page for GG, which has 4k pages)
#define NV_RSA_SIGN_SIZE          "rsa_sign_size"
#define NV_LEN_RSA_SIGN_SIZE      4
#define NV_OFFSET_RSA_SIGN_SIZE   (NV_RSA2_OFFSET)

#define NV_RSA_SIGN               "rsa_sign"
#define NV_LEN_RSA_SIGN           2048
#define NV_OFFSET_RSA_SIGN        (NV_OFFSET_RSA_SIGN_SIZE + NV_LEN_RSA_SIGN_SIZE)

#define NV_RSA_VERIFY_SIZE        "rsa_verify_size"
#define NV_LEN_RSA_VERIFY_SIZE    4
#define NV_OFFSET_RSA_VERIFY_SIZE (NV_OFFSET_RSA_SIGN + NV_LEN_RSA_SIGN)

#define NV_RSA_VERIFY             "rsa_verify"
#define NV_LEN_RSA_VERIFY         1024
#define NV_OFFSET_RSA_VERIFY      (NV_OFFSET_RSA_VERIFY_SIZE + NV_LEN_RSA_VERIFY_SIZE)

// Remote Attestation page
#define NV_ATTEST_SQN             "attest_sqn"
#define NV_LEN_ATTEST_SQN         4
#define NV_OFFSET_ATTEST_SQN      (NV_RA_OFFSET)

// SEEC page
#define NV_SEEC_SQN               "seec_sqn"
#define NV_LEN_SEEC_SQN           4
#define NV_OFFSET_SEEC_SQN        (NV_SEEC_OFFSET)

typedef struct _item {
    char     name[32];
    uint32_t offset;
    uint32_t len;
    char     type;
} Item;

int check_flash_device();
int do_read(off_t offset, size_t len, uint8_t *buf);
int do_erase(off_t offset, size_t size);
int do_write(off_t offset, size_t len, uint8_t *buf);
Item * get_item(const char *item_name);
int read_item(const char *item_name, int buf_len, uint8_t *buf);
int read_item_exact(const char *item_name, int buf_len, uint8_t *buf);
int write_item(char *item_name, int buf_len, uint8_t *buf);

#ifdef __cplusplus
}
#endif

#endif // ifndef __FLASH__
