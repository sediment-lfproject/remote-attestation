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

#ifndef __FLASH_BOARD__
#define __FLASH_BOARD__

#ifdef __cplusplus
extern "C" {
#endif

#define NV_FLASH_OFFSET 0x001ff000 // page 511
#define NV_RSA_OFFSET   0x001fe000 // page 510: public and private keys
#define NV_RSA2_OFFSET  0x001fd000 // page 509: sign and verify keys
#define NV_RA_OFFSET    0x001fc000 // page 508: attestation SQN
#define NV_SEEC_OFFSET  0x001fb000 // page 507: seec SQN
#define NV_PAGE_SIZE    4096
#define NV_BLOCK_SIZE   4
#define NV_SPLIT_PAGES  1 // if RSA and WKD are in difference pages

#define CODE_START_ADDR 0x00000000

#ifdef __cplusplus
}
#endif

#endif // ifndef __FLASH_BOARD__
