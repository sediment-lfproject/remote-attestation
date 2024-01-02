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

#ifndef __FLASH_BOARD__
#define __FLASH_BOARD__

#ifdef __cplusplus
extern "C" {
#endif

#define NV_SEDIMENT_PAGE   0x001ff000 // page 511
#define NV_SQN_PAGE        0x001fe000 // page 508
#define NV_SEEC_PAGE_1     0x001fd000 // page 507
#define NV_SEEC_PAGE_2     0x001fc000 // page 506
#define NV_PAGE_SIZE       4096
#define NV_BLOCK_SIZE      4

#define CODE_START_ADDR 0x00000000

#ifdef __cplusplus
}
#endif

#endif // ifndef __FLASH_BOARD__
