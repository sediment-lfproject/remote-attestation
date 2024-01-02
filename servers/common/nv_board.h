/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

/*
 * For servers, these are irrelevant
 */

#ifndef __FLASH_BOARD__
#define __FLASH_BOARD__

#ifdef __cplusplus
extern "C" {
#endif

#define NV_SEDIMENT_PAGE   0
#define NV_SQN_PAGE        0
#define NV_SEEC_PAGE_1     0
#define NV_SEEC_PAGE_2     0

#define NV_PAGE_SIZE       0
#define NV_BLOCK_SIZE      1

#define CODE_START_ADDR 0x00000000

#ifdef __cplusplus
}
#endif

#endif // ifndef __FLASH_BOARD__
