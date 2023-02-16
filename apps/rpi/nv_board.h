/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

/*
 * For RPI, only NV item names are used.
 */

#ifndef __FLASH_BOARD__
#define __FLASH_BOARD__

#ifdef __cplusplus
extern "C" {
#endif

#define NV_FLASH_OFFSET 0 //
#define NV_PAGE_SIZE    0
#define NV_BLOCK_SIZE   1

#define CODE_START_ADDR 0x00000000

#ifdef __cplusplus
}
#endif

#endif // ifndef __FLASH_BOARD__
