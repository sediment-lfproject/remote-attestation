# Copyright (c) 2023-2024 Peraton Labs
# SPDX-License-Identifier: Apache-2.0
# Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).

# current directory is build/
set(UTIL "../sediment/utils")

set(boards giant;pearl;nordic)

foreach(bd IN LISTS boards)
  execute_process(
    COMMAND python3 "${UTIL}/gen_config.py" "${bd}"
    OUTPUT_VARIABLE ARCHH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE ret)

  if(ret EQUAL "1")
    message(FATAL_ERROR "failed to generate config from config.json")
  endif()
endforeach()
