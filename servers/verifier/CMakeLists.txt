# Copyright (c) 2023 Peraton Labs
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.14)

project(sediment VERSION 0.0.0 LANGUAGES C CXX ASM)

set(SEEC_ENABLED OFF CACHE BOOL "SEEC is not included")
include(${CMAKE_CURRENT_SOURCE_DIR}/../common/CMakeLists.txt)

add_custom_command(
  TARGET app POST_BUILD
  COMMAND mv ${CMAKE_CURRENT_BINARY_DIR}/app ${CMAKE_CURRENT_BINARY_DIR}/verifier
  COMMENT "rename app to verifier"
)
 
