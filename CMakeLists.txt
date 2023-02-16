# Copyright (c) 2023 Peraton Labs
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.14)

set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_C_COMPILER clang)
#set(CMAKE_CXX_COMPILER g++)
#set(CMAKE_C_COMPILER gcc)

project(sediment VERSION 0.0.0 LANGUAGES C CXX ASM)

set(USE_CLANG TRUE)

message("${CMAKE_CURRENT_SOURCE_DIR}")

#message("CMAKE_SOURCE_DIR = ${CMAKE_SOURCE_DIR}")
#message("CMAKE_BINARY_DIR = ${CMAKE_BINARY_DIR}")
#message("CMAKE_CURRENT_SOURCE_DIR = ${CMAKE_CURRENT_SOURCE_DIR}")
#message("CMAKE_CURRENT_BINARY_DIR = ${CMAKE_CURRENT_BINARY_DIR}")

add_subdirectory(modules)

