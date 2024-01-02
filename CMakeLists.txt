# Copyright (c) 2023-2024 Peraton Labs
# SPDX-License-Identifier: Apache-2.0
# Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).

cmake_minimum_required(VERSION 3.14)

set(CMAKE_CXX_COMPILER g++)
set(CMAKE_C_COMPILER gcc)
set(RPI_BUILD true)

project(sediment VERSION 0.0.0 LANGUAGES C CXX ASM)

set(ARC ${CMAKE_SYSTEM_PROCESSOR})
set(LIB "lib/${ARC}")

option(SPDLOG_ENABLED "SPDLOG Enabled" ON)
option(MYSQL_ENABLED "MySQL Enabled" OFF)

if(NOT WIN32)
  string(ASCII 27 Esc)
  set(ColourReset "${Esc}[m")
  set(BoldGreen   "${Esc}[1;32m")
endif()

include(${CMAKE_CURRENT_SOURCE_DIR}/version.cmake)

add_compile_definitions(PLATFORM_RPI=1)

### COMMON
set(PROTOCOL      modules/protocol)
set(MQTT          modules/mqtt)

set(SVR_COMMON    servers/common)

include_directories(${PROTOCOL})
include_directories(${MQTT})
include_directories(${PROVER} PRIVATE data)
include_directories(include)
include_directories(modules)
include_directories(${SVR_COMMON})
include_directories(${CMAKE_CURRENT_BINARY_DIR}/generated)

link_libraries(
  mbedtls
  mbedcrypto
  mbedx509  
  mysqlcppconn
  paho-mqttpp3
  paho-mqtt3as
)

### PROVER
set(PROVER      prover)
set(APPS_COMMON apps/common)
set(RPI         apps/rpi)

file(GLOB PROVER_SRC
  ${RPI}/*.cpp
  ${APPS_COMMON}/*.cpp
  ${SVR_COMMON}/CommandLine.cpp
  servers/verifier/ConfigAttest.cpp
)

add_executable(${PROVER}
  ${PROVER_SRC}
)

target_include_directories(${PROVER} PRIVATE ${APPS_COMMON})
target_link_libraries(${PROVER} PRIVATE
  protocol
  dl
  pthread
)

### SERVER
set(server_libs
    sediment_server
    ssl
    crypto
    sqlite3
    pthread
    protocol
)

### VERIFIER
set(SVR_VERIFIER  servers/verifier)
set(VERIFIER verifier)

file(GLOB VERIFIER_SRC
  ${SVR_VERIFIER}/*.cpp
)

add_executable(${VERIFIER}
  ${VERIFIER_SRC}
)

target_link_libraries(${VERIFIER} PRIVATE
  ${server_libs}
)

### FIREWALL
set(FIREWALL firewall)
set(SVR_FIREWALL  servers/firewall)

file(GLOB FIREWALL_SRC
  ${SVR_FIREWALL}/*.cpp
)

add_executable(${FIREWALL}
  ${FIREWALL_SRC}
)

target_link_libraries(${FIREWALL} PRIVATE
  ${server_libs}
)

##########

set_target_properties(${PROVER}
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    )

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -g -Wall -Wextra")
target_link_options(${PROVER} PRIVATE "-Wl,--gc-sections")

if(DEFINED CLANG_FLAGS)
  compile_options(${PROVER} PUBLIC ${CLANG_FLAGS})
endif()

if(DEFINED UBUNTU_AFTER_2017)
  compile_options(${PROVER} PUBLIC ${UBUNTU_AFTER_2017})
endif()
add_subdirectory(apps/rpi/udf)
add_subdirectory(modules/protocol)
add_subdirectory(servers/common)
