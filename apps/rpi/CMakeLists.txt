# Copyright (c) 2023 Peraton Labs
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.14)

set(CMAKE_CXX_COMPILER g++)
set(CMAKE_C_COMPILER gcc)
set(RPI_BUILD true)

project(sediment VERSION 0.0.0 LANGUAGES C CXX ASM)

# Note ARCH is set in JEDI. Use a different name for now.
# TODO: Remove the one in JEDI later.
set(ARC ${CMAKE_SYSTEM_PROCESSOR})
set(LIB "../../lib/${ARC}")
message("ARC = ${CMAKE_SYSTEM_PROCESSOR}")

option (SEEC_ENABLED "include SEEC" OFF)

add_compile_definitions(PLATFORM_RPI=1)

set(DEV_COMMON ../../apps/common)
set(PROTOCOL   ../../modules/protocol)
set(MQTT       ../../modules/mqtt)

if(SEEC_ENABLED)
  add_compile_definitions(SEEC_ENABLED=1)
  set(AUTH       ../../modules/authentication/ingredient2)
  set(SEEC       ../../modules/seec)
  set(JEDI       ../../modules/seec/jedi)
endif(SEEC_ENABLED)

file(GLOB SOURCES
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  *.cpp
  ${DEV_COMMON}/*.cpp
  ${PROTOCOL}/*.cpp
  ${MQTT}/*.cpp
  ${AUTH}/Verify.cpp
  ${AUTH}/Sign.cpp
  ${SEEC}/*.cpp
  ../../servers/common/CommandLine.cpp
)

set(APP sediment)

add_executable(${APP}
  ${SOURCES}
)

target_include_directories(${APP} PRIVATE ../../data)
target_include_directories(${APP} PRIVATE ${DEV_COMMON})
target_include_directories(${APP} PRIVATE ${PROTOCOL})
target_include_directories(${APP} PRIVATE ${MQTT})
target_include_directories(${APP} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(${APP} PRIVATE ../../include)
target_include_directories(${APP} PRIVATE ../../modules)
target_include_directories(${APP} PRIVATE ../../servers/common)

if(SEEC_ENABLED)
  target_include_directories(${APP} PRIVATE ${JEDI}/include)
  target_include_directories(${APP} PRIVATE ${SEEC})
endif(SEEC_ENABLED)

target_link_libraries(${APP} PRIVATE
  dl
  pthread
  mbedtls
  mbedcrypto
  mbedx509  
  paho-mqttpp3
  paho-mqtt3as
)

if(SEEC_ENABLED)
target_link_libraries(${APP} PRIVATE
  pairing
)
endif(SEEC_ENABLED)

set_target_properties(${APP}
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    )

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -g -Wall -Wextra")
target_link_options(${APP} PRIVATE "-Wl,--gc-sections")

if(DEFINED CLANG_FLAGS)
  target_compile_options(${APP} PUBLIC ${CLANG_FLAGS})
endif()

if(DEFINED UBUNTU_AFTER_2017)
  target_compile_options(${APP} PUBLIC ${UBUNTU_AFTER_2017})
endif()

if(SEEC_ENABLED)
  add_subdirectory(../../modules/seec/jedi jedi)
endif(SEEC_ENABLED)

add_subdirectory(udf udf)
