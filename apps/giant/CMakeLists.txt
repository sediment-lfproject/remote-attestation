# Copyright (c) 2023-2024 Peraton Labs
# SPDX-License-Identifier: Apache-2.0
# Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).

cmake_minimum_required(VERSION 3.13.1)

set(CONF_FILE prj.conf mbed.conf)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(attestation-mbed)

#option (WITH_JEDI "Use JEDI." OFF)
option (SEEC_ENABLED "include SEEC" OFF)

#add_compile_definitions(LOG_NONE)
add_compile_definitions(PLATFORM_GIANT_GECKO=1)

set(DEV_COMMON ../../apps/common)
set(PROTOCOL   ../../modules/protocol)
set(MQTT       ../../modules/mqtt)
set(MQTT_ZEPHYR ../zephyr/mqtt)
set(ZEPHYR_APP ../zephyr)

if(SEEC_ENABLED)
  add_compile_definitions(SEEC_ENABLED=1)
  set(AUTH       ../../modules/authentication/ingredient2)
  set(SEEC       ../../modules/seec)
  set(JEDI       ../../modules/seec/jedi)
endif(SEEC_ENABLED)

FILE(GLOB source
  *.c
  *.cpp
  ${DEV_COMMON}/*.cpp
  ${PROTOCOL}/*.cpp
  ${MQTT_ZEPHYR}/Mqtt.cpp
  ${AUTH}/Verify.cpp
  ${AUTH}/Sign.cpp
  ${SEEC}/*.cpp
  ${ZEPHYR_APP}/*.c
  ${ZEPHYR_APP}/*.cpp
)

target_sources(app PRIVATE
  ${source}
)

include(${ZEPHYR_BASE}/samples/net/common/common.cmake)

if(SEEC_ENABLED)
  add_subdirectory(${JEDI} jedi)
endif(SEEC_ENABLED)

target_include_directories(app PRIVATE ../../data)
target_include_directories(app PRIVATE ${ZEPHYR_APP})
target_include_directories(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(app PRIVATE ${DEV_COMMON})
target_include_directories(app PRIVATE ${PROTOCOL})
target_include_directories(app PRIVATE ${MQTT})
target_include_directories(app PRIVATE .././../modules)

if(SEEC_ENABLED)
  target_include_directories(app PRIVATE ${JEDI}/include)
  target_include_directories(app PRIVATE ${SEEC})
endif(SEEC_ENABLED)
