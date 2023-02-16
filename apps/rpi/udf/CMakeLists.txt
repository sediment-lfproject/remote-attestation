# Copyright (c) 2023 Peraton Labs
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.9)

set(LIB_UDF sediment_udf)
project(${LIB_UDF} VERSION 1.0.1 DESCRIPTION "sediment UDF description")

add_library(${LIB_UDF} SHARED udf.cpp)

set_target_properties(${LIB_UDF} PROPERTIES
    VERSION ${PROJECT_VERSION}
    PREFIX ""
    NO_SONAME true
    SOVERSION 1)
    
target_include_directories(${LIB_UDF} PRIVATE .)
target_include_directories(${LIB_UDF} PRIVATE ../../../modules/protocol)

install(TARGETS ${LIB_UDF}
    LIBRARY DESTINATION ..
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

add_custom_command(
  TARGET ${LIB_UDF} POST_BUILD
  COMMAND mv ${LIB_UDF}.so ..
  COMMENT "mv ${LIB_UDF}.so .."
)
