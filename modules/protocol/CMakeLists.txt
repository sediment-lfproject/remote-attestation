file(GLOB CPP_SOURCES
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  ../mqtt/*.cpp
  *.cpp
)

set(TARGET protocol)

add_library(${TARGET}
  ${CPP_SOURCES}
)
