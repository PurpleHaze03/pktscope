cmake_minimum_required(VERSION 3.16)
project(pktscope VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

# --- dependencies -----------------------------------------------------------
find_library(PCAP_LIB pcap REQUIRED)
find_path(PCAP_INCLUDE pcap/pcap.h REQUIRED)

# --- core library (everything except main) ----------------------------------
add_library(pktscope_core
  src/protocols.cpp
  src/dissector.cpp
  src/flow.cpp
)
target_include_directories(pktscope_core PUBLIC
  ${CMAKE_SOURCE_DIR}/include ${PCAP_INCLUDE})
target_link_libraries(pktscope_core PUBLIC ${PCAP_LIB})

# --- tests ------------------------------------------------------------------
enable_testing()
add_executable(pktscope_tests
  tests/test_main.cpp
  tests/test_parsers.cpp
)
target_include_directories(pktscope_tests PRIVATE
  ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party ${CMAKE_SOURCE_DIR}/tests)
target_link_libraries(pktscope_tests PRIVATE pktscope_core)
add_test(NAME unit COMMAND pktscope_tests)
