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

set(CURSES_NEED_NCURSES TRUE)
find_package(Curses REQUIRED)

# --- core library (everything except main) ----------------------------------
add_library(pktscope_core
  src/protocols.cpp
  src/dissector.cpp
  src/flow.cpp
  src/detect.cpp
  src/stats.cpp
  src/capture.cpp
  src/report.cpp
  src/tui.cpp
)
target_include_directories(pktscope_core PUBLIC
  ${CMAKE_SOURCE_DIR}/include ${PCAP_INCLUDE} ${CURSES_INCLUDE_DIRS})
target_link_libraries(pktscope_core PUBLIC ${PCAP_LIB} ${CURSES_LIBRARIES})

# --- executable -------------------------------------------------------------
add_executable(pktscope src/main.cpp)
target_link_libraries(pktscope PRIVATE pktscope_core)

# --- tests ------------------------------------------------------------------
enable_testing()
add_executable(pktscope_tests
  tests/test_main.cpp
  tests/test_parsers.cpp
  tests/test_detectors.cpp
  tests/test_flow.cpp
  tests/test_pcap_integration.cpp
)
target_include_directories(pktscope_tests PRIVATE
  ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party ${CMAKE_SOURCE_DIR}/tests)
target_compile_definitions(pktscope_tests PRIVATE
  PKTSCOPE_DATA_DIR="${CMAKE_SOURCE_DIR}/tests/data")
target_link_libraries(pktscope_tests PRIVATE pktscope_core)
add_test(NAME unit COMMAND pktscope_tests)
