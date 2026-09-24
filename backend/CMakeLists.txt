cmake_minimum_required(VERSION 3.20)
project(ai_agent_ledger CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)  # PoW loop needs optimisation
endif()

find_package(OpenSSL 3 REQUIRED)
find_package(PostgreSQL REQUIRED)
find_package(Threads REQUIRED)

# DB-free core: crypto, chain primitives, rules engine.
add_library(ledger_core STATIC
  src/crypto.cpp
  src/chain.cpp
  src/confidence.cpp
  src/env.cpp)
target_include_directories(ledger_core PUBLIC src third_party)
target_link_libraries(ledger_core PUBLIC OpenSSL::Crypto Threads::Threads)

add_executable(ledger_server
  src/main.cpp
  src/db.cpp
  src/ledger.cpp
  src/miner.cpp
  src/api.cpp)
target_link_libraries(ledger_server PRIVATE ledger_core PostgreSQL::PostgreSQL)

add_executable(ledger_selftest src/selftest.cpp)
target_link_libraries(ledger_selftest PRIVATE ledger_core)

if(WIN32)
  target_compile_definitions(ledger_core PUBLIC _WIN32_WINNT=0x0A00 NOMINMAX)
  target_link_libraries(ledger_server PRIVATE ws2_32)
endif()
if(MINGW)
  foreach(t ledger_server ledger_selftest)
    target_link_options(${t} PRIVATE -static-libgcc -static-libstdc++)
  endforeach()
endif()
