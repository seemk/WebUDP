project(WebUdp)
cmake_minimum_required(VERSION 3.5)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

add_library(Wu
  CRC32.cpp
  Wu.cpp
  WuCert.cpp
  WuArena.cpp
  WuDataChannel.cpp
  WuNetwork.cpp
  WuPool.cpp
  WuSctp.cpp
  WuSdp.cpp
  WuString.cpp
  WuStun.cpp
  WuCrypto.cpp
  WuRng.cpp
  WuQueue.cpp
  picohttpparser.c
)

target_include_directories(Wu
  PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<INSTALL_INTERFACE:include>
  PRIVATE OpenSSL::SSL
)

target_link_libraries(Wu
  PRIVATE OpenSSL::SSL
  PRIVATE OpenSSL::Crypto
  PRIVATE Threads::Threads
)

target_compile_options(Wu
  PRIVATE
  -Wall
  $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions>
  $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>
)

install(TARGETS Wu EXPORT WuTargets
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  RUNTIME DESTINATION bin
  INCLUDES DESTINATION include
  PUBLIC_HEADER DESTINATION include
)

install(FILES Wu.h DESTINATION include)

install(EXPORT WuTargets
  FILE WuTargets.cmake
  NAMESPACE Wu::
  DESTINATION lib/cmake/Wu
)

add_executable(EchoServer examples/EchoServer.cpp)
target_link_libraries(EchoServer Wu)

set_target_properties(Wu EchoServer PROPERTIES
  CXX_STANDARD 11
)
