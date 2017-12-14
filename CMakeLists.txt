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

add_library(WuHost
  WuHost.cpp
  WuNetwork.cpp
)

target_include_directories(Wu
  PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<INSTALL_INTERFACE:include>
  PRIVATE OpenSSL::SSL
)

target_include_directories(WuHost
  PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<INSTALL_INTERFACE:include>
)

target_link_libraries(Wu
  PRIVATE OpenSSL::SSL
  PRIVATE OpenSSL::Crypto
  PRIVATE Threads::Threads
)

target_link_libraries(WuHost Wu)

target_compile_options(Wu
  PRIVATE
  -Wall
  $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions>
  $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>
)

target_compile_options(WuHost
  PRIVATE
  -Wall
  $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions>
  $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>
)

target_compile_definitions(WuHost
  PUBLIC
  WU_EPOLL=1
)

install(TARGETS Wu WuHost EXPORT WuTargets
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  RUNTIME DESTINATION bin
  INCLUDES DESTINATION include
  PUBLIC_HEADER DESTINATION include
)

install(FILES Wu.h WuHost.h DESTINATION include)

install(EXPORT WuTargets
  FILE WuTargets.cmake
  NAMESPACE Wu::
  DESTINATION lib/cmake/Wu
)

add_executable(EchoServer examples/EchoServer.cpp)
target_link_libraries(EchoServer WuHost)

set_target_properties(Wu WuHost EchoServer PROPERTIES
  CXX_STANDARD 11
)
