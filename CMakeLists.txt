project(WebRTCServer)
cmake_minimum_required(VERSION 3.5)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD 11)

option(WU_BUILD_TESTS "Build tests" OFF)

add_definitions(-Wall -Werror)

include_directories(
  ${OPENSSL_INCLUDE_DIR}  
)

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
  WuQueue.c
  picohttpparser.c
)

add_executable(EchoServer examples/EchoServer.cpp)

set(WU_LIBRARIES
  Wu
  ${OPENSSL_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
  PARENT_SCOPE
)

set(WU_LIBRARIES
  Wu
  ${OPENSSL_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
)

target_link_libraries(EchoServer ${WU_LIBRARIES})

if (WU_BUILD_TESTS)
  add_executable(sdp_test
    sdp_test.cpp
    WuSdp.cpp
    WuRng.cpp
  )

  add_executable(crc_test
    crc_test.cpp
    CRC32.cpp
  )

  add_executable(FuzzSdp
    test/fuzz/FuzzSdp.cpp
    WuSdp.cpp
    WuRng.cpp
  )

  add_executable(FuzzStun
    test/fuzz/FuzzStun.cpp
    WuStun.cpp
    WuString.cpp
    WuCrypto.cpp
    CRC32.cpp
  )

  add_executable(FuzzSctp
    test/fuzz/FuzzSctp.cpp
    WuSctp.cpp
    CRC32.cpp
  )

  target_link_libraries(FuzzStun
    ${OPENSSL_LIBRARIES}
  )
endif()
