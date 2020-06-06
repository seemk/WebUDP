project(WebUdp)
cmake_minimum_required(VERSION 3.7)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

if (${OPENSSL_VERSION} VERSION_LESS "1.0.2")
  message(FATAL_ERROR "Invalid OpenSSL version ${OPENSSL_VERSION}")
endif()

option(WITH_NODE "Build Node bindings" OFF)
option(WITH_TESTS "Build tests" OFF)

set(EXAMPLES_DIR ${CMAKE_CURRENT_BINARY_DIR}/examples)

add_library(Wu
  CRC32.cpp
  Wu.cpp
  WuArena.cpp
  WuPool.cpp
  WuSctp.cpp
  WuSdp.cpp
  WuString.cpp
  WuStun.cpp
  WuCrypto.cpp
  WuRng.cpp
  WuQueue.cpp
)

if (UNIX AND NOT APPLE)
  add_library(WuHost
    WuHostEpoll.cpp
    WuNetwork.cpp
    picohttpparser.c
  )
else ()
  message(WARNING "Unsupported platform, defaulting to null (no-op) implementation")
  add_library(WuHost
    WuHostNull.cpp
  )
endif()

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
  -fPIC
  $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions>
  $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>
)

target_compile_options(WuHost
  PRIVATE
  -Wall
  $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions>
  $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>
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

add_executable(EchoServer examples/EchoServer.c)
target_link_libraries(EchoServer WuHost)

set_target_properties(Wu WuHost EchoServer PROPERTIES
  CXX_STANDARD 11
  RUNTIME_OUTPUT_DIRECTORY ${EXAMPLES_DIR}
)

file(MAKE_DIRECTORY ${EXAMPLES_DIR})
file(COPY examples/client DESTINATION ${EXAMPLES_DIR})

if (WITH_NODE)
  find_program(NPM npm)

  if (NPM)
    cmake_policy(SET CMP0070 NEW)

    file (GENERATE OUTPUT binding.gyp
      INPUT ${CMAKE_CURRENT_SOURCE_DIR}/binding.gyp.in
    )

    file (GENERATE OUTPUT package.json
      INPUT ${CMAKE_CURRENT_SOURCE_DIR}/package.json
    )

    add_custom_target(node ALL
      COMMAND npm install
      COMMAND npm run configure
      COMMAND npm run build
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )

    add_custom_command(TARGET node POST_BUILD
      COMMAND ${CMAKE_COMMAND}
        -E copy ${CMAKE_CURRENT_BINARY_DIR}/build/Release/WebUDP.node ${EXAMPLES_DIR}
    )

    add_dependencies(node Wu)

    file(COPY examples/EchoServer.js DESTINATION ${EXAMPLES_DIR})
  else()
    message(WARNING "npm not found, skipping Node bindings")
  endif()

endif()

if (WITH_TESTS)
  set(TESTS_DIR ${CMAKE_CURRENT_BINARY_DIR}/tests)
  file(MAKE_DIRECTORY ${TESTS_DIR})

  add_executable(FuzzSdp test/FuzzSdp.cpp)
  add_executable(FuzzSctp test/FuzzSctp.cpp)
  add_executable(FuzzStun test/FuzzStun.cpp)
  target_link_libraries(FuzzSdp Wu)
  target_link_libraries(FuzzSctp Wu)
  target_link_libraries(FuzzStun Wu)
  file(COPY test/data DESTINATION ${TESTS_DIR})
endif()
