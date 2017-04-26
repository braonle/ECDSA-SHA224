cmake_minimum_required(VERSION 3.5)
project(ISO_ECDSA_SHA224)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set(SOURCE_FILES Claimer.h Verifier.h Sync.h Sync.cpp Claimer.cpp Verifier.cpp main.cpp Const.h)

add_executable(ISO_ECDSA_SHA224 ${SOURCE_FILES})

target_link_libraries(${PROJECT_NAME} cryptopp)