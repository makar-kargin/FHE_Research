cmake_minimum_required(VERSION 3.10)
project(SEALPerfTest)

set(CMAKE_CXX_STANDARD 17)

find_package(SEAL REQUIRED)

add_executable(seal_perf_test seal_perf_test.cpp)
target_link_libraries(seal_perf_test SEAL::seal_shared)