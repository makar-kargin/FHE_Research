cmake_minimum_required(VERSION 3.10)
project(HElibPerfTest)

set(CMAKE_CXX_STANDARD 17)

find_package(helib REQUIRED)

add_executable(helib_perf_test helib_perf_test.cpp)
target_link_libraries(helib_perf_test helib)
