cmake_minimum_required(VERSION 3.20)
project(SECURE_PROGRAMMING_PASSWORD_MANAGER)

enable_testing()
include(cmake/fetch_gtest.cmake)
include(cmake/fetch_boost.cmake)

set(COMMON_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/common/include)

add_subdirectory(src)
add_subdirectory(test)
