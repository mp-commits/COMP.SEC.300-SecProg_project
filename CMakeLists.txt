cmake_minimum_required(VERSION 3.20)
project(SECURE_PROGRAMMING_PASSWORD_MANAGER)

enable_testing()
include(cmake/fetch_gtest.cmake)

add_subdirectory(src)
add_subdirectory(test)