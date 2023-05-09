cmake_minimum_required(VERSION 3.11)
project(SECURE_PROGRAMMING_PASSWORD_MANAGER)
set(EXECUTABLE_NAME manager)

enable_testing()
include(cmake/fetch_clip.cmake)
include(cmake/fetch_gtest.cmake)
include(cmake/fetch_boost.cmake)

set(COMMON_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/common/include)

option(ENABLE_EXAMPLES "Copy examples to the binary directory" OFF)
set(ENABLE_EXAMPLES ON)

set(SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/examples)
set(DEST_DIR ${CMAKE_CURRENT_BINARY_DIR})

if (ENABLE_EXAMPLES)
    message(STATUS "Copying examples")
    file(COPY ${SOURCE_DIR} DESTINATION ${DEST_DIR})
endif()

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/git_version.cpp
           ${CMAKE_CURRENT_BINARY_DIR}/_git_version.cpp
    COMMAND ${CMAKE_COMMAND} -P
            ${CMAKE_CURRENT_SOURCE_DIR}/cmake/git_version.cmake)

add_subdirectory(src)
add_subdirectory(test)

add_executable(${EXECUTABLE_NAME} main.cpp ${CMAKE_CURRENT_BINARY_DIR}/git_version.cpp)

target_link_libraries(${EXECUTABLE_NAME} 
    PRIVATE 
        cli-static
        manager-static
)
