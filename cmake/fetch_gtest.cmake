message(STATUS "Fetching googletest")
include(FetchContent)

FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG release-1.12.0
        GIT_SHALLOW TRUE
        GIT_PROGRESS TRUE)
FetchContent_MakeAvailable(googletest)

add_library(GTest::GTest INTERFACE IMPORTED)
target_link_libraries(GTest::GTest INTERFACE gtest_main)
