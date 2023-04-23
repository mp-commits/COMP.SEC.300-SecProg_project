message(STATUS "Fetching boost. DO NOT PANIC! This will take some time (up to 10 minutes)!")
include(FetchContent)

set(BOOST_INCLUDE_LIBRARIES json tokenizer)
set(BOOST_ENABLE_CMAKE ON)

include(FetchContent)
FetchContent_Declare(
    Boost
        GIT_REPOSITORY https://github.com/boostorg/boost.git
        GIT_TAG boost-1.81.0
        GIT_SHALLOW TRUE
        GIT_PROGRESS TRUE
)
FetchContent_MakeAvailable(Boost)
