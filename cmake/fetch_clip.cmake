message(STATUS "Fetching clip")
include(FetchContent)

FetchContent_Declare(
        clip
        GIT_REPOSITORY https://github.com/dacap/clip.git
        GIT_TAG v1.5
        GIT_SHALLOW TRUE
        GIT_PROGRESS TRUE
)

set(CLIP_EXAMPLES OFF CACHE BOOL "Compile clip examples")
set(CLIP_TESTS OFF CACHE BOOL "Compile clip tests")

FetchContent_MakeAvailable(clip)

target_include_directories(clip PUBLIC ${clip_SOURCE_DIR})

add_library(decap::clip ALIAS clip)
