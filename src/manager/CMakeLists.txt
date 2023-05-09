project(manager)

add_library(${PROJECT_NAME}-static STATIC manager.cpp)

target_include_directories(${PROJECT_NAME}-static
    PUBLIC
        include
)
