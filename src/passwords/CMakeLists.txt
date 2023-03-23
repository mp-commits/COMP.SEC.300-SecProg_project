project(passwords)

add_library(${PROJECT_NAME}-static STATIC passwords.cpp)

target_include_directories(${PROJECT_NAME}-static
    PUBLIC
        include
)
