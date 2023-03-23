project(cli)

add_library(${PROJECT_NAME}-static STATIC cli.cpp)

target_include_directories(${PROJECT_NAME}-static
    PUBLIC
        include
)

target_link_libraries(${PROJECT_NAME}-static 
    PRIVATE
        manager_operations-static
)
