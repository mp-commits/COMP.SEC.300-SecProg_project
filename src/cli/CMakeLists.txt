project(cli)

add_library(${PROJECT_NAME}-static STATIC cli.cpp)

target_include_directories(${PROJECT_NAME}-static
    PUBLIC
        include
        ${COMMON_INCLUDE_DIR}
)

target_link_libraries(${PROJECT_NAME}-static
    PUBLIC
        manager-static
    PRIVATE
        manager_services-static
)
