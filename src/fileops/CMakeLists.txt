project(fileops)

add_library(${PROJECT_NAME}-static 
    STATIC 
        fileops.cpp 
)

target_include_directories(${PROJECT_NAME}-static
    PUBLIC
        include
        COMMON_INCLUDE_DIR
)

target_link_libraries(${PROJECT_NAME}-static 
    PUBLIC
        Boost::tokenizer
        encryption-static
        manager-static
        idservice-static
)
