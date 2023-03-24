project(fileops)

add_library(${PROJECT_NAME}-static 
    STATIC 
        cryptfile.cpp 
        inputfile.cpp
)

target_include_directories(${PROJECT_NAME}-static
    PUBLIC
        include
        COMMON_INCLUDE_DIR
)

target_link_libraries(${PROJECT_NAME}-static 
    PUBLIC
        encryption-static
        passwords-static
)
