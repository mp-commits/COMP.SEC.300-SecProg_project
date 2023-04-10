project(manager_services)

add_library(${PROJECT_NAME}-static 
    STATIC 
        add.cpp
        copy.cpp
        load.cpp
        port.cpp
        save.cpp
        view.cpp
)

target_include_directories(${PROJECT_NAME}-static 
    PUBLIC 
        include
        ${COMMON_INCLUDE_DIR}
)

target_link_libraries(${PROJECT_NAME}-static
    PUBLIC
        Boost::tokenizer
        decap::clip
        encryption-static
        fileops-static
        passwords-static
)
