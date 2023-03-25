project(manager_operations)

add_library(${PROJECT_NAME}-static 
    STATIC 
        add.cpp 
        find.cpp
        load.cpp
        save.cpp
        view.cpp
)

target_include_directories(${PROJECT_NAME}-static 
    PUBLIC 
        include
)

target_link_libraries(${PROJECT_NAME}-static
    PUBLIC
        encryption-static
        fileops-static
        passwords-static
)
