project(password_manager)

add_subdirectory(cli)
add_subdirectory(encryption)
add_subdirectory(fileops)
add_subdirectory(operations)
add_subdirectory(passwords)

add_executable(${PROJECT_NAME} main.cpp)

target_link_libraries(${PROJECT_NAME} 
    PRIVATE 
        cli-static
)
