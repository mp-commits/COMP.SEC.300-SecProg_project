project(password_manager)

add_subdirectory(encryption)
add_subdirectory(fileops)
add_subdirectory(passwords)

add_executable(${PROJECT_NAME} main.cpp)

target_link_libraries(${PROJECT_NAME} 
    PRIVATE 
        encryption-static
)
