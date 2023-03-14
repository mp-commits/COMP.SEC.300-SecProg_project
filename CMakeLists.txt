cmake_minimum_required(VERSION 3.20)
project(password_manager)

add_subdirectory(encryption)

add_executable(${PROJECT_NAME} main.cpp)

target_link_libraries(${PROJECT_NAME} 
    PRIVATE 
        encryption-static
)
