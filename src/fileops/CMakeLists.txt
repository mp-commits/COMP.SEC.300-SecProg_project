project(filops)

add_library(${PROJECT_NAME}-static STATIC cryptfile.cpp inputfile.cpp)

target_include_directories(${PROJECT_NAME}-static
    PUBLIC
        include
)

target_link_libraries(${PROJECT_NAME}-static 
    PRIVATE
        encryption-static
)
