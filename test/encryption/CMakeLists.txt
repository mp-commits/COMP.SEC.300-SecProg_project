project(encryptionTest)
include(CTest)

add_executable(${PROJECT_NAME} encryption_test.cpp)

target_link_libraries(${PROJECT_NAME} 
    PRIVATE
        encryption-static 
        GTest::GTest
)

add_test(${PROJECT_NAME}_gtest ${PROJECT_NAME})
