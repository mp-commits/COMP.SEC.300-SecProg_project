if (WIN32)
    find_library(CRYPTO_LIBRARIES NAMES libcrypto PATHS "C:/Program Files/OpenSSL-Win64/lib")
    include_directories("C:/Program Files/OpenSSL-Win64/include")
else()
    include(FindPkgConfig)
    pkg_search_module(CRYPTO libcrypto REQUIRED)
    include_directories(${CRYPTO_INCLUDE_DIRS})
endif()

add_library(encryption-static 
    STATIC 
        encryption.cpp
)

target_include_directories(encryption-static 
    PUBLIC 
        include
        ${COMMON_INCLUDE_DIR}
)

target_link_libraries(encryption-static 
    PRIVATE 
        ${CRYPTO_LIBRARIES}
)
