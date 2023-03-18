include(FindPkgConfig)
pkg_search_module(CRYPTO libcrypto REQUIRED)
include_directories(${CRYPTO_INCLUDE_DIRS})

add_library(encryption-static 
    STATIC 
        encryption.cpp
)

target_include_directories(encryption-static 
    PUBLIC 
        include
)

target_link_libraries(encryption-static 
    PRIVATE 
        ${CRYPTO_LIBRARIES}
)
