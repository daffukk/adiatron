cmake_minimum_required(VERSION 3.10)
project(crypto)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_library(SODIUM_LIBRARY sodium REQUIRED)

add_executable(encrypt encrypt.cpp generateKeys.cpp)
target_link_libraries(encrypt PRIVATE ${SODIUM_LIBRARY})
add_executable(decrypt decrypt.cpp generateKeys.cpp)
target_link_libraries(decrypt PRIVATE ${SODIUM_LIBRARY})
