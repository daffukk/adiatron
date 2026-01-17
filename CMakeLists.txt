cmake_minimum_required(VERSION 3.10)
project(adiatron)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_library(SODIUM_LIBRARY sodium REQUIRED)

add_executable(${PROJECT_NAME} main.cpp decrypt.cpp encrypt.cpp generateKeys.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE ${SODIUM_LIBRARY})
