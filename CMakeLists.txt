cmake_minimum_required(VERSION 3.10)
project(adiatron)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_library(SODIUM_LIBRARY sodium REQUIRED)

add_executable(${PROJECT_NAME} 
  src/main.cpp 
  src/decrypt.cpp 
  src/encrypt.cpp 
  src/filesystem.cpp
  src/keygen.cpp
  src/serialization.cpp
  src/terminal.cpp
  src/utils.cpp
  src/list.cpp
  src/extract.cpp
)
target_include_directories(${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(${PROJECT_NAME} PRIVATE ${SODIUM_LIBRARY})
