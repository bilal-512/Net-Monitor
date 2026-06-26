cmake_minimum_required(VERSION 3.20)

# Project name 
project(Network-Monitor VERSION 1.0 LANGUAGES CXX)

#
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

#  executable
add_executable(Network-Monitor
    src/main.cpp
)

#  include directory
target_include_directories(Network-Monitor PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)
