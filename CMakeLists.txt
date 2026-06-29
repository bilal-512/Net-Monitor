cmake_minimum_required(VERSION 3.20)

# Project name
project(Network-Monitor VERSION 1.0 LANGUAGES CXX)

# C++20 standard — required for structured bindings, ranges, etc.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Collect all source files
set(SOURCES
    src/main.cpp
    src/LogParser.cpp
    src/Analyzer.cpp
    src/ThreatDetector.cpp
    src/SearchFilter.cpp
    src/ReportGenerator.cpp
    src/Dashboard.cpp
)

# Build the executable
add_executable(Network-Monitor ${SOURCES})

# Include directory
target_include_directories(Network-Monitor PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)

# Enable useful compiler warnings
if (MSVC)
    target_compile_options(Network-Monitor PRIVATE /W4)
else()
    target_compile_options(Network-Monitor PRIVATE -Wall -Wextra -Wpedantic)
endif()
