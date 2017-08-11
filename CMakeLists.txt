cmake_minimum_required(VERSION 3.2)
include(ExternalProject)

# Options.
option(RETOOLS_LIBDEBUG "Enable libdebug" OFF)
option(RETOOLS_USE_CCACHE "Build with ccache" OFF)
set(BUILD_TYPE "DEBUG" CACHE STRING "Select type of build [DEBUG | RELEASE | FUZZING | COVERAGE]")

# retools version.
set(RETOOLS_VERSION_MAJOR 0)
set(RETOOLS_VERSION_MINOR 1)
set(RETOOLS_VERSION_PATCH 0)

project(retools VERSION ${RETOOLS_VERSION_MAJOR}.${RETOOLS_VERSION_MINOR}.${RETOOLS_VERSION_PATCH})
message(STATUS "Building ${PROJECT_NAME} ${PROJECT_VERSION}.")

# Configure ccache if available.
find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND AND RETOOLS_USE_CCACHE)
    message(STATUS "Using ccache for compilation.")
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif()

# Enable C++11 standard.
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Disable C++ exceptions.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-unwind-tables -fno-asynchronous-unwind-tables")

# Enable @rpath for shared libraries.
set(CMAKE_MACOSX_RPATH 1)

if(BUILD_TYPE STREQUAL "COVERAGE")
    message(STATUS "Code coverage build")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -g -fno-omit-frame-pointer -fprofile-arcs -ftest-coverage")

elseif(BUILD_TYPE STREQUAL "DEBUG")
    message(STATUS "Debug build")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O1 -g -fno-omit-frame-pointer -w -Wall -Wextra")

elseif(BUILD_TYPE STREQUAL "RELEASE")
    message(STATUS "Release build")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -w")
    add_definitions(-DNDEBUG)

elseif(BUILD_TYPE STREQUAL "FUZZING")
    message(STATUS "Fuzzing build")
    add_definitions(-DFUZZING)

endif()

# Build third party dependencies.
add_subdirectory(third_party)

# Build header only utilities.
add_subdirectory(src/utilities)

# Call source code generators.
add_subdirectory(src/libspec)

# Build related libraries.
add_subdirectory(src/libbinary)
add_subdirectory(src/libdisassembly)
add_subdirectory(src/libemulation)

# Build libdebug if enabled.
if(RETOOLS_LIBDEBUG)
    add_subdirectory(src/libdebug)
endif()

# Build the tools.
add_subdirectory(src/tools)

# Build the bindings.
add_subdirectory(bindings)

# Build the tests.
add_subdirectory(tests)
