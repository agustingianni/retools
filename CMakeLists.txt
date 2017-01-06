cmake_minimum_required(VERSION 2.8)

# Options.
option(USE_CCACHE "Build with ccache" OFF)
set(BUILD_TYPE "DEBUG" CACHE STRING "Select type of build [DEBUG | RELEASE | FUZZING | COVERAGE]")

# Configure ccache if available.
if(USE_CCACHE)
    find_program(CCACHE_FOUND ccache)
    if(CCACHE_FOUND)
        message("-- Found 'cache', using it for compilation.")
        set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
        set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
    endif(CCACHE_FOUND)
endif(USE_CCACHE)

# Enable C++14 standard.
set(CMAKE_CXX_STANDARD 14)
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

# Build related libraries.
add_subdirectory(src/libbinary)
add_subdirectory(src/libdisassembly)
add_subdirectory(src/libemulation)

# Build the tools.
add_subdirectory(src/tools)

# Build the bindings.
add_subdirectory(bindings)

# Build the tests.
add_subdirectory(tests)
