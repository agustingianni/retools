cmake_minimum_required(VERSION 2.8)

# Options.
option(DEBUG "Build with debugging on" ON)

# Enable compiler warnings.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

# Enable C++11 standard.
set(CMAKE_CXX_STANDARD 11)

# Disable C++ exceptions.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-unwind-tables -fno-asynchronous-unwind-tables")

# Enable @rpath for shared libraries.
set(CMAKE_MACOSX_RPATH 1)

# Enable debugging.
if (DEBUG)
    message(STATUS "Debugging is ON")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O1 -g -fno-omit-frame-pointer -w")
endif(DEBUG)

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
