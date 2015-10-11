cmake_minimum_required(VERSION 2.8)

# Enable compiler warnings.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

# Disable C++ exceptions and enable C++11 globaly.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-unwind-tables -fno-asynchronous-unwind-tables -Wno-int-to-void-pointer-cast")

# Enable debugging.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O1 -g -fno-omit-frame-pointer")

# Enable address sanitizer (overflows & shit).
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")

# Build related libraries.
add_subdirectory(src/libbinary)
add_subdirectory(src/libdisassembly)
add_subdirectory(src/libemulation)
# add_subdirectory(src/libsymbolic)

# Build the tools.
add_subdirectory(src/tools)

# Build the bindings.
add_subdirectory(bindings)

# Build the tests.
add_subdirectory(tests)

project(retools)

add_executable(
	retools
	${CMAKE_CURRENT_SOURCE_DIR}/src/retools.cpp
)

target_include_directories(
	retools
	PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}/src/libbinary
)

# Enable c++11 on the target.
set_target_properties(
	retools
	PROPERTIES 
	COMPILE_FLAGS "-std=c++11"
)

target_link_libraries(
	retools
	binary
)
