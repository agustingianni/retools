project(binary_info)

add_executable(
	binary_info
	${CMAKE_CURRENT_SOURCE_DIR}/binary_info.cpp
)

# Link to libdisassembly.
target_link_libraries(
	binary_info
	binary
)
