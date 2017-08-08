project(random)

# For some reason unicorn on linux is not linked with threads so we need to link it ourselves.
find_package(Threads)

add_executable(
	random
	${CMAKE_CURRENT_SOURCE_DIR}/random.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/../../test_utils.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/../../test_utils.h
)

target_include_directories(
	random
	PRIVATE
	../../
)

target_link_libraries(
	random
	emulation
	disassembly
	capstone
	unicorn
	${CMAKE_THREAD_LIBS_INIT}
)
