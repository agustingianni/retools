message(STATUS "Building required third-party libraries from source, this may take a while ...")

add_subdirectory(darm)
add_subdirectory(lldb)
add_subdirectory(unicorn)
add_subdirectory(capstone)