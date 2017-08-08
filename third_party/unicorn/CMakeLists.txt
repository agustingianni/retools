set(TARGET_NAME target_unicorn)
set(UNICORN_GIT_URL "https://github.com/unicorn-engine/unicorn.git" CACHE STRING "URL to the unicorn lib repo")
ExternalProject_Add(
    ${TARGET_NAME}
    GIT_REPOSITORY    ${UNICORN_GIT_URL}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND     ./make.sh
    INSTALL_COMMAND   DESTDIR=<INSTALL_DIR> ./make.sh install
    BUILD_IN_SOURCE   1
    INSTALL_DIR       "package"
    GIT_SHALLOW       1
)

# Retrieve the installation directory path.
ExternalProject_get_property(${TARGET_NAME} INSTALL_DIR)

# Create variables pointing to the needed lib and include directories.
if(APPLE)
set(UNICORN_LIBRARIES_DIR "${INSTALL_DIR}/usr/local/lib")
set(UNICORN_INCLUDES_DIR "${INSTALL_DIR}/usr/local/include")
else()
set(UNICORN_LIBRARIES_DIR "${INSTALL_DIR}/usr/lib")
set(UNICORN_INCLUDES_DIR "${INSTALL_DIR}/usr/include")
endif()

# Create the directories.
file(MAKE_DIRECTORY "${UNICORN_LIBRARIES_DIR}")
file(MAKE_DIRECTORY "${UNICORN_INCLUDES_DIR}")

# Library names.
set(UNICORN_STATIC_LIBRARY_NAME "${CMAKE_STATIC_LIBRARY_PREFIX}unicorn${CMAKE_STATIC_LIBRARY_SUFFIX}")
set(UNICORN_SHARED_LIBRARY_NAME "${CMAKE_SHARED_LIBRARY_PREFIX}unicorn${CMAKE_SHARED_LIBRARY_SUFFIX}")

# Library paths.
set(UNICORN_STATIC_LIBRARY_PATH "${UNICORN_LIBRARIES_DIR}/${UNICORN_STATIC_LIBRARY_NAME}")
set(UNICORN_SHARED_LIBRARY_PATH "${UNICORN_LIBRARIES_DIR}/${UNICORN_SHARED_LIBRARY_NAME}")

message(STATUS "unicorn installation details:")
message(STATUS "  Include files  = ${UNICORN_INCLUDES_DIR}")
message(STATUS "  Library files  = ${UNICORN_LIBRARIES_DIR}")
message(STATUS "  Static library = ${UNICORN_STATIC_LIBRARY_NAME}")
message(STATUS "  Shared library = ${UNICORN_SHARED_LIBRARY_NAME}")

# Create an imported target so we can use the external project as a dependency.
add_library(unicorn SHARED IMPORTED GLOBAL)
set_target_properties(unicorn PROPERTIES IMPORTED_IMPLIB               ${UNICORN_STATIC_LIBRARY_PATH})
set_target_properties(unicorn PROPERTIES IMPORTED_LOCATION             ${UNICORN_SHARED_LIBRARY_PATH})
set_target_properties(unicorn PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${UNICORN_INCLUDES_DIR})
add_dependencies(unicorn ${TARGET_NAME})
