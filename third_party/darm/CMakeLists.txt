set(TARGET_NAME target_darm)
set(DARM_GIT_URL "https://github.com/jbremer/darm.git" CACHE STRING "URL to the darm lib repo")
ExternalProject_Add(
    ${TARGET_NAME}
    GIT_REPOSITORY    ${DARM_GIT_URL}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND     make
    INSTALL_COMMAND   bash ${CMAKE_CURRENT_SOURCE_DIR}/install.sh <BINARY_DIR> <INSTALL_DIR>
    BUILD_IN_SOURCE   1
    INSTALL_DIR       "package"
    GIT_SHALLOW       1
)

# Retrieve the installation directory path.
ExternalProject_get_property(${TARGET_NAME} INSTALL_DIR)

# Create variables pointing to the needed lib and include directories.
set(DARM_LIBRARIES_DIR "${INSTALL_DIR}/usr/local/lib")
set(DARM_INCLUDES_DIR "${INSTALL_DIR}/usr/local/include")

# Create the directories.
file(MAKE_DIRECTORY "${DARM_LIBRARIES_DIR}")
file(MAKE_DIRECTORY "${DARM_INCLUDES_DIR}")

# Library names.
set(DARM_STATIC_LIBRARY_NAME "${CMAKE_STATIC_LIBRARY_PREFIX}darm${CMAKE_STATIC_LIBRARY_SUFFIX}")
set(DARM_SHARED_LIBRARY_NAME "${CMAKE_SHARED_LIBRARY_PREFIX}darm${CMAKE_SHARED_LIBRARY_SUFFIX}")

# Library paths.
set(DARM_STATIC_LIBRARY_PATH "${DARM_LIBRARIES_DIR}/${DARM_STATIC_LIBRARY_NAME}")
set(DARM_SHARED_LIBRARY_PATH "${DARM_LIBRARIES_DIR}/${DARM_SHARED_LIBRARY_NAME}")

message(STATUS "darm installation details:")
message(STATUS "  Include files  = ${DARM_INCLUDES_DIR}")
message(STATUS "  Library files  = ${DARM_LIBRARIES_DIR}")
message(STATUS "  Static library = ${DARM_STATIC_LIBRARY_NAME}")
message(STATUS "  Shared library = ${DARM_SHARED_LIBRARY_PATH}")

# Create an imported target so we can use the external project as a dependency.
add_library(darm SHARED IMPORTED GLOBAL)
set_target_properties(darm PROPERTIES IMPORTED_IMPLIB               ${DARM_STATIC_LIBRARY_PATH})
set_target_properties(darm PROPERTIES IMPORTED_LOCATION             ${DARM_SHARED_LIBRARY_PATH})
set_target_properties(darm PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${DARM_INCLUDES_DIR})
add_dependencies(darm ${TARGET_NAME})
