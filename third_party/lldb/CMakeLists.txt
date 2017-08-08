set(TARGET_NAME target_lldb)
set(LLDB_GIT_URL "https://git.llvm.org/git/lldb.git/" CACHE STRING "URL to the lldb repo")
ExternalProject_Add(
    ${TARGET_NAME}
    GIT_REPOSITORY    ${LLDB_GIT_URL}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND     ""
    INSTALL_COMMAND   ""
    GIT_SHALLOW       1
)

# Retrieve the installation directory path.
ExternalProject_get_property(${TARGET_NAME} INSTALL_DIR)

# Create variables pointing to the needed lib and include directories.
set(LLDB_INCLUDES_DIR "${INSTALL_DIR}/include")

message(STATUS "LLDB installation details:")
message(STATUS "  Include files = ${LLDB_INCLUDES_DIR}")

include_directories(${LLDB_INCLUDES_DIR})
