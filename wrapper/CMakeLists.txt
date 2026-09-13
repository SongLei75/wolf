cmake_minimum_required(VERSION 3.10)

# Cross-compile detection: Linux host targeting Windows
if(NOT WIN32 AND NOT CMAKE_CROSSCOMPILING)
    find_program(_MINGW_GCC x86_64-w64-mingw32-gcc)
    if(_MINGW_GCC AND CMAKE_BINARY_DIR MATCHES "build-win")
        set(CMAKE_SYSTEM_NAME Windows)
        set(CMAKE_SYSTEM_PROCESSOR x86_64)
        set(CMAKE_C_COMPILER "${_MINGW_GCC}")
        set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
        set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
        set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
    endif()
endif()

project(wolfssh_wrapper C)

# Find the pre-built wolfssh/wolfssl from the superbuild output
# Detect platform and set appropriate paths
if(WIN32)
    set(WOLFSSH_PREFIX "${CMAKE_SOURCE_DIR}/../out/build/windows/wolfssh-src" CACHE PATH
        "Path to wolfssh source dir (Windows)")
    set(WOLFSSL_PREFIX "${CMAKE_SOURCE_DIR}/../out/build/windows/stage/wolfssl" CACHE PATH
        "Path to wolfssl install prefix (Windows)")
    set(WOLFSSH_BUILD "${CMAKE_SOURCE_DIR}/../out/build/windows/wolfssh-src" CACHE PATH
        "Path to wolfssh build dir for config.h (Windows)")
    set(LIB_DIRS
        "${CMAKE_SOURCE_DIR}/../out/build/windows/wolfssh-src/src/.libs"
        "${CMAKE_SOURCE_DIR}/../out/build/windows/stage/wolfssl/lib"
        CACHE STRING "Library search paths (Windows)")
else()
    set(WOLFSSH_PREFIX "${CMAKE_SOURCE_DIR}/../out/build/linux/stage/wolfssh" CACHE PATH
        "Path to wolfssh install prefix")
    set(WOLFSSL_PREFIX "${CMAKE_SOURCE_DIR}/../out/build/linux/stage/wolfssl" CACHE PATH
        "Path to wolfssl install prefix")
    set(WOLFSSH_BUILD "${CMAKE_SOURCE_DIR}/../out/build/linux/wolfssh-src" CACHE PATH
        "Path to wolfssh build dir (for config.h)")
    set(LIB_DIRS "${CMAKE_SOURCE_DIR}/../out/release/linux/lib" CACHE STRING
        "Library search paths")
endif()

# Includes
include_directories(
    ${WOLFSSH_PREFIX}/include
    ${WOLFSSL_PREFIX}/include
    ${WOLFSSH_BUILD}
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Library search path
link_directories(${LIB_DIRS})

# ─── Python headers ───
if(WIN32)
    # MinGW cross-compile: look for Windows Python headers if available
    find_path(PYTHON_INCLUDE_DIR Python.h
        HINTS /usr/x86_64-w64-mingw32/include/python3)
else()
    execute_process(
        COMMAND python3 -c "import sysconfig; print(sysconfig.get_path('include'))"
        OUTPUT_VARIABLE PYTHON_INCLUDE_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()
if(NOT PYTHON_INCLUDE_DIR)
    message(FATAL_ERROR "Python headers not found — required for unified build")
endif()
message(STATUS "Python include: ${PYTHON_INCLUDE_DIR}")

# ─── Common compile definitions ───
set(COMPILE_DEFS
    HAVE_CONFIG_H
    WOLFSSH_TEST_CLIENT
    WOLFSSH_CERTS
    WOLFSSH_SFTP
    WOLFSSH_FWD
    OPENSSL_ALL
    WOLFSSL_IP_ALT_NAME
)

add_library(wolfssh_wrapper SHARED wolfssh_wrapper.c)
set_target_properties(wolfssh_wrapper PROPERTIES PREFIX "")
target_compile_definitions(wolfssh_wrapper PRIVATE ${COMPILE_DEFS})
target_include_directories(wolfssh_wrapper PRIVATE ${PYTHON_INCLUDE_DIR})

# Compiler flags
if(WIN32)
    target_compile_options(wolfssh_wrapper PRIVATE -Wall -Wno-unused-function)
    target_compile_definitions(wolfssh_wrapper PRIVATE USE_WINDOWS_API WIN32_LEAN_AND_MEAN)
    target_link_libraries(wolfssh_wrapper wolfssh wolfssl ws2_32 m)
else()
    target_compile_options(wolfssh_wrapper PRIVATE -fPIC -Wall -Wno-unused-function)
    target_link_libraries(wolfssh_wrapper wolfssh wolfssl pthread m)
endif()

# Install
install(TARGETS wolfssh_wrapper DESTINATION lib)
