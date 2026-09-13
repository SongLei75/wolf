cmake_minimum_required(VERSION 3.20)
project(wolfssh_x509_superbuild NONE)

include(ExternalProject)
include(ProcessorCount)

ProcessorCount(HOST_JOBS)
if(HOST_JOBS EQUAL 0)
    set(HOST_JOBS 4)
endif()

find_program(BASH_EXECUTABLE bash REQUIRED)
find_program(MAKE_EXECUTABLE make REQUIRED)
find_program(MINGW_GCC x86_64-w64-mingw32-gcc)
find_program(MINGW_AR x86_64-w64-mingw32-ar)
find_program(MINGW_RANLIB x86_64-w64-mingw32-ranlib)
find_program(MINGW_STRIP x86_64-w64-mingw32-strip)
find_program(MINGW_WINDRES x86_64-w64-mingw32-windres)

set(ROOT_DIR "${CMAKE_SOURCE_DIR}")
set(OUT_DIR "${ROOT_DIR}/out")
set(BUILD_ROOT "${OUT_DIR}/build")
set(RELEASE_ROOT "${OUT_DIR}/release")
set(LINUX_ROOT "${BUILD_ROOT}/linux")
set(LINUX_STAGE_ROOT "${LINUX_ROOT}/stage")
set(WOLFSSL_LINUX_SRC "${LINUX_ROOT}/wolfssl-src")
set(WOLFSSL_LINUX_BUILD "${LINUX_ROOT}/wolfssl-build")
set(WOLFSSL_LINUX_STAGE "${LINUX_STAGE_ROOT}/wolfssl")
set(WOLFSSH_LINUX_SRC "${LINUX_ROOT}/wolfssh-src")
set(WOLFSSH_LINUX_STAGE "${LINUX_STAGE_ROOT}/wolfssh")
set(LINUX_RELEASE_DIR "${RELEASE_ROOT}/linux")

set(WINDOWS_ROOT "${BUILD_ROOT}/windows")
set(WINDOWS_STAGE_ROOT "${WINDOWS_ROOT}/stage")
set(WOLFSSL_WINDOWS_SRC "${WINDOWS_ROOT}/wolfssl-src")
set(WOLFSSL_WINDOWS_BUILD "${WINDOWS_ROOT}/wolfssl-build")
set(WOLFSSL_WINDOWS_STAGE "${WINDOWS_STAGE_ROOT}/wolfssl")
set(WOLFSSH_WINDOWS_SRC "${WINDOWS_ROOT}/wolfssh-src")
set(WOLFSSH_WINDOWS_STAGE "${WINDOWS_STAGE_ROOT}/wolfssh")
set(WINDOWS_RELEASE_DIR "${RELEASE_ROOT}/windows")

file(MAKE_DIRECTORY "${BUILD_ROOT}" "${RELEASE_ROOT}")

add_custom_command(
    OUTPUT "${WOLFSSH_LINUX_SRC}/.prepared"
    COMMAND "${CMAKE_COMMAND}" -E rm -rf "${WOLFSSH_LINUX_SRC}"
    COMMAND "${CMAKE_COMMAND}" -E copy_directory "${ROOT_DIR}/wolfssh" "${WOLFSSH_LINUX_SRC}"
    COMMAND "${CMAKE_COMMAND}" -E touch "${WOLFSSH_LINUX_SRC}/.prepared"
    DEPENDS "${ROOT_DIR}/wolfssh/configure.ac"
    VERBATIM
)
add_custom_target(prepare_wolfssh_linux DEPENDS "${WOLFSSH_LINUX_SRC}/.prepared")

add_custom_command(
    OUTPUT "${WOLFSSL_LINUX_SRC}/.prepared"
    COMMAND "${CMAKE_COMMAND}" -E rm -rf "${WOLFSSL_LINUX_SRC}"
    COMMAND "${CMAKE_COMMAND}" -E copy_directory "${ROOT_DIR}/wolfssl" "${WOLFSSL_LINUX_SRC}"
    COMMAND "${CMAKE_COMMAND}" -E touch "${WOLFSSL_LINUX_SRC}/.prepared"
    DEPENDS "${ROOT_DIR}/wolfssl/configure.ac"
    VERBATIM
)
add_custom_target(prepare_wolfssl_linux DEPENDS "${WOLFSSL_LINUX_SRC}/.prepared")

ExternalProject_Add(wolfssl_linux
    SOURCE_DIR "${WOLFSSL_LINUX_SRC}"
    BINARY_DIR "${WOLFSSL_LINUX_BUILD}"
    CMAKE_ARGS
        "-DCMAKE_INSTALL_PREFIX=${WOLFSSL_LINUX_STAGE}"
        "-DCMAKE_BUILD_TYPE=Release"
        "-DWOLFSSL_WOLFSSH=yes"
        "-DWOLFSSL_IP_ALT_NAME=yes"
    DEPENDS prepare_wolfssl_linux
)
ExternalProject_Add(wolfssh_linux
    SOURCE_DIR "${WOLFSSH_LINUX_SRC}"
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND "${BASH_EXECUTABLE}" -lc
        "cd '${WOLFSSH_LINUX_SRC}' && ./autogen.sh && ./configure --prefix='${WOLFSSH_LINUX_STAGE}' --with-wolfssl='${WOLFSSL_LINUX_STAGE}' --enable-certs --enable-sshclient --enable-scp --enable-sftp --enable-fwd"
    BUILD_COMMAND "${MAKE_EXECUTABLE}" -C "${WOLFSSH_LINUX_SRC}" -j${HOST_JOBS}
    INSTALL_COMMAND "${MAKE_EXECUTABLE}" -C "${WOLFSSH_LINUX_SRC}" install
    DEPENDS prepare_wolfssh_linux wolfssl_linux
)

add_custom_command(
    OUTPUT "${LINUX_RELEASE_DIR}/.packaged"
    COMMAND "${CMAKE_COMMAND}" -E rm -rf "${LINUX_RELEASE_DIR}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${LINUX_RELEASE_DIR}/bin" "${LINUX_RELEASE_DIR}/lib"
    COMMAND "${CMAKE_COMMAND}" -E copy "${WOLFSSH_LINUX_SRC}/apps/wolfssh/.libs/wolfssh" "${LINUX_RELEASE_DIR}/bin/wolfssh"
    COMMAND "${CMAKE_COMMAND}" -E copy "${WOLFSSH_LINUX_SRC}/examples/client/.libs/client" "${LINUX_RELEASE_DIR}/bin/wolfssh-x509-client"
    COMMAND "${CMAKE_COMMAND}" -E copy "${WOLFSSH_LINUX_SRC}/examples/scpclient/.libs/wolfscp" "${LINUX_RELEASE_DIR}/bin/wolfscp"
    COMMAND "${CMAKE_COMMAND}" -E copy "${WOLFSSH_LINUX_SRC}/examples/sftpclient/.libs/wolfsftp" "${LINUX_RELEASE_DIR}/bin/wolfsftp"
    COMMAND "${CMAKE_COMMAND}" -E copy_directory "${WOLFSSH_LINUX_STAGE}/lib" "${LINUX_RELEASE_DIR}/lib"
    COMMAND "${CMAKE_COMMAND}" -E copy_directory "${WOLFSSL_LINUX_STAGE}/lib" "${LINUX_RELEASE_DIR}/lib"
    COMMAND "${CMAKE_COMMAND}" -E touch "${LINUX_RELEASE_DIR}/.packaged"
    DEPENDS wolfssh_linux
    VERBATIM
)
add_custom_target(linux DEPENDS "${LINUX_RELEASE_DIR}/.packaged")

add_custom_command(
    OUTPUT "${WOLFSSH_WINDOWS_SRC}/.prepared"
    COMMAND "${CMAKE_COMMAND}" -E rm -rf "${WOLFSSH_WINDOWS_SRC}"
    COMMAND "${CMAKE_COMMAND}" -E copy_directory "${ROOT_DIR}/wolfssh" "${WOLFSSH_WINDOWS_SRC}"
    COMMAND "${CMAKE_COMMAND}" -E touch "${WOLFSSH_WINDOWS_SRC}/.prepared"
    DEPENDS "${ROOT_DIR}/wolfssh/configure.ac"
    VERBATIM
)
add_custom_target(prepare_wolfssh_windows DEPENDS "${WOLFSSH_WINDOWS_SRC}/.prepared")

add_custom_command(
    OUTPUT "${WOLFSSL_WINDOWS_SRC}/.prepared"
    COMMAND "${CMAKE_COMMAND}" -E rm -rf "${WOLFSSL_WINDOWS_SRC}"
    COMMAND "${CMAKE_COMMAND}" -E copy_directory "${ROOT_DIR}/wolfssl" "${WOLFSSL_WINDOWS_SRC}"
    COMMAND "${CMAKE_COMMAND}" -E touch "${WOLFSSL_WINDOWS_SRC}/.prepared"
    DEPENDS "${ROOT_DIR}/wolfssl/configure.ac"
    VERBATIM
)
add_custom_target(prepare_wolfssl_windows DEPENDS "${WOLFSSL_WINDOWS_SRC}/.prepared")

ExternalProject_Add(wolfssl_windows
    DOWNLOAD_COMMAND ""
    UPDATE_COMMAND ""
    PATCH_COMMAND ""
    TEST_COMMAND ""
    SOURCE_DIR "${WOLFSSL_WINDOWS_SRC}"
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND "${BASH_EXECUTABLE}" -lc
        "cd '${WOLFSSL_WINDOWS_SRC}' && ./autogen.sh && CC='${MINGW_GCC}' AR='${MINGW_AR}' RANLIB='${MINGW_RANLIB}' STRIP='${MINGW_STRIP}' WINDRES='${MINGW_WINDRES}' ./configure --host=x86_64-w64-mingw32 --prefix='${WOLFSSL_WINDOWS_STAGE}' --enable-shared --disable-static --enable-wolfssh --enable-ip-alt-name"
    BUILD_COMMAND "${MAKE_EXECUTABLE}" -C "${WOLFSSL_WINDOWS_SRC}" -j${HOST_JOBS}
    INSTALL_COMMAND "${MAKE_EXECUTABLE}" -C "${WOLFSSL_WINDOWS_SRC}" install
    DEPENDS prepare_wolfssl_windows
)

ExternalProject_Add(wolfssh_windows
    DOWNLOAD_COMMAND ""
    UPDATE_COMMAND ""
    PATCH_COMMAND ""
    TEST_COMMAND ""
    SOURCE_DIR "${WOLFSSH_WINDOWS_SRC}"
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND "${BASH_EXECUTABLE}" -lc
        "cd '${WOLFSSH_WINDOWS_SRC}' && ./autogen.sh && CC='${MINGW_GCC}' AR='${MINGW_AR}' RANLIB='${MINGW_RANLIB}' STRIP='${MINGW_STRIP}' WINDRES='${MINGW_WINDRES}' CPPFLAGS='-DUSE_WINDOWS_API' LIBS='-lws2_32 -lcrypt32 -ladvapi32' ./configure --host=x86_64-w64-mingw32 --prefix='${WOLFSSH_WINDOWS_STAGE}' --with-wolfssl='${WOLFSSL_WINDOWS_STAGE}' --enable-certs --enable-sshclient --enable-scp --enable-sftp --enable-fwd"
    BUILD_COMMAND "${MAKE_EXECUTABLE}" -C "${WOLFSSH_WINDOWS_SRC}" -j${HOST_JOBS} apps/wolfssh/wolfssh.exe examples/client/client.exe examples/scpclient/wolfscp.exe examples/sftpclient/wolfsftp.exe
    INSTALL_COMMAND "${CMAKE_COMMAND}" -E echo "Skipping wolfssh install step; package copies the built Windows binaries directly"
    DEPENDS prepare_wolfssh_windows wolfssl_windows
)

add_custom_command(
    OUTPUT "${WINDOWS_RELEASE_DIR}/.packaged"
    COMMAND "${CMAKE_COMMAND}" -E rm -rf "${WINDOWS_RELEASE_DIR}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${WINDOWS_RELEASE_DIR}/bin"
    COMMAND "${CMAKE_COMMAND}" -E copy "${WOLFSSH_WINDOWS_SRC}/apps/wolfssh/.libs/wolfssh.exe" "${WINDOWS_RELEASE_DIR}/bin/wolfssh.exe"
    COMMAND "${CMAKE_COMMAND}" -E copy "${WOLFSSH_WINDOWS_SRC}/examples/client/.libs/client.exe" "${WINDOWS_RELEASE_DIR}/bin/wolfssh-x509-client.exe"
    COMMAND "${CMAKE_COMMAND}" -E copy "${WOLFSSH_WINDOWS_SRC}/examples/scpclient/.libs/wolfscp.exe" "${WINDOWS_RELEASE_DIR}/bin/wolfscp.exe"
    COMMAND "${CMAKE_COMMAND}" -E copy "${WOLFSSH_WINDOWS_SRC}/examples/sftpclient/.libs/wolfsftp.exe" "${WINDOWS_RELEASE_DIR}/bin/wolfsftp.exe"
    COMMAND "${BASH_EXECUTABLE}" -lc "cp -a \"$(${MINGW_GCC} -print-file-name=libwinpthread-1.dll)\" '${WINDOWS_RELEASE_DIR}/bin/'"
    COMMAND "${BASH_EXECUTABLE}" -lc "cp -a '${WOLFSSL_WINDOWS_STAGE}/bin/'*.dll '${WINDOWS_RELEASE_DIR}/bin/'"
    COMMAND "${CMAKE_COMMAND}" -E copy "${WOLFSSH_WINDOWS_SRC}/src/.libs/libwolfssh-18.dll" "${WINDOWS_RELEASE_DIR}/bin/libwolfssh-18.dll"
    COMMAND "${CMAKE_COMMAND}" -E touch "${WINDOWS_RELEASE_DIR}/.packaged"
    DEPENDS wolfssh_windows
    VERBATIM
)
add_custom_target(windows DEPENDS "${WINDOWS_RELEASE_DIR}/.packaged")
