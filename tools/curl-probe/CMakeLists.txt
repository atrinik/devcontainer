cmake_minimum_required(VERSION 3.21)

# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 The Atrinik Project
# This bridge builds only the pinned protocol/library, never the game.
project(atrinik-curl-qualification LANGUAGES C)
include(CTest)

set(ATRINIK_CLASSIC_SOURCE_DIR "" CACHE PATH "Clean pinned Classic source checkout")
set(ATRINIK_CLASSIC_QUALIFICATION_COMMIT
    "66923f8dc65ecbb607df0dd2235517bbca705e3c" CACHE STRING
    "Full Classic commit from the producer's committed consumer manifest")
set(qualification_commit "${ATRINIK_CLASSIC_QUALIFICATION_COMMIT}")
string(LENGTH "${qualification_commit}" qualification_commit_length)
if (NOT qualification_commit MATCHES "^[0-9a-f]+$" OR
        NOT qualification_commit_length EQUAL 40)
    message(FATAL_ERROR "ATRINIK_CLASSIC_QUALIFICATION_COMMIT must be a full lowercase Git SHA")
endif ()
if (NOT EXISTS "${ATRINIK_CLASSIC_SOURCE_DIR}/libatrinik/curl.c")
    message(FATAL_ERROR "ATRINIK_CLASSIC_SOURCE_DIR must name the pinned Classic checkout")
endif ()
file(REAL_PATH "${ATRINIK_CLASSIC_SOURCE_DIR}" ATRINIK_CLASSIC_SOURCE_DIR)
include("${ATRINIK_CLASSIC_SOURCE_DIR}/cmake/AtrinikVersion.cmake")
execute_process(
    COMMAND ${ATRINIK_OWNER_GIT_COMMAND} -C "${ATRINIK_CLASSIC_SOURCE_DIR}" rev-parse HEAD
    OUTPUT_VARIABLE actual_commit OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE git_result)
if (NOT git_result EQUAL 0 OR NOT actual_commit STREQUAL qualification_commit)
    message(FATAL_ERROR "Classic cancellation qualification requires ${qualification_commit}")
endif ()
execute_process(
    COMMAND ${ATRINIK_OWNER_GIT_COMMAND} -C "${ATRINIK_CLASSIC_SOURCE_DIR}" diff --quiet HEAD --
    RESULT_VARIABLE dirty_result)
if (NOT dirty_result EQUAL 0)
    message(FATAL_ERROR "Classic cancellation qualification requires clean tracked source")
endif ()

if (NOT TARGET Atrinik::Core)
    # libatrinik inherits this target policy when embedded. Its sibling protocol
    # reads the pinned owner's version, not this qualification project's version.
    function(atrinik_configure_target target)
        target_compile_features(${target} PRIVATE c_std_17)
        target_compile_definitions(${target} PRIVATE _GNU_SOURCE)
        if (CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
            target_compile_options(${target} PRIVATE -Wall -Wextra -Wno-unused-parameter
                -fno-common -Werror)
        endif ()
    endfunction()
    if (MINGW)
        add_compile_definitions(HAVE_STRUCT_TIMESPEC NOCRYPT __USE_MINGW_ANSI_STDIO=0)
        set(PLUGIN_SUFFIX ".dll")
    else ()
        set(LINUX true)
        set(PLUGIN_SUFFIX ".so")
    endif ()
    set(LIBATRINIK_PACKAGE_LAYOUT ON CACHE BOOL "Namespaced Classic headers" FORCE)
    # Avoid unrelated unit executables; this bridge registers its own test below.
    set(BUILD_TESTING OFF)
    add_subdirectory("${ATRINIK_CLASSIC_SOURCE_DIR}/protocol" "classic-protocol")
    add_subdirectory("${ATRINIK_CLASSIC_SOURCE_DIR}/libatrinik" "classic-libatrinik")
else ()
    # An embedding consumer may reuse its already-built target, but not an
    # installed or mismatched library with an unverified cancellation helper.
    get_target_property(core_source Atrinik::Core SOURCE_DIR)
    file(REAL_PATH "${core_source}" core_source)
    if (NOT core_source STREQUAL "${ATRINIK_CLASSIC_SOURCE_DIR}/libatrinik")
        message(FATAL_ERROR "Existing Atrinik::Core does not belong to the pinned checkout")
    endif ()
endif ()

find_package(Threads REQUIRED)
add_executable(atrinik-curl-cancellation-probe cancellation.c)
target_compile_features(atrinik-curl-cancellation-probe PRIVATE c_std_17)
target_link_libraries(atrinik-curl-cancellation-probe PRIVATE Atrinik::Core Threads::Threads)
if (WIN32)
    target_link_libraries(atrinik-curl-cancellation-probe PRIVATE ws2_32)
endif ()
if (MINGW)
    target_compile_definitions(atrinik-curl-cancellation-probe PRIVATE HAVE_STRUCT_TIMESPEC)
endif ()
if (CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(atrinik-curl-cancellation-probe PRIVATE -Wall -Wextra -Werror)
endif ()
add_test(NAME atrinik-curl-cancellation-qualification COMMAND atrinik-curl-cancellation-probe)
set_tests_properties(atrinik-curl-cancellation-qualification PROPERTIES TIMEOUT 15)
