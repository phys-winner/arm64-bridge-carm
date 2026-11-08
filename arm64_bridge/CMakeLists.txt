cmake_minimum_required(VERSION 3.22)
project(arm32_bridge LANGUAGES C CXX)

# Pass -DBRIDGE_TARGET=<name> to match the game's System.loadLibrary() call.
set(BRIDGE_TARGET arm32_bridge CACHE STRING "Bridge library target name")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Per-call tracing takes locks and formats strings on every guest->host call.
# The game makes tens of millions of these calls in a single race, so keep it
# opt-in for targeted diagnostics rather than shipping it in normal builds.
option(BRIDGE_ENABLE_PER_CALL_TRACE "Trace every guest thunk dispatch" OFF)
option(BRIDGE_ENABLE_HEAP_DIAGNOSTICS "Scan and log every guest heap allocation" OFF)
option(BRIDGE_ENABLE_COLLISION_PROBE "Trace selected collision solver calls" OFF)
option(BRIDGE_ENABLE_LOGS "Emit bridge Android logs and bridge_diag.txt" ON)
option(BRIDGE_FIX_MASSLESS_STATIC "Treat physics objects with missing/nonpositive mass as immovable" ON)
option(BRIDGE_TEST_FORCE_EXTERNAL_OBB "Diagnostic only: skip embedded OBB to exercise external fallback" OFF)

set(BRIDGE_TRACE_SOURCE src/diag_trace.cpp)
if(NOT BRIDGE_ENABLE_LOGS)
    set(BRIDGE_TRACE_SOURCE src/diag_trace_stub.cpp)
endif()

include(FetchContent)

# Size: applied before FetchContent so dynarmic/fmt/mcl inherit them. Only
# JNI_OnLoad has to be exported (everything else is registered at runtime), so
# hiding the rest drops the dynsym table and most of .rela.
add_compile_options(-fvisibility=hidden -fvisibility-inlines-hidden
                    -ffunction-sections -fdata-sections)
add_link_options(-Wl,--gc-sections -Wl,--icf=all -Wl,--exclude-libs,ALL)

# Boost Headers
set(BOOST_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost")
set(BOOST_INCLUDEDIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost")
set(Boost_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost")
set(Boost_NO_SYSTEM_PATHS ON)
set(Boost_FOUND TRUE)
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost")

# Configure Dynarmic.
# NOTE: the real option is DYNARMIC_FRONTENDS (a list), not DYNARMIC_ENABLE_A32/A64 --
# the old names were silently ignored, so A64 was being built too.
set(DYNARMIC_FRONTENDS "A32" CACHE STRING "" FORCE)
set(DYNARMIC_TESTS OFF CACHE BOOL "" FORCE)
set(DYNARMIC_WARNINGS_AS_ERRORS OFF CACHE BOOL "" FORCE)
set(DYNARMIC_USE_BUNDLED_EXTERNALS ON CACHE BOOL "" FORCE)  # cross-compiling: never pick up host libs

message(STATUS "Configuring pinned Dynarmic dependency...")
FetchContent_Declare(
    dynarmic
    GIT_REPOSITORY https://github.com/azahar-emu/dynarmic.git
    GIT_TAG        e77b1ba0b7da7cbe93021b01a663acfe7c4dd516
)
FetchContent_MakeAvailable(dynarmic)

set(BRIDGE_SOURCES
    src/elf_loader.cpp
    src/dynarmic_host.cpp
    src/thunk_manager.cpp
    ${BRIDGE_TRACE_SOURCE}
    src/thunks_gl.cpp
    src/thunks_gl_gles2_core.cpp
    src/thunks_gles1.cpp
    src/thunks_egl.cpp
    src/thunks_android.cpp
    src/native_handle_table.cpp
    src/thunks_libc.cpp
    src/thunks_zlib.cpp
    src/thunks_libc_extra.cpp
    src/thunks_opensles.cpp   # drop this line if the game is not on FMOD Ex
    src/jni_fake_env.cpp
    src/jni_bridge.cpp
)

add_library(${BRIDGE_TARGET} SHARED ${BRIDGE_SOURCES})

function(bridge_configure_logging target)
    target_compile_definitions(${target} PRIVATE
        BRIDGE_ENABLE_LOGS=$<BOOL:${BRIDGE_ENABLE_LOGS}>
    )
    if(NOT BRIDGE_ENABLE_LOGS)
        target_compile_options(${target} PRIVATE
            -include "${CMAKE_CURRENT_SOURCE_DIR}/src/bridge_log_policy.h"
        )
    endif()
endfunction()

bridge_configure_logging(${BRIDGE_TARGET})
bridge_configure_logging(dynarmic)

target_include_directories(${BRIDGE_TARGET} PRIVATE
    src
    ${dynarmic_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost
)

target_link_libraries(${BRIDGE_TARGET} PRIVATE
    dynarmic
    GLESv2
    GLESv1_CM
    EGL
    OpenSLES
    log
    android
    m
    z
)

target_compile_definitions(${BRIDGE_TARGET} PRIVATE
    ANDROID
    __ANDROID__
    BRIDGE_ENABLE_PER_CALL_TRACE=$<BOOL:${BRIDGE_ENABLE_PER_CALL_TRACE}>
    BRIDGE_ENABLE_HEAP_DIAGNOSTICS=$<BOOL:${BRIDGE_ENABLE_HEAP_DIAGNOSTICS}>
    BRIDGE_ENABLE_COLLISION_PROBE=$<BOOL:${BRIDGE_ENABLE_COLLISION_PROBE}>
    BRIDGE_FIX_MASSLESS_STATIC=$<BOOL:${BRIDGE_FIX_MASSLESS_STATIC}>
    BRIDGE_TEST_FORCE_EXTERNAL_OBB=$<BOOL:${BRIDGE_TEST_FORCE_EXTERNAL_OBB}>
)

# Android 15+ devices boot with 16 KB pages; a 4 KB-aligned LOAD segment trips
# the "app isn't 16 KB compatible" loader warning.
target_link_options(${BRIDGE_TARGET} PRIVATE
    "-Wl,-z,max-page-size=16384"
    "-Wl,-z,common-page-size=16384"
    "-Wl,-z,relro"
    "-Wl,-z,now"
)

option(BRIDGE_BUILD_TESTS "Build Android bridge component regression" OFF)
if(BRIDGE_BUILD_TESTS)
    add_executable(bridge_regression tests/bridge_regression.cpp ${BRIDGE_SOURCES})
    target_include_directories(bridge_regression PRIVATE src ${dynarmic_SOURCE_DIR}/include)
    target_link_libraries(bridge_regression PRIVATE dynarmic GLESv2 EGL OpenSLES log android m z)
    target_link_options(bridge_regression PRIVATE "-Wl,-z,max-page-size=16384" "-Wl,-z,common-page-size=16384")
    target_compile_definitions(bridge_regression PRIVATE BRIDGE_GAME_MC4=0)
    target_link_libraries(bridge_regression PRIVATE GLESv1_CM)
    bridge_configure_logging(bridge_regression)

    add_executable(input_queue_lifetime_test tests/input_queue_lifetime_test.cpp ${BRIDGE_SOURCES})
    target_include_directories(input_queue_lifetime_test PRIVATE src ${dynarmic_SOURCE_DIR}/include)
    target_link_libraries(input_queue_lifetime_test PRIVATE dynarmic GLESv2 GLESv1_CM EGL OpenSLES log android m z)
    target_link_options(input_queue_lifetime_test PRIVATE "-Wl,-z,max-page-size=16384" "-Wl,-z,common-page-size=16384")
    bridge_configure_logging(input_queue_lifetime_test)
endif()
