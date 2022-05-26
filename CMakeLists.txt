cmake_minimum_required(VERSION 3.8)

cmake_policy(PUSH)
cmake_policy(SET CMP0063 NEW) # Honor visibility properties.

# Don't create a project if it was already created by another CMakeLists.txt.
# This allows one library to embed another library without making a collision.
if (NOT CMAKE_PROJECT_NAME OR "${CMAKE_PROJECT_NAME}" STREQUAL "asmtk")
  project(asmtk CXX)
endif()

include(GNUInstallDirs)

# =============================================================================
# [AsmTK - Deprecated]
# =============================================================================

if (DEFINED ASMTK_BUILD_EMBED)
  message(DEPRECATION "ASMTK_BUILD_EMBED is deprecated, use ASMTK_EMBED")
  set(ASMTK_EMBED "${ASMTK_BUILD_EMBED}")
endif()

if (DEFINED ASMTK_BUILD_STATIC)
  message(DEPRECATION "ASMTK_BUILD_STATIC is deprecated, use ASMTK_STATIC")
  set(ASMTK_STATIC "${ASMTK_BUILD_STATIC}")
endif()

# =============================================================================
# [AsmTK - Configuration]
# =============================================================================

if (NOT DEFINED ASMTK_DIR)
  set(ASMTK_DIR "${CMAKE_CURRENT_LIST_DIR}")
endif()

if (NOT DEFINED ASMJIT_DIR)
  set(ASMJIT_DIR "${ASMTK_DIR}/../asmjit")
endif()

if (NOT DEFINED ASMJIT_EXTERNAL)
  set(ASMJIT_EXTERNAL FALSE)
endif()

if (NOT DEFINED ASMTK_EMBED)
  set(ASMTK_EMBED FALSE)
endif()

if (NOT DEFINED ASMTK_STATIC)
  set(ASMTK_STATIC ${ASMJIT_EMBED})
endif()

set(ASMTK_DIR    "${ASMTK_DIR}"  CACHE PATH "Location of 'asmtk'")
set(ASMJIT_DIR   "${ASMJIT_DIR}" CACHE PATH "Location of 'asmjit'")

set(ASMJIT_EXTERNAL ${ASMJIT_EXTERNAL} CACHE BOOL "External 'asmjit'")

set(ASMTK_TEST   ${ASMTK_TEST}   CACHE BOOL "Build 'asmtk' test applications")
set(ASMTK_EMBED  ${ASMTK_EMBED}  CACHE BOOL "Embed 'asmtk' library (no targets)")
set(ASMTK_STATIC ${ASMTK_STATIC} CACHE BOOL "Build 'asmtk' library as static")

# =============================================================================
# [AsmTK - Project]
# =============================================================================

set(ASMTK_INCLUDE_DIRS "${ASMTK_DIR}/src")       # Include directory is the same as source dir.
set(ASMTK_CFLAGS "")                             # Public compiler flags.
set(ASMTK_PRIVATE_CFLAGS "")                     # Private compiler flags independent of build type.
set(ASMTK_PRIVATE_CFLAGS_DBG "")                 # Private compiler flags used by debug builds.
set(ASMTK_PRIVATE_CFLAGS_REL "")                 # Private compiler flags used by release builds.

if (NOT ASMTK_NO_CUSTOM_FLAGS)
  if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC" OR "x${CMAKE_CXX_SIMULATE_ID}" STREQUAL "xMSVC")
    list(APPEND ASMTK_PRIVATE_CFLAGS
      -MP                      # [+] Multi-Process Compilation.
      -GR-                     # [-] Runtime type information.
      -GF                      # [+] Eliminate duplicate strings.
      -Zc:inline               # [+] Remove unreferenced COMDAT.
      -Zc:strictStrings        # [+] Strict const qualification of string literals.
      -Zc:threadSafeInit-      # [-] Thread-safe statics.
      -W4)                     # [+] Warning level 4.

    list(APPEND ASMTK_PRIVATE_CFLAGS_DBG
      -GS)                     # [+] Buffer security-check.

    list(APPEND ASMTK_PRIVATE_CFLAGS_REL
      -GS-                     # [-] Buffer security-check.
      -O2                      # [+] Favor speed over size.
      -Oi)                     # [+] Generate intrinsic functions.
  elseif ("${CMAKE_CXX_COMPILER_ID}" MATCHES "^(GNU|Clang|AppleClang)$")
    list(APPEND ASMTK_PRIVATE_CFLAGS -Wall -Wextra -Wconversion)
    list(APPEND ASMTK_PRIVATE_CFLAGS -fno-math-errno -fno-threadsafe-statics)
    list(APPEND ASMTK_PRIVATE_CFLAGS_REL -O2)
  endif()
endif()

if (ASMTK_EMBED)
  set(ASMTK_TARGET_TYPE "EMBED")
elseif (ASMTK_STATIC)
  set(ASMTK_TARGET_TYPE "STATIC")
else()
  set(ASMTK_TARGET_TYPE "SHARED")
endif()

if (ASMTK_EMBED OR ASMTK_STATIC)
  List(APPEND ASMTK_CFLAGS         "-DASMTK_STATIC")
  List(APPEND ASMTK_PRIVATE_CFLAGS "-DASMTK_STATIC")
endif()

if (ASMJIT_EXTERNAL)
  find_package(asmjit CONFIG REQUIRED)
else()
  include("${ASMJIT_DIR}/CMakeLists.txt")
  list(APPEND ASMTK_PRIVATE_CFLAGS ${ASMJIT_CFLAGS})
  list(REMOVE_DUPLICATES ASMTK_PRIVATE_CFLAGS)
endif()

# =============================================================================
# [AsmTK - Source]
# =============================================================================

function(asmtk_add_source out base_dir)
  set(src_array)
  foreach(file ${ARGN})
    set(src_file "${ASMTK_DIR}/${base_dir}/${file}")
    list(APPEND src_array ${src_file})
  endforeach()
  source_group(TREE "${ASMTK_DIR}" FILES ${src_array})

  set(out_tmp ${${out}})
  list(APPEND out_tmp ${src_array})
  set("${out}" "${out_tmp}" PARENT_SCOPE)
endfunction()

set(ASMTK_SRC "")
set(ASMTK_SRC_LIST
  asmtk/asmtk.h
  asmtk/asmparser.cpp
  asmtk/asmparser.h
  asmtk/asmtokenizer.cpp
  asmtk/asmtokenizer.h
  asmtk/elfdefs.h
  asmtk/globals.h
  asmtk/parserutils.h
  asmtk/strtod.h
)
asmtk_add_source(ASMTK_SRC src ${ASMTK_SRC_LIST})

# =============================================================================
# [AsmTK - Summary]
# =============================================================================

message("** AsmTK Summary **")
message("   ASMTK_DIR=${ASMTK_DIR}")
message("   ASMJIT_EXTERNAL=${ASMJIT_EXTERNAL}")
message("   ASMTK_TEST=${ASMTK_TEST}")
message("   ASMTK_TARGET_TYPE=${ASMTK_TARGET_TYPE}")
message("   ASMTK_CFLAGS=${ASMTK_CFLAGS}")
message("   ASMTK_PRIVATE_CFLAGS=${ASMTK_PRIVATE_CFLAGS}")
message("   ASMTK_PRIVATE_CFLAGS_DBG=${ASMTK_PRIVATE_CFLAGS_DBG}")
message("   ASMTK_PRIVATE_CFLAGS_REL=${ASMTK_PRIVATE_CFLAGS_REL}")

# =============================================================================
# [AsmTK - Targets]
# =============================================================================

if (NOT ASMTK_EMBED)
  add_library(asmtk ${ASMTK_TARGET_TYPE} ${ASMTK_SRC})
  target_compile_features(asmtk PUBLIC cxx_std_11)
  target_compile_options(asmtk PUBLIC ${ASMTK_CFLAGS})
  target_compile_options(asmtk PRIVATE ${ASMTK_PRIVATE_CFLAGS}
    $<$<CONFIG:Debug>:${ASMTK_PRIVATE_CFLAGS_DBG}>
    $<$<NOT:$<CONFIG:Debug>>:${ASMTK_PRIVATE_CFLAGS_REL}>)

  if(ASMJIT_EXTERNAL)
    target_link_libraries(asmtk PUBLIC ${ASMJIT_LIBRARY})
    find_path(ASMJIT_INCLUDE_DIR NAMES asmjit/asmjit.h)
    target_include_directories(asmtk PRIVATE ${ASMJIT_INCLUDE_DIR})
  else()
    target_link_libraries(asmtk PUBLIC asmjit::asmjit)
  endif()

  target_include_directories(asmtk BEFORE INTERFACE
          $<BUILD_INTERFACE:${ASMTK_INCLUDE_DIRS}>
          $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

  set_property(TARGET asmtk PROPERTY CXX_VISIBILITY_PRESET hidden)

  # Add asmjit::asmtk target (alias to asmtk).
  add_library(asmjit::asmtk ALIAS asmtk)
  # TODO: [CMAKE] Deprecated alias - we use projectname::libraryname convention now.
  add_library(AsmTK::AsmTK ALIAS asmtk)

  # Add AsmTK install instructions (library and public headers).
  if (NOT ASMTK_NO_INSTALL)
    install(TARGETS asmtk
            EXPORT asmtk-config
            RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
            ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
    install(EXPORT asmtk-config
            NAMESPACE asmjit::
            DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/asmtk")

    foreach(_src_file ${ASMTK_SRC_LIST})
      if ("${_src_file}" MATCHES "\\.h$" AND NOT "${_src_file}" MATCHES "_p\\.h$")
        get_filename_component(_src_dir ${_src_file} PATH)
        install(FILES "${ASMTK_DIR}/src/${_src_file}" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${_src_dir}")
      endif()
    endforeach()
  endif()

  if (ASMTK_TEST AND NOT ASMJIT_EMBED)
    set(ASMTK_SAMPLES_SRC
      asmtk_test_x86cmd
      asmtk_test_x86handler
      asmtk_test_x86parser)

    foreach(_target ${ASMTK_SAMPLES_SRC})
      add_executable(${_target} "${ASMTK_DIR}/test/${_target}.cpp")
      target_link_libraries(${_target} AsmJit::AsmJit AsmTK::AsmTK)
      target_compile_features(${_target} PUBLIC cxx_std_11)
      set_property(TARGET ${_target} PROPERTY CXX_VISIBILITY_PRESET hidden)
    endforeach()
  endif()
endif()

cmake_policy(POP)
