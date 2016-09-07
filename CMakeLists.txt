cmake_minimum_required(VERSION 3.1)
include(CheckCXXCompilerFlag)

# =============================================================================
# [AsmTK - Configuration]
# =============================================================================

# set(ASMTK_EMBED FALSE)                        # Embed, asmtk will not create any targets.
# set(ASMTK_STATIC FALSE)                       # Whether to build a static library.
# set(ASMTK_BUILD_TEST FALSE)                   # Whether to build tests and samples.

# =============================================================================
# [AsmTK - Build / Embed]
# =============================================================================

# Do not create a project if this CMakeLists.txt is included from another
# project. This makes it easy to embed or create a static library.
if(NOT CMAKE_PROJECT_NAME OR "${CMAKE_PROJECT_NAME}" MATCHES "^asmtk$")
  project(asmtk C CXX)
  set(ASMTK_SIGNATURE "Standalone")
else()
  set(ASMTK_SIGNATURE "Included")
endif()

if(ASMTK_EMBED)
  set(ASMTK_SIGNATURE "${ASMTK_SIGNATURE} | Mode=Embed")
  set(ASMTK_STATIC TRUE)
elseif(ASMTK_STATIC)
  set(ASMTK_SIGNATURE "${ASMTK_SIGNATURE} | Mode=Static")
else()
  set(ASMTK_SIGNATURE "${ASMTK_SIGNATURE} | Mode=Shared")
endif()

if(ASMTK_BUILD_TEST)
  set(ASMTK_SIGNATURE "${ASMTK_SIGNATURE} | Test=On")
else()
  set(ASMTK_SIGNATURE "${ASMTK_SIGNATURE} | Test=Off")
endif()

if(NOT ASMTK_DIR)
  set(ASMTK_DIR ${CMAKE_CURRENT_LIST_DIR})
endif()

message("-- [asmtk] ${ASMTK_SIGNATURE}")
message("-- [asmtk] ASMTK_DIR=${ASMTK_DIR}")

# =============================================================================
# [AsmTK - Flags / Deps]
# =============================================================================

set(ASMTK_SOURCE_DIR "${ASMTK_DIR}/src")
set(ASMTK_INCLUDE_DIR "${ASMTK_SOURCE_DIR}")

set(ASMTK_D "-D") # Used to define a C/C++ preprocessor parameter (-D or /D).
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
  set(ASMTK_D "/D")
endif()

if(NOT ASMJIT_DIR)
  set(ASMJIT_DIR "${ASMTK_DIR}/../asmjit")
endif()

set(ASMJIT_EMBED TRUE)
include("${ASMJIT_DIR}/CMakeLists.txt")

set(ASMTK_PRIVATE_CFLAGS ${ASMJIT_PRIVATE_CFLAGS})
set(ASMTK_PRIVATE_CFLAGS_DBG ${ASMJIT_PRIVATE_CFLAGS_DBG})
set(ASMTK_PRIVATE_CFLAGS_REL ${ASMJIT_PRIVATE_CFLAGS_REL})

if(ASMTK_EMBED)
  list(APPEND ASMTK_PRIVATE_CFLAGS "${ASMJIT_D}ASMTK_EMBED")
elseif(ASMTK_STATIC)
  list(APPEND ASMTK_PRIVATE_CFLAGS "${ASMJIT_D}ASMTK_STATIC")
endif()

# =============================================================================
# [AsmTK - Source]
# =============================================================================

set(ASMTK_SRC
  ${ASMTK_SOURCE_DIR}/asmtk/asmtk.h
  ${ASMTK_SOURCE_DIR}/asmtk/asmparser.cpp
  ${ASMTK_SOURCE_DIR}/asmtk/asmparser.h
  ${ASMTK_SOURCE_DIR}/asmtk/asmtokenizer.cpp
  ${ASMTK_SOURCE_DIR}/asmtk/asmtokenizer.h
  ${ASMTK_SOURCE_DIR}/asmtk/strtod.h)

# =============================================================================
# [AsmTK - Targets]
# =============================================================================

if(NOT ASMTK_EMBED)
  if(ASMTK_BUILD_TEST)
    set(ASMTK_TEST_CFLAGS
      ${ASMJIT_CFLAGS}
      ${ASMTK_D}ASMJIT_BUILD_X86
      ${ASMTK_D}ASMJIT_EMBED
      ${ASMTK_D}ASMTK_EMBED
      ${ASMTK_D}ASMTK_TEST)

    set(ASMTK_TEST_SRC
      asmtk_test_cmd
      asmtk_test_handler
      asmtk_test_x86)

    foreach(_target ${ASMTK_TEST_SRC})
      add_executable(${_target} ${ASMJIT_SRC} ${ASMTK_SRC} "${ASMTK_DIR}/test/${_target}.cpp")
      target_link_libraries(${_target} ${ASMJIT_DEPS})
      target_include_directories(${_target} BEFORE PRIVATE ${ASMJIT_INCLUDE_DIR})
      set_target_properties(${_target} PROPERTIES LINK_FLAGS "${ASMJIT_PRIVATE_LFLAGS}")

      if(CMAKE_BUILD_TYPE)
        if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
          target_compile_options(${_target} PRIVATE ${ASMTK_TEST_CFLAGS} ${ASMTK_PRIVATE_CFLAGS} ${ASMTK_PRIVATE_CFLAGS_DBG})
        else()
          target_compile_options(${_target} PRIVATE ${ASMTK_TEST_CFLAGS} ${ASMTK_PRIVATE_CFLAGS} ${ASMTK_PRIVATE_CFLAGS_REL})
        endif()
      else()
        target_compile_options(${_target} PRIVATE ${ASMTK_TEST_CFLAGS} ${ASMTK_PRIVATE_CFLAGS}
          $<$<CONFIG:Debug>:${ASMTK_PRIVATE_CFLAGS_DBG}>
          $<$<NOT:$<CONFIG:Debug>>:${ASMTK_PRIVATE_CFLAGS_REL}>)
      endif()
    endforeach()
  endif()
endif()
