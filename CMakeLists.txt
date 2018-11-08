cmake_minimum_required(VERSION 3.1)

# Don't create a project if it was already created by another CMakeLists.txt.
# This allows one library to embed another library without a project collision.
if(NOT CMAKE_PROJECT_NAME OR "${CMAKE_PROJECT_NAME}" STREQUAL "asmtk")
  project(asmtk C CXX)
endif()

if(NOT DEFINED ASMJIT_EMBED)
  set(ASMJIT_EMBED TRUE)
endif()

# =============================================================================
# [AsmTK - Configuration]
# =============================================================================

set(ASMTK_DIR        "${CMAKE_CURRENT_LIST_DIR}" CACHE PATH "Location of 'asmtk'")
set(ASMJIT_DIR       "${ASMTK_DIR}/../asmjit"    CACHE PATH "Location of 'asmjit'")

set(ASMTK_EMBED      FALSE          CACHE BOOLEAN "Embed 'asmtk' library (no targets)")
set(ASMTK_STATIC     ${ASMTK_EMBED} CACHE BOOLEAN "Build 'asmtk' library as static")
set(ASMTK_BUILD_TEST FALSE          CACHE BOOLEAN "Build 'asmtk_test' applications")

# =============================================================================
# [AsmTK - Project]
# =============================================================================

include("${ASMTK_DIR}/CxxProject.cmake")
cxx_project(asmtk)
cxx_detect_standard(ASMTK_PRIVATE_CFLAGS)

include("${ASMJIT_DIR}/CMakeLists.txt")
list(APPEND ASMTK_DEPS ${ASMJIT_LIBS})
list(APPEND ASMTK_PRIVATE_CFLAGS ${ASMJIT_CFLAGS})

list(REMOVE_DUPLICATES ASMTK_DEPS)
list(REMOVE_DUPLICATES ASMTK_PRIVATE_CFLAGS)

cxx_project_info(asmtk)

# =============================================================================
# [AsmTK - Source]
# =============================================================================

set(ASMTK_SRC "")

cxx_add_source(asmtk ASMTK_SRC asmtk
  asmtk.h
  asmparser.cpp
  asmparser.h
  asmtokenizer.cpp
  asmtokenizer.h
  elfdefs.h
  globals.h
  strtod.h
)

if(ASMJIT_EMBED)
  list(APPEND ASMTK_SRC ${ASMJIT_SRC})
endif()

# =============================================================================
# [AsmTK - Targets]
# =============================================================================

if(NOT ASMTK_EMBED)
  # Add `asmtk` library.
  cxx_add_library(asmtk asmtk 
    "${ASMTK_SRC}"
    "${ASMTK_DEPS}"
    "${ASMTK_PRIVATE_CFLAGS}"
    "${ASMTK_PRIVATE_CFLAGS_DBG}"
    "${ASMTK_PRIVATE_CFLAGS_REL}")
  target_include_directories(asmtk BEFORE PRIVATE ${ASMJIT_INCLUDE_DIR})
  set_target_properties(asmtk PROPERTIES LINK_FLAGS "${ASMJIT_PRIVATE_LFLAGS}")

  foreach(_src_file ${ASMTK_SRC})
    get_filename_component(_src_dir ${_src_file} PATH)
    get_filename_component(_src_name ${_src_file} NAME)
    string(REGEX REPLACE "^${ASMTK_SOURCE_DIR}/" "" targetpath "${_src_dir}")
    if("${_src_name}" MATCHES ".h$")
      if(NOT "${_src_name}" MATCHES "_p.h$")
        install(FILES ${_src_file} DESTINATION "include/${targetpath}")
      endif()
    endif()
  endforeach()

  # Add `asmtk` tests and samples.
  if(ASMTK_BUILD_TEST)
    set(ASMTK_TEST_CFLAGS
      ${ASMJIT_CFLAGS}
      ${CXX_DEFINE}ASMJIT_BUILD_X86
      ${CXX_DEFINE}ASMJIT_EMBED
      ${CXX_DEFINE}ASMTK_EMBED
      ${CXX_DEFINE}ASMTK_TEST)

    set(ASMTK_SAMPLES_SRC
      asmtk_test_cmd
      asmtk_test_handler
      asmtk_test_x86)

    set(TARGET_LIBS asmtk)

    if(NOT ASMJIT_EMBED)
      list(APPEND TARGET_LIBS asmjit)
    endif()

    foreach(_target ${ASMTK_SAMPLES_SRC})
      add_executable(${_target} "${ASMTK_DIR}/test/${_target}.cpp")
      target_link_libraries(${_target} ${TARGET_LIBS} ${ASMJIT_DEPS})
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
