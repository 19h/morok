#==============================================================================
# Test tree.  Mirrors the source layering; each group is added only when present
# and when its prerequisites are available.
#==============================================================================

function(morok_add_test_group subdir)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${subdir}/CMakeLists.txt")
    add_subdirectory(${subdir})
  endif()
endfunction()

# Pure-layer unit tests (no LLVM).
morok_add_test_group(unit/core)
morok_add_test_group(unit/config)

# Configure-time regressions must run even when only pure layers are available.
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
  add_test(NAME "cmake/llvm_discovery"
    COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/cmake/llvm_discovery.py"
            "${CMAKE_COMMAND}" "${PROJECT_SOURCE_DIR}"
            "${CMAKE_C_COMPILER}" "${CMAKE_CXX_COMPILER}")
  set_tests_properties("cmake/llvm_discovery" PROPERTIES LABELS "cmake" TIMEOUT 120)
endif()

# LLVM-backed tests (IR construction) and end-to-end differential tests.
if(Morok_LLVM_FOUND)
  morok_add_test_group(ir)
  morok_add_test_group(e2e)
endif()
