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

# LLVM-backed tests (IR construction) and end-to-end differential tests.
if(Morok_LLVM_FOUND)
  morok_add_test_group(ir)
  morok_add_test_group(e2e)
endif()
