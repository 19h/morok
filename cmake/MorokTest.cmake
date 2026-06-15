#==============================================================================
# MorokTest.cmake
#
# `morok_add_unit_test` builds one doctest executable and registers a CTest
# entry per test-module translation unit, using doctest's --source-file filter.
# This gives per-module granularity (`ctest -R core/galois8`), runs modules in
# parallel under `ctest -j`, and is robust to rich test-case names (commas,
# operators, unicode) that defeat binary-enumeration discovery.  An aggregate
# "<name>" entry runs the whole binary for a single-command full check.
#==============================================================================

# The single TU that defines doctest's implementation + main(), linked into each
# test executable (the test TUs themselves are header-only registrations, so we
# avoid the duplicate-main clash a per-source WITH_MAIN define would cause).
set(MOROK_DOCTEST_MAIN "${CMAKE_SOURCE_DIR}/tests/support/doctest_main.cpp"
    CACHE INTERNAL "")

# morok_add_unit_test(<name>
#     SOURCES   <src>...
#     [LINK     <lib>...]          # extra libraries beyond doctest
#     [NO_MAIN]                    # provide your own main()
#     [LABELS   <label>...])
function(morok_add_unit_test name)
  cmake_parse_arguments(T "NO_MAIN" "" "SOURCES;LINK;LABELS" ${ARGN})
  if(NOT T_SOURCES)
    message(FATAL_ERROR "morok_add_unit_test(${name}): SOURCES is required")
  endif()

  set(_sources ${T_SOURCES})
  if(NOT T_NO_MAIN)
    list(APPEND _sources "${MOROK_DOCTEST_MAIN}")
  endif()

  add_executable(${name} ${_sources})
  target_link_libraries(${name} PRIVATE doctest::doctest morok::warnings ${T_LINK})
  target_compile_features(${name} PRIVATE cxx_std_23)

  # Per-module CTest entries via doctest's source-file filter.
  foreach(src IN LISTS T_SOURCES)
    get_filename_component(_stem "${src}" NAME_WE)
    add_test(NAME "${name}/${_stem}"
      COMMAND ${name} "--source-file=*${_stem}.*" --no-intro=true)
    set_tests_properties("${name}/${_stem}" PROPERTIES LABELS "${T_LABELS}")
  endforeach()

  # Aggregate entry: the entire suite in one process.
  add_test(NAME "${name}" COMMAND ${name})
  set_tests_properties("${name}" PROPERTIES LABELS "${T_LABELS};aggregate")
endfunction()
