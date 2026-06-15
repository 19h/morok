#==============================================================================
# morok_core unit tests.
#
# Every algorithm gets its own translation unit; doctest discovery then exposes
# each TEST_CASE as an individual CTest entry.  The whole suite links only the
# pure core, so it builds and runs in well under a second with no LLVM.
#==============================================================================

morok_add_unit_test(morok_core_tests
  SOURCES
    test_splitmix64.cpp
    test_xoshiro256.cpp
    test_random.cpp
    test_galois8.cpp
    test_mba_identities.cpp
    test_substitution_identities.cpp
    test_feistel.cpp
    test_xorshare.cpp
    test_logistic_map.cpp
    test_knuth_hash.cpp
    test_entropy.cpp
  LINK
    morok::core
  LABELS core unit)
