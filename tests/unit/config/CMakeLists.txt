#==============================================================================
# morok_config unit tests (pure; no LLVM).
#==============================================================================

morok_add_unit_test(morok_config_tests
  SOURCES
    test_preset.cpp
    test_merge.cpp
    test_resolve.cpp
    test_toml_loader.cpp
  LINK
    morok::config
  LABELS config unit)
