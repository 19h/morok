#==============================================================================
# Host-side Linux ELF native pack preparation/finalization tool.
#==============================================================================

add_library(morok_packer STATIC NativePack.cpp)
add_library(morok::packer ALIAS morok_packer)
target_compile_features(morok_packer PUBLIC cxx_std_23)
target_include_directories(morok_packer PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(morok_packer PUBLIC morok::core
  PRIVATE morok::warnings morok::sanitizers)

add_executable(morok-native-pack Main.cpp)
target_compile_features(morok-native-pack PRIVATE cxx_std_23)
target_link_libraries(morok-native-pack PRIVATE morok::packer morok::warnings)
