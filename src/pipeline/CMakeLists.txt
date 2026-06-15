#==============================================================================
# morok_plugin (libMorok) — the loadable New-PM pass plugin.
#
# Built as a MODULE that does NOT link LLVM: the host process (opt / clang)
# provides the LLVM symbols at dlopen time, so we allow undefined symbols.  This
# keeps the plugin tiny and fast to link.  Targets plugin API v2 via
# <llvm/Plugins/PassPlugin.h> (validated in MorokLLVM.cmake).
#==============================================================================

add_library(morok_plugin MODULE
  Scheduler.cpp
  Plugin.cpp)

set_target_properties(morok_plugin PROPERTIES
  OUTPUT_NAME Morok
  PREFIX "lib")

target_compile_features(morok_plugin PRIVATE cxx_std_23)
target_link_libraries(morok_plugin
  PRIVATE morok::passes morok::config morok::warnings morok::no_eh_rtti)

# Resolve LLVM symbols from the loading process rather than linking LLVM.
if(APPLE)
  set_target_properties(morok_plugin PROPERTIES SUFFIX ".dylib")
  target_link_options(morok_plugin PRIVATE -Wl,-undefined,dynamic_lookup)
elseif(UNIX)
  target_link_options(morok_plugin PRIVATE -Wl,--allow-shlib-undefined)
endif()
