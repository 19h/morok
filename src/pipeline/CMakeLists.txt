#==============================================================================
# morok_plugin (libMorok) — the loadable New-PM pass plugin.
#
# On Unix the plugin is a MODULE that does NOT link LLVM: the host process
# (opt / clang) provides the LLVM symbols at dlopen time, so we allow undefined
# symbols (Mach-O resolves them by default; Linux clang/opt are built with
# --export-dynamic). Uses plugin API v2/v3 via <llvm/Plugins/PassPlugin.h>.
#
# On Windows there is no load-time undefined-symbol resolution (PE/COFF has no
# -Wl,-undefined,dynamic_lookup / --allow-shlib-undefined), and the single
# shared LLVM.dll model is unsupported on MSVC LLVM (the 65535 PE export limit;
# LLVM_BUILD_LLVM_DYLIB is "not available on Windows").  So there the plugin
# instead STATICALLY links the LLVM component libs it uses straight into the
# MODULE and exports exactly one symbol (llvmGetPassPluginInfo, via
# __declspec(dllexport) in Plugin.cpp).  Because it imports no LLVM from the
# host, (a) the export limit never bites and (b) the one DLL loads into BOTH
# opt.exe and clang.exe (no host module name is baked into a PE import lib).
# Morok is transform-only — every entry point runs on the host's PassBuilder /
# Module / Function; its own LLVM copy is only *called* on host IR, never
# constructs a context, parses cl::opts at the host command line, or calls
# llvm_shutdown — so the second static LLVM copy is dormant state, not a
# duplicate-init hazard.  The IR ABI is identical because plugin and host come
# from the same LLVM install (same commit, ABI checks FORCE_OFF, -fno-rtti):
# this is the very invariant the tests/ir suite already relies on, since it
# links these same LLVM static libs into clang++-built test code on Windows and
# round-trips host IR through dyn_cast<> correctly.
#==============================================================================

if(WIN32)
  add_library(morok_plugin MODULE
    Scheduler.cpp
    Plugin.cpp)

  set_target_properties(morok_plugin PROPERTIES
    OUTPUT_NAME Morok
    PREFIX "lib"
    SUFFIX ".dll")

  target_compile_features(morok_plugin PRIVATE cxx_std_23)
  target_link_libraries(morok_plugin
    PRIVATE morok::passes morok::config morok::warnings morok::no_eh_rtti)

  # Static-link the LLVM components every llvm:: symbol Morok references
  # resolves to.  Superset of the tests/ir working set (core/support/irreader/
  # asmparser/transformutils) plus analysis (verifyModule), passes (PassBuilder
  # / PassPluginLibraryInfo), bitwriter (WriteBitcode) and demangle
  # (llvm::demangle in Plugin.cpp).  Unknown component names are dropped and
  # transitive deps are pulled in, so over-listing is safe.
  morok_llvm_map_components(_morok_win_llvm_libs
    core support irreader asmparser bitwriter
    analysis transformutils passes demangle)
  target_link_libraries(morok_plugin PRIVATE ${_morok_win_llvm_libs})

  # Force-export the plugin entry point.  <llvm/Plugins/PassPlugin.h> forward-
  # declares llvmGetPassPluginInfo WITHOUT dllexport, so clang ignores the
  # dllexport on our definition (-Wdll-attribute-on-redeclaration) and the DLL
  # would export nothing — opt's GetProcAddress("llvmGetPassPluginInfo") would
  # then fail to load the plugin.  /EXPORT names it explicitly (extern "C", so
  # undecorated on x64).
  #
  # Anchor objects (cl::Option::anchor, CallbackVH::anchor,
  # GenericOptionValue::anchor) are vtable-only — only the vtable references
  # them, so the linker can dead-strip the defining object and leave the vtable
  # slot unresolved (LLVM D76642 → LNK2019).  Force the libs that host the
  # anchors in whole.  /WHOLEARCHIVE needs the full .lib PATH — lld-link tries
  # to *open* a bare name as a file ("could not open 'LLVMCore'"), so resolve
  # the imported LLVM targets to their archive paths.  LINKER: routes each flag
  # through the clang driver to lld-link verbatim.  If a first CI link reports
  # unresolved anchors in another component, widen this set from the LNK2019
  # list.
  target_link_options(morok_plugin PRIVATE
    "LINKER:/EXPORT:llvmGetPassPluginInfo"
    "LINKER:/WHOLEARCHIVE:$<TARGET_LINKER_FILE:LLVMCore>"
    "LINKER:/WHOLEARCHIVE:$<TARGET_LINKER_FILE:LLVMSupport>")

  return()
endif()

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
