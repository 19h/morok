#==============================================================================
# MorokWarnings.cmake
#
# Defines two INTERFACE targets that encode the project's compilation policy:
#
#   morok::warnings   strict diagnostics (opt-in -Werror via MOROK_WERROR)
#   morok::no_eh_rtti  -fno-exceptions -fno-rtti, required for any TU that
#                      includes LLVM headers (LLVM here is built without EH/RTTI;
#                      deriving/linking against it with EH/RTTI on is ODR-unsafe).
#
# Linking these onto a target keeps the policy in one place instead of being
# sprinkled across every CMakeLists.
#==============================================================================

add_library(morok_warnings INTERFACE)
add_library(morok::warnings ALIAS morok_warnings)

target_compile_options(morok_warnings INTERFACE
  $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang,AppleClang>:
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wconversion
    -Wsign-conversion
    -Wcast-qual
    -Wold-style-cast
    -Wnon-virtual-dtor
    -Woverloaded-virtual
    -Wdouble-promotion
    -Wformat=2
    -Wimplicit-fallthrough
  >)

if(MOROK_WERROR)
  target_compile_options(morok_warnings INTERFACE
    $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang,AppleClang>:-Werror>)
endif()

# Exception-free / RTTI-free policy for LLVM-facing code.
add_library(morok_no_eh_rtti INTERFACE)
add_library(morok::no_eh_rtti ALIAS morok_no_eh_rtti)
target_compile_options(morok_no_eh_rtti INTERFACE
  $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang,AppleClang>:-fno-exceptions;-fno-rtti>)

# Optional sanitizers for the pure layers and their tests.  We deliberately do
# NOT sanitize the LLVM-facing libraries: they would need an ASan-instrumented
# LLVM to be meaningful and link-clean.
add_library(morok_sanitizers INTERFACE)
add_library(morok::sanitizers ALIAS morok_sanitizers)
if(MOROK_SANITIZE)
  target_compile_options(morok_sanitizers INTERFACE
    -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(morok_sanitizers INTERFACE
    -fsanitize=address,undefined)
endif()
