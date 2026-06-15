// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/config/Resolver.hpp — merging and per-function policy resolution.
//
// The effective configuration for a function is computed by layering:
//     preset  <  file [passes.*]  <  matching [[policy]] rules (in order)
// Each layer's set fields override the previous.  Name demangling (for matching
// human-readable policy regexes against mangled symbols) is injected as a
// callback so this layer needs no LLVM and stays unit-testable.

#ifndef MOROK_CONFIG_RESOLVER_HPP
#define MOROK_CONFIG_RESOLVER_HPP

#include "morok/config/PassConfig.hpp"
#include "morok/config/Preset.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace morok::config {

/// A per-module/function override rule.
struct Policy {
    std::string module_regex; ///< ECMAScript regex on the module source path
    std::string
        func_regex; ///< regex on the function name (empty = module-wide)
    Preset preset =
        Preset::None;     ///< optional preset base for matched functions
    PassConfig overrides; ///< specific field overrides (highest within rule)
};

/// Top-level configuration: globals, base pass config, and ordered policies.
struct Config {
    Preset preset = Preset::None;
    std::uint64_t seed = 0;
    bool verbose = false;
    bool trace = false;
    bool demangle_names = true;
    PassConfig passes;
    std::vector<Policy> policies;
};

/// A name demangler: maps a possibly-mangled symbol to a human-readable form.
/// Return the input unchanged if nothing was demangled.
using Demangler = std::function<std::string(std::string_view)>;

/// Copy every *set* field of `src` over `dst` (src wins).  Non-empty string
/// vectors in `src` replace those in `dst`.
void merge(PassConfig &dst, const PassConfig &src);

/// Resolve the effective pass configuration for one module/function pair.
///
/// Starts from `cfg.passes`, then applies each matching policy in order.  A
/// policy matches when its module regex matches `module_name` and (if present)
/// its function regex matches the raw function name or, when `demangle` is
/// provided and `cfg.demangle_names` is true, the demangled name.  Invalid
/// regexes are skipped (never throw out of this call).
PassConfig resolve(const Config &cfg, std::string_view module_name,
                   std::string_view func_name, const Demangler &demangle = {});

} // namespace morok::config

#endif // MOROK_CONFIG_RESOLVER_HPP
