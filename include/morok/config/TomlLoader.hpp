// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/config/TomlLoader.hpp — parse a Morok configuration from TOML.
//
// Parsing never throws to the caller: malformed input yields `ok == false` with
// a human-readable `error`, and a defaulted Config.  The schema mirrors the
// documented `[global]`, `[passes.*]`, and `[[policy]]` layout.

#ifndef MOROK_CONFIG_TOML_LOADER_HPP
#define MOROK_CONFIG_TOML_LOADER_HPP

#include "morok/config/Resolver.hpp"

#include <string>
#include <string_view>

namespace morok::config {

/// Outcome of a load attempt.
struct LoadResult {
    Config config;     ///< parsed config, or defaults on error
    bool ok = false;   ///< true when parsing succeeded
    std::string error; ///< diagnostic when !ok
};

/// Parse configuration from an in-memory TOML document.
LoadResult loadFromString(std::string_view toml_text);

/// Parse configuration from a TOML file on disk.
LoadResult loadFromFile(std::string_view path);

} // namespace morok::config

#endif // MOROK_CONFIG_TOML_LOADER_HPP
