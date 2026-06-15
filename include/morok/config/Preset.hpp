// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/config/Preset.hpp — named intensity presets.

#ifndef MOROK_CONFIG_PRESET_HPP
#define MOROK_CONFIG_PRESET_HPP

#include "morok/config/PassConfig.hpp"

#include <string_view>

namespace morok::config {

/// Intensity presets.  `None` leaves everything unset (pure cl::opt defaults).
enum class Preset { None, Low, Mid, High };

/// Parse a preset name; unknown / empty strings map to `None`.
Preset parsePreset(std::string_view name) noexcept;

/// Canonical lowercase name for a preset.
std::string_view presetName(Preset p) noexcept;

/// The fully-specified pass configuration for a preset (every field set, except
/// for `None` which returns an all-unset config).
PassConfig presetConfig(Preset p);

} // namespace morok::config

#endif // MOROK_CONFIG_PRESET_HPP
