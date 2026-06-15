// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/core/Splitmix64.hpp — the splitmix64 mixing function.
//
// splitmix64 (Steele, Lea, Flood — "Fast Splittable Pseudorandom Number
// Generators", OOPSLA'14) is a fast 64-bit mixer with excellent avalanche.
// We use it for two distinct jobs:
//
//   1. As a stand-alone *mixer* (`mix`): a pure function that avalanches one
//      64-bit word into another.  Used to fold raw entropy sources into the
//      seed words of the main engine, and to derive four seed words from a
//      single user-supplied seed.
//
//   2. As a tiny *generator* (operator()): a stateful 64-bit stream, handy for
//      seeding a larger engine without correlation between its state words.
//
// Everything here is `constexpr` and free of side effects, so the unit tests
// can evaluate it at compile time and the optimiser can fold it away.

#ifndef MOROK_CORE_SPLITMIX64_HPP
#define MOROK_CORE_SPLITMIX64_HPP

#include <cstdint>

namespace morok::core {

/// A splitmix64 mixer / generator.
///
/// Models `std::uniform_random_bit_generator`, so it can drive the standard
/// distribution adaptors as well as Morok's own helpers.
class Splitmix64 {
public:
    using result_type = std::uint64_t;

    static constexpr result_type min() noexcept { return 0; }
    static constexpr result_type max() noexcept { return UINT64_MAX; }

    /// Construct a generator with the given 64-bit seed.
    constexpr explicit Splitmix64(std::uint64_t seed) noexcept : state_(seed) {}

    /// Advance the stream and return the next 64-bit output.
    constexpr result_type operator()() noexcept {
        state_ += kGamma;
        return finalize(state_);
    }

    /// Pure, stateless avalanche of a single 64-bit word.
    ///
    /// Equivalent to advancing a generator seeded with `x - kGamma` once, i.e.
    /// the value obtained by adding the gamma constant and finalising.  This is
    /// the exact transform used to fold entropy into seed words.
    static constexpr result_type mix(std::uint64_t x) noexcept {
        return finalize(x + kGamma);
    }

private:
    // Odd "golden gamma" increment — the fractional part of the golden ratio.
    static constexpr std::uint64_t kGamma = 0x9E3779B97F4A7C15ULL;

    static constexpr std::uint64_t finalize(std::uint64_t z) noexcept {
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }

    std::uint64_t state_;
};

} // namespace morok::core

#endif // MOROK_CORE_SPLITMIX64_HPP
