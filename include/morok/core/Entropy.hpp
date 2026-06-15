// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/core/Entropy.hpp — seeding the PRNG from multiple entropy sources.
//
// The obfuscator must not be predictable from the build time alone, so the
// engine is seeded from several independent sources (high-resolution clock,
// ASLR'd stack and heap pointers, a cycle counter, the process id, and — where
// available — a hardware timer).  The *collection* of those sources is
// inherently impure and lives in Entropy.cpp; the *mixing* of collected sources
// into engine seed words is a pure function kept here so it can be tested
// deterministically.

#ifndef MOROK_CORE_ENTROPY_HPP
#define MOROK_CORE_ENTROPY_HPP

#include "morok/core/Xoshiro256.hpp"

#include <array>
#include <cstdint>

namespace morok::core {

/// A snapshot of collected entropy.  Each field is one (already-diffused)
/// 64-bit source; absent sources are simply zero and contribute nothing.
struct EntropySources {
    std::uint64_t wallClockNs = 0;  ///< nanosecond wall clock
    std::uint64_t stackHash = 0;    ///< hashed stack-pointer address (ASLR)
    std::uint64_t heapHash = 0;     ///< hashed heap-pointer address (ASLR)
    std::uint64_t cycleCounter = 0; ///< CPU cycle counter, if available
    std::uint64_t pid = 0;          ///< hashed process id
    std::uint64_t hwA = 0;          ///< hardware timer / RNG source A
    std::uint64_t hwB = 0;          ///< hardware source B
    std::uint64_t hwC = 0;          ///< hardware source C

    /// Combine the sources into four engine seed words.  Each word XORs a
    /// distinct subset so that it depends on several entropy dimensions; an
    /// attacker must enumerate all sources simultaneously to predict the
    /// stream.
    constexpr std::array<std::uint64_t, 4> seedWords() const noexcept {
        return {
            wallClockNs ^ stackHash ^ hwA,
            heapHash ^ cycleCounter ^ hwB,
            wallClockNs ^ pid ^ cycleCounter ^ hwC,
            stackHash ^ heapHash ^ pid ^ hwA ^ hwC,
        };
    }
};

/// Build an engine from a fixed set of sources (deterministic given the input).
constexpr Xoshiro256pp makeEngine(const EntropySources &src) noexcept {
    const auto w = src.seedWords();
    return Xoshiro256pp::fromWords(w[0], w[1], w[2], w[3]);
}

/// Collect live entropy from the host environment (impure).
EntropySources collectEntropy() noexcept;

/// Convenience: collect entropy and build a freshly seeded engine.
Xoshiro256pp makeSeededEngine() noexcept;

} // namespace morok::core

#endif // MOROK_CORE_ENTROPY_HPP
