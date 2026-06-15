// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/core/Xoshiro256.hpp — the xoshiro256++ pseudo-random engine.
//
// xoshiro256++ (Blackman & Vigna, 2018) is the obfuscator's core PRNG.
// Properties relevant here:
//
//   • Period 2^256 - 1; passes BigCrush and PractRand beyond 32 TiB.
//   • 256-bit state cannot be reconstructed from a finite output window
//     without solving a non-linear system — unlike the mt19937_64 it replaces,
//     whose full state is recoverable from 624 consecutive outputs.
//
// The engine is deliberately decoupled from *seeding policy*: it only knows how
// to step its state and how to be constructed from four state words.  Seeding
// from a single user seed or from collected entropy lives in `Entropy.hpp`,
// and bounded sampling lives in `Random.hpp`.  This keeps each concern
// independently testable.

#ifndef MOROK_CORE_XOSHIRO256_HPP
#define MOROK_CORE_XOSHIRO256_HPP

#include "morok/core/Splitmix64.hpp"

#include <array>
#include <cstdint>

namespace morok::core {

/// xoshiro256++ generator.  Models `std::uniform_random_bit_generator`.
class Xoshiro256pp {
public:
    using result_type = std::uint64_t;
    using state_type = std::array<std::uint64_t, 4>;

    static constexpr result_type min() noexcept { return 0; }
    static constexpr result_type max() noexcept { return UINT64_MAX; }

    /// Construct directly from four state words.
    ///
    /// xoshiro's state must not be all-zero (that is a fixed point producing an
    /// all-zero stream); an all-zero argument is replaced by a fixed non-zero
    /// sentinel, matching the reference seeding guard.
    constexpr explicit Xoshiro256pp(state_type state) noexcept : s_(state) {
        if ((s_[0] | s_[1] | s_[2] | s_[3]) == 0)
            s_[0] = kZeroStateSentinel;
    }

    /// Build an engine by avalanching four independent entropy words through
    /// splitmix64.  Each output word then depends on all 64 bits of its source.
    static constexpr Xoshiro256pp fromWords(std::uint64_t w0, std::uint64_t w1,
                                            std::uint64_t w2,
                                            std::uint64_t w3) noexcept {
        return Xoshiro256pp(state_type{Splitmix64::mix(w0), Splitmix64::mix(w1),
                                       Splitmix64::mix(w2),
                                       Splitmix64::mix(w3)});
    }

    /// Expand a single 64-bit seed into a full engine.  The four seed words are
    /// derived from the seed with fixed decorrelating offsets before mixing, so
    /// distinct seeds yield well-separated states.
    static constexpr Xoshiro256pp fromSeed(std::uint64_t seed) noexcept {
        return fromWords(seed, seed ^ 0xDEADBEEFDEADBEEFULL,
                         seed + 0x9E3779B97F4A7C15ULL, ~seed);
    }

    /// The current internal state (exposed for testing and serialisation).
    constexpr const state_type &state() const noexcept { return s_; }

    /// Step the state and return the next 64-bit output.
    constexpr result_type operator()() noexcept {
        const std::uint64_t result = rotl(s_[0] + s_[3], 23) + s_[0];
        const std::uint64_t t = s_[1] << 17;
        s_[2] ^= s_[0];
        s_[3] ^= s_[1];
        s_[1] ^= s_[2];
        s_[0] ^= s_[3];
        s_[2] ^= t;
        s_[3] = rotl(s_[3], 45);
        return result;
    }

private:
    static constexpr std::uint64_t kZeroStateSentinel = 0xDEADC0DEFEEDBEEFULL;

    static constexpr std::uint64_t rotl(std::uint64_t x, int k) noexcept {
        return (x << k) | (x >> (64 - k));
    }

    state_type s_;
};

} // namespace morok::core

#endif // MOROK_CORE_XOSHIRO256_HPP
