// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/core/Feistel.hpp — a balanced Feistel network over integer halves.
//
// The constant-encryption pass optionally runs each constant through a 4-round
// balanced Feistel permutation before the XOR-share layer, giving the
// reconstruction a non-linear component (the round function multiplies by an
// odd key, defeating purely affine/XOR recovery).  Four rounds clear the
// Luby–Rackoff pseudo-random-permutation threshold.
//
// The round function is  F_r(x) = ((x * mult_r) ^ xor_r) & halfmask,
// with `mult_r` forced odd so the network is invertible for every key.
// Encryption and decryption use identical keys; only the round order reverses.

#ifndef MOROK_CORE_FEISTEL_HPP
#define MOROK_CORE_FEISTEL_HPP

#include "morok/core/Random.hpp"

#include <array>
#include <cstdint>

namespace morok::core {

/// Per-round Feistel key material: an odd multiplier and an XOR constant.
struct FeistelRoundKey {
    std::uint64_t mult; ///< forced odd → invertible modulo 2^half
    std::uint64_t xork;
};

/// Keys for the fixed 4-round network.
struct FeistelKeys {
    static constexpr int kRounds = 4;
    std::array<FeistelRoundKey, kRounds> rounds{};
};

namespace detail {
constexpr std::uint64_t lowMask(unsigned bits) noexcept {
    return bits >= 64 ? ~std::uint64_t{0} : ((std::uint64_t{1} << bits) - 1u);
}
} // namespace detail

/// Generate Feistel keys for a value of `bits` width using `gen`.
/// `bits` must be even and >= 16; each key is masked to the half-width and the
/// multiplier's low bit is forced set.
template <BitGenerator G> FeistelKeys makeFeistelKeys(G &gen, unsigned bits) {
    const std::uint64_t mask = detail::lowMask(bits / 2);
    FeistelKeys keys;
    for (auto &rk : keys.rounds) {
        rk.mult = (gen() | 1u) & mask;
        rk.xork = gen() & mask;
    }
    return keys;
}

/// Encrypt `value` (interpreted as a `bits`-wide integer) with the network.
constexpr std::uint64_t feistelEncrypt(std::uint64_t value, unsigned bits,
                                       const FeistelKeys &keys) noexcept {
    const unsigned half = bits / 2;
    const std::uint64_t mask = detail::lowMask(half);
    std::uint64_t l = (value >> half) & mask;
    std::uint64_t r = value & mask;
    for (const auto &rk : keys.rounds) {
        const std::uint64_t f = ((r * rk.mult) ^ rk.xork) & mask;
        const std::uint64_t newR = (l ^ f) & mask;
        l = r;
        r = newR;
    }
    return ((l << half) | r) & detail::lowMask(bits);
}

/// Invert `feistelEncrypt`: recovers the original value for the same keys.
constexpr std::uint64_t feistelDecrypt(std::uint64_t value, unsigned bits,
                                       const FeistelKeys &keys) noexcept {
    const unsigned half = bits / 2;
    const std::uint64_t mask = detail::lowMask(half);
    std::uint64_t l = (value >> half) & mask;
    std::uint64_t r = value & mask;
    for (int i = FeistelKeys::kRounds - 1; i >= 0; --i) {
        const auto &rk = keys.rounds[static_cast<std::size_t>(i)];
        const std::uint64_t f = ((l * rk.mult) ^ rk.xork) & mask;
        const std::uint64_t newL = (r ^ f) & mask;
        r = l;
        l = newL;
    }
    return ((l << half) | r) & detail::lowMask(bits);
}

} // namespace morok::core

#endif // MOROK_CORE_FEISTEL_HPP
