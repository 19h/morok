// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/core/XorShare.hpp — additive (XOR) secret sharing of a constant.
//
// The constant-encryption pass replaces a literal V with k global "shares"
// whose XOR reconstructs V at runtime.  k-1 shares are uniformly random; the
// last is V XOR (all the random shares), so the value never appears in the
// binary and recovery requires every share.  This is an information-theoretic
// split: any k-1 shares are independent of V.

#ifndef MOROK_CORE_XOR_SHARE_HPP
#define MOROK_CORE_XOR_SHARE_HPP

#include "morok/core/Random.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace morok::core {

/// Minimum and maximum supported share counts (matching the pass clamp).
inline constexpr std::size_t kMinShares = 2;
inline constexpr std::size_t kMaxShares = 8;

/// Split `value` (a `bits`-wide integer) into `count` XOR shares using `gen`.
///
/// `count` is clamped to [kMinShares, kMaxShares].  The first `count-1` shares
/// are random (masked to `bits`); the last is the value XOR-folded with them so
/// that `reconstruct(split(v)) == v` exactly.
template <BitGenerator G>
std::vector<std::uint64_t>
splitXorShares(std::uint64_t value, std::size_t count, unsigned bits, G &gen) {
    if (count < kMinShares)
        count = kMinShares;
    if (count > kMaxShares)
        count = kMaxShares;
    const std::uint64_t mask =
        bits >= 64 ? ~std::uint64_t{0} : ((std::uint64_t{1} << bits) - 1u);

    std::vector<std::uint64_t> shares(count);
    std::uint64_t acc = value & mask;
    for (std::size_t i = 0; i + 1 < count; ++i) {
        const std::uint64_t r = gen() & mask;
        shares[i] = r;
        acc ^= r;
    }
    shares[count - 1] = acc & mask;
    return shares;
}

/// Reconstruct the original value by XOR-folding all shares.
constexpr std::uint64_t
reconstructXorShares(const std::vector<std::uint64_t> &shares) noexcept {
    std::uint64_t acc = 0;
    for (std::uint64_t s : shares)
        acc ^= s;
    return acc;
}

} // namespace morok::core

#endif // MOROK_CORE_XOR_SHARE_HPP
