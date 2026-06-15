// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/core/KnuthHash.hpp — invertible multiplicative encoding of branch
// targets.
//
// The indirect-branch pass hides jump-table entries behind a reversible
// multiplicative transform over the ring Z/2^64:
//
//      encode(raw) = ((raw + delta) * mult) ^ xork
//      decode(enc) = ((enc ^ xork) * mult^{-1}) - delta
//
// `mult` is forced odd, which (Knuth's observation) makes it a unit modulo any
// power of two, so the inverse always exists.  The inverse is obtained by
// Newton–Hensel iteration, which doubles the number of correct low bits each
// step.

#ifndef MOROK_CORE_KNUTH_HASH_HPP
#define MOROK_CORE_KNUTH_HASH_HPP

#include <cstdint>

namespace morok::core {

/// Key material for the multiplicative branch-target transform.
struct KnuthKey {
    std::uint64_t delta = 0; ///< additive offset
    std::uint64_t mult = 1;  ///< multiplier (must be odd; see `make`)
    std::uint64_t xork = 0;  ///< final XOR mask

    /// Build a key from three random words, forcing the multiplier odd.
    static constexpr KnuthKey make(std::uint64_t delta, std::uint64_t mult,
                                   std::uint64_t xork) noexcept {
        return KnuthKey{delta, mult | 1u, xork};
    }
};

/// Multiplicative inverse of an odd 64-bit `a` modulo 2^64.
///
/// Newton–Hensel: x <- x * (2 - a*x).  Seeding with `a` (correct modulo 8 for
/// odd `a`) and iterating five times reaches full 64-bit precision.
constexpr std::uint64_t modInverse64(std::uint64_t a) noexcept {
    std::uint64_t x = a; // odd ⇒ a*a ≡ 1 (mod 8): correct to 3 bits
    for (int i = 0; i < 5; ++i)
        x *= 2u - a * x; // 3 → 6 → 12 → 24 → 48 → 96 ≥ 64 correct bits
    return x;
}

/// Encode a raw branch-target value with `key` (all arithmetic mod 2^64).
constexpr std::uint64_t knuthEncode(std::uint64_t raw,
                                    const KnuthKey &key) noexcept {
    return ((raw + key.delta) * key.mult) ^ key.xork;
}

/// Decode a value produced by `knuthEncode`, given the precomputed inverse.
constexpr std::uint64_t knuthDecode(std::uint64_t enc, const KnuthKey &key,
                                    std::uint64_t multInv) noexcept {
    return ((enc ^ key.xork) * multInv) - key.delta;
}

/// Decode, computing the inverse on demand.
constexpr std::uint64_t knuthDecode(std::uint64_t enc,
                                    const KnuthKey &key) noexcept {
    return knuthDecode(enc, key, modInverse64(key.mult));
}

} // namespace morok::core

#endif // MOROK_CORE_KNUTH_HASH_HPP
