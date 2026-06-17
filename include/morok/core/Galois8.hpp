// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/core/Galois8.hpp — arithmetic in GF(2^8) and the Vernam-GF8 byte
// cipher.
//
// The string-encryption pass protects every byte of a literal with an
// independent one-time pad *and* a multiplication in the Rijndael field
// GF(2^8).  Splitting the cipher math out here lets us prove the round-trip
// exhaustively (all 256 plaintexts × all 255 non-zero multipliers) without any
// LLVM machinery, and lets the pass emit exactly this arithmetic into the IR
// decryptor.
//
// Field: GF(2)[x]/(x^8 + x^4 + x^3 + x + 1) — the AES reduction polynomial,
// 0x11B, whose in-byte feedback term is 0x1B.

#ifndef MOROK_CORE_GALOIS8_HPP
#define MOROK_CORE_GALOIS8_HPP

#include <cstdint>

namespace morok::core::gf8 {

/// In-byte feedback term of the AES reduction polynomial x^8+x^4+x^3+x+1.
inline constexpr std::uint8_t kReductionPoly = 0x1B;

namespace detail {

constexpr std::uint8_t maskFromBit(std::uint8_t bit) noexcept {
    return static_cast<std::uint8_t>(0u - static_cast<unsigned>(bit & 1u));
}

constexpr std::uint8_t eqMask(std::uint8_t a, std::uint8_t b) noexcept {
    std::uint8_t x = static_cast<std::uint8_t>(a ^ b);
    x = static_cast<std::uint8_t>(x | (x >> 4));
    x = static_cast<std::uint8_t>(x | (x >> 2));
    x = static_cast<std::uint8_t>(x | (x >> 1));
    return maskFromBit(static_cast<std::uint8_t>((x ^ 1u) & 1u));
}

} // namespace detail

/// Addition in GF(2^8) is bitwise XOR.
constexpr std::uint8_t add(std::uint8_t a, std::uint8_t b) noexcept {
    return static_cast<std::uint8_t>(a ^ b);
}

/// Multiply by the field generator x (i.e. by 0x02), reducing mod 0x11B.
constexpr std::uint8_t xtime(std::uint8_t a) noexcept {
    const std::uint8_t shifted = static_cast<std::uint8_t>(a << 1);
    const std::uint8_t reduce = static_cast<std::uint8_t>(
        kReductionPoly &
        detail::maskFromBit(static_cast<std::uint8_t>(a >> 7)));
    return static_cast<std::uint8_t>(shifted ^ reduce);
}

/// Field multiplication via fixed-round shift-and-add over xtime.  The
/// multiplier bits select masked terms instead of branches, so runtime users do
/// not leak key/share bits through branch timing.
constexpr std::uint8_t mul(std::uint8_t a, std::uint8_t b) noexcept {
    std::uint8_t result = 0;
    for (int i = 0; i < 8; ++i) {
        result =
            static_cast<std::uint8_t>(result ^ (a & detail::maskFromBit(b)));
        a = xtime(a);
        b = static_cast<std::uint8_t>(b >> 1);
    }
    return result;
}

/// Multiplicative inverse in GF(2^8).  `inv(0)` is defined as 0 by convention
/// (the cipher never multiplies by a zero key).  Computed by a fixed exhaustive
/// scan with masked selection rather than early exit.
constexpr std::uint8_t inv(std::uint8_t a) noexcept {
    std::uint8_t result = 0;
    for (unsigned b = 1; b < 256; ++b)
        result = static_cast<std::uint8_t>(
            result | (static_cast<std::uint8_t>(b) &
                      detail::eqMask(mul(a, static_cast<std::uint8_t>(b)), 1)));
    return result;
}

// ── Vernam-GF8 per-byte cipher ───────────────────────────────────────────────
//
// encrypt: c = (p ⊕ k1) · k2            (XOR pad, then field multiply)
// decrypt: p = (c · k2⁻¹) ⊕ k1          (multiply by inverse, then XOR pad)
//
// k2 must be a non-zero field element; the runtime decryptor stores k2⁻¹ so it
// never has to invert anything.

/// Encrypt one byte with pad `k1` and non-zero multiplier `k2`.
constexpr std::uint8_t encryptByte(std::uint8_t p, std::uint8_t k1,
                                   std::uint8_t k2) noexcept {
    return mul(static_cast<std::uint8_t>(p ^ k1), k2);
}

/// Decrypt one byte with pad `k1` and the precomputed inverse `k2inv =
/// inv(k2)`.
constexpr std::uint8_t decryptByte(std::uint8_t c, std::uint8_t k1,
                                   std::uint8_t k2inv) noexcept {
    return static_cast<std::uint8_t>(mul(c, k2inv) ^ k1);
}

} // namespace morok::core::gf8

#endif // MOROK_CORE_GALOIS8_HPP
