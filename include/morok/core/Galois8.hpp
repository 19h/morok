// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
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

/// Addition in GF(2^8) is bitwise XOR.
constexpr std::uint8_t add(std::uint8_t a, std::uint8_t b) noexcept {
    return static_cast<std::uint8_t>(a ^ b);
}

/// Multiply by the field generator x (i.e. by 0x02), reducing mod 0x11B.
constexpr std::uint8_t xtime(std::uint8_t a) noexcept {
    const std::uint8_t shifted = static_cast<std::uint8_t>(a << 1);
    return (a & 0x80u) ? static_cast<std::uint8_t>(shifted ^ kReductionPoly)
                       : shifted;
}

/// Field multiplication via shift-and-add (Russian-peasant) over xtime.
constexpr std::uint8_t mul(std::uint8_t a, std::uint8_t b) noexcept {
    std::uint8_t result = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1u)
            result = static_cast<std::uint8_t>(result ^ a);
        a = xtime(a);
        b = static_cast<std::uint8_t>(b >> 1);
    }
    return result;
}

/// Multiplicative inverse in GF(2^8).  `inv(0)` is defined as 0 by convention
/// (the cipher never multiplies by a zero key).  Computed by exhaustive search,
/// which is constexpr-evaluable and trivially auditable.
constexpr std::uint8_t inv(std::uint8_t a) noexcept {
    if (a == 0)
        return 0;
    for (unsigned b = 1; b < 256; ++b)
        if (mul(a, static_cast<std::uint8_t>(b)) == 1)
            return static_cast<std::uint8_t>(b);
    return 0; // unreachable for non-zero a
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
