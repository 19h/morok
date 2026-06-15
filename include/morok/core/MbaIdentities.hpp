// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/core/MbaIdentities.hpp — Mixed Boolean-Arithmetic rewrite rules.
//
// Each function returns a value provably equal, in the ring Z/2^n, to the
// arithmetic/bitwise operation it stands in for.  The MBA pass selects a
// variant at random and emits the corresponding expression tree into the IR;
// keeping the algebra here means we can verify every identity exhaustively on
// 8-bit operands (all 65 536 pairs) and fuzz the wider widths, independently of
// any IR.
//
// Implementation note: all operands are widened to uint64_t, the expression is
// evaluated there, and the result is truncated back to T.  Truncation commutes
// with +, -, *, <<, ~, &, |, ^ (they are all compatible with the quotient map
// Z/2^64 -> Z/2^n), so the truncated 64-bit result equals the exact n-bit
// modular result — while avoiding the signed-overflow UB that narrow-integer
// promotion to `int` would cause for multiplications.

#ifndef MOROK_CORE_MBA_IDENTITIES_HPP
#define MOROK_CORE_MBA_IDENTITIES_HPP

#include <concepts>
#include <cstdint>

namespace morok::core::mba {

/// The number of distinct rewrite variants available per operator.
inline constexpr int kAddVariants = 8;
inline constexpr int kSubVariants = 7;
inline constexpr int kXorVariants = 7;
inline constexpr int kAndVariants = 8;
inline constexpr int kOrVariants = 7;
inline constexpr int kMulVariants = 5;
inline constexpr int kZeroTermKinds = 8;

namespace detail {
using U = std::uint64_t;
template <std::unsigned_integral T> constexpr T narrow(U v) noexcept {
    return static_cast<T>(v);
}
} // namespace detail

/// The carry lemma underpinning the random-constant ADD/SUB variants:
///     x + r == (x ^ r) + 2 * (x & r).
/// Returned value should equal `x + r` (mod 2^n) for every x, r.
template <std::unsigned_integral T> constexpr T carrySum(T x, T r) noexcept {
    const detail::U xu = x, ru = r;
    return detail::narrow<T>((xu ^ ru) + 2u * (xu & ru));
}

/// ADD: 8 variants (`r` is a random constant; only used by variants 3, 5).
template <std::unsigned_integral T>
constexpr T add(T a, T b, T r, int variant) noexcept {
    const detail::U au = a, bu = b, ru = r;
    switch (variant) {
    case 1:
        return detail::narrow<T>(2u * (au | bu) - (au ^ bu));
    case 2:
        return detail::narrow<T>((au | bu) + (au & bu));
    case 3:
        return detail::narrow<T>((au ^ ru) + (bu ^ ru) + 2u * (au & ru) +
                                 2u * (bu & ru) - 2u * ru);
    case 4:
        return detail::narrow<T>(~((~au) - bu));
    case 5:
        return detail::narrow<T>((au + ru) + (bu - ru));
    case 6:
        return detail::narrow<T>(0u - ((0u - au) + (0u - bu)));
    case 7:
        return detail::narrow<T>((au - 1u) + (bu + 1u));
    case 0:
    default:
        return detail::narrow<T>((au ^ bu) + ((au & bu) << 1));
    }
}

/// SUB: 7 variants (`r` used by variants 1, 6).
template <std::unsigned_integral T>
constexpr T sub(T a, T b, T r, int variant) noexcept {
    const detail::U au = a, bu = b, ru = r;
    switch (variant) {
    case 1:
        return detail::narrow<T>(((au ^ ru) - (bu ^ ru)) + 2u * (au & ru) -
                                 2u * (bu & ru));
    case 2:
        return detail::narrow<T>((au + ~bu) + 1u);
    case 3:
        return detail::narrow<T>(~((~au) + bu));
    case 4:
        return detail::narrow<T>(((au | ~bu) + (au & ~bu)) + 1u);
    case 5:
        return detail::narrow<T>(2u * (au & ~bu) - (bu ^ au));
    case 6:
        return detail::narrow<T>((au + ru) - (bu + ru));
    case 0:
    default:
        return detail::narrow<T>((au ^ bu) - 2u * ((~au) & bu));
    }
}

/// XOR: 7 variants (`r` used by variants 2, 5 — and cancels in both).
template <std::unsigned_integral T>
constexpr T xor_(T a, T b, T r, int variant) noexcept {
    const detail::U au = a, bu = b, ru = r;
    switch (variant) {
    case 1:
        return detail::narrow<T>((au + bu) - 2u * (au & bu));
    case 2:
        return detail::narrow<T>((au - bu) + 2u * ((~au) & bu));
    case 3:
        return detail::narrow<T>((au | bu) ^ (au & bu));
    case 4:
        return detail::narrow<T>((~au) ^ (~bu));
    case 5:
        return detail::narrow<T>((au ^ ru) ^ (bu ^ ru));
    case 6:
        return detail::narrow<T>(2u * (au | bu) - (au + bu));
    case 0:
    default:
        return detail::narrow<T>((au | bu) - (au & bu));
    }
}

/// AND: 8 variants (`r` used by variants 3, 4, 7 — structurally a no-op).
template <std::unsigned_integral T>
constexpr T and_(T a, T b, T r, int variant) noexcept {
    const detail::U au = a, bu = b, ru = r;
    switch (variant) {
    case 1:
        return detail::narrow<T>((au ^ bu) ^ (au | bu));
    case 2:
        return detail::narrow<T>((au | bu) ^ (au ^ bu));
    case 3:
        return detail::narrow<T>(((au & ru) & (bu & ru)) |
                                 ((au & ~ru) & (bu & ~ru)));
    case 4:
        return detail::narrow<T>((~((~au) | (~bu))) & (ru | ~ru));
    case 5:
        return detail::narrow<T>(((~au) ^ bu) & au);
    case 6:
        return detail::narrow<T>(~(~(au & bu) & ~(au & bu)));
    case 7:
        return detail::narrow<T>(~(((au ^ ru) ^ ~ru) | ((bu ^ ru) ^ ~ru)));
    case 0:
    default:
        return detail::narrow<T>(~((~au) | (~bu)));
    }
}

/// OR: 7 variants (`r` used by variant 5 — and cancels).
template <std::unsigned_integral T>
constexpr T or_(T a, T b, T r, int variant) noexcept {
    const detail::U au = a, bu = b, ru = r;
    switch (variant) {
    case 1:
        return detail::narrow<T>(~((~au) & (~bu)));
    case 2:
        return detail::narrow<T>((au ^ bu) + (au & bu));
    case 3:
        return detail::narrow<T>((au & ~bu) + bu);
    case 4:
        return detail::narrow<T>((bu & ~au) + au);
    case 5:
        return detail::narrow<T>(((au + bu + ru) - (au & bu)) - ru);
    case 6:
        return detail::narrow<T>(au + ((~au) & bu));
    case 0:
    default:
        return detail::narrow<T>((au + bu) - (au & bu));
    }
}

/// MUL: 5 variants.  Variant 2 is a Karatsuba half-split parameterised by the
/// operand bit-width; widths below 4 fall back to a plain product (as the pass
/// does).  `r` used by variant 1.
template <std::unsigned_integral T>
constexpr T mul(T a, T b, T r, int variant, unsigned width) noexcept {
    const detail::U au = a, bu = b, ru = r;
    switch (variant) {
    case 1:
        return detail::narrow<T>((au + ru) * (bu + ru) - (au + ru) * ru -
                                 bu * ru);
    case 2: {
        if (width < 4)
            return detail::narrow<T>(au * bu);
        const unsigned k = width / 2;
        const detail::U mask = (detail::U{1} << k) - 1u;
        const detail::U bh = bu >> k;
        const detail::U bl = bu & mask;
        return detail::narrow<T>(((au * bh) << k) + (au * bl));
    }
    case 3:
        return detail::narrow<T>((0u - (au * (~bu))) - au);
    case 4:
        return detail::narrow<T>(au * (bu + 1u) - au);
    case 0:
    default:
        return detail::narrow<T>((au | bu) * (au & bu) +
                                 (au & ~bu) * (bu & ~au));
    }
}

/// Zero-valued "noise" terms: each returns 0 (mod 2^n) for all inputs, letting
/// the pass fold opaque-but-vanishing subexpressions into a result.
template <std::unsigned_integral T>
constexpr T zeroTerm(T a, T b, T r, int kind) noexcept {
    const detail::U au = a, bu = b, ru = r;
    switch (kind & 7) {
    case 0:
        return detail::narrow<T>(au ^ au);
    case 1:
        return detail::narrow<T>(bu ^ bu);
    case 2:
        return detail::narrow<T>(au & ~au);
    case 3:
        return detail::narrow<T>(bu & ~bu);
    case 4:
        return detail::narrow<T>((au | ~au) + 1u);
    case 5:
        return detail::narrow<T>((au ^ bu) ^ (au ^ bu));
    case 6:
        return detail::narrow<T>((au + ru) - (au + ru));
    case 7:
    default:
        return detail::narrow<T>((au & bu) - (au & bu));
    }
}

} // namespace morok::core::mba

#endif // MOROK_CORE_MBA_IDENTITIES_HPP
