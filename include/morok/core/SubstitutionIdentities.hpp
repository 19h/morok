// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/core/SubstitutionIdentities.hpp — the instruction-substitution catalog.
//
// For each integer opcode the substitution pass can pick from several
// expressions that are equal to `a OP b` in the ring Z/2^n.  Every expression
// here is a pure function so the catalog can be verified exhaustively on 8-bit
// operands and fuzzed at wider widths, independently of any IR emission.
//
// Conventions (identical to MbaIdentities.hpp): operands are widened to
// uint64_t, evaluated, then truncated to the operand width; this is exact for
// +,-,*,<<,~,&,|,^ and avoids narrow-integer promotion UB.  Shifts carry an
// explicit width because logical/arithmetic right shifts are width-dependent.
// `r`, `r1`, `r2` are random constants that provably cancel.

#ifndef MOROK_CORE_SUBSTITUTION_IDENTITIES_HPP
#define MOROK_CORE_SUBSTITUTION_IDENTITIES_HPP

#include <concepts>
#include <cstdint>

namespace morok::core::subst {

inline constexpr int kAddVariants = 13;
inline constexpr int kSubVariants = 10;
inline constexpr int kAndVariants = 10;
inline constexpr int kOrVariants = 10;
inline constexpr int kXorVariants = 12;
inline constexpr int kMulVariants = 7;
inline constexpr int kShlVariants = 2;
inline constexpr int kLShrVariants = 2;
inline constexpr int kAShrVariants = 2;

namespace detail {
using U = std::uint64_t;

template <std::unsigned_integral T> constexpr T narrow(U v) noexcept {
    return static_cast<T>(v);
}

constexpr U widthMask(unsigned w) noexcept {
    return w >= 64 ? ~U{0} : ((U{1} << w) - 1u);
}

/// Logical right shift of the low `w` bits of `a` by `k`.
constexpr U lshrN(U a, unsigned k, unsigned w) noexcept {
    return (a & widthMask(w)) >> k;
}

/// Arithmetic (sign-propagating) right shift of a `w`-bit value by `k`.
constexpr U ashrN(U a, unsigned k, unsigned w) noexcept {
    const U m = widthMask(w);
    const unsigned pad = 64u - w;
    const std::int64_t s = static_cast<std::int64_t>((a & m) << pad) >> pad;
    return static_cast<U>(s >> k) & m;
}
} // namespace detail

// ── ADD (13) ─────────────────────────────────────────────────────────────────
template <std::unsigned_integral T>
constexpr T add(T a, T b, T r1, T r2, int variant) noexcept {
    const detail::U au = a, bu = b, r = r1, s = r2;
    switch (variant) {
    case 0:
        return detail::narrow<T>(au - (0u - bu));
    case 1:
        return detail::narrow<T>(0u - ((0u - au) + (0u - bu)));
    case 2:
        return detail::narrow<T>(((au + r) + bu) - r);
    case 3:
        return detail::narrow<T>(((au - r) + bu) + r);
    case 4:
        return detail::narrow<T>(au - (~bu + 1u));
    case 5:
        return detail::narrow<T>((au & bu) + (au | bu));
    case 6:
        return detail::narrow<T>((au ^ bu) + 2u * (au & bu));
    case 7:
    case 11: {
        const detail::U p = au | bu, q = au & bu;
        const detail::U sx = p ^ q, t = (p & q) << 1;
        return detail::narrow<T>(2u * (sx | t) - (sx ^ t));
    }
    case 8:
        return detail::narrow<T>((au ^ r) + (bu ^ r) + 2u * (au & r) +
                                 2u * (bu & r) - 2u * r);
    case 9:
        return detail::narrow<T>(~((~au) - bu));
    case 10:
        return detail::narrow<T>((((au + r) + (bu + s)) - r) - s);
    case 12:
    default:
        return detail::narrow<T>(0u - ((0u - au) + (0u - bu)));
    }
}

// ── SUB (10) ─────────────────────────────────────────────────────────────────
template <std::unsigned_integral T>
constexpr T sub(T a, T b, T r1, int variant) noexcept {
    const detail::U au = a, bu = b, r = r1;
    switch (variant) {
    case 0:
        return detail::narrow<T>(au + (0u - bu));
    case 1:
        return detail::narrow<T>(((au + r) - bu) - r);
    case 2:
        return detail::narrow<T>(((au - r) - bu) + r);
    case 3:
        return detail::narrow<T>((au & ~bu) - ((~au) & bu));
    case 4:
    case 7:
        return detail::narrow<T>(2u * (au & ~bu) - (au ^ bu));
    case 5:
        return detail::narrow<T>((au + ~bu) + 1u);
    case 6:
        return detail::narrow<T>(~((~au) + bu));
    case 8:
        return detail::narrow<T>(0u - ((0u - au) + bu));
    case 9:
    default:
        return detail::narrow<T>((au + r) - (bu + r));
    }
}

// ── AND (10) ─────────────────────────────────────────────────────────────────
template <std::unsigned_integral T>
constexpr T and_(T a, T b, T r1, int variant) noexcept {
    const detail::U au = a, bu = b, r = r1;
    switch (variant) {
    case 0:
        return detail::narrow<T>((au ^ ~bu) & au);
    case 1:
        return detail::narrow<T>((au | bu) & ~(au ^ bu));
    case 2:
        return detail::narrow<T>((~au | bu) + (au + 1u));
    case 3:
        return detail::narrow<T>((~((~au) | (~bu))) & (r | ~r));
    case 4:
        return detail::narrow<T>(~((~au) | (~bu)));
    case 5:
        return detail::narrow<T>(~(~(au & bu)));
    case 6:
        return detail::narrow<T>((au ^ bu) ^ (au | bu));
    case 7:
        return detail::narrow<T>(~(((au ^ r) ^ ~r) | ((bu ^ r) ^ ~r)));
    case 8:
        return detail::narrow<T>(((au & r) & (bu & r)) |
                                 ((au & ~r) & (bu & ~r)));
    case 9:
    default:
        return detail::narrow<T>(~((~au) | (~bu)));
    }
}

// ── OR (10) ──────────────────────────────────────────────────────────────────
template <std::unsigned_integral T>
constexpr T or_(T a, T b, T r1, int variant) noexcept {
    const detail::U au = a, bu = b, r = r1;
    switch (variant) {
    case 0:
        return detail::narrow<T>((au & bu) | (au ^ bu));
    case 1:
        return detail::narrow<T>((au + (au ^ bu)) - (au & ~bu));
    case 2:
        return detail::narrow<T>(((au + bu) + 1u) + ~(bu & au));
    case 3:
        return detail::narrow<T>((au ^ bu) | (au & bu));
    case 4:
    case 7:
        return detail::narrow<T>(~(~(au | bu)));
    case 5:
        return detail::narrow<T>(~((~au) & (~bu)));
    case 6:
        return detail::narrow<T>((au ^ bu) | (au & bu));
    case 8:
        return detail::narrow<T>(((au + bu) + r) - (au & bu) - r);
    case 9:
    default:
        return detail::narrow<T>(((au + bu) + r) - (~((~au) | (~bu))) - r);
    }
}

// ── XOR (12) ─────────────────────────────────────────────────────────────────
template <std::unsigned_integral T>
constexpr T xor_(T a, T b, T r1, T r2, int variant, unsigned width) noexcept {
    const detail::U au = a, bu = b, r = r1, s = r2;
    switch (variant) {
    case 0:
        return detail::narrow<T>(((~au) & bu) | (au & ~bu));
    case 1:
        return detail::narrow<T>((au + bu) - 2u * (au & bu));
    case 2:
        return detail::narrow<T>(au - (2u * (bu & ~(au ^ bu)) - bu));
    case 3:
        return detail::narrow<T>((au ^ r) ^ (bu ^ r));
    case 4:
    case 5:
        return detail::narrow<T>(au ^ bu);
    case 6:
        return detail::narrow<T>((au - bu) + 2u * ((~au) & bu));
    case 7:
        return detail::narrow<T>((au + bu) - 2u * (~((~au) | (~bu))));
    case 8:
        return detail::narrow<T>((~au) ^ (~bu));
    case 9: {
        if (width < 4)
            return detail::narrow<T>(((~au) & bu) | (au & ~bu));
        const unsigned k = width / 2;
        const detail::U mask = detail::widthMask(k);
        const detail::U hi =
            (detail::lshrN(au, k, width) ^ detail::lshrN(bu, k, width)) << k;
        const detail::U lo = (au & mask) ^ (bu & mask);
        return detail::narrow<T>(hi ^ lo);
    }
    case 10:
        return detail::narrow<T>(((au ^ r) ^ (bu ^ s)) ^ (r ^ s));
    case 11:
    default:
        return detail::narrow<T>((au | bu) - (au & bu));
    }
}

// ── MUL (7) ──────────────────────────────────────────────────────────────────
template <std::unsigned_integral T>
constexpr T mul(T a, T b, T r1, int variant, unsigned width) noexcept {
    const detail::U au = a, bu = b, r = r1;
    switch (variant) {
    case 0:
        return detail::narrow<T>((au | bu) * (au & bu) +
                                 (au & ~bu) * (bu & ~au));
    case 1:
        return detail::narrow<T>((au | bu) * (au & bu) +
                                 (~(au | ~bu)) * (au & ~bu));
    case 2: {
        if (width < 4)
            return detail::narrow<T>(0u - (au * (0u - bu))); // safe fallback
        const unsigned k = width / 2;
        const detail::U bh = detail::lshrN(bu, k, width);
        const detail::U bl = bu & detail::widthMask(k);
        return detail::narrow<T>(((au * bh) << k) + (au * bl));
    }
    case 3:
        return detail::narrow<T>((((au + r) * (bu + r)) - ((au + r) * r)) -
                                 (bu * r));
    case 4:
        return detail::narrow<T>(0u - (au * (0u - bu)));
    case 5:
        return detail::narrow<T>(au * (bu + 1u) - au);
    case 6:
    default:
        return detail::narrow<T>((0u - (au * ~bu)) - au);
    }
}

// ── SHL (2) — constant shift amount `k < width` ─────────────────────────────
constexpr std::uint64_t shl(std::uint64_t a, unsigned k, std::uint64_t r,
                            int variant, unsigned width) noexcept {
    const detail::U m = detail::widthMask(width);
    switch (variant) {
    case 0:
        return (a * (detail::U{1} << k)) & m;
    case 1:
    default:
        return (((a + r) << k) - ((r << k) & m)) & m;
    }
}

// ── LSHR (2) — logical, constant `k`, 0 < k < width ─────────────────────────
constexpr std::uint64_t lshr(std::uint64_t a, unsigned k, std::uint64_t r,
                             int variant, unsigned width) noexcept {
    switch (variant) {
    case 0: {
        const detail::U clearLow = ~((detail::U{1} << k) - 1u);
        return detail::lshrN(a & clearLow, k, width);
    }
    case 1:
    default:
        return detail::lshrN(a ^ r, k, width) ^ detail::lshrN(r, k, width);
    }
}

// ── ASHR (2) — arithmetic, constant `k`, 0 < k < width ──────────────────────
constexpr std::uint64_t ashr(std::uint64_t a, unsigned k, std::uint64_t r1,
                             std::uint64_t r2, int variant,
                             unsigned width) noexcept {
    switch (variant) {
    case 0:
        return detail::ashrN(a ^ r1, k, width) ^ detail::ashrN(r1, k, width);
    case 1:
    default:
        return detail::ashrN(a ^ r1 ^ r2, k, width) ^
               detail::ashrN(r1, k, width) ^ detail::ashrN(r2, k, width);
    }
}

} // namespace morok::core::subst

#endif // MOROK_CORE_SUBSTITUTION_IDENTITIES_HPP
