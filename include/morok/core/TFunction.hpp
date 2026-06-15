// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/core/TFunction.hpp — a single-cycle T-function state generator.

#ifndef MOROK_CORE_TFUNCTION_HPP
#define MOROK_CORE_TFUNCTION_HPP

#include <cstdint>

namespace morok::core::tfunc {

/// Default single-cycle constant (C == 5 mod 8 ⇒ full 2^n period).
inline constexpr std::uint64_t kDefaultC = 5;

/// True iff `C` yields a single 2^n cycle for `step`: C == 5 or 7 mod 8.
constexpr bool isSingleCycleConstant(std::uint64_t C) noexcept {
    const std::uint64_t r = C & 7u;
    return r == 5u || r == 7u;
}

namespace detail {
constexpr std::uint64_t widthMask(unsigned bits) noexcept {
    return bits >= 64 ? ~std::uint64_t{0}
                      : ((std::uint64_t{1} << bits) - 1u);
}
} // namespace detail

/// One quadratic T-function step on the low `bits` of `x`.
///
/// step(x) = x + (x*x | C) mod 2^bits.  Klimov-Shamir's criterion for this
/// family is local to the low three bits of `C`, so C == 5 or 7 mod 8 is a
/// single full-period cycle at every word width.
constexpr std::uint64_t step(std::uint64_t x, unsigned bits,
                             std::uint64_t C = kDefaultC) noexcept {
    const std::uint64_t m = detail::widthMask(bits);
    const std::uint64_t xc = x & m;
    return (xc + ((xc * xc) | (C & m))) & m;
}

/// Invert `step` by triangular low-to-high bit lifting.
constexpr std::uint64_t inverse(std::uint64_t y, unsigned bits,
                                std::uint64_t C = kDefaultC) noexcept {
    const unsigned w = bits >= 64 ? 64u : bits;
    const std::uint64_t m = detail::widthMask(bits);
    const std::uint64_t yc = y & m;
    std::uint64_t x = 0;
    for (unsigned b = 0; b < w; ++b) {
        const std::uint64_t bit = std::uint64_t{1} << b;
        if (((step(x, bits, C) >> b) & 1u) != ((yc >> b) & 1u))
            x |= bit;
    }
    return x;
}

/// Iterate `step` `count` times from `x`.
constexpr std::uint64_t advance(std::uint64_t x, std::uint32_t count,
                                unsigned bits,
                                std::uint64_t C = kDefaultC) noexcept {
    for (std::uint32_t i = 0; i < count; ++i)
        x = step(x, bits, C);
    return x;
}

/// Compile-time transition correction for dispatcher edges:
/// step(encodedI) ^ correction(encodedI,idJ) == idJ.
constexpr std::uint64_t correction(std::uint64_t encodedI, std::uint64_t idJ,
                                   unsigned bits,
                                   std::uint64_t C = kDefaultC) noexcept {
    return step(encodedI, bits, C) ^ (idJ & detail::widthMask(bits));
}

} // namespace morok::core::tfunc

#endif // MOROK_CORE_TFUNCTION_HPP
