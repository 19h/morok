// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/core/LogisticMap.hpp — the chaotic state generator for control-flow
// flattening.
//
// The chaos-state-machine pass drives its dispatcher with the logistic map
//      x_{n+1} = r * x_n * (1 - x_n),   r ≈ 3.99982
// evaluated in Q16 fixed point (no floating point): the integer state in
// [0, 65535] represents x_real = state / 65536.  The parameter is encoded as
// r * 2^14 = 65533, and the final `>> 30` divides by 2^16 * 2^14 to return to
// Q16.  Two guards keep the orbit off the absorbing fixed point at 0.
//
// The transition between dispatcher states j = f(i) is realised at runtime as
//      next = step(current) XOR correction(i, j),
// where correction(i, j) = step(case_i) XOR case_j is a compile-time constant;
// the XOR telescopes so `next == case_j` exactly.

#ifndef MOROK_CORE_LOGISTIC_MAP_HPP
#define MOROK_CORE_LOGISTIC_MAP_HPP

#include <cstdint>

namespace morok::core::chaos {

/// Q16 scale: the fixed-point representation of 1.0.
inline constexpr std::uint64_t kOne = 65536;
/// r * 2^14, the logistic parameter in the chaotic regime (~3.99982).
inline constexpr std::uint64_t kRScaled = 65533;
/// Guard substituted for a zero input state (absorbing fixed point escape).
inline constexpr std::uint32_t kInputGuard = 0x1337;
/// Guard substituted for a zero output state.
inline constexpr std::uint32_t kOutputGuard = 0xC0DE;
/// Default orbit seed when none is supplied.
inline constexpr std::uint32_t kDefaultSeed = 0x4B1D;
/// Default number of warm-up iterations to skip the initial transient.
inline constexpr std::uint32_t kDefaultWarmup = 64;

/// One deterministic logistic-map iteration in Q16 fixed point.
///
/// Pure and total: the input is taken modulo 2^16, an all-zero state is mapped
/// to `kInputGuard`, and a zero result is mapped to `kOutputGuard`, so the
/// orbit never collapses.  Output is always in [1, 65533].
constexpr std::uint32_t step(std::uint32_t x) noexcept {
    std::uint64_t xc = x & 0xFFFFu;
    if (xc == 0)
        xc = kInputGuard;
    const std::uint64_t inv = kOne - xc; // (1 - x) in Q16
    const std::uint64_t prod = xc * inv; // Q32 product
    const std::uint32_t next =
        static_cast<std::uint32_t>((prod * kRScaled) >> 30);
    return next ? next : kOutputGuard;
}

/// Iterate `step` `count` times starting from `x`.
constexpr std::uint32_t warmup(std::uint32_t x, std::uint32_t count) noexcept {
    for (std::uint32_t i = 0; i < count; ++i)
        x = step(x);
    return x;
}

/// Compile-time correction constant so that, at runtime,
///     step(case_i) XOR correction(case_i, case_j) == case_j.
constexpr std::uint32_t correction(std::uint32_t case_i,
                                   std::uint32_t case_j) noexcept {
    return step(case_i) ^ case_j;
}

} // namespace morok::core::chaos

#endif // MOROK_CORE_LOGISTIC_MAP_HPP
