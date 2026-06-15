// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/core/ShamirGf256.hpp — Shamir (k,n) threshold sharing in GF(2^8).

#ifndef MOROK_CORE_SHAMIR_GF256_HPP
#define MOROK_CORE_SHAMIR_GF256_HPP

#include "morok/core/Galois8.hpp"
#include "morok/core/Random.hpp"

#include <cstdint>
#include <initializer_list>
#include <utility>
#include <vector>

namespace morok::core::shamir {

inline constexpr std::size_t kMinThreshold = 2;
inline constexpr std::size_t kMaxShares = 255;

using Share = std::pair<std::uint8_t, std::uint8_t>;

template <class Coeffs>
constexpr std::uint8_t evalPoly(const Coeffs &coeffs,
                                std::uint8_t x) noexcept {
    std::uint8_t acc = 0;
    for (std::size_t i = coeffs.size(); i-- > 0;)
        acc = gf8::add(gf8::mul(acc, x), coeffs[i]);
    return acc;
}

template <BitGenerator G>
std::vector<Share> split(std::uint8_t secret, std::size_t k, std::size_t n,
                         G &gen) {
    if (k < kMinThreshold)
        k = kMinThreshold;
    if (n > kMaxShares)
        n = kMaxShares;
    if (n < k)
        n = k;

    std::vector<std::uint8_t> coeffs(k);
    coeffs[0] = secret;
    for (std::size_t i = 1; i < k; ++i)
        coeffs[i] = static_cast<std::uint8_t>(gen() & 0xFFu);

    std::vector<Share> shares;
    shares.reserve(n);
    for (std::size_t i = 1; i <= n; ++i) {
        const auto x = static_cast<std::uint8_t>(i);
        shares.emplace_back(x, evalPoly(coeffs, x));
    }
    return shares;
}

template <class Shares>
constexpr std::uint8_t reconstruct(const Shares &shares) noexcept {
    std::uint8_t secret = 0;
    for (std::size_t j = 0; j < shares.size(); ++j) {
        const std::uint8_t xj = shares[j].first;
        const std::uint8_t yj = shares[j].second;
        std::uint8_t num = 1;
        std::uint8_t den = 1;
        for (std::size_t m = 0; m < shares.size(); ++m) {
            if (m == j)
                continue;
            const std::uint8_t xm = shares[m].first;
            num = gf8::mul(num, xm);
            den = gf8::mul(den, static_cast<std::uint8_t>(xj ^ xm));
        }
        const std::uint8_t basis = gf8::mul(num, gf8::inv(den));
        secret = gf8::add(secret, gf8::mul(yj, basis));
    }
    return secret;
}

constexpr std::uint8_t
reconstruct(std::initializer_list<Share> shares) noexcept {
    std::uint8_t secret = 0;
    std::size_t j = 0;
    for (Share sj : shares) {
        const std::uint8_t xj = sj.first;
        const std::uint8_t yj = sj.second;
        std::uint8_t num = 1;
        std::uint8_t den = 1;
        std::size_t m = 0;
        for (Share sm : shares) {
            if (m++ == j)
                continue;
            const std::uint8_t xm = sm.first;
            num = gf8::mul(num, xm);
            den = gf8::mul(den, static_cast<std::uint8_t>(xj ^ xm));
        }
        const std::uint8_t basis = gf8::mul(num, gf8::inv(den));
        secret = gf8::add(secret, gf8::mul(yj, basis));
        ++j;
    }
    return secret;
}

} // namespace morok::core::shamir

#endif // MOROK_CORE_SHAMIR_GF256_HPP
