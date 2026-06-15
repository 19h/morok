// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/core/MqGf2.hpp — multivariate-quadratic gates over GF(2).

#ifndef MOROK_CORE_MQ_GF2_HPP
#define MOROK_CORE_MQ_GF2_HPP

#include "morok/core/Random.hpp"

#include <cstdint>
#include <vector>

namespace morok::core::mq {

/// One quadratic form over `m` GF(2) variables.  `quad` stores coefficients for
/// i <= j in row-major triangular order.
struct QuadForm {
    unsigned m = 0;
    std::vector<std::uint8_t> quad;
    std::vector<std::uint8_t> lin;
    std::uint8_t cst = 0;
};

/// Packed coefficient index for (i,j), where i <= j < m.
constexpr std::size_t triIndex(unsigned i, unsigned j,
                               unsigned m) noexcept {
    return static_cast<std::size_t>(i) * m -
           (static_cast<std::size_t>(i) * (i - 1u)) / 2u + (j - i);
}

/// Evaluate `f` at bit-vector `x`. Missing input bits are treated as zero.
inline std::uint8_t evalForm(const QuadForm &f,
                             const std::vector<std::uint8_t> &x) noexcept {
    std::uint8_t v = static_cast<std::uint8_t>(f.cst & 1u);
    if (f.lin.size() < f.m ||
        f.quad.size() < static_cast<std::size_t>(f.m) * (f.m + 1u) / 2u)
        return v;

    for (unsigned i = 0; i < f.m; ++i) {
        const std::uint8_t xi =
            i < x.size() ? static_cast<std::uint8_t>(x[i] & 1u) : 0u;
        v ^= static_cast<std::uint8_t>((f.lin[i] & 1u) & xi);
    }
    for (unsigned i = 0; i < f.m; ++i) {
        const std::uint8_t xi =
            i < x.size() ? static_cast<std::uint8_t>(x[i] & 1u) : 0u;
        for (unsigned j = i; j < f.m; ++j) {
            const std::uint8_t xj =
                j < x.size() ? static_cast<std::uint8_t>(x[j] & 1u) : 0u;
            const std::uint8_t q =
                f.quad[triIndex(i, j, f.m)] & 1u;
            v ^= static_cast<std::uint8_t>(q & xi & xj);
        }
    }
    return static_cast<std::uint8_t>(v & 1u);
}

/// Generate a random quadratic form whose constant is rebased so `s` is a root.
template <BitGenerator G>
QuadForm makePlantedForm(unsigned m, const std::vector<std::uint8_t> &s,
                         std::uint32_t density, G &gen) {
    QuadForm f;
    f.m = m;
    f.lin.resize(m);
    f.quad.resize(static_cast<std::size_t>(m) * (m + 1u) / 2u);
    for (std::uint8_t &q : f.quad)
        q = chance(gen, density) ? 1u : 0u;
    for (std::uint8_t &l : f.lin)
        l = chance(gen, density) ? 1u : 0u;
    f.cst = chance(gen, 50) ? 1u : 0u;
    f.cst ^= evalForm(f, s);
    f.cst &= 1u;
    return f;
}

/// A system of quadratic forms.  It opens when every form evaluates to zero.
struct Gate {
    std::vector<QuadForm> forms;

    bool opens(const std::vector<std::uint8_t> &x) const noexcept {
        for (const QuadForm &f : forms)
            if (evalForm(f, x) != 0u)
                return false;
        return true;
    }
};

/// Build `eqs` planted forms over `m` variables.
template <BitGenerator G>
Gate makePlantedGate(unsigned m, unsigned eqs,
                     const std::vector<std::uint8_t> &s,
                     std::uint32_t density, G &gen) {
    Gate g;
    g.forms.reserve(eqs);
    for (unsigned e = 0; e < eqs; ++e)
        g.forms.push_back(makePlantedForm(m, s, density, gen));
    return g;
}

} // namespace morok::core::mq

#endif // MOROK_CORE_MQ_GF2_HPP
