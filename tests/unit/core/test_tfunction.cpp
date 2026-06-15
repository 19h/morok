// SPDX-License-Identifier: MIT
//
// Unit tests for morok::core::tfunc — single-cycle T-function generator.

#include "doctest.h"

#include "morok/core/TFunction.hpp"
#include "morok/core/Xoshiro256.hpp"

#include <cstdint>
#include <vector>

namespace tfunc = morok::core::tfunc;

namespace {

bool orbitFromZeroIsFull(unsigned bits, std::uint64_t C) {
    const std::uint64_t n = std::uint64_t{1} << bits;
    std::vector<bool> seen(static_cast<std::size_t>(n));
    std::uint64_t x = 0;
    for (std::uint64_t i = 0; i < n; ++i) {
        if (seen[static_cast<std::size_t>(x)])
            return false;
        seen[static_cast<std::size_t>(x)] = true;
        x = tfunc::step(x, bits, C);
    }
    return x == 0;
}

} // namespace

TEST_CASE("tfunc single-cycle constants are exactly residues 5 or 7 mod 8") {
    for (std::uint64_t C = 0; C < 256; ++C) {
        const bool expected = (C % 8 == 5) || (C % 8 == 7);
        CHECK(tfunc::isSingleCycleConstant(C) == expected);
    }
}

TEST_CASE("tfunc default reference vector is stable") {
    std::uint64_t x = 0;
    x = tfunc::step(x, 64, 5);
    CHECK(x == 0x0000000000000005ULL);
    x = tfunc::step(x, 64, 5);
    CHECK(x == 0x0000000000000022ULL);
    x = tfunc::step(x, 64, 5);
    CHECK(x == 0x00000000000004A7ULL);
    x = tfunc::step(x, 64, 5);
    CHECK(x == 0x000000000015A99CULL);
    x = tfunc::step(x, 64, 5);
    CHECK(x == 0x000001D5440D00B1ULL);
}

TEST_CASE("tfunc valid constants form full orbits on practical widths") {
    for (unsigned bits : {4u, 8u, 12u, 16u}) {
        CHECK(orbitFromZeroIsFull(bits, 5));
        CHECK(orbitFromZeroIsFull(bits, 7));
        CHECK(orbitFromZeroIsFull(bits, 13));
        CHECK_FALSE(orbitFromZeroIsFull(bits, 1));
        CHECK_FALSE(orbitFromZeroIsFull(bits, 3));
    }
}

TEST_CASE("tfunc inverse round-trips every 16-bit state") {
    for (std::uint64_t y = 0; y <= 0xFFFFu; ++y) {
        const std::uint64_t x5 = tfunc::inverse(y, 16, 5);
        CHECK(tfunc::step(x5, 16, 5) == y);
        const std::uint64_t x7 = tfunc::inverse(y, 16, 7);
        CHECK(tfunc::step(x7, 16, 7) == y);
    }
}

TEST_CASE("tfunc correction telescopes") {
    auto g = morok::core::Xoshiro256pp::fromSeed(0x710F);
    for (int t = 0; t < 100000; ++t) {
        const auto i = static_cast<std::uint32_t>(g());
        const auto j = static_cast<std::uint32_t>(g());
        const auto C = (g() & 1u) ? 5u : 7u;
        CHECK((tfunc::step(i, 32, C) ^ tfunc::correction(i, j, 32, C)) == j);
    }
}

TEST_CASE("tfunc helpers are constexpr") {
    static_assert(tfunc::isSingleCycleConstant(5));
    static_assert(tfunc::step(0, 64, 5) == 5);
    static_assert(tfunc::correction(10, 20, 32, 5) ==
                  (tfunc::step(10, 32, 5) ^ 20u));
}
