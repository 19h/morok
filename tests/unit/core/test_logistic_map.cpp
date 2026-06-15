// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Unit tests for morok::core::chaos — the logistic-map state generator.

#include "doctest.h"

#include "morok/core/LogisticMap.hpp"
#include "morok/core/Xoshiro256.hpp"

#include <cstdint>
#include <set>

namespace chaos = morok::core::chaos;

TEST_CASE("chaos::step is deterministic and pure") {
    for (std::uint32_t x : {0u, 1u, 0x1234u, 0xFFFFu, 0x4B1Du})
        CHECK(chaos::step(x) == chaos::step(x));
}

TEST_CASE("chaos::step output never leaves [1, 65533] (16-bit exhaustive)") {
    for (std::uint32_t x = 0; x <= 0xFFFFu; ++x) {
        const std::uint32_t y = chaos::step(x);
        REQUIRE(y >= 1u);
        REQUIRE(y <= 65533u);
    }
}

TEST_CASE("chaos::step never returns the absorbing zero state") {
    for (std::uint32_t x = 0; x <= 0xFFFFu; ++x)
        REQUIRE(chaos::step(x) != 0u);
}

TEST_CASE("chaos warmup is deterministic and equals manual iteration") {
    std::uint32_t x = chaos::kDefaultSeed;
    for (std::uint32_t i = 0; i < 64; ++i)
        x = chaos::step(x);
    CHECK(chaos::warmup(chaos::kDefaultSeed, 64) == x);
    CHECK(chaos::warmup(chaos::kDefaultSeed, 0) == chaos::kDefaultSeed);
}

TEST_CASE("chaos correction telescopes: step(i) ^ correction(i,j) == j") {
    auto g = morok::core::Xoshiro256pp::fromSeed(0xC0DE);
    for (int t = 0; t < 100000; ++t) {
        const auto i = static_cast<std::uint32_t>(g());
        const auto j = static_cast<std::uint32_t>(g());
        REQUIRE((chaos::step(i) ^ chaos::correction(i, j)) == j);
    }
}

TEST_CASE("chaos orbit is varied (not a trivial fixed point or short cycle)") {
    std::set<std::uint32_t> seen;
    std::uint32_t x = chaos::kDefaultSeed;
    for (int i = 0; i < 2000; ++i) {
        x = chaos::step(x);
        seen.insert(x);
    }
    // The pure integer map eventually falls into a cycle (the production pass
    // adds an anti-stuck perturbation for exactly this reason), but a healthy
    // chaotic orbit still visits many distinct states before repeating — far
    // more than a fixed point (1) or a short limit cycle.
    CHECK(seen.size() > 100);
}

TEST_CASE("chaos constants are constexpr") {
    static_assert(chaos::step(chaos::kDefaultSeed) != 0);
    static_assert(chaos::correction(10, 20) == (chaos::step(10) ^ 20u));
}
