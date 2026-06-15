// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Unit tests for morok::core::Xoshiro256pp.

#include "doctest.h"

#include "morok/core/Xoshiro256.hpp"

#include <array>
#include <random>
#include <set>

using morok::core::Xoshiro256pp;

TEST_CASE("xoshiro256++ is deterministic for equal seeds") {
    auto a = Xoshiro256pp::fromSeed(0x1337);
    auto b = Xoshiro256pp::fromSeed(0x1337);
    for (int i = 0; i < 10000; ++i)
        CHECK(a() == b());
}

TEST_CASE("xoshiro256++ distinct seeds produce distinct streams") {
    auto a = Xoshiro256pp::fromSeed(1);
    auto b = Xoshiro256pp::fromSeed(2);
    bool anyDiff = false;
    for (int i = 0; i < 16; ++i)
        anyDiff |= (a() != b());
    CHECK(anyDiff);
}

TEST_CASE("xoshiro256++ all-zero state is replaced by a non-degenerate one") {
    Xoshiro256pp z(std::array<std::uint64_t, 4>{0, 0, 0, 0});
    // The guard must prevent the all-zero fixed point (which emits only zeros).
    bool anyNonZero = false;
    for (int i = 0; i < 8; ++i)
        anyNonZero |= (z() != 0);
    CHECK(anyNonZero);
}

TEST_CASE("xoshiro256++ does not immediately cycle") {
    auto g = Xoshiro256pp::fromSeed(0xDEADBEEF);
    std::set<std::uint64_t> seen;
    for (int i = 0; i < 5000; ++i)
        seen.insert(g());
    // With period 2^256-1, 5000 draws should all be distinct.
    CHECK(seen.size() == 5000);
}

TEST_CASE("xoshiro256++ high bit is roughly balanced") {
    auto g = Xoshiro256pp::fromSeed(42);
    int ones = 0;
    constexpr int N = 100000;
    for (int i = 0; i < N; ++i)
        ones += static_cast<int>(g() >> 63);
    CHECK(ones > N * 45 / 100);
    CHECK(ones < N * 55 / 100);
}

TEST_CASE("xoshiro256++ fromWords avalanches the seed words") {
    auto a = Xoshiro256pp::fromWords(0, 0, 0, 1);
    auto b = Xoshiro256pp::fromWords(0, 0, 0, 2);
    CHECK(a.state() != b.state());
    CHECK(a() != b());
}

TEST_CASE("xoshiro256++ models a uniform random bit generator") {
    static_assert(std::uniform_random_bit_generator<Xoshiro256pp>);
    static_assert(Xoshiro256pp::min() == 0);
    static_assert(Xoshiro256pp::max() == ~0ULL);
}
