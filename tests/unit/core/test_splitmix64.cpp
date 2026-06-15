// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Unit tests for morok::core::Splitmix64.

#include "doctest.h"

#include "morok/core/Splitmix64.hpp"

#include <random>

using morok::core::Splitmix64;

TEST_CASE("splitmix64 matches reference vectors for seed 0") {
    // Canonical splitmix64 outputs for seed 0 (Vigna's reference
    // implementation).
    Splitmix64 g(0);
    CHECK(g() == 0xE220A8397B1DCDAFULL);
    CHECK(g() == 0x6E789E6AA1B965F4ULL);
    CHECK(g() == 0x06C45D188009454FULL);
}

TEST_CASE("splitmix64 is deterministic for equal seeds") {
    Splitmix64 a(0xCAFEBABEDEADBEEFULL);
    Splitmix64 b(0xCAFEBABEDEADBEEFULL);
    for (int i = 0; i < 1000; ++i)
        CHECK(a() == b());
}

TEST_CASE("splitmix64 distinct seeds diverge immediately") {
    Splitmix64 a(1);
    Splitmix64 b(2);
    CHECK(a() != b());
}

TEST_CASE("splitmix64::mix equals one generator step from the prior state") {
    // operator() does state += gamma then finalize; so mix(x) ==
    // finalize(x+gamma) equals the first output of a generator seeded with x.
    for (std::uint64_t x :
         {0ULL, 1ULL, 0x9E3779B97F4A7C15ULL, ~0ULL, 0x0123456789ABCDEFULL}) {
        Splitmix64 g(x);
        CHECK(Splitmix64::mix(x) == g());
    }
}

TEST_CASE("splitmix64::mix avalanches (distinct inputs, distinct outputs)") {
    CHECK(Splitmix64::mix(0) != Splitmix64::mix(1));
    // A single-bit input change should flip many output bits.
    const std::uint64_t a = Splitmix64::mix(0x5555555555555555ULL);
    const std::uint64_t b = Splitmix64::mix(0x5555555555555554ULL);
    const int flipped = __builtin_popcountll(a ^ b);
    CHECK(flipped > 16); // strong avalanche; expected ~32
}

TEST_CASE("splitmix64 models a uniform random bit generator") {
    static_assert(Splitmix64::min() == 0);
    static_assert(Splitmix64::max() == ~0ULL);
    static_assert(std::uniform_random_bit_generator<Splitmix64>);
}

TEST_CASE("splitmix64 is usable in constant expressions") {
    constexpr std::uint64_t v = Splitmix64::mix(0);
    static_assert(v == 0xE220A8397B1DCDAFULL);
    CHECK(v == 0xE220A8397B1DCDAFULL);
}
