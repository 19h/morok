// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Unit tests for morok::core Knuth multiplicative branch-target encoding.

#include "doctest.h"

#include "morok/core/KnuthHash.hpp"
#include "morok/core/Xoshiro256.hpp"

#include <cstdint>

using namespace morok::core;

TEST_CASE("modInverse64 yields the true inverse for odd inputs") {
    auto g = Xoshiro256pp::fromSeed(0x1357);
    for (int i = 0; i < 100000; ++i) {
        const std::uint64_t a = g() | 1u; // force odd
        REQUIRE(a * modInverse64(a) == 1u);
    }
}

TEST_CASE("KnuthKey::make forces the multiplier odd") {
    CHECK((KnuthKey::make(0, 0, 0).mult & 1u) == 1u);
    CHECK((KnuthKey::make(0, 0x1000, 0).mult & 1u) == 1u);
    CHECK(KnuthKey::make(0, 0xDEADBEEFCAFEF00CULL, 0).mult ==
          0xDEADBEEFCAFEF00DULL);
}

TEST_CASE("knuth encode/decode round-trips for random keys and targets") {
    auto g = Xoshiro256pp::fromSeed(0x2468);
    for (int i = 0; i < 100000; ++i) {
        const KnuthKey key = KnuthKey::make(g(), g(), g());
        const std::uint64_t raw = g();
        const std::uint64_t enc = knuthEncode(raw, key);
        REQUIRE(knuthDecode(enc, key) == raw);
    }
}

TEST_CASE("knuth golden vector matches the reference implementation") {
    const KnuthKey key = KnuthKey::make(
        0x0123456789ABCDEFULL, 0xDEADBEEFCAFEF00DULL, 0xA5A5A5A55A5A5A5AULL);
    CHECK(modInverse64(key.mult) == 0xA761C9B0BCBEDEC5ULL);
    const std::uint64_t raw = 0x0000000140001000ULL;
    const std::uint64_t enc = knuthEncode(raw, key);
    CHECK(enc == 0x1A00A88C7CB60F79ULL);
    CHECK(knuthDecode(enc, key) == raw);
}

TEST_CASE("knuth encoding actually obscures the target") {
    const KnuthKey key = KnuthKey::make(0xCAFE, 0xBEEF, 0xF00D);
    int changed = 0;
    for (std::uint64_t raw = 0; raw < 1000; ++raw)
        changed += (knuthEncode(raw, key) != raw) ? 1 : 0;
    CHECK(changed == 1000);
}

TEST_CASE("knuth primitives are constexpr") {
    constexpr KnuthKey key = KnuthKey::make(1, 3, 5);
    static_assert(key.mult == 3);
    static_assert(modInverse64(3) * 3u == 1u);
    static_assert(knuthDecode(knuthEncode(0xABCD, key), key) == 0xABCD);
}
