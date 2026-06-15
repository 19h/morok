// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Unit tests for morok::core Feistel network: it must be an invertible
// permutation for every key, at each supported width.

#include "doctest.h"

#include "morok/core/Feistel.hpp"
#include "morok/core/Xoshiro256.hpp"

#include <cstdint>
#include <vector>

using namespace morok::core;

namespace {
std::uint64_t widthMask(unsigned bits) {
    return bits >= 64 ? ~std::uint64_t{0} : ((std::uint64_t{1} << bits) - 1u);
}
} // namespace

TEST_CASE("feistel round-trips at 16/32/64 bits for random keys and values") {
    auto g = Xoshiro256pp::fromSeed(0xFE15);
    for (unsigned bits : {16u, 32u, 64u}) {
        const std::uint64_t m = widthMask(bits);
        for (int trial = 0; trial < 200; ++trial) {
            const FeistelKeys keys = makeFeistelKeys(g, bits);
            for (int i = 0; i < 200; ++i) {
                const std::uint64_t v = g() & m;
                const std::uint64_t enc = feistelEncrypt(v, bits, keys);
                CHECK((enc & ~m) == 0); // ciphertext stays within width
                REQUIRE(feistelDecrypt(enc, bits, keys) == v);
            }
        }
    }
}

TEST_CASE("feistel multipliers are forced odd (invertible mod 2^half)") {
    auto g = Xoshiro256pp::fromSeed(7);
    for (unsigned bits : {16u, 32u, 64u}) {
        const FeistelKeys keys = makeFeistelKeys(g, bits);
        for (const auto &rk : keys.rounds)
            CHECK((rk.mult & 1u) == 1u);
    }
}

TEST_CASE("feistel is a permutation (no collisions on a sampled domain)") {
    auto g = Xoshiro256pp::fromSeed(0xC0FFEE);
    const unsigned bits = 16;
    const FeistelKeys keys = makeFeistelKeys(g, bits);
    // Exhaustive injectivity on the full 16-bit domain.
    std::vector<bool> seen(1u << bits, false);
    for (std::uint32_t v = 0; v < (1u << bits); ++v) {
        const std::uint64_t e = feistelEncrypt(v, bits, keys);
        REQUIRE(e < (1u << bits));
        REQUIRE_FALSE(seen[e]);
        seen[e] = true;
    }
}

TEST_CASE("feistel actually transforms most inputs") {
    auto g = Xoshiro256pp::fromSeed(1);
    const FeistelKeys keys = makeFeistelKeys(g, 32);
    int changed = 0;
    for (std::uint32_t v = 0; v < 1000; ++v)
        changed += (feistelEncrypt(v, 32, keys) != v) ? 1 : 0;
    CHECK(changed > 990);
}
