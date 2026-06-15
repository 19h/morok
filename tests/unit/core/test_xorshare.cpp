// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Unit tests for morok::core XOR secret sharing.

#include "doctest.h"

#include "morok/core/XorShare.hpp"
#include "morok/core/Xoshiro256.hpp"

#include <cstdint>

using namespace morok::core;

namespace {
std::uint64_t widthMask(unsigned bits) {
    return bits >= 64 ? ~std::uint64_t{0} : ((std::uint64_t{1} << bits) - 1u);
}
} // namespace

TEST_CASE("xor shares reconstruct the original value for k in [2,8]") {
    auto g = Xoshiro256pp::fromSeed(0x5A4E);
    for (unsigned bits : {8u, 16u, 32u, 64u}) {
        const std::uint64_t m = widthMask(bits);
        for (std::size_t k = 2; k <= 8; ++k)
            for (int i = 0; i < 2000; ++i) {
                const std::uint64_t v = g() & m;
                const auto shares = splitXorShares(v, k, bits, g);
                REQUIRE(shares.size() == k);
                REQUIRE(reconstructXorShares(shares) == v);
                for (std::uint64_t s : shares)
                    REQUIRE((s & ~m) == 0); // each share stays within width
            }
    }
}

TEST_CASE("share count is clamped to [kMinShares, kMaxShares]") {
    auto g = Xoshiro256pp::fromSeed(1);
    CHECK(splitXorShares(0x1234, 0, 32, g).size() == kMinShares);
    CHECK(splitXorShares(0x1234, 1, 32, g).size() == kMinShares);
    CHECK(splitXorShares(0x1234, 9, 32, g).size() == kMaxShares);
    CHECK(splitXorShares(0x1234, 100, 32, g).size() == kMaxShares);
}

TEST_CASE("the leading shares are genuinely random (not the value)") {
    auto g = Xoshiro256pp::fromSeed(2);
    const std::uint64_t v = 0xDEADBEEF;
    const auto shares = splitXorShares(v, 4, 32, g);
    // It is astronomically unlikely all three random shares equal the value.
    int equalToValue = 0;
    for (std::size_t i = 0; i + 1 < shares.size(); ++i)
        equalToValue += (shares[i] == v) ? 1 : 0;
    CHECK(equalToValue < 3);
}

TEST_CASE("empty share list reconstructs to zero") {
    CHECK(reconstructXorShares({}) == 0);
}
