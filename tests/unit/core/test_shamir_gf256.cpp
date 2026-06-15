// SPDX-License-Identifier: MIT
//
// Unit tests for morok::core::shamir — threshold sharing in GF(2^8).

#include "doctest.h"

#include "morok/core/ShamirGf256.hpp"
#include "morok/core/Xoshiro256.hpp"

#include <array>
#include <cstdint>
#include <vector>

namespace shamir = morok::core::shamir;

TEST_CASE("shamir reference vector reconstructs from every 3-subset") {
    const std::vector<shamir::Share> shares = {
        {1, 0xD3}, {2, 0x7E}, {3, 0xEF}, {4, 0x2E}, {5, 0xBF}};
    for (std::size_t a = 0; a < shares.size(); ++a)
        for (std::size_t b = a + 1; b < shares.size(); ++b)
            for (std::size_t c = b + 1; c < shares.size(); ++c)
                CHECK(shamir::reconstruct({shares[a], shares[b], shares[c]}) ==
                      0x42);
}

TEST_CASE("shamir exhaustive byte round-trip for k=3 n=5") {
    auto engine = morok::core::Xoshiro256pp::fromSeed(0x5A11);
    for (unsigned secret = 0; secret < 256; ++secret) {
        const auto shares =
            shamir::split(static_cast<std::uint8_t>(secret), 3, 5, engine);
        REQUIRE(shares.size() == 5);
        for (std::size_t a = 0; a < shares.size(); ++a)
            for (std::size_t b = a + 1; b < shares.size(); ++b)
                for (std::size_t c = b + 1; c < shares.size(); ++c)
                    CHECK(shamir::reconstruct(
                              {shares[a], shares[b], shares[c]}) == secret);
    }
}

TEST_CASE("shamir split clamps invalid thresholds safely") {
    auto engine = morok::core::Xoshiro256pp::fromSeed(0xCAFE);
    CHECK(shamir::split(0x11, 1, 1, engine).size() == 2u);
    CHECK(shamir::split(0x22, 5, 3, engine).size() == 5u);
    CHECK(shamir::split(0x33, 3, 300, engine).size() == 255u);
}

TEST_CASE("shamir evalPoly and reconstruct are constexpr-capable") {
    static_assert(shamir::evalPoly(std::array<std::uint8_t, 3>{0x42, 0x1D,
                                                               0x8C},
                                   1) == 0xD3);
    static_assert(shamir::reconstruct(
                      std::array<shamir::Share, 3>{{{1, 0xD3}, {2, 0x7E},
                                                    {3, 0xEF}}}) == 0x42);
}
