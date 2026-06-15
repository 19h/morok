// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Unit tests for morok::core::gf8 — GF(2^8) field axioms and the Vernam cipher.

#include "doctest.h"

#include "morok/core/Galois8.hpp"

#include <cstdint>

namespace gf8 = morok::core::gf8;

TEST_CASE("gf8 addition is XOR") {
    for (int a = 0; a < 256; ++a)
        for (int b = 0; b < 256; ++b)
            CHECK(gf8::add(static_cast<std::uint8_t>(a),
                           static_cast<std::uint8_t>(b)) ==
                  static_cast<std::uint8_t>(a ^ b));
}

TEST_CASE("gf8 xtime equals multiplication by 2") {
    for (int a = 0; a < 256; ++a)
        CHECK(gf8::xtime(static_cast<std::uint8_t>(a)) ==
              gf8::mul(static_cast<std::uint8_t>(a), 2));
}

TEST_CASE("gf8 multiplication is commutative") {
    for (int a = 0; a < 256; ++a)
        for (int b = 0; b < 256; ++b)
            CHECK(gf8::mul(static_cast<std::uint8_t>(a),
                           static_cast<std::uint8_t>(b)) ==
                  gf8::mul(static_cast<std::uint8_t>(b),
                           static_cast<std::uint8_t>(a)));
}

TEST_CASE("gf8 has multiplicative identity 1 and absorbing 0") {
    for (int a = 0; a < 256; ++a) {
        CHECK(gf8::mul(static_cast<std::uint8_t>(a), 1) == a);
        CHECK(gf8::mul(static_cast<std::uint8_t>(a), 0) == 0);
    }
}

TEST_CASE("gf8 multiplication distributes over addition (exhaustive a,b; "
          "sampled c)") {
    for (int c = 0; c < 256; ++c)
        for (int a = 0; a < 256; ++a)
            for (int b = 0; b < 256; ++b) {
                const auto lhs = gf8::mul(static_cast<std::uint8_t>(c),
                                          static_cast<std::uint8_t>(a ^ b));
                const auto rhs =
                    gf8::add(gf8::mul(static_cast<std::uint8_t>(c),
                                      static_cast<std::uint8_t>(a)),
                             gf8::mul(static_cast<std::uint8_t>(c),
                                      static_cast<std::uint8_t>(b)));
                REQUIRE(lhs == rhs);
            }
}

TEST_CASE("gf8 multiplication is associative (sampled multiplier c)") {
    for (int c : {1, 2, 3, 7, 0x1B, 0x53, 0xFF}) {
        for (int a = 0; a < 256; ++a)
            for (int b = 0; b < 256; ++b) {
                const auto lhs =
                    gf8::mul(gf8::mul(static_cast<std::uint8_t>(a),
                                      static_cast<std::uint8_t>(b)),
                             static_cast<std::uint8_t>(c));
                const auto rhs =
                    gf8::mul(static_cast<std::uint8_t>(a),
                             gf8::mul(static_cast<std::uint8_t>(b),
                                      static_cast<std::uint8_t>(c)));
                REQUIRE(lhs == rhs);
            }
    }
}

TEST_CASE("gf8 inverse satisfies a * inv(a) == 1 for every non-zero element") {
    CHECK(gf8::inv(0) == 0); // convention
    for (int a = 1; a < 256; ++a)
        CHECK(gf8::mul(static_cast<std::uint8_t>(a),
                       gf8::inv(static_cast<std::uint8_t>(a))) == 1);
}

TEST_CASE("Vernam-GF8 cipher round-trips every byte under every non-zero key") {
    for (int k2 = 1; k2 < 256; ++k2) {
        const auto k2inv = gf8::inv(static_cast<std::uint8_t>(k2));
        for (int k1 : {0, 0x1F, 0x5A, 0xFF}) {
            for (int p = 0; p < 256; ++p) {
                const auto c = gf8::encryptByte(static_cast<std::uint8_t>(p),
                                                static_cast<std::uint8_t>(k1),
                                                static_cast<std::uint8_t>(k2));
                const auto back =
                    gf8::decryptByte(c, static_cast<std::uint8_t>(k1), k2inv);
                REQUIRE(back == static_cast<std::uint8_t>(p));
            }
        }
    }
}

TEST_CASE("Vernam-GF8 worked example: 'A' under k1=0x1F, k2=0x03") {
    const auto c = gf8::encryptByte(0x41, 0x1F, 0x03);
    CHECK(c == 0xE2);
    CHECK(gf8::inv(0x03) == 0xF6);
    CHECK(gf8::decryptByte(c, 0x1F, gf8::inv(0x03)) == 0x41);
}

TEST_CASE("gf8 is constexpr-evaluable") {
    static_assert(gf8::mul(0x03, 0xF6) == 1);
    static_assert(gf8::encryptByte(0x41, 0x1F, 0x03) == 0xE2);
}
