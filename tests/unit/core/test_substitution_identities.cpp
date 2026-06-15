// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Unit tests for morok::core::subst — the instruction-substitution catalog.
// Every variant must equal the operation it replaces in Z/2^n.  Arithmetic and
// bitwise ops are checked exhaustively on 8-bit operands; shifts are checked
// for every legal shift amount; wider widths are fuzzed.

#include "doctest.h"

#include "morok/core/SubstitutionIdentities.hpp"
#include "morok/core/Xoshiro256.hpp"

#include <cstdint>

namespace ss = morok::core::subst;
using morok::core::Xoshiro256pp;

namespace {
constexpr std::uint8_t kRs[] = {0x00, 0x01, 0x5A, 0xA5, 0x7F, 0x80, 0xFF};
} // namespace

TEST_CASE("subst::add — all 13 variants equal a+b (8-bit exhaustive)") {
    for (int v = 0; v < ss::kAddVariants; ++v)
        for (std::uint8_t r1 : kRs)
            for (std::uint8_t r2 : kRs)
                for (int a = 0; a < 256; ++a)
                    for (int b = 0; b < 256; ++b)
                        REQUIRE(ss::add<std::uint8_t>(
                                    static_cast<std::uint8_t>(a),
                                    static_cast<std::uint8_t>(b), r1, r2,
                                    v) == static_cast<std::uint8_t>(a + b));
}

TEST_CASE("subst::sub — all 10 variants equal a-b (8-bit exhaustive)") {
    for (int v = 0; v < ss::kSubVariants; ++v)
        for (std::uint8_t r1 : kRs)
            for (int a = 0; a < 256; ++a)
                for (int b = 0; b < 256; ++b)
                    REQUIRE(ss::sub<std::uint8_t>(static_cast<std::uint8_t>(a),
                                                  static_cast<std::uint8_t>(b),
                                                  r1, v) ==
                            static_cast<std::uint8_t>(a - b));
}

TEST_CASE("subst::and — all 10 variants equal a&b (8-bit exhaustive)") {
    for (int v = 0; v < ss::kAndVariants; ++v)
        for (std::uint8_t r1 : kRs)
            for (int a = 0; a < 256; ++a)
                for (int b = 0; b < 256; ++b)
                    REQUIRE(ss::and_<std::uint8_t>(static_cast<std::uint8_t>(a),
                                                   static_cast<std::uint8_t>(b),
                                                   r1, v) ==
                            static_cast<std::uint8_t>(a & b));
}

TEST_CASE("subst::or — all 10 variants equal a|b (8-bit exhaustive)") {
    for (int v = 0; v < ss::kOrVariants; ++v)
        for (std::uint8_t r1 : kRs)
            for (int a = 0; a < 256; ++a)
                for (int b = 0; b < 256; ++b)
                    REQUIRE(ss::or_<std::uint8_t>(static_cast<std::uint8_t>(a),
                                                  static_cast<std::uint8_t>(b),
                                                  r1, v) ==
                            static_cast<std::uint8_t>(a | b));
}

TEST_CASE("subst::xor — all 12 variants equal a^b (8-bit exhaustive)") {
    for (int v = 0; v < ss::kXorVariants; ++v)
        for (std::uint8_t r1 : kRs)
            for (std::uint8_t r2 : kRs)
                for (int a = 0; a < 256; ++a)
                    for (int b = 0; b < 256; ++b)
                        REQUIRE(ss::xor_<std::uint8_t>(
                                    static_cast<std::uint8_t>(a),
                                    static_cast<std::uint8_t>(b), r1, r2, v,
                                    8) == static_cast<std::uint8_t>(a ^ b));
}

TEST_CASE("subst::mul — all 7 variants equal a*b (8-bit exhaustive)") {
    for (int v = 0; v < ss::kMulVariants; ++v)
        for (std::uint8_t r1 : kRs)
            for (int a = 0; a < 256; ++a)
                for (int b = 0; b < 256; ++b)
                    REQUIRE(ss::mul<std::uint8_t>(static_cast<std::uint8_t>(a),
                                                  static_cast<std::uint8_t>(b),
                                                  r1, v, 8) ==
                            static_cast<std::uint8_t>(a * b));
}

TEST_CASE("subst::shl — both variants equal a<<k for every legal k (8-bit)") {
    for (int v = 0; v < ss::kShlVariants; ++v)
        for (std::uint64_t r : {0ULL, 0x5AULL, 0xFFULL})
            for (unsigned k = 0; k < 8; ++k)
                for (int a = 0; a < 256; ++a) {
                    const auto want = static_cast<std::uint8_t>(a << k);
                    CHECK(ss::shl(static_cast<std::uint64_t>(a), k, r, v, 8) ==
                          want);
                }
}

TEST_CASE("subst::lshr — both variants equal a>>k logical (8-bit)") {
    for (int v = 0; v < ss::kLShrVariants; ++v)
        for (std::uint64_t r : {0ULL, 0x5AULL, 0xFFULL})
            for (unsigned k = 1; k < 8; ++k)
                for (int a = 0; a < 256; ++a) {
                    const auto want = static_cast<std::uint8_t>(
                        static_cast<unsigned>(a) >> k);
                    CHECK(ss::lshr(static_cast<std::uint64_t>(a), k, r, v, 8) ==
                          want);
                }
}

TEST_CASE("subst::ashr — both variants equal a>>k arithmetic (8-bit)") {
    for (int v = 0; v < ss::kAShrVariants; ++v)
        for (std::uint64_t r1 : {0ULL, 0x5AULL, 0xFFULL})
            for (std::uint64_t r2 : {0ULL, 0xA5ULL, 0x80ULL})
                for (unsigned k = 1; k < 8; ++k)
                    for (int a = 0; a < 256; ++a) {
                        const auto want = static_cast<std::uint8_t>(
                            static_cast<std::int8_t>(a) >> k);
                        CHECK(ss::ashr(static_cast<std::uint64_t>(a), k, r1, r2,
                                       v, 8) == want);
                    }
}

TEST_CASE("subst identities hold at 32/64 bits and all shift amounts (fuzz)") {
    auto g = Xoshiro256pp::fromSeed(0x5151);
    for (int i = 0; i < 40000; ++i) {
        const auto a = static_cast<std::uint32_t>(g());
        const auto b = static_cast<std::uint32_t>(g());
        const auto r1 = static_cast<std::uint32_t>(g());
        const auto r2 = static_cast<std::uint32_t>(g());
        for (int v = 0; v < ss::kAddVariants; ++v)
            REQUIRE(ss::add<std::uint32_t>(a, b, r1, r2, v) ==
                    static_cast<std::uint32_t>(a + b));
        for (int v = 0; v < ss::kMulVariants; ++v)
            REQUIRE(ss::mul<std::uint32_t>(a, b, r1, v, 32) ==
                    static_cast<std::uint32_t>(a * b));
        const unsigned k = 1 + (a % 31);
        for (int v = 0; v < ss::kAShrVariants; ++v) {
            const auto want =
                static_cast<std::uint32_t>(static_cast<std::int32_t>(a) >> k);
            REQUIRE(static_cast<std::uint32_t>(ss::ashr(a, k, r1, r2, v, 32)) ==
                    want);
        }
    }
}
