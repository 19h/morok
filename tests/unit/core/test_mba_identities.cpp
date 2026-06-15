// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Unit tests for morok::core::mba — every Mixed Boolean-Arithmetic rewrite must
// equal the operation it replaces, in the ring Z/2^n.  Verified exhaustively on
// 8-bit operands (all 65 536 pairs) for several random constants, and fuzzed at
// wider widths.

#include "doctest.h"

#include "morok/core/MbaIdentities.hpp"
#include "morok/core/Xoshiro256.hpp"

#include <cstdint>

namespace mba = morok::core::mba;
using morok::core::Xoshiro256pp;

namespace {
// A spread of random constants exercised by each identity (the r-using ones
// must cancel for every value of r).
constexpr std::uint8_t kRs[] = {0x00, 0x01, 0x5A, 0xA5, 0x7F, 0x80, 0xFF, 0x39};

template <class Fn, class Ref> void checkAll8(int variants, Fn fn, Ref ref) {
    for (int v = 0; v < variants; ++v)
        for (std::uint8_t r : kRs)
            for (int a = 0; a < 256; ++a)
                for (int b = 0; b < 256; ++b) {
                    const auto got = fn(static_cast<std::uint8_t>(a),
                                        static_cast<std::uint8_t>(b), r, v);
                    const auto want = ref(static_cast<std::uint8_t>(a),
                                          static_cast<std::uint8_t>(b));
                    REQUIRE_MESSAGE(got == want, "variant=" << v << " a=" << a
                                                            << " b=" << b
                                                            << " r=" << int(r));
                }
}
} // namespace

TEST_CASE("mba::add variants all equal a+b (8-bit exhaustive)") {
    checkAll8(
        mba::kAddVariants,
        [](std::uint8_t a, std::uint8_t b, std::uint8_t r, int v) {
            return mba::add<std::uint8_t>(a, b, r, v);
        },
        [](std::uint8_t a, std::uint8_t b) {
            return static_cast<std::uint8_t>(a + b);
        });
}

TEST_CASE("mba::sub variants all equal a-b (8-bit exhaustive)") {
    checkAll8(
        mba::kSubVariants,
        [](std::uint8_t a, std::uint8_t b, std::uint8_t r, int v) {
            return mba::sub<std::uint8_t>(a, b, r, v);
        },
        [](std::uint8_t a, std::uint8_t b) {
            return static_cast<std::uint8_t>(a - b);
        });
}

TEST_CASE("mba::xor variants all equal a^b (8-bit exhaustive)") {
    checkAll8(
        mba::kXorVariants,
        [](std::uint8_t a, std::uint8_t b, std::uint8_t r, int v) {
            return mba::xor_<std::uint8_t>(a, b, r, v);
        },
        [](std::uint8_t a, std::uint8_t b) {
            return static_cast<std::uint8_t>(a ^ b);
        });
}

TEST_CASE("mba::and variants all equal a&b (8-bit exhaustive)") {
    checkAll8(
        mba::kAndVariants,
        [](std::uint8_t a, std::uint8_t b, std::uint8_t r, int v) {
            return mba::and_<std::uint8_t>(a, b, r, v);
        },
        [](std::uint8_t a, std::uint8_t b) {
            return static_cast<std::uint8_t>(a & b);
        });
}

TEST_CASE("mba::or variants all equal a|b (8-bit exhaustive)") {
    checkAll8(
        mba::kOrVariants,
        [](std::uint8_t a, std::uint8_t b, std::uint8_t r, int v) {
            return mba::or_<std::uint8_t>(a, b, r, v);
        },
        [](std::uint8_t a, std::uint8_t b) {
            return static_cast<std::uint8_t>(a | b);
        });
}

TEST_CASE("mba::mul variants all equal a*b (8-bit exhaustive)") {
    for (int v = 0; v < mba::kMulVariants; ++v)
        for (std::uint8_t r : kRs)
            for (int a = 0; a < 256; ++a)
                for (int b = 0; b < 256; ++b) {
                    const auto got = mba::mul<std::uint8_t>(
                        static_cast<std::uint8_t>(a),
                        static_cast<std::uint8_t>(b), r, v, 8);
                    REQUIRE(got == static_cast<std::uint8_t>(a * b));
                }
}

TEST_CASE("mba carry lemma x+r == (x^r) + 2*(x&r) (8-bit exhaustive)") {
    for (int x = 0; x < 256; ++x)
        for (int r = 0; r < 256; ++r)
            REQUIRE(mba::carrySum<std::uint8_t>(static_cast<std::uint8_t>(x),
                                                static_cast<std::uint8_t>(r)) ==
                    static_cast<std::uint8_t>(x + r));
}

TEST_CASE("mba zero-terms are identically zero (8-bit exhaustive)") {
    for (int kind = 0; kind < mba::kZeroTermKinds; ++kind)
        for (std::uint8_t r : kRs)
            for (int a = 0; a < 256; ++a)
                for (int b = 0; b < 256; ++b)
                    REQUIRE(mba::zeroTerm<std::uint8_t>(
                                static_cast<std::uint8_t>(a),
                                static_cast<std::uint8_t>(b), r, kind) == 0);
}

TEST_CASE("mba identities hold at 32 and 64 bits (randomised fuzz)") {
    auto g = Xoshiro256pp::fromSeed(0x9001);
    for (int i = 0; i < 50000; ++i) {
        const auto a32 = static_cast<std::uint32_t>(g());
        const auto b32 = static_cast<std::uint32_t>(g());
        const auto r32 = static_cast<std::uint32_t>(g());
        for (int v = 0; v < mba::kAddVariants; ++v)
            REQUIRE(mba::add<std::uint32_t>(a32, b32, r32, v) ==
                    static_cast<std::uint32_t>(a32 + b32));
        for (int v = 0; v < mba::kMulVariants; ++v)
            REQUIRE(mba::mul<std::uint32_t>(a32, b32, r32, v, 32) ==
                    static_cast<std::uint32_t>(a32 * b32));

        const auto a64 = g(), b64 = g(), r64 = g();
        for (int v = 0; v < mba::kSubVariants; ++v)
            REQUIRE(mba::sub<std::uint64_t>(a64, b64, r64, v) == a64 - b64);
        for (int v = 0; v < mba::kMulVariants; ++v)
            REQUIRE(mba::mul<std::uint64_t>(a64, b64, r64, v, 64) == a64 * b64);
    }
}
