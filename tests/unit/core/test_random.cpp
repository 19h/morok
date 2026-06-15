// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Unit tests for morok::core bounded sampling and scrambling.

#include "doctest.h"

#include "morok/core/Random.hpp"
#include "morok/core/Xoshiro256.hpp"

#include <array>
#include <cstdint>
#include <vector>

using namespace morok::core;

namespace {
// Deterministic generator replaying a fixed queue of 64-bit words (wraps).
// boundedU32 consumes the high 32 bits of each draw, so test words are placed
// in the high half.
struct SeqGen {
    using result_type = std::uint64_t;
    static constexpr result_type min() noexcept { return 0; }
    static constexpr result_type max() noexcept { return ~0ULL; }
    std::vector<std::uint64_t> words;
    std::size_t i = 0;
    result_type operator()() noexcept { return words[i++ % words.size()]; }
};
static constexpr std::uint64_t hi(std::uint32_t v) {
    return static_cast<std::uint64_t>(v) << 32;
}
} // namespace

TEST_CASE("boundedU32 returns 0 for a zero bound") {
    auto g = Xoshiro256pp::fromSeed(1);
    CHECK(boundedU32(g, 0) == 0);
}

TEST_CASE("boundedU32 always stays within [0, bound)") {
    auto g = Xoshiro256pp::fromSeed(7);
    for (std::uint32_t bound :
         {1u, 2u, 3u, 7u, 10u, 256u, 1000u, 0x7FFFFFFFu}) {
        for (int i = 0; i < 5000; ++i) {
            const std::uint32_t v = boundedU32(g, bound);
            CHECK(v < bound);
        }
    }
}

TEST_CASE("boundedU32 covers the whole range for small bounds") {
    auto g = Xoshiro256pp::fromSeed(99);
    for (std::uint32_t bound : {2u, 3u, 5u, 8u}) {
        std::vector<bool> hit(bound, false);
        for (int i = 0; i < 100000; ++i)
            hit[boundedU32(g, bound)] = true;
        for (std::uint32_t v = 0; v < bound; ++v)
            CHECK(hit[v]);
    }
}

TEST_CASE("boundedU32 rejection discards biased low residues") {
    // bound = 3, 2^32 mod 3 == 1, so threshold == 1: the value 0 must be
    // rejected and the next draw used.  Feed hi(0) then hi(3): result should be
    // 3 % 3 == 0 from the SECOND word, proving the first was rejected.
    SeqGen g{{hi(0), hi(3)}};
    CHECK(boundedU32(g, 3) == 0);
    CHECK(g.i == 2); // both words consumed → first was rejected
}

TEST_CASE("rangeU32 maps into [min, max) and clamps inverted ranges") {
    auto g = Xoshiro256pp::fromSeed(123);
    for (int i = 0; i < 5000; ++i) {
        const std::uint32_t v = rangeU32(g, 100, 200);
        CHECK(v >= 100);
        CHECK(v < 200);
    }
    CHECK(rangeU32(g, 50, 50) == 50);
    CHECK(rangeU32(g, 80, 10) == 80);
}

TEST_CASE("chance honours its boundary probabilities") {
    auto g = Xoshiro256pp::fromSeed(5);
    CHECK_FALSE(chance(g, 0));
    CHECK(chance(g, 100));
    CHECK(chance(g, 250)); // saturates at 100
}

TEST_CASE("chance frequency tracks the requested percentage") {
    auto g = Xoshiro256pp::fromSeed(2024);
    int hits = 0;
    constexpr int N = 100000;
    for (int i = 0; i < N; ++i)
        hits += chance(g, 30) ? 1 : 0;
    CHECK(hits > N * 27 / 100);
    CHECK(hits < N * 33 / 100);
}

TEST_CASE("Scrambler maps stably and deterministically") {
    auto g = Xoshiro256pp::fromSeed(0xABCD);
    Scrambler s;
    const std::uint32_t a = s(g, 42);
    CHECK(s(g, 42) == a); // stable on repeat
    const std::uint32_t b = s(g, 43);
    CHECK(s.size() == 2);
    CHECK(a != b); // overwhelmingly likely distinct images
    s.clear();
    CHECK(s.size() == 0);
}
