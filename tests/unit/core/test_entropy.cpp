// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Unit tests for morok::core entropy seeding.  The mixing is pure and tested
// deterministically; the collection is exercised only for liveness.

#include "doctest.h"

#include "morok/core/Entropy.hpp"

#include <cstdint>

using namespace morok::core;

TEST_CASE("seedWords is a pure deterministic function of its sources") {
    EntropySources s;
    s.wallClockNs = 0x1111111111111111ULL;
    s.stackHash = 0x2222222222222222ULL;
    s.heapHash = 0x3333333333333333ULL;
    s.cycleCounter = 0x4444444444444444ULL;
    s.pid = 0x5555555555555555ULL;
    const auto a = s.seedWords();
    const auto b = s.seedWords();
    CHECK(a == b);
}

TEST_CASE("seedWords mixes every source into the words") {
    EntropySources base;
    const auto w0 = base.seedWords();
    // Flipping any single source must change at least one seed word.
    for (std::uint64_t EntropySources::*field :
         {&EntropySources::wallClockNs, &EntropySources::stackHash,
          &EntropySources::heapHash, &EntropySources::cycleCounter,
          &EntropySources::pid, &EntropySources::hwA, &EntropySources::hwC}) {
        EntropySources s;
        s.*field = 0xA5A5A5A5A5A5A5A5ULL;
        CHECK(s.seedWords() != w0);
    }
}

TEST_CASE("makeEngine is deterministic given fixed sources") {
    EntropySources s;
    s.wallClockNs = 0xDEADBEEF;
    s.pid = 0x1234;
    auto e1 = makeEngine(s);
    auto e2 = makeEngine(s);
    for (int i = 0; i < 100; ++i)
        CHECK(e1() == e2());
}

TEST_CASE("collectEntropy produces a usable, non-degenerate seed") {
    const EntropySources s = collectEntropy();
    const auto w = s.seedWords();
    CHECK((w[0] | w[1] | w[2] | w[3]) != 0);
}

TEST_CASE("makeSeededEngine yields a working generator") {
    auto g = makeSeededEngine();
    bool anyNonZero = false;
    for (int i = 0; i < 16; ++i)
        anyNonZero |= (g() != 0);
    CHECK(anyNonZero);
}
