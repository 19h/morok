// SPDX-License-Identifier: MIT
//
// Unit tests for morok::core::mq — planted MQ gates over GF(2).

#include "doctest.h"

#include "morok/core/MqGf2.hpp"
#include "morok/core/Xoshiro256.hpp"

#include <cstdint>
#include <vector>

namespace mq = morok::core::mq;

TEST_CASE("mq triangular coefficient index is a bijection") {
    for (unsigned m = 1; m <= 16; ++m) {
        std::vector<bool> seen(static_cast<std::size_t>(m) * (m + 1) / 2);
        for (unsigned i = 0; i < m; ++i) {
            for (unsigned j = i; j < m; ++j) {
                const std::size_t idx = mq::triIndex(i, j, m);
                REQUIRE(idx < seen.size());
                CHECK_FALSE(seen[idx]);
                seen[idx] = true;
            }
        }
        for (bool hit : seen)
            CHECK(hit);
    }
}

TEST_CASE("mq evalForm matches a brute force quadratic reference") {
    mq::QuadForm f;
    f.m = 4;
    f.lin = {1, 0, 1, 1};
    f.quad.assign(10, 0);
    f.quad[mq::triIndex(0, 0, f.m)] = 1;
    f.quad[mq::triIndex(0, 2, f.m)] = 1;
    f.quad[mq::triIndex(1, 3, f.m)] = 1;
    f.quad[mq::triIndex(2, 3, f.m)] = 1;
    f.cst = 1;

    for (unsigned mask = 0; mask < 16; ++mask) {
        std::vector<std::uint8_t> x(4);
        for (unsigned bit = 0; bit < 4; ++bit)
            x[bit] = static_cast<std::uint8_t>((mask >> bit) & 1u);

        std::uint8_t ref = f.cst;
        for (unsigned i = 0; i < f.m; ++i)
            ref ^= static_cast<std::uint8_t>(f.lin[i] & x[i]);
        for (unsigned i = 0; i < f.m; ++i)
            for (unsigned j = i; j < f.m; ++j)
                ref ^= static_cast<std::uint8_t>(
                    f.quad[mq::triIndex(i, j, f.m)] & x[i] & x[j]);

        CHECK(mq::evalForm(f, x) == (ref & 1u));
    }
}

TEST_CASE("mq planted gate opens at planted assignment") {
    auto engine = morok::core::Xoshiro256pp::fromSeed(0x4d51);
    const std::vector<std::uint8_t> planted = {
        1, 0, 1, 1, 0, 0, 1, 0,
        1, 1, 0, 1, 0, 1, 0, 0,
    };

    const mq::Gate gate =
        mq::makePlantedGate(16, 12, planted, 55, engine);

    CHECK(gate.forms.size() == 12u);
    CHECK(gate.opens(planted));

    for (const mq::QuadForm &form : gate.forms) {
        CHECK(form.m == planted.size());
        CHECK(form.lin.size() == planted.size());
        CHECK(form.quad.size() == planted.size() * (planted.size() + 1) / 2);
        CHECK(mq::evalForm(form, planted) == 0u);
    }
}

TEST_CASE("mq planted gate rejects a large random non-root sample") {
    auto gateEngine = morok::core::Xoshiro256pp::fromSeed(0x600d);
    auto sampleEngine = morok::core::Xoshiro256pp::fromSeed(0x5a1ad);
    std::vector<std::uint8_t> planted(12);
    for (unsigned i = 0; i < planted.size(); ++i)
        planted[i] = static_cast<std::uint8_t>((i * 5 + 1) & 1u);

    const mq::Gate gate =
        mq::makePlantedGate(12, 20, planted, 50, gateEngine);

    unsigned falseOpens = 0;
    for (unsigned sample = 0; sample < 4096; ++sample) {
        std::vector<std::uint8_t> x(12);
        for (unsigned bit = 0; bit < x.size(); ++bit)
            x[bit] =
                static_cast<std::uint8_t>((sampleEngine() >> bit) & 1u);
        if (x == planted)
            continue;
        if (gate.opens(x))
            ++falseOpens;
    }

    CHECK(falseOpens == 0u);
}
