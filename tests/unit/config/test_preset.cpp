// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Unit tests for morok::config presets.

#include "doctest.h"

#include "morok/config/Preset.hpp"

using namespace morok::config;

TEST_CASE("preset names round-trip") {
    CHECK(parsePreset("low") == Preset::Low);
    CHECK(parsePreset("mid") == Preset::Mid);
    CHECK(parsePreset("high") == Preset::High);
    CHECK(parsePreset("none") == Preset::None);
    CHECK(parsePreset("") == Preset::None);
    CHECK(parsePreset("bogus") == Preset::None);
    CHECK(presetName(Preset::Low) == "low");
    CHECK(presetName(Preset::Mid) == "mid");
    CHECK(presetName(Preset::High) == "high");
    CHECK(presetName(Preset::None) == "none");
}

TEST_CASE("preset 'none' leaves every field unset") {
    const PassConfig c = presetConfig(Preset::None);
    CHECK_FALSE(c.bcf.enabled.has_value());
    CHECK_FALSE(c.sub.probability.has_value());
    CHECK_FALSE(c.const_enc.share_count.has_value());
    CHECK_FALSE(c.csm.enabled.has_value());
}

TEST_CASE("low preset matches the documented table") {
    const PassConfig c = presetConfig(Preset::Low);
    CHECK(c.bcf.probability == 30u);
    CHECK(c.bcf.complexity == 2u);
    CHECK(c.sub.probability == 40u);
    CHECK(c.mba.layers == 1u);
    CHECK(c.mba.heuristic == false);
    CHECK(c.const_enc.share_count == 2u);
    CHECK(c.const_enc.feistel == false);
    CHECK(c.vec.enabled == false);
    CHECK(c.csm.enabled == false);
    CHECK(c.flatten.enabled == false);
}

TEST_CASE("mid preset matches the documented table") {
    const PassConfig c = presetConfig(Preset::Mid);
    CHECK(c.bcf.probability == 60u);
    CHECK(c.bcf.complexity == 4u);
    CHECK(c.sub.probability == 60u);
    CHECK(c.mba.layers == 2u);
    CHECK(c.mba.heuristic == true);
    CHECK(c.const_enc.share_count == 3u);
    CHECK(c.const_enc.feistel == false);
    CHECK(c.vec.width == 128u);
    CHECK(c.flatten.enabled == true);
    CHECK(c.csm.enabled == false);
    CHECK(c.indir_branch.enabled == true);
}

TEST_CASE("high preset matches the documented table") {
    const PassConfig c = presetConfig(Preset::High);
    CHECK(c.bcf.probability == 75u);
    CHECK(c.bcf.iterations == 2u);
    CHECK(c.bcf.complexity == 6u);
    CHECK(c.bcf.entropy_chain == true);
    CHECK(c.sub.iterations == 2u);
    CHECK(c.mba.layers == 3u);
    CHECK(c.const_enc.share_count == 4u);
    CHECK(c.const_enc.feistel == true);
    CHECK(c.vec.width == 256u);
    CHECK(c.vec.shuffle == true);
    CHECK(c.csm.enabled == true);
    CHECK(c.flatten.enabled == false);
    CHECK(c.func_wrap.enabled == true);
    CHECK(c.fco.enabled == true);
}
