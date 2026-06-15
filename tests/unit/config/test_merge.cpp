// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Unit tests for morok::config::merge precedence.

#include "doctest.h"

#include "morok/config/Resolver.hpp"

using namespace morok::config;

TEST_CASE("merge copies set fields and leaves unset ones untouched") {
    PassConfig dst;
    dst.bcf.probability = 10u;
    dst.bcf.iterations = 1u;

    PassConfig src;
    src.bcf.probability = 90u; // set → overrides
    // src.bcf.iterations unset → dst keeps its value

    merge(dst, src);
    CHECK(dst.bcf.probability == 90u);
    CHECK(dst.bcf.iterations == 1u);
}

TEST_CASE("merge fills previously-unset fields from src") {
    PassConfig dst;
    PassConfig src;
    src.mba.enabled = true;
    src.mba.layers = 3u;

    merge(dst, src);
    CHECK(dst.mba.enabled == true);
    CHECK(dst.mba.layers == 3u);
}

TEST_CASE("merge replaces non-empty string vectors but not empty ones") {
    PassConfig dst;
    dst.str_enc.skip_content = {"keep"};

    PassConfig src; // empty skip_content → must not clobber
    merge(dst, src);
    REQUIRE(dst.str_enc.skip_content.size() == 1);
    CHECK(dst.str_enc.skip_content[0] == "keep");

    src.str_enc.skip_content = {"a", "b"};
    merge(dst, src);
    REQUIRE(dst.str_enc.skip_content.size() == 2);
    CHECK(dst.str_enc.skip_content[0] == "a");
}

TEST_CASE("merge is layerable: preset base then targeted overrides") {
    PassConfig eff = presetConfig(Preset::Mid);
    CHECK(eff.const_enc.share_count == 3u);

    PassConfig override_;
    override_.const_enc.share_count = 6u;
    override_.bcf.probability = 90u;
    merge(eff, override_);

    CHECK(eff.const_enc.share_count == 6u); // overridden
    CHECK(eff.bcf.probability == 90u);      // overridden
    CHECK(eff.mba.layers == 2u);            // preserved from preset
    CHECK(eff.flatten.enabled == true);     // preserved from preset
}

TEST_CASE("merge handles every pass family") {
    PassConfig dst;
    PassConfig src;
    src.split.splits = 8u;
    src.vec.width = 512u;
    src.csm.warmup = 256u;
    src.indir_branch.enabled = true;
    src.func_wrap.times = 3u;
    src.fco.enabled = true;
    src.anti_dbg.enabled = true;
    merge(dst, src);
    CHECK(dst.split.splits == 8u);
    CHECK(dst.vec.width == 512u);
    CHECK(dst.csm.warmup == 256u);
    CHECK(dst.indir_branch.enabled == true);
    CHECK(dst.func_wrap.times == 3u);
    CHECK(dst.fco.enabled == true);
    CHECK(dst.anti_dbg.enabled == true);
}
