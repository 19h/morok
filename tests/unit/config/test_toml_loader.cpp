// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Unit tests for morok::config TOML loading.

#include "doctest.h"

#include "morok/config/Resolver.hpp"
#include "morok/config/TomlLoader.hpp"

using namespace morok::config;

TEST_CASE("empty document parses to all-default config") {
    const auto r = loadFromString("");
    REQUIRE(r.ok);
    CHECK(r.config.preset == Preset::None);
    CHECK(r.config.seed == 0u);
    CHECK(r.config.demangle_names == true);
    CHECK(r.config.policies.empty());
}

TEST_CASE("global section is parsed") {
    const auto r = loadFromString(R"(
    [global]
    preset = "high"
    seed = 0xDEADBEEF1337
    verbose = true
    demangle_names = false
  )");
    REQUIRE(r.ok);
    CHECK(r.config.preset == Preset::High);
    CHECK(r.config.seed == 0xDEADBEEF1337ULL);
    CHECK(r.config.verbose == true);
    CHECK(r.config.demangle_names == false);
}

TEST_CASE("preset is the base and [passes.*] overrides it") {
    const auto r = loadFromString(R"(
    [global]
    preset = "mid"
    [passes.bcf]
    probability = 88
    [passes.constant_encryption]
    share_count = 6
    feistel = true
  )");
    REQUIRE(r.ok);
    // From the mid preset base:
    CHECK(r.config.passes.mba.layers == 2u);
    CHECK(r.config.passes.flatten.enabled == true);
    // Overridden by [passes.*]:
    CHECK(r.config.passes.bcf.probability == 88u);
    CHECK(r.config.passes.const_enc.share_count == 6u);
    CHECK(r.config.passes.const_enc.feistel == true);
}

TEST_CASE("string-array filters are parsed") {
    const auto r = loadFromString(R"(
    [passes.string_encryption]
    enabled = true
    probability = 100
    skip_content = ["Usage:", "debug"]
    force_content = ["secret", "key"]
    [passes.constant_encryption]
    force_value = ["0xDEADBEEF", "0xCAFEBABE"]
  )");
    REQUIRE(r.ok);
    REQUIRE(r.config.passes.str_enc.skip_content.size() == 2);
    CHECK(r.config.passes.str_enc.skip_content[0] == "Usage:");
    REQUIRE(r.config.passes.str_enc.force_content.size() == 2);
    CHECK(r.config.passes.str_enc.force_content[1] == "key");
    REQUIRE(r.config.passes.const_enc.force_value.size() == 2);
    CHECK(r.config.passes.const_enc.force_value[0] == "0xDEADBEEF");
}

TEST_CASE("policy array is parsed in order with inline overrides") {
    const auto r = loadFromString(R"(
    [[policy]]
    module = ".*crypto.*"
    function = ".*encrypt.*"
    preset = "high"
    passes.bcf.probability = 90

    [[policy]]
    module = ".*"
    function = "^main$"
    passes.bcf.enabled = false
    passes.substitution.enabled = false
  )");
    REQUIRE(r.ok);
    REQUIRE(r.config.policies.size() == 2);
    CHECK(r.config.policies[0].module_regex == ".*crypto.*");
    CHECK(r.config.policies[0].func_regex == ".*encrypt.*");
    CHECK(r.config.policies[0].preset == Preset::High);
    CHECK(r.config.policies[0].overrides.bcf.probability == 90u);
    CHECK(r.config.policies[1].func_regex == "^main$");
    CHECK(r.config.policies[1].overrides.bcf.enabled == false);
    CHECK(r.config.policies[1].overrides.sub.enabled == false);
}

TEST_CASE("loaded policies resolve end-to-end") {
    const auto r = loadFromString(R"(
    [global]
    preset = "low"
    [[policy]]
    module = ".*app.*"
    function = "^core$"
    preset = "high"
  )");
    REQUIRE(r.ok);
    // core in app.c → upgraded to high
    CHECK(resolve(r.config, "src/app.c", "core").csm.enabled == true);
    // other functions stay at the low global base
    CHECK(resolve(r.config, "src/app.c", "helper").csm.enabled == false);
}

TEST_CASE("malformed TOML reports an error instead of throwing") {
    const auto r = loadFromString("this is = = not valid toml [[[");
    CHECK_FALSE(r.ok);
    CHECK_FALSE(r.error.empty());
    // Defaults are returned so callers can proceed safely.
    CHECK(r.config.preset == Preset::None);
}

TEST_CASE("missing file reports an error") {
    const auto r = loadFromFile("/nonexistent/path/morok-does-not-exist.toml");
    CHECK_FALSE(r.ok);
    CHECK_FALSE(r.error.empty());
}
