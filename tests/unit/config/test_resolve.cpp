// SPDX-License-Identifier: MIT
//
// Unit tests for morok::config::resolve — per-function policy resolution.

#include "doctest.h"

#include "morok/config/Resolver.hpp"

#include <string>

using namespace morok::config;

TEST_CASE("resolve returns the global config when no policy matches") {
    Config cfg;
    cfg.passes.bcf.probability = 50u;
    Policy p;
    p.module_regex = "nomatch";
    p.overrides.bcf.probability = 99u;
    cfg.policies.push_back(p);

    const PassConfig eff = resolve(cfg, "src/foo.c", "bar");
    CHECK(eff.bcf.probability == 50u);
}

TEST_CASE("a matching policy overrides the global config") {
    Config cfg;
    cfg.passes.bcf.probability = 50u;
    Policy p;
    p.module_regex = ".*crypto.*";
    p.func_regex = ".*encrypt.*";
    p.overrides.bcf.probability = 90u;
    cfg.policies.push_back(p);

    CHECK(resolve(cfg, "src/crypto.c", "do_encrypt").bcf.probability == 90u);
    CHECK(resolve(cfg, "src/crypto.c", "other").bcf.probability == 50u);
    CHECK(resolve(cfg, "src/net.c", "do_encrypt").bcf.probability == 50u);
}

TEST_CASE("policy overrides decoy_strings toggle") {
    Config cfg;
    cfg.passes.decoy_strings.enabled = false;

    Policy p;
    p.module_regex = ".*";
    p.func_regex = "^hot$";
    p.overrides.decoy_strings.enabled = true;
    cfg.policies.push_back(p);

    CHECK(resolve(cfg, "m", "hot").decoy_strings.enabled == true);
    CHECK(resolve(cfg, "m", "cold").decoy_strings.enabled == false);
}

TEST_CASE("module-wide policy (empty function regex) matches every function") {
    Config cfg;
    Policy p;
    p.module_regex = ".*";
    p.overrides.sub.enabled = false;
    cfg.policies.push_back(p);
    CHECK(resolve(cfg, "anything", "main").sub.enabled == false);
}

TEST_CASE("later policies win over earlier ones for the same field") {
    Config cfg;
    Policy a;
    a.module_regex = ".*";
    a.overrides.bcf.probability = 10u;
    Policy b;
    b.module_regex = ".*";
    b.overrides.bcf.probability = 20u;
    cfg.policies.push_back(a);
    cfg.policies.push_back(b);
    CHECK(resolve(cfg, "x", "y").bcf.probability == 20u);
}

TEST_CASE("policy preset applies as a base, with overrides on top") {
    Config cfg;
    Policy p;
    p.module_regex = ".*";
    p.func_regex = "^hot$";
    p.preset = Preset::High;           // base: bcf.prob 75, csm on, ...
    p.overrides.bcf.probability = 99u; // override on top of the preset
    cfg.policies.push_back(p);

    const PassConfig eff = resolve(cfg, "m", "hot");
    CHECK(eff.bcf.probability == 99u); // override wins
    CHECK(eff.csm.enabled == true);    // from the high preset base
    CHECK(eff.mba.layers == 3u);       // from the high preset base
}

TEST_CASE("invalid regexes are skipped, never throw") {
    Config cfg;
    cfg.passes.bcf.probability = 7u;
    Policy bad;
    bad.module_regex = "([unclosed"; // invalid
    bad.overrides.bcf.probability = 99u;
    cfg.policies.push_back(bad);
    CHECK(resolve(cfg, "anything", "fn").bcf.probability == 7u);
}

TEST_CASE("demangled names are matched when a demangler is supplied") {
    Config cfg;
    Policy p;
    p.module_regex = ".*";
    p.func_regex = "my_crate::crypto::.*";
    p.overrides.bcf.enabled = true;
    cfg.policies.push_back(p);

    const Demangler demangle = [](std::string_view s) -> std::string {
        if (s == "_ZN8my_crate6crypto7encryptE")
            return "my_crate::crypto::encrypt";
        return std::string(s);
    };

    // Raw mangled name does not match the human-readable pattern...
    CHECK_FALSE(resolve(cfg, "m", "_ZN8my_crate6crypto7encryptE")
                    .bcf.enabled.has_value());
    // ...but with the demangler it does.
    CHECK(resolve(cfg, "m", "_ZN8my_crate6crypto7encryptE", demangle)
              .bcf.enabled == true);
}

TEST_CASE("demangling is disabled when demangle_names is false") {
    Config cfg;
    cfg.demangle_names = false;
    Policy p;
    p.module_regex = ".*";
    p.func_regex = "readable";
    p.overrides.bcf.enabled = true;
    cfg.policies.push_back(p);
    const Demangler demangle = [](std::string_view) {
        return std::string("readable");
    };
    CHECK_FALSE(resolve(cfg, "m", "mangled", demangle).bcf.enabled.has_value());
}
