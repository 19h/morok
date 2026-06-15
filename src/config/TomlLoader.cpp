// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/config/TomlLoader.cpp — TOML → Config parsing (toml++).
//
// Parsing is exception-isolated: toml++ may throw on malformed input, but every
// error is caught and converted into a LoadResult, so no exception escapes this
// translation unit into the (exception-free) LLVM layers that link it.

#include "morok/config/TomlLoader.hpp"

#define TOML_IMPLEMENTATION
#include "toml.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace morok::config {

namespace {

using Node = toml::node_view<const toml::node>;

Opt<std::uint32_t> readU32(const Node &v) {
    if (auto i = v.value<std::int64_t>())
        return static_cast<std::uint32_t>(*i);
    return std::nullopt;
}

Opt<bool> readBool(const Node &v) {
    if (auto b = v.value<bool>())
        return *b;
    return std::nullopt;
}

void readStrArr(const Node &v, std::vector<std::string> &out) {
    if (const auto *arr = v.as_array())
        for (const auto &el : *arr)
            if (auto s = el.value<std::string>())
                out.push_back(*s);
}

void parseBcf(const toml::table &t, BcfConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.iterations = readU32(t["iterations"]);
    c.complexity = readU32(t["complexity"]);
    c.entropy_chain = readBool(t["entropy_chain"]);
    c.junk_asm = readBool(t["junk_asm"]);
    c.junk_asm_min = readU32(t["junk_asm_min"]);
    c.junk_asm_max = readU32(t["junk_asm_max"]);
}

void parseSub(const toml::table &t, SubConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.iterations = readU32(t["iterations"]);
}

void parseMba(const toml::table &t, MbaConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.layers = readU32(t["layers"]);
    c.heuristic = readBool(t["heuristic"]);
}

void parseSplit(const toml::table &t, SplitConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.splits = readU32(t["splits"]);
    c.stack_confusion = readBool(t["stack_confusion"]);
}

void parseStrEnc(const toml::table &t, StrEncConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    readStrArr(t["skip_content"], c.skip_content);
    readStrArr(t["force_content"], c.force_content);
}

void parseConstEnc(const toml::table &t, ConstEncConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.iterations = readU32(t["iterations"]);
    c.share_count = readU32(t["share_count"]);
    c.feistel = readBool(t["feistel"]);
    c.substitute_xor = readBool(t["substitute_xor"]);
    c.substitute_xor_prob = readU32(t["substitute_xor_prob"]);
    c.globalize = readBool(t["globalize"]);
    c.globalize_prob = readU32(t["globalize_prob"]);
    readStrArr(t["skip_value"], c.skip_value);
    readStrArr(t["force_value"], c.force_value);
}

void parseVec(const toml::table &t, VecConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.width = readU32(t["width"]);
    c.shuffle = readBool(t["shuffle"]);
    c.lift_comparisons = readBool(t["lift_comparisons"]);
}

void parseCsm(const toml::table &t, CsmConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.nested_dispatch = readBool(t["nested_dispatch"]);
    c.warmup = readU32(t["warmup"]);
}

void parseFuncWrap(const toml::table &t, PassConfig::FuncWrapConfig &c) {
    c.enabled = readBool(t["enabled"]);
    c.probability = readU32(t["probability"]);
    c.times = readU32(t["times"]);
}

void parseToggle(const toml::table &t, ToggleConfig &c) {
    c.enabled = readBool(t["enabled"]);
}

void parsePasses(const toml::table &p, PassConfig &pc) {
    if (auto *t = p["bcf"].as_table())
        parseBcf(*t, pc.bcf);
    if (auto *t = p["substitution"].as_table())
        parseSub(*t, pc.sub);
    if (auto *t = p["mba"].as_table())
        parseMba(*t, pc.mba);
    if (auto *t = p["split_blocks"].as_table())
        parseSplit(*t, pc.split);
    if (auto *t = p["string_encryption"].as_table())
        parseStrEnc(*t, pc.str_enc);
    if (auto *t = p["constant_encryption"].as_table())
        parseConstEnc(*t, pc.const_enc);
    if (auto *t = p["vector_obfuscation"].as_table())
        parseVec(*t, pc.vec);
    if (auto *t = p["chaos_state_machine"].as_table())
        parseCsm(*t, pc.csm);
    if (auto *t = p["flattening"].as_table())
        parseToggle(*t, pc.flatten);
    if (auto *t = p["indirect_branch"].as_table())
        parseToggle(*t, pc.indir_branch);
    if (auto *t = p["function_wrapper"].as_table())
        parseFuncWrap(*t, pc.func_wrap);
    if (auto *t = p["function_call_obfuscate"].as_table())
        parseToggle(*t, pc.fco);
    if (auto *t = p["anti_hooking"].as_table())
        parseToggle(*t, pc.anti_hook);
    if (auto *t = p["anti_debugging"].as_table())
        parseToggle(*t, pc.anti_dbg);
    if (auto *t = p["anti_class_dump"].as_table())
        parseToggle(*t, pc.anti_class_dump);
}

Policy parsePolicy(const toml::table &pt) {
    Policy pol;
    if (auto v = pt["module"].value<std::string>())
        pol.module_regex = *v;
    if (auto v = pt["function"].value<std::string>())
        pol.func_regex = *v;
    if (auto v = pt["preset"].value<std::string>())
        pol.preset = parsePreset(*v);
    if (auto *passes = pt["passes"].as_table())
        parsePasses(*passes, pol.overrides);
    return pol;
}

Config buildConfig(const toml::table &tbl) {
    Config cfg;
    if (const auto *global = tbl["global"].as_table()) {
        if (auto v = (*global)["preset"].value<std::string>())
            cfg.preset = parsePreset(*v);
        if (auto v = (*global)["seed"].value<std::int64_t>())
            cfg.seed = static_cast<std::uint64_t>(*v);
        if (auto v = (*global)["verbose"].value<bool>())
            cfg.verbose = *v;
        if (auto v = (*global)["trace"].value<bool>())
            cfg.trace = *v;
        if (auto v = (*global)["demangle_names"].value<bool>())
            cfg.demangle_names = *v;
    }

    // Preset is the lowest-priority base for pass parameters.
    if (cfg.preset != Preset::None)
        cfg.passes = presetConfig(cfg.preset);

    // [passes.*] overrides on top of the preset.
    if (const auto *passes = tbl["passes"].as_table())
        parsePasses(*passes, cfg.passes);

    // Ordered [[policy]] rules.
    if (const auto *arr = tbl["policy"].as_array())
        for (const auto &el : *arr)
            if (const auto *t = el.as_table())
                cfg.policies.push_back(parsePolicy(*t));

    return cfg;
}

} // namespace

LoadResult loadFromString(std::string_view toml_text) {
    LoadResult r;
    try {
        auto tbl = toml::parse(toml_text);
        r.config = buildConfig(tbl);
        r.ok = true;
    } catch (const toml::parse_error &e) {
        r.error = std::string("TOML parse error: ") + e.what();
    } catch (const std::exception &e) {
        r.error = std::string("config error: ") + e.what();
    }
    return r;
}

LoadResult loadFromFile(std::string_view path) {
    LoadResult r;
    try {
        auto tbl = toml::parse_file(path);
        r.config = buildConfig(tbl);
        r.ok = true;
    } catch (const toml::parse_error &e) {
        r.error = std::string("TOML parse error: ") + e.what();
    } catch (const std::exception &e) {
        r.error = std::string("config error: ") + e.what();
    }
    return r;
}

} // namespace morok::config
