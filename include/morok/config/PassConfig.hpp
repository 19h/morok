// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/config/PassConfig.hpp — the structured configuration model.
//
// Every per-pass option is an std::optional: "unset" means "fall through to the
// pass's own default".  This lets presets, file settings, and per-function
// policies be layered by merging only the fields each level actually specifies.
// The model is deliberately free of LLVM and I/O so it can be unit-tested in
// isolation; loading (TOML) and resolution (policy/preset merge) are separate
// translation units.

#ifndef MOROK_CONFIG_PASS_CONFIG_HPP
#define MOROK_CONFIG_PASS_CONFIG_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace morok::config {

template <class T> using Opt = std::optional<T>;

struct BcfConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability; // 0–100
    Opt<std::uint32_t> iterations;
    Opt<std::uint32_t> complexity; // predicate depth
    Opt<bool> entropy_chain;
    Opt<bool> junk_asm;
    Opt<std::uint32_t> junk_asm_min;
    Opt<std::uint32_t> junk_asm_max;
};

struct SubConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> iterations;
};

struct MbaConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> layers; // 1–3
    Opt<bool> heuristic;
};

struct SplitConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> splits;
    Opt<bool> stack_confusion;
};

struct StrEncConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    std::vector<std::string> skip_content;
    std::vector<std::string> force_content;
};

struct ConstEncConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> iterations;
    Opt<std::uint32_t> share_count; // 2–8
    Opt<bool> feistel;
    Opt<bool> substitute_xor;
    Opt<std::uint32_t> substitute_xor_prob;
    Opt<bool> globalize;
    Opt<std::uint32_t> globalize_prob;
    std::vector<std::string> skip_value;
    std::vector<std::string> force_value;
};

struct VecConfig {
    Opt<bool> enabled;
    Opt<std::uint32_t> probability;
    Opt<std::uint32_t> width; // 128 | 256 | 512
    Opt<bool> shuffle;
    Opt<bool> lift_comparisons;
};

struct CsmConfig {
    Opt<bool> enabled;
    Opt<bool> nested_dispatch;
    Opt<std::uint32_t> warmup;
};

struct ToggleConfig {
    Opt<bool> enabled;
};

/// The full set of per-pass options.
struct PassConfig {
    BcfConfig bcf;
    SubConfig sub;
    MbaConfig mba;
    SplitConfig split;
    StrEncConfig str_enc;
    ConstEncConfig const_enc;
    VecConfig vec;
    CsmConfig csm;
    ToggleConfig flatten;
    ToggleConfig indir_branch;
    ToggleConfig fco;
    ToggleConfig anti_hook;
    ToggleConfig anti_dbg;
    ToggleConfig anti_class_dump;

    struct FuncWrapConfig {
        Opt<bool> enabled;
        Opt<std::uint32_t> probability;
        Opt<std::uint32_t> times;
    } func_wrap;
};

} // namespace morok::config

#endif // MOROK_CONFIG_PASS_CONFIG_HPP
