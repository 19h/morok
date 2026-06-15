// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/config/Resolver.cpp — merge and policy resolution.

#include "morok/config/Resolver.hpp"

#include <regex>
#include <string>

namespace morok::config {

namespace {

// Copy a set optional from src to dst.
template <class T> void mergeOpt(Opt<T> &dst, const Opt<T> &src) {
    if (src.has_value())
        dst = src;
}
// Replace dst with src when src is non-empty.
void mergeVec(std::vector<std::string> &dst,
              const std::vector<std::string> &src) {
    if (!src.empty())
        dst = src;
}

// Match `text` against an ECMAScript regex; invalid patterns never throw out.
bool regexSearch(const std::string &pattern, const std::string &text) {
    try {
        std::regex re(pattern, std::regex::ECMAScript | std::regex::optimize);
        return std::regex_search(text, re);
    } catch (const std::regex_error &) {
        return false;
    }
}

} // namespace

void merge(PassConfig &dst, const PassConfig &src) {
    // BCF
    mergeOpt(dst.bcf.enabled, src.bcf.enabled);
    mergeOpt(dst.bcf.probability, src.bcf.probability);
    mergeOpt(dst.bcf.iterations, src.bcf.iterations);
    mergeOpt(dst.bcf.complexity, src.bcf.complexity);
    mergeOpt(dst.bcf.entropy_chain, src.bcf.entropy_chain);
    mergeOpt(dst.bcf.junk_asm, src.bcf.junk_asm);
    mergeOpt(dst.bcf.junk_asm_min, src.bcf.junk_asm_min);
    mergeOpt(dst.bcf.junk_asm_max, src.bcf.junk_asm_max);
    // Sub
    mergeOpt(dst.sub.enabled, src.sub.enabled);
    mergeOpt(dst.sub.probability, src.sub.probability);
    mergeOpt(dst.sub.iterations, src.sub.iterations);
    // MBA
    mergeOpt(dst.mba.enabled, src.mba.enabled);
    mergeOpt(dst.mba.probability, src.mba.probability);
    mergeOpt(dst.mba.layers, src.mba.layers);
    mergeOpt(dst.mba.heuristic, src.mba.heuristic);
    // Split
    mergeOpt(dst.split.enabled, src.split.enabled);
    mergeOpt(dst.split.splits, src.split.splits);
    mergeOpt(dst.split.stack_confusion, src.split.stack_confusion);
    // StrEnc
    mergeOpt(dst.str_enc.enabled, src.str_enc.enabled);
    mergeOpt(dst.str_enc.probability, src.str_enc.probability);
    mergeVec(dst.str_enc.skip_content, src.str_enc.skip_content);
    mergeVec(dst.str_enc.force_content, src.str_enc.force_content);
    // ConstEnc
    mergeOpt(dst.const_enc.enabled, src.const_enc.enabled);
    mergeOpt(dst.const_enc.iterations, src.const_enc.iterations);
    mergeOpt(dst.const_enc.share_count, src.const_enc.share_count);
    mergeOpt(dst.const_enc.feistel, src.const_enc.feistel);
    mergeOpt(dst.const_enc.substitute_xor, src.const_enc.substitute_xor);
    mergeOpt(dst.const_enc.substitute_xor_prob,
             src.const_enc.substitute_xor_prob);
    mergeOpt(dst.const_enc.globalize, src.const_enc.globalize);
    mergeOpt(dst.const_enc.globalize_prob, src.const_enc.globalize_prob);
    mergeVec(dst.const_enc.skip_value, src.const_enc.skip_value);
    mergeVec(dst.const_enc.force_value, src.const_enc.force_value);
    // Vec
    mergeOpt(dst.vec.enabled, src.vec.enabled);
    mergeOpt(dst.vec.probability, src.vec.probability);
    mergeOpt(dst.vec.width, src.vec.width);
    mergeOpt(dst.vec.shuffle, src.vec.shuffle);
    mergeOpt(dst.vec.lift_comparisons, src.vec.lift_comparisons);
    // CSM
    mergeOpt(dst.csm.enabled, src.csm.enabled);
    mergeOpt(dst.csm.nested_dispatch, src.csm.nested_dispatch);
    mergeOpt(dst.csm.warmup, src.csm.warmup);
    // Toggles
    mergeOpt(dst.flatten.enabled, src.flatten.enabled);
    mergeOpt(dst.indir_branch.enabled, src.indir_branch.enabled);
    mergeOpt(dst.fco.enabled, src.fco.enabled);
    mergeOpt(dst.anti_hook.enabled, src.anti_hook.enabled);
    mergeOpt(dst.anti_dbg.enabled, src.anti_dbg.enabled);
    mergeOpt(dst.anti_class_dump.enabled, src.anti_class_dump.enabled);
    // FuncWrap
    mergeOpt(dst.func_wrap.enabled, src.func_wrap.enabled);
    mergeOpt(dst.func_wrap.probability, src.func_wrap.probability);
    mergeOpt(dst.func_wrap.times, src.func_wrap.times);
}

PassConfig resolve(const Config &cfg, std::string_view module_name,
                   std::string_view func_name, const Demangler &demangle) {
    PassConfig eff = cfg.passes;

    const std::string module_str(module_name);
    const std::string func_str(func_name);
    std::string demangled;
    if (cfg.demangle_names && demangle && !func_str.empty()) {
        std::string d = demangle(func_name);
        if (d != func_str)
            demangled = std::move(d);
    }

    for (const auto &pol : cfg.policies) {
        if (!regexSearch(pol.module_regex, module_str))
            continue;

        if (!pol.func_regex.empty()) {
            bool matched = regexSearch(pol.func_regex, func_str);
            if (!matched && !demangled.empty())
                matched = regexSearch(pol.func_regex, demangled);
            if (!matched)
                continue;
        }

        if (pol.preset != Preset::None)
            merge(eff, presetConfig(pol.preset));
        merge(eff, pol.overrides);
    }

    return eff;
}

} // namespace morok::config
