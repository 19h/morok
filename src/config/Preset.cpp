// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/config/Preset.cpp — preset intensity tables.
//
//  Preset  BCF prob/loop/compl  Sub prob/loop  MBA prob/layers  ConstEnc
//  k/feistel  Vec  CSM low     30 / 1 / 2           40 / 1         30 / 1 2 /
//  no              off  off mid     60 / 1 / 4           60 / 1         50 / 2
//  3 / no              128  off high    75 / 2 / 6           80 / 2         70
//  / 3           4 / yes             256  on

#include "morok/config/Preset.hpp"

namespace morok::config {

Preset parsePreset(std::string_view name) noexcept {
    if (name == "low")
        return Preset::Low;
    if (name == "mid")
        return Preset::Mid;
    if (name == "high")
        return Preset::High;
    return Preset::None;
}

std::string_view presetName(Preset p) noexcept {
    switch (p) {
    case Preset::Low:
        return "low";
    case Preset::Mid:
        return "mid";
    case Preset::High:
        return "high";
    case Preset::None:
        break;
    }
    return "none";
}

namespace {

PassConfig makeLow() {
    PassConfig c;
    c.bcf.enabled = true;
    c.bcf.probability = 30;
    c.bcf.iterations = 1;
    c.bcf.complexity = 2;
    c.bcf.entropy_chain = false;
    c.bcf.junk_asm = false;
    c.bcf.junk_asm_min = 0;
    c.bcf.junk_asm_max = 0;

    c.sub.enabled = true;
    c.sub.probability = 40;
    c.sub.iterations = 1;

    c.mba.enabled = true;
    c.mba.probability = 30;
    c.mba.layers = 1;
    c.mba.heuristic = false;

    c.str_enc.enabled = true;
    c.str_enc.probability = 70;

    c.const_enc.enabled = true;
    c.const_enc.iterations = 1;
    c.const_enc.share_count = 2;
    c.const_enc.feistel = false;
    c.const_enc.substitute_xor = false;
    c.const_enc.substitute_xor_prob = 0;
    c.const_enc.globalize = false;
    c.const_enc.globalize_prob = 0;

    c.split.enabled = true;
    c.split.splits = 2;
    c.split.stack_confusion = false;

    c.vec.enabled = false;
    c.csm.enabled = false;
    c.flatten.enabled = false;
    c.indir_branch.enabled = false;
    c.func_wrap.enabled = false;
    c.fco.enabled = false;
    c.anti_hook.enabled = false;
    c.anti_dbg.enabled = false;
    c.anti_class_dump.enabled = false;
    return c;
}

PassConfig makeMid() {
    PassConfig c;
    c.bcf.enabled = true;
    c.bcf.probability = 60;
    c.bcf.iterations = 1;
    c.bcf.complexity = 4;
    c.bcf.entropy_chain = false;
    c.bcf.junk_asm = false;
    c.bcf.junk_asm_min = 2;
    c.bcf.junk_asm_max = 4;

    c.sub.enabled = true;
    c.sub.probability = 60;
    c.sub.iterations = 1;

    c.mba.enabled = true;
    c.mba.probability = 50;
    c.mba.layers = 2;
    c.mba.heuristic = true;

    c.str_enc.enabled = true;
    c.str_enc.probability = 100;

    c.const_enc.enabled = true;
    c.const_enc.iterations = 1;
    c.const_enc.share_count = 3;
    c.const_enc.feistel = false;
    c.const_enc.substitute_xor = true;
    c.const_enc.substitute_xor_prob = 40;
    c.const_enc.globalize = false;
    c.const_enc.globalize_prob = 50;

    c.split.enabled = true;
    c.split.splits = 3;
    c.split.stack_confusion = true;

    c.vec.enabled = true;
    c.vec.probability = 40;
    c.vec.width = 128;
    c.vec.shuffle = false;
    c.vec.lift_comparisons = true;

    c.csm.enabled = false;
    c.flatten.enabled = true;
    c.indir_branch.enabled = true;

    c.func_wrap.enabled = false;
    c.fco.enabled = false;
    c.anti_hook.enabled = false;
    c.anti_dbg.enabled = false;
    c.anti_class_dump.enabled = false;
    return c;
}

PassConfig makeHigh() {
    PassConfig c;
    c.bcf.enabled = true;
    c.bcf.probability = 75;
    c.bcf.iterations = 2;
    c.bcf.complexity = 6;
    c.bcf.entropy_chain = true;
    c.bcf.junk_asm = true;
    c.bcf.junk_asm_min = 2;
    c.bcf.junk_asm_max = 4;

    c.sub.enabled = true;
    c.sub.probability = 80;
    c.sub.iterations = 2;

    c.mba.enabled = true;
    c.mba.probability = 70;
    c.mba.layers = 3;
    c.mba.heuristic = true;

    c.str_enc.enabled = true;
    c.str_enc.probability = 100;

    c.const_enc.enabled = true;
    c.const_enc.iterations = 2;
    c.const_enc.share_count = 4;
    c.const_enc.feistel = true;
    c.const_enc.substitute_xor = true;
    c.const_enc.substitute_xor_prob = 60;
    c.const_enc.globalize = false;
    c.const_enc.globalize_prob = 50;

    c.split.enabled = true;
    c.split.splits = 5;
    c.split.stack_confusion = true;

    c.vec.enabled = true;
    c.vec.probability = 65;
    c.vec.width = 256;
    c.vec.shuffle = true;
    c.vec.lift_comparisons = true;

    c.csm.enabled = true;
    c.csm.nested_dispatch = false;
    c.csm.warmup = 128;
    c.flatten.enabled = false;

    c.indir_branch.enabled = true;

    c.func_wrap.enabled = true;
    c.func_wrap.probability = 50;
    c.func_wrap.times = 1;

    c.fco.enabled = true;

    c.anti_hook.enabled = false;
    c.anti_dbg.enabled = false;
    c.anti_class_dump.enabled = false;
    return c;
}

} // namespace

PassConfig presetConfig(Preset p) {
    switch (p) {
    case Preset::Low:
        return makeLow();
    case Preset::Mid:
        return makeMid();
    case Preset::High:
        return makeHigh();
    case Preset::None:
        break;
    }
    return {};
}

} // namespace morok::config
