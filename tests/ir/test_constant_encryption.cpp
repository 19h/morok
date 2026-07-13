// SPDX-License-Identifier: MIT
//
// Tests for ConstantEncryption — hide scalar int/FP literals behind XOR secret
// shares (plus optional Feistel / substitute-XOR / globalize layers), and lower
// wide-magic switches into encrypted equality chains.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/ConstantEncryption.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;
using namespace morok::test;

namespace {

// A well-mixed function with three wide-magic constants across binops.
const char *kArith = R"ir(
define i32 @arith(i32 %a, i32 %b) {
entry:
  %0 = add i32 %a, 305419896
  %1 = mul i32 %0, 305419896
  %2 = sub i32 %1, 19088743
  ret i32 %2
}
)ir";

// A single add carrying exactly one encryptable literal.
const char *kHide = R"ir(
define i32 @hide(i32 %x) {
entry:
  %r = add i32 %x, 305419896
  ret i32 %r
}
)ir";

// Exactly one eligible constant in the whole function (the return value).
const char *kOneConst = R"ir(
define i32 @one() {
entry:
  ret i32 305419896
}
)ir";

// A decision gate: a wide-magic compare next to an untouched wide-magic add.
const char *kGate = R"ir(
define i32 @gate(i32 %x) {
entry:
  %cmp = icmp eq i32 %x, 305419896
  %keepadd = add i32 %x, 19088743
  %sel = select i1 %cmp, i32 %keepadd, i32 0
  ret i32 %sel
}
)ir";

// A switch whose only case value is a wide magic (a folded license chain).
const char *kSwitchMagic = R"ir(
define i32 @dispatch(i32 %x) {
entry:
  switch i32 %x, label %def [
    i32 305419896, label %hit
  ]
hit:
  ret i32 1
def:
  ret i32 0
}
)ir";

// A dense small-value switch (jump-table dispatch) — no wide magic.
const char *kSwitchSmall = R"ir(
define i32 @dispatch_small(i32 %x) {
entry:
  switch i32 %x, label %def [
    i32 1, label %a
    i32 2, label %b
  ]
a:
  ret i32 10
b:
  ret i32 20
def:
  ret i32 0
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

} // namespace

TEST_CASE("constantEncryptFunction grows the function and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t binopsBefore = countBinops(*F);

    morok::passes::ConstEncParams params;
    params.probability = 100u;
    params.share_count = 2u;

    auto rng = makeRng(1);
    CHECK(morok::passes::constantEncryptFunction(*F, params, rng));
    // Each of the three literals reconstructs from >=1 volatile XOR, so the
    // binop count strictly grows and two share globals appear per constant.
    CHECK(countBinops(*F) > binopsBefore);
    CHECK(countGlobals(*M, "morok.share") >= std::size_t{6});
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("constantEncryptFunction respects probability=0 as a no-op") {
    LLVMContext ctx;
    auto M = parse(ctx, kHide);
    Function *F = M->getFunction("hide");
    REQUIRE(F);

    morok::passes::ConstEncParams params;
    params.probability = 0u;

    auto rng = makeRng(2);
    CHECK_FALSE(morok::passes::constantEncryptFunction(*F, params, rng));
    // Nothing emitted; the literal is still a plain operand of the add.
    CHECK(countGlobals(*M, "morok.share") == std::size_t{0});
    CHECK(instructionHasConstantOperand(findNamedInstruction(*F, "r"),
                                        305419896));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("constantEncryptFunction is safe on declarations and "
          "constant-free functions") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare i32 @ext(i32)

define i32 @id(i32 %x) {
entry:
  ret i32 %x
}

define void @empty() {
entry:
  ret void
}
)ir");

    morok::passes::ConstEncParams params;
    params.probability = 100u;

    auto rng = makeRng(3);
    CHECK_FALSE(morok::passes::constantEncryptFunction(*M->getFunction("ext"),
                                                       params, rng));
    CHECK_FALSE(morok::passes::constantEncryptFunction(*M->getFunction("id"),
                                                       params, rng));
    CHECK_FALSE(morok::passes::constantEncryptFunction(*M->getFunction("empty"),
                                                       params, rng));
    CHECK(countGlobals(*M, "morok.share") == std::size_t{0});
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("constantEncryptFunction removes the plaintext literal operand") {
    LLVMContext ctx;
    auto M = parse(ctx, kHide);
    Function *F = M->getFunction("hide");
    REQUIRE(F);
    CHECK(instructionHasConstantOperand(findNamedInstruction(*F, "r"),
                                        305419896));

    morok::passes::ConstEncParams params;
    params.probability = 100u;

    auto rng = makeRng(4);
    CHECK(morok::passes::constantEncryptFunction(*F, params, rng));
    // The add's literal operand is now a runtime reconstruction, never 0x12345678.
    CHECK_FALSE(instructionHasConstantOperand(findNamedInstruction(*F, "r"),
                                              305419896));
    CHECK(countGlobals(*M, "morok.share") >= std::size_t{2});
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("constantEncryptFunction clamps share_count to [2,8]") {
    morok::passes::ConstEncParams high;
    high.probability = 100u;
    high.share_count = 100u; // clamps down to kMaxShares (8)

    morok::passes::ConstEncParams low;
    low.probability = 100u;
    low.share_count = 1u; // clamps up to kMinShares (2)

    morok::passes::ConstEncParams zero;
    zero.probability = 100u;
    zero.share_count = 0u; // clamps up to kMinShares (2)

    LLVMContext ctx;
    auto Mhigh = parse(ctx, kOneConst);
    auto Mlow = parse(ctx, kOneConst);
    auto Mzero = parse(ctx, kOneConst);

    auto rngHigh = makeRng(5);
    auto rngLow = makeRng(6);
    auto rngZero = makeRng(7);
    CHECK(morok::passes::constantEncryptFunction(*Mhigh->getFunction("one"),
                                                 high, rngHigh));
    CHECK(morok::passes::constantEncryptFunction(*Mlow->getFunction("one"), low,
                                                 rngLow));
    CHECK(morok::passes::constantEncryptFunction(*Mzero->getFunction("one"),
                                                 zero, rngZero));

    // Exactly one constant, so the share-global count equals the clamped k.
    CHECK(countGlobals(*Mhigh, "morok.share") == std::size_t{8});
    CHECK(countGlobals(*Mlow, "morok.share") == std::size_t{2});
    CHECK(countGlobals(*Mzero, "morok.share") == std::size_t{2});
    CHECK_FALSE(verifyModule(*Mhigh));
    CHECK_FALSE(verifyModule(*Mlow));
    CHECK_FALSE(verifyModule(*Mzero));
}

TEST_CASE("constantEncryptFunction feistel, substitute and globalize layers "
          "emit their channels") {
    LLVMContext ctx;
    auto Mlayered = parse(ctx, kHide);
    auto Mplain = parse(ctx, kHide);

    morok::passes::ConstEncParams layered;
    layered.probability = 100u;
    layered.share_count = 2u;
    layered.feistel = true;            // 4-round inverse -> multiplies
    layered.substitute_xor = true;     // runtime-key XOR -> morok.subkey
    layered.substitute_xor_prob = 100u;
    layered.globalize = true;          // route via morok.const.global
    layered.globalize_prob = 100u;

    morok::passes::ConstEncParams plain;
    plain.probability = 100u;
    plain.share_count = 2u;

    auto rngLayered = makeRng(8);
    auto rngPlain = makeRng(9);
    CHECK(morok::passes::constantEncryptFunction(*Mlayered->getFunction("hide"),
                                                 layered, rngLayered));
    CHECK(morok::passes::constantEncryptFunction(*Mplain->getFunction("hide"),
                                                 plain, rngPlain));

    Function *Fl = Mlayered->getFunction("hide");
    REQUIRE(Fl);
    // Feistel decrypt is the only source of multiplies here (the source add has
    // none); substitute and globalize add their own named channels.
    CHECK(countOpcode(*Mlayered, Instruction::Mul) >= std::size_t{1});
    CHECK(countGlobals(*Mlayered, "morok.subkey") >= std::size_t{1});
    CHECK(countGlobals(*Mlayered, "morok.const.global") >= std::size_t{1});
    CHECK(findNamedInstruction(*Fl, "morok.sub.undo") != nullptr);
    CHECK(findNamedInstruction(*Fl, "morok.const.global.load") != nullptr);
    CHECK_FALSE(verifyModule(*Mlayered));

    // The plain path uses only volatile loads + XOR: no multiplies, no keys.
    CHECK(countOpcode(*Mplain, Instruction::Mul) == std::size_t{0});
    CHECK(countGlobals(*Mplain, "morok.subkey") == std::size_t{0});
    CHECK(countGlobals(*Mplain, "morok.const.global") == std::size_t{0});
    CHECK_FALSE(verifyModule(*Mplain));
}

TEST_CASE("constantEncryptFunction is deterministic for a fixed seed "
          "and input") {
    LLVMContext ctxA;
    LLVMContext ctxB;
    auto Ma = parse(ctxA, kArith);
    auto Mb = parse(ctxB, kArith);

    morok::passes::ConstEncParams params;
    params.probability = 100u;
    params.share_count = 3u;

    // Two independent engines from the same seed must draw the same sequence,
    // so the transformed modules print byte-identically.
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0x51ED);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0x51ED);
    morok::ir::IRRandom rngA(engineA);
    morok::ir::IRRandom rngB(engineB);
    CHECK(morok::passes::constantEncryptFunction(*Ma->getFunction("arith"),
                                                 params, rngA));
    CHECK(morok::passes::constantEncryptFunction(*Mb->getFunction("arith"),
                                                 params, rngB));

    std::string textA;
    std::string textB;
    {
        raw_string_ostream osa(textA);
        Ma->print(osa, nullptr);
    }
    {
        raw_string_ostream osb(textB);
        Mb->print(osb, nullptr);
    }
    CHECK(textA == textB);
    CHECK_FALSE(verifyModule(*Ma));
    CHECK_FALSE(verifyModule(*Mb));
}

TEST_CASE("constantEncryptFunction conditions_only encrypts only wide "
          "gate magics") {
    LLVMContext ctx;
    auto M = parse(ctx, kGate);
    Function *F = M->getFunction("gate");
    REQUIRE(F);

    morok::passes::ConstEncParams params;
    params.probability = 100u;
    params.conditions_only = true;

    auto rng = makeRng(10);
    CHECK(morok::passes::constantEncryptFunction(*F, params, rng));
    // The compare's magic operand is hidden...
    CHECK_FALSE(instructionHasConstantOperand(
        findNamedInstruction(*F, "cmp"), 305419896));
    // ...but the sibling add (not a decision gate) keeps its literal.
    CHECK(instructionHasConstantOperand(findNamedInstruction(*F, "keepadd"),
                                        19088743));
    CHECK(countGlobals(*M, "morok.share") >= std::size_t{2});
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("constantEncryptFunction deSwitchGateConstantsFunction lowers "
          "wide-magic switches") {
    morok::passes::ConstEncParams params;
    params.probability = 100u;
    params.share_count = 2u;

    // A switch on a wide magic is lowered into an encrypted equality chain.
    {
        LLVMContext ctx;
        auto M = parse(ctx, kSwitchMagic);
        Function *F = M->getFunction("dispatch");
        REQUIRE(F);

        auto rng = makeRng(11);
        CHECK(morok::passes::deSwitchGateConstantsFunction(*F, params, rng));
        CHECK(countOpcode(*M, Instruction::Switch) == std::size_t{0});
        CHECK(findNamedInstruction(*F, "morok.deswitch.eq") != nullptr);
        CHECK(countGlobals(*M, "morok.share") >= std::size_t{2});
        CHECK_FALSE(verifyModule(*M));
    }

    // A dense small-value switch carries no wide magic: left untouched.
    {
        LLVMContext ctx;
        auto M = parse(ctx, kSwitchSmall);
        Function *F = M->getFunction("dispatch_small");
        REQUIRE(F);

        auto rng = makeRng(12);
        CHECK_FALSE(
            morok::passes::deSwitchGateConstantsFunction(*F, params, rng));
        CHECK(countOpcode(*M, Instruction::Switch) == std::size_t{1});
        CHECK(countGlobals(*M, "morok.share") == std::size_t{0});
        CHECK_FALSE(verifyModule(*M));
    }

    // Declarations are skipped without crashing.
    {
        LLVMContext ctx;
        auto M = parse(ctx, R"ir(
declare i32 @ext_switch(i32)
)ir");
        Function *F = M->getFunction("ext_switch");
        REQUIRE(F);

        auto rng = makeRng(13);
        CHECK_FALSE(
            morok::passes::deSwitchGateConstantsFunction(*F, params, rng));
        CHECK_FALSE(verifyModule(*M));
    }
}
