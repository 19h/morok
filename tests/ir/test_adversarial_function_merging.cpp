// SPDX-License-Identifier: MIT
//
// Tests for AdversarialFunctionMerging — fuse same-signature functions behind a
// hidden selector dispatcher and outline shared scalar op/compare fragments.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/AdversarialFunctionMerging.hpp"

#include "llvm/IR/Attributes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;
using namespace morok::test;

namespace {

// Three functions sharing the exact signature i32(i32, i32) — one signature
// group with enough members to merge — plus outline-eligible integer ops.
const char *kThreeIntFns = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @alpha(i32 %x, i32 %y) {
entry:
  %a = add i32 %x, %y
  %b = mul i32 %a, %x
  %c = xor i32 %b, %y
  ret i32 %c
}

define i32 @beta(i32 %x, i32 %y) {
entry:
  %d = sub i32 %x, %y
  %e = and i32 %d, %x
  %f = or i32 %e, %y
  ret i32 %f
}

define i32 @gamma(i32 %x, i32 %y) {
entry:
  %g = add i32 %x, %y
  ret i32 %g
}
)ir";

// Two functions with *different* signatures: no signature group ever reaches
// two members, so the pass has nothing to merge.
const char *kDistinctSigFns = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @only_i32(i32 %x) {
entry:
  ret i32 %x
}

define i64 @only_i64(i64 %x) {
entry:
  ret i64 %x
}
)ir";

const char *kDeclarationOnly = R"ir(
declare i32 @ext(i32)
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

} // namespace

TEST_CASE("adversarialFunctionMergingModule merges same-signature functions "
          "and grows the module") {
    LLVMContext ctx;
    auto M = parse(ctx, kThreeIntFns);

    CHECK(countFunctions(*M, "morok.afm.") == 0);
    CHECK(countGlobals(*M, "morok.afm.") == 0);

    auto rng = makeRng(0xAF01);
    morok::passes::AdversarialMergeParams p;
    p.probability = 100;

    CHECK(morok::passes::adversarialFunctionMergingModule(*M, p, rng));

    // At minimum: three impl clones + one dispatcher were added, along with the
    // selector/key hidden-channel globals (one pair per merged function).
    CHECK(countFunctions(*M, "morok.afm.") >= 4);
    CHECK(countGlobals(*M, "morok.afm.") >= 6);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("adversarialFunctionMergingModule emits impl clones a switch "
          "dispatcher and the selector channel") {
    LLVMContext ctx;
    auto M = parse(ctx, kThreeIntFns);

    auto rng = makeRng(0xAF02);
    morok::passes::AdversarialMergeParams p;
    p.probability = 100;
    p.max_functions = 4;
    p.outline_probability = 0; // isolate the merge output from outlining noise

    CHECK(morok::passes::adversarialFunctionMergingModule(*M, p, rng));

    // All three same-signature bodies are cloned behind one dispatcher.
    CHECK(countFunctions(*M, "morok.afm.impl.") == 3);
    CHECK(countFunctions(*M, "morok.afm.outline.") == 0);

    Function *disp = M->getFunction("morok.afm.dispatch.0");
    REQUIRE(disp != nullptr);
    CHECK(disp->hasInternalLinkage());
    bool hasSwitch = false;
    for (Instruction &I : instructions(*disp))
        if (isa<SwitchInst>(&I))
            hasSwitch = true;
    CHECK(hasSwitch);

    // One encoded-selector global and one key global per merged function.
    CHECK(countGlobals(*M, "morok.afm.selector.") == 3);
    CHECK(countGlobals(*M, "morok.afm.key.") == 3);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("adversarialFunctionMergingModule rewrites originals as dispatcher "
          "wrappers") {
    LLVMContext ctx;
    auto M = parse(ctx, kThreeIntFns);

    auto rng = makeRng(0xAF03);
    morok::passes::AdversarialMergeParams p;
    p.probability = 100;
    p.outline_probability = 0;

    CHECK(morok::passes::adversarialFunctionMergingModule(*M, p, rng));

    // The public symbol survives but its body is now a thin wrapper that decodes
    // a hidden selector and tail-forwards to the dispatcher.
    Function *alpha = M->getFunction("alpha");
    REQUIRE(alpha != nullptr);
    CHECK_FALSE(alpha->isDeclaration());
    CHECK(alpha->hasFnAttribute(Attribute::NoInline));

    // Exactly one call into a morok.afm.dispatch.* function.
    CHECK(countCallsToPrefix(*alpha, "morok.afm.dispatch.") == 1);

    // The hidden selector is materialised as encoded-load + key-load + xor.
    CHECK(countNamedInstructions(*alpha, "morok.afm.selector") == 3);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("adversarialFunctionMergingModule outlines scalar fragments into "
          "shared helpers") {
    LLVMContext ctx;
    auto M = parse(ctx, kThreeIntFns);

    auto rng = makeRng(0xAF04);
    morok::passes::AdversarialMergeParams p;
    p.probability = 100;
    p.outline_probability = 100;
    p.max_outlines = 8;

    CHECK(morok::passes::adversarialFunctionMergingModule(*M, p, rng));

    // Outlined ops become internal noinline helpers named by opcode+scalar type.
    CHECK(M->getFunction("morok.afm.outline.add.i32") != nullptr);
    CHECK(countFunctions(*M, "morok.afm.outline.") >= 3);
    CHECK(countGlobals(*M, "morok.afm.key.outline.") >= 1);

    // The outlined calls live inside the cloned impl bodies, not the wrappers.
    std::size_t outlineCalls = 0;
    for (Function &Fn : *M)
        if (Fn.getName().starts_with("morok.afm.impl."))
            outlineCalls += countCallsToPrefix(Fn, "morok.afm.outline.");
    CHECK(outlineCalls >= 1);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("adversarialFunctionMergingModule skips outlining when "
          "outline_probability is zero") {
    LLVMContext ctx;
    auto M = parse(ctx, kThreeIntFns);

    auto rng = makeRng(0xAF05);
    morok::passes::AdversarialMergeParams p;
    p.probability = 100;
    p.outline_probability = 0;

    // The merge still fires; only the outlining stage is gated off.
    CHECK(morok::passes::adversarialFunctionMergingModule(*M, p, rng));
    CHECK(M->getFunction("morok.afm.dispatch.0") != nullptr);
    CHECK(countFunctions(*M, "morok.afm.outline.") == 0);
    CHECK(countGlobals(*M, "morok.afm.key.outline.") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("adversarialFunctionMergingModule is a no-op when the gates are "
          "closed") {
    LLVMContext ctx;

    // probability == 0 short-circuits before any mutation.
    auto M = parse(ctx, kThreeIntFns);
    auto rng = makeRng(0xAF06);
    morok::passes::AdversarialMergeParams p;
    p.probability = 0;
    CHECK_FALSE(morok::passes::adversarialFunctionMergingModule(*M, p, rng));
    CHECK(countFunctions(*M, "morok.afm.") == 0);
    CHECK_FALSE(verifyModule(*M));

    // max_functions < 2 cannot form a dispatcher, so the pass declines.
    auto M2 = parse(ctx, kThreeIntFns);
    auto rng2 = makeRng(0xAF07);
    morok::passes::AdversarialMergeParams p2;
    p2.probability = 100;
    p2.max_functions = 1;
    CHECK_FALSE(morok::passes::adversarialFunctionMergingModule(*M2, p2, rng2));
    CHECK(countFunctions(*M2, "morok.afm.") == 0);
    CHECK_FALSE(verifyModule(*M2));
}

TEST_CASE("adversarialFunctionMergingModule requires two same-signature "
          "functions") {
    LLVMContext ctx;

    // Distinct signatures: no group ever reaches two members.
    auto M = parse(ctx, kDistinctSigFns);
    auto rng = makeRng(0xAF08);
    morok::passes::AdversarialMergeParams p;
    p.probability = 100;
    CHECK_FALSE(morok::passes::adversarialFunctionMergingModule(*M, p, rng));
    CHECK(countFunctions(*M, "morok.afm.") == 0);
    CHECK_FALSE(verifyModule(*M));

    // Declaration-only module: nothing eligible, no crash.
    auto Mdecl = parse(ctx, kDeclarationOnly);
    auto rngDecl = makeRng(0xAF09);
    CHECK_FALSE(
        morok::passes::adversarialFunctionMergingModule(*Mdecl, p, rngDecl));
    CHECK_FALSE(verifyModule(*Mdecl));
}

TEST_CASE("adversarialFunctionMergingModule is idempotent under a second run") {
    LLVMContext ctx;
    auto M = parse(ctx, kThreeIntFns);

    auto rng = makeRng(0xAF0A);
    morok::passes::AdversarialMergeParams p;
    p.probability = 100;

    CHECK(morok::passes::adversarialFunctionMergingModule(*M, p, rng));
    CHECK_FALSE(verifyModule(*M));

    // hasExistingAfm() detects the prior morok.afm.* symbols and declines.
    auto rng2 = makeRng(0xAF0B);
    CHECK_FALSE(morok::passes::adversarialFunctionMergingModule(*M, p, rng2));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("adversarialFunctionMergingModule is deterministic for a fixed seed") {
    LLVMContext ctx1;
    LLVMContext ctx2;
    auto M1 = parse(ctx1, kThreeIntFns);
    auto M2 = parse(ctx2, kThreeIntFns);

    // Fresh engines from the same seed give two identical RNG streams; the
    // helper's static engine cannot be relied on to reset, so seed directly.
    auto engine1 = morok::core::Xoshiro256pp::fromSeed(0xBEEF);
    auto engine2 = morok::core::Xoshiro256pp::fromSeed(0xBEEF);
    morok::ir::IRRandom r1(engine1);
    morok::ir::IRRandom r2(engine2);

    morok::passes::AdversarialMergeParams p;
    p.probability = 100;
    p.outline_probability = 100;

    CHECK(morok::passes::adversarialFunctionMergingModule(*M1, p, r1));
    CHECK(morok::passes::adversarialFunctionMergingModule(*M2, p, r2));

    std::string s1;
    std::string s2;
    raw_string_ostream os1(s1);
    raw_string_ostream os2(s2);
    M1->print(os1, nullptr);
    M2->print(os2, nullptr);
    os1.flush();
    os2.flush();
    CHECK(s1 == s2);
    CHECK_FALSE(verifyModule(*M1));
    CHECK_FALSE(verifyModule(*M2));
}

TEST_CASE("adversarialFunctionMergingModule caps merged implementations at "
          "max_functions") {
    LLVMContext ctx;
    auto M = parse(ctx, kThreeIntFns);

    auto rng = makeRng(0xAF0C);
    morok::passes::AdversarialMergeParams p;
    p.probability = 100;
    p.max_functions = 2; // clamp floor; only two of the three may be merged
    p.outline_probability = 0;

    CHECK(morok::passes::adversarialFunctionMergingModule(*M, p, rng));

    // Exactly two clones and two wrapper selector globals despite three
    // candidates in the group.
    CHECK(countFunctions(*M, "morok.afm.impl.") == 2);
    CHECK(countGlobals(*M, "morok.afm.selector.") == 2);
    CHECK(M->getFunction("morok.afm.dispatch.0") != nullptr);
    CHECK_FALSE(verifyModule(*M));
}
