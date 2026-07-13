// SPDX-License-Identifier: MIT
//
// Tests for AdversarialSelfTuning — score-guided candidate search that replays
// only the strongest verified obfuscation bundle and records a choice marker.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/AdversarialSelfTuning.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// Rich enough that the ValueRecovery bundle's stack-coalescing action always
// fires: two locally-used static allocas, arithmetic, a conditional branch and
// a PHI.  The explicit linux triple keeps the fixture platform-neutral.
const char *kRichModule = R"ir(
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

define i32 @compute(i32 %n, ptr %out) {
entry:
  %a = alloca i32, align 4
  %b = alloca i32, align 4
  store i32 %n, ptr %a, align 4
  %la = load i32, ptr %a, align 4
  %sum = add i32 %la, 7
  store i32 %sum, ptr %b, align 4
  %lb = load i32, ptr %b, align 4
  %prod = mul i32 %lb, 3
  %cmp = icmp sgt i32 %prod, 100
  br i1 %cmp, label %then, label %else

then:
  %dec = sub i32 %prod, 1
  br label %join

else:
  %flip = xor i32 %prod, 255
  br label %join

join:
  %res = phi i32 [ %dec, %then ], [ %flip, %else ]
  store i32 %res, ptr %out, align 4
  ret i32 %res
}
)ir";

// A module whose recovery-pressure components are all easy to reason about:
// an alloca (lvar), a conditional branch and a PHI (cfg).
const char *kScoreModule = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @scored(i32 %n) {
entry:
  %slot = alloca i32, align 4
  store i32 %n, ptr %slot, align 4
  %v = load i32, ptr %slot, align 4
  %cmp = icmp sgt i32 %v, 0
  br i1 %cmp, label %pos, label %neg
pos:
  %a = add i32 %v, 1
  br label %end
neg:
  %b = sub i32 0, %v
  br label %end
end:
  %r = phi i32 [ %a, %pos ], [ %b, %neg ]
  ret i32 %r
}
)ir";

const char *kDeclModule = R"ir(
target triple = "x86_64-unknown-linux-gnu"
declare i32 @ext(i32)
)ir";

const char *kTrivialModule = R"ir(
target triple = "x86_64-unknown-linux-gnu"
define void @empty() {
entry:
  ret void
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

std::size_t moduleInstructionCount(Module &M) {
    std::size_t n = 0;
    for (Function &F : M)
        for (BasicBlock &BB : F)
            n += BB.size();
    return n;
}

std::string renderModule(Module &M) {
    std::string text;
    raw_string_ostream os(text);
    M.print(os, nullptr);
    os.flush();
    return text;
}

} // namespace

TEST_CASE("adversarialSelfTuneModule grows the module and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kRichModule);

    const std::size_t globalsBefore = countGlobals(*M, "");
    const std::size_t instsBefore = moduleInstructionCount(*M);

    morok::passes::AdversarialTuningParams p;
    p.max_candidates = 5u;
    p.max_candidate_passes = 3u;
    p.score_floor = 1u; // any positive improvement is enough to fire
    p.emit_marker = true;

    auto rng = makeRng(0x51E1);
    CHECK(morok::passes::adversarialSelfTuneModule(*M, p, rng));

    // A successful tune always adds the two marker globals plus whatever the
    // winning candidate introduced, and never shrinks the body.
    CHECK(countGlobals(*M, "") >= globalsBefore + 2u);
    CHECK(moduleInstructionCount(*M) >= instsBefore);
    CHECK(countGlobals(*M, "morok.tune.") == 2u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("adversarialSelfTuneModule honors disabled parameter gates") {
    LLVMContext ctx;

    SUBCASE("zero candidates is a no-op") {
        auto M = parse(ctx, kRichModule);
        const std::size_t before = countGlobals(*M, "");

        morok::passes::AdversarialTuningParams p;
        p.max_candidates = 0u;

        auto rng = makeRng(0x51E2);
        CHECK_FALSE(morok::passes::adversarialSelfTuneModule(*M, p, rng));
        CHECK(countGlobals(*M, "") == before);
        CHECK(countGlobals(*M, "morok.tune.") == 0u);
        CHECK_FALSE(verifyModule(*M));
    }

    SUBCASE("zero candidate passes is a no-op") {
        auto M = parse(ctx, kRichModule);
        const std::size_t before = countGlobals(*M, "");

        morok::passes::AdversarialTuningParams p;
        p.max_candidate_passes = 0u;

        auto rng = makeRng(0x51E3);
        CHECK_FALSE(morok::passes::adversarialSelfTuneModule(*M, p, rng));
        CHECK(countGlobals(*M, "") == before);
        CHECK(countGlobals(*M, "morok.tune.") == 0u);
        CHECK_FALSE(verifyModule(*M));
    }
}

TEST_CASE("adversarialSelfTuneModule declines when the score floor is out of reach") {
    LLVMContext ctx;
    auto M = parse(ctx, kRichModule);
    const std::size_t before = countGlobals(*M, "");

    morok::passes::AdversarialTuningParams p;
    p.max_candidates = 5u;
    p.max_candidate_passes = 3u;
    p.score_floor = 4000000000u; // no small-module candidate improves this much
    p.emit_marker = true;

    auto rng = makeRng(0x51E4);
    CHECK_FALSE(morok::passes::adversarialSelfTuneModule(*M, p, rng));
    CHECK(countGlobals(*M, "") == before);
    CHECK(countGlobals(*M, "morok.tune.") == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("adversarialSelfTuneModule is safe on declarations and trivial functions") {
    LLVMContext ctx;

    SUBCASE("declaration-only module declines and stays valid") {
        auto M = parse(ctx, kDeclModule);
        morok::passes::AdversarialTuningParams p;

        auto rng = makeRng(0x51E5);
        // No eligible defined function, so no candidate can change anything.
        CHECK_FALSE(morok::passes::adversarialSelfTuneModule(*M, p, rng));
        CHECK(countGlobals(*M, "morok.tune.") == 0u);
        CHECK_FALSE(verifyModule(*M));
    }

    SUBCASE("trivial single-block function does not crash") {
        auto M = parse(ctx, kTrivialModule);
        morok::passes::AdversarialTuningParams p;

        auto rng = makeRng(0x51E6);
        // Result value is unimportant; the module must survive intact.
        (void)morok::passes::adversarialSelfTuneModule(*M, p, rng);
        CHECK_FALSE(verifyModule(*M));
    }
}

TEST_CASE("adversarialSelfTuneModule is deterministic for a fixed seed") {
    LLVMContext ctx;
    auto M1 = parse(ctx, kRichModule);
    auto M2 = parse(ctx, kRichModule);

    morok::passes::AdversarialTuningParams p;
    p.max_candidates = 5u;
    p.max_candidate_passes = 3u;
    p.score_floor = 1u;
    p.emit_marker = true;

    // Two independent engines from the same seed produce identical streams; the
    // shared-static makeRng helper cannot be used here because it advances one
    // engine across calls.
    auto engineOne = morok::core::Xoshiro256pp::fromSeed(0x0BADF00D);
    morok::ir::IRRandom rngOne(engineOne);
    auto engineTwo = morok::core::Xoshiro256pp::fromSeed(0x0BADF00D);
    morok::ir::IRRandom rngTwo(engineTwo);

    const bool changedOne =
        morok::passes::adversarialSelfTuneModule(*M1, p, rngOne);
    const bool changedTwo =
        morok::passes::adversarialSelfTuneModule(*M2, p, rngTwo);

    CHECK(changedOne == changedTwo);
    CHECK(renderModule(*M1) == renderModule(*M2));
    CHECK_FALSE(verifyModule(*M1));
    CHECK_FALSE(verifyModule(*M2));
}

TEST_CASE("adversarialSelfTuneModule emits a well-formed choice marker") {
    LLVMContext ctx;
    auto M = parse(ctx, kRichModule);

    morok::passes::AdversarialTuningParams p;
    p.max_candidates = 5u;
    p.max_candidate_passes = 3u;
    p.score_floor = 1u;
    p.emit_marker = true;

    auto rng = makeRng(0x51E7);
    REQUIRE(morok::passes::adversarialSelfTuneModule(*M, p, rng));

    // Private-linkage globals are invisible to Module::getGlobalVariable's
    // default lookup, so scan the global list directly.
    GlobalVariable *choice = nullptr;
    GlobalVariable *score = nullptr;
    for (GlobalVariable &G : M->globals()) {
        if (G.getName() == "morok.tune.choice")
            choice = &G;
        else if (G.getName() == "morok.tune.score")
            score = &G;
    }

    REQUIRE(choice != nullptr);
    REQUIRE(choice->hasInitializer());
    auto *choiceInit = dyn_cast<ConstantInt>(choice->getInitializer());
    REQUIRE(choiceInit != nullptr);
    CHECK(choiceInit->getType()->isIntegerTy(64));
    const std::uint64_t kind = choiceInit->getZExtValue();
    // The recorded candidate kind is one of the five CandidateKind enumerators.
    CHECK(kind >= 1u);
    CHECK(kind <= 5u);

    REQUIRE(score != nullptr);
    auto *scoreArrTy = dyn_cast<ArrayType>(score->getValueType());
    REQUIRE(scoreArrTy != nullptr);
    // emitChoiceMarker packs exactly eight i64 score words.
    CHECK(scoreArrTy->getNumElements() == std::uint64_t{8});
    CHECK(scoreArrTy->getElementType()->isIntegerTy(64));

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("adversarialSelfTuneModule omits markers when emit_marker is false") {
    LLVMContext ctx;
    auto M = parse(ctx, kRichModule);

    morok::passes::AdversarialTuningParams p;
    p.max_candidates = 5u;
    p.max_candidate_passes = 3u;
    p.score_floor = 1u;
    p.emit_marker = false;

    auto rng = makeRng(0x51E8);
    // The transformation still applies, but no choice marker is planted.
    CHECK(morok::passes::adversarialSelfTuneModule(*M, p, rng));
    CHECK(countGlobals(*M, "morok.tune.") == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("adversarialSelfTuneModule refuses to re-tune an already-marked module") {
    LLVMContext ctx;
    auto M = parse(ctx, kRichModule);

    morok::passes::AdversarialTuningParams p;
    p.max_candidates = 5u;
    p.max_candidate_passes = 3u;
    p.score_floor = 1u;
    p.emit_marker = true;

    auto rng1 = makeRng(0x51E9);
    REQUIRE(morok::passes::adversarialSelfTuneModule(*M, p, rng1));
    CHECK(countGlobals(*M, "morok.tune.") == 2u);

    const std::size_t globalsAfterFirst = countGlobals(*M, "");

    // The existing morok.tune.* marker makes the second run bail out early.
    auto rng2 = makeRng(0x51EA);
    CHECK_FALSE(morok::passes::adversarialSelfTuneModule(*M, p, rng2));
    CHECK(countGlobals(*M, "") == globalsAfterFirst);
    CHECK(countGlobals(*M, "morok.tune.") == 2u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("adversarialScoreModule reports a weighted total over recovery pressures") {
    LLVMContext ctx;
    auto M = parse(ctx, kScoreModule);

    const morok::passes::AdversarialScore s =
        morok::passes::adversarialScoreModule(*M);

    // finalizeScore weighting: cfg*3 + lvar*3 + type*2 + symbolic*2 + diff.
    const std::uint64_t expected =
        s.cfg_recovery * 3u + s.lvar_recovery * 3u + s.type_recovery * 2u +
        s.symbolic_pressure * 2u + s.diff_resistance;
    CHECK(s.total == expected);

    // The fixture exercises each of these pressures at least once.
    CHECK(s.cfg_recovery > 0u);   // block count, conditional branch and PHI
    CHECK(s.lvar_recovery > 0u);  // the alloca and the PHI
    CHECK(s.diff_resistance > 0u); // one per scored instruction
    CHECK(s.total > 0u);

    // A declaration-only module contributes nothing to any pressure.
    auto D = parse(ctx, kDeclModule);
    const morok::passes::AdversarialScore empty =
        morok::passes::adversarialScoreModule(*D);
    CHECK(empty.total == 0u);
    CHECK(empty.cfg_recovery == 0u);
    CHECK(empty.diff_resistance == 0u);
}
