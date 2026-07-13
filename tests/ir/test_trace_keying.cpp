// SPDX-License-Identifier: MIT
//
// Tests for TraceKeying — execution-trace keyed CFG-edge guards and latent
// mismatch state.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/TraceKeying.hpp"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"

using namespace llvm;
using namespace morok::test;

namespace {

// Diamond CFG: `entry` fans out to `then`/`else`, both merge in `join`.
// Non-entry blocks (then, else, join) are all trace-eligible: each has a
// predecessor that ends in a direct (branch/switch) terminator.
const char *kBranchy = R"ir(
define i32 @flow(i32 %a, i32 %b) {
entry:
  %c = icmp slt i32 %a, %b
  br i1 %c, label %then, label %else
then:
  %t = add i32 %a, 1
  br label %join
else:
  %e = sub i32 %b, 1
  br label %join
join:
  %p = phi i32 [ %t, %then ], [ %e, %else ]
  %r = mul i32 %p, %a
  ret i32 %r
}
)ir";

// Wide switch: five trace-eligible non-entry blocks (c1..c3, d, join). Used to
// exercise the max_blocks cap when probability is saturated.
const char *kWide = R"ir(
define i32 @wide(i32 %a) {
entry:
  switch i32 %a, label %d [
    i32 1, label %c1
    i32 2, label %c2
    i32 3, label %c3
  ]
c1:
  %v1 = add i32 %a, 1
  br label %join
c2:
  %v2 = add i32 %a, 2
  br label %join
c3:
  %v3 = add i32 %a, 3
  br label %join
d:
  %v4 = add i32 %a, 4
  br label %join
join:
  %p = phi i32 [ %v1, %c1 ], [ %v2, %c2 ], [ %v3, %c3 ], [ %v4, %d ]
  ret i32 %p
}
)ir";

// Single-block function: `entry` is the only block, so nothing is eligible.
const char *kTrivial = R"ir(
define i32 @trivial(i32 %x) {
entry:
  %r = add i32 %x, 1
  ret i32 %r
}
)ir";

// A branchy function that already lives in the pass's own `morok.` namespace;
// its body would otherwise be eligible, so it isolates the generated-name guard.
const char *kGenerated = R"ir(
define i32 @"morok.helper"(i32 %a, i32 %b) {
entry:
  %c = icmp slt i32 %a, %b
  br i1 %c, label %then, label %else
then:
  %t = add i32 %a, 1
  br label %join
else:
  %e = sub i32 %b, 1
  br label %join
join:
  %p = phi i32 [ %t, %then ], [ %e, %else ]
  ret i32 %p
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

std::size_t countInstructions(Function &F) {
    std::size_t n = 0;
    for (BasicBlock &BB : F)
        n += BB.size();
    return n;
}

std::size_t countBlocksWithPrefix(Function &F, StringRef prefix) {
    std::size_t n = 0;
    for (BasicBlock &BB : F)
        if (BB.getName().starts_with(prefix))
            ++n;
    return n;
}

} // namespace

TEST_CASE("traceKeyFunction instruments branchy IR and grows it") {
    LLVMContext ctx;
    auto M = parse(ctx, kBranchy);
    Function *F = M->getFunction("flow");
    REQUIRE(F);
    const std::size_t blocksBefore = F->size();
    const std::size_t instsBefore = countInstructions(*F);
    const std::size_t globalsBefore = countGlobals(*M, "morok.trace");

    auto rng = makeRng();
    CHECK(morok::passes::traceKeyFunction(
        *F, {/*probability=*/100, /*max_blocks=*/8}, rng));
    CHECK(F->size() > blocksBefore);
    CHECK(countInstructions(*F) > instsBefore);
    CHECK(countGlobals(*M, "morok.trace") > globalsBefore);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("traceKeyFunction respects probability=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kBranchy);
    Function *F = M->getFunction("flow");
    REQUIRE(F);
    const std::size_t blocksBefore = F->size();
    const std::size_t instsBefore = countInstructions(*F);

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::traceKeyFunction(
        *F, {/*probability=*/0, /*max_blocks=*/8}, rng));
    CHECK(F->size() == blocksBefore);
    CHECK(countInstructions(*F) == instsBefore);
    CHECK(countGlobals(*M, "morok.trace") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("traceKeyFunction respects max_blocks=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kBranchy);
    Function *F = M->getFunction("flow");
    REQUIRE(F);
    const std::size_t blocksBefore = F->size();

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::traceKeyFunction(
        *F, {/*probability=*/100, /*max_blocks=*/0}, rng));
    CHECK(F->size() == blocksBefore);
    CHECK(countGlobals(*M, "morok.trace") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("traceKeyFunction skips declarations") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare i32 @external(i32)
)ir");
    Function *F = M->getFunction("external");
    REQUIRE(F);

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::traceKeyFunction(
        *F, {/*probability=*/100, /*max_blocks=*/8}, rng));
    CHECK(countGlobals(*M, "morok.trace") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("traceKeyFunction skips morok-generated functions") {
    LLVMContext ctx;
    auto M = parse(ctx, kGenerated);
    Function *F = M->getFunction("morok.helper");
    REQUIRE(F);
    const std::size_t blocksBefore = F->size();
    const std::size_t instsBefore = countInstructions(*F);

    auto rng = makeRng();
    // The body is branchy, so only the generated-name guard prevents firing.
    CHECK_FALSE(morok::passes::traceKeyFunction(
        *F, {/*probability=*/100, /*max_blocks=*/8}, rng));
    CHECK(F->size() == blocksBefore);
    CHECK(countInstructions(*F) == instsBefore);
    CHECK(countGlobals(*M, "morok.trace") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("traceKeyFunction is a no-op on single-block functions") {
    LLVMContext ctx;
    auto M = parse(ctx, kTrivial);
    Function *F = M->getFunction("trivial");
    REQUIRE(F);
    const std::size_t blocksBefore = F->size();
    const std::size_t instsBefore = countInstructions(*F);

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::traceKeyFunction(
        *F, {/*probability=*/100, /*max_blocks=*/8}, rng));
    CHECK(F->size() == blocksBefore);
    CHECK(countInstructions(*F) == instsBefore);
    CHECK(countGlobals(*M, "morok.trace") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("traceKeyFunction honors the max_blocks cap") {
    LLVMContext ctx;
    auto M = parse(ctx, kWide);
    Function *F = M->getFunction("wide");
    REQUIRE(F);

    auto rng = makeRng();
    // Five eligible blocks, probability saturated: the cap bounds the guards.
    const std::uint32_t cap = 2;
    CHECK(morok::passes::traceKeyFunction(
        *F, {/*probability=*/100, /*max_blocks=*/cap}, rng));
    const std::size_t bodies = countBlocksWithPrefix(*F, "morok.trace.body");
    CHECK(bodies >= 1);
    CHECK(bodies <= cap);
    // One guarded body per selected block, saturated to the cap.
    CHECK(bodies == cap);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("traceKeyFunction emits trace globals, accumulator, guard PHI and "
          "latent atomic") {
    LLVMContext ctx;
    auto M = parse(ctx, kBranchy);
    Function *F = M->getFunction("flow");
    REQUIRE(F);

    auto rng = makeRng();
    REQUIRE(morok::passes::traceKeyFunction(
        *F, {/*probability=*/100, /*max_blocks=*/8}, rng));

    // Two module-wide latent-state globals: private seed and latent accumulator.
    CHECK(M->getGlobalVariable("morok.trace.seed", true) != nullptr);
    CHECK(M->getGlobalVariable("morok.trace.latent", true) != nullptr);
    CHECK(countGlobals(*M, "morok.trace") == 2);

    // Per-function volatile accumulator slot.
    CHECK(countNamedAllocas(*F, "morok.trace.state") >= 1);

    // Edge-carried expected value PHIs and the equality guard comparison.
    CHECK(countNamedInstructions(*F, "morok.trace.expected") >= 1);
    CHECK(countNamedInstructions(*F, "morok.trace.guard") >= 1);

    // Guard/record blocks materialised by the split.
    CHECK(countBlocksWithPrefix(*F, "morok.trace.body") >= 1);
    CHECK(countBlocksWithPrefix(*F, "morok.trace.record") >= 1);

    // Latent state is folded in through an atomic read-modify-write.
    CHECK(countOpcode(*M, static_cast<unsigned>(Instruction::AtomicRMW)) >= 1);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("traceKeyFunction is structurally deterministic for a fixed seed") {
    LLVMContext ctxA;
    LLVMContext ctxB;
    auto MA = parse(ctxA, kBranchy);
    auto MB = parse(ctxB, kBranchy);
    Function *FA = MA->getFunction("flow");
    Function *FB = MB->getFunction("flow");
    REQUIRE(FA);
    REQUIRE(FB);

    // Two independent engines seeded identically (not the shared makeRng static).
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0x9E3779B9ULL);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0x9E3779B9ULL);
    morok::ir::IRRandom rngA(engineA);
    morok::ir::IRRandom rngB(engineB);

    const bool firedA = morok::passes::traceKeyFunction(
        *FA, {/*probability=*/100, /*max_blocks=*/8}, rngA);
    const bool firedB = morok::passes::traceKeyFunction(
        *FB, {/*probability=*/100, /*max_blocks=*/8}, rngB);

    CHECK(firedA);
    CHECK(firedA == firedB);
    CHECK(FA->size() == FB->size());
    CHECK(countInstructions(*FA) == countInstructions(*FB));
    CHECK(countBlocksWithPrefix(*FA, "morok.trace.body") ==
          countBlocksWithPrefix(*FB, "morok.trace.body"));
    CHECK(countOpcode(*MA, static_cast<unsigned>(Instruction::AtomicRMW)) ==
          countOpcode(*MB, static_cast<unsigned>(Instruction::AtomicRMW)));
    CHECK_FALSE(verifyModule(*MA));
    CHECK_FALSE(verifyModule(*MB));
}
