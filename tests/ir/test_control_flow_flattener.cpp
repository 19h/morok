// SPDX-License-Identifier: MIT
//
// Tests for ControlFlowFlattener — reusable CFG-flattening engine.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/ControlFlowFlattener.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"

using namespace llvm;
using namespace morok::test;

namespace {

const char *kBranchy = R"ir(
define i32 @branchy(i32 %a, i32 %b) {
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

const char *kSingleBlock = R"ir(
define i32 @trivial(i32 %x) {
entry:
  ret i32 %x
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 17) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

// Simple nextState: store the successor's id directly (identity flattening).
morok::ir::NextStateFn identityNextState() {
    return [](IRBuilder<> &B, AllocaInst * /*stateVar*/,
              std::uint32_t /*currentId*/,
              const morok::ir::SuccessorIds &succ) -> Value * {
        return ConstantInt::get(B.getInt32Ty(), succ.defaultId);
    };
}

} // namespace

TEST_CASE("flattenControlFlow collapses a branchy function") {
    LLVMContext ctx;
    auto M = parse(ctx, kBranchy);
    Function *F = M->getFunction("branchy");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng(17);
    CHECK(morok::ir::flattenControlFlow(*F, rng, identityNextState()));
    CHECK(F->size() > before);

    // Must have a switch dispatcher
    bool hasSwitch = false;
    for (Instruction &I : instructions(*F))
        if (isa<SwitchInst>(&I))
            hasSwitch = true;
    CHECK(hasSwitch);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("flattenControlFlow returns false for single-block functions") {
    LLVMContext ctx;
    auto M = parse(ctx, kSingleBlock);
    Function *F = M->getFunction("trivial");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng(18);
    CHECK_FALSE(morok::ir::flattenControlFlow(*F, rng, identityNextState()));
    CHECK(F->size() == before);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("flattenControlFlow returns false for declarations") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare i32 @external(i32)
)ir");
    Function *F = M->getFunction("external");
    REQUIRE(F);

    auto rng = makeRng(19);
    CHECK_FALSE(morok::ir::flattenControlFlow(*F, rng, identityNextState()));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("flattenControlFlow invokes nextState callback") {
    LLVMContext ctx;
    auto M = parse(ctx, kBranchy);
    Function *F = M->getFunction("branchy");
    REQUIRE(F);

    bool callbackInvoked = false;
    auto customNextState = [&callbackInvoked](
                               IRBuilder<> &B, AllocaInst * /*stateVar*/,
                               std::uint32_t /*currentId*/,
                               const morok::ir::SuccessorIds &succ) -> Value * {
        callbackInvoked = true;
        return ConstantInt::get(B.getInt32Ty(), succ.defaultId);
    };

    auto rng = makeRng(20);
    CHECK(morok::ir::flattenControlFlow(*F, rng, customNextState));
    CHECK(callbackInvoked);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("flattenControlFlow with encodeState callback") {
    LLVMContext ctx;
    auto M = parse(ctx, kBranchy);
    Function *F = M->getFunction("branchy");
    REQUIRE(F);

    // Encode state ids by XORing with a constant
    auto encodeState = [](std::uint32_t logicalId) -> std::uint32_t {
        return logicalId ^ 0xDEAD;
    };

    auto rng = makeRng(21);
    CHECK(morok::ir::flattenControlFlow(*F, rng, identityNextState(),
                                        encodeState));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("flattenControlFlow handles functions with loops") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @loop(i32 %n) {
entry:
  br label %loop
loop:
  %i = phi i32 [ 0, %entry ], [ %next, %loop ]
  %next = add i32 %i, 1
  %done = icmp sge i32 %next, %n
  br i1 %done, label %exit, label %loop
exit:
  ret i32 %next
}
)ir");
    Function *F = M->getFunction("loop");
    REQUIRE(F);

    auto rng = makeRng(22);
    CHECK(morok::ir::flattenControlFlow(*F, rng, identityNextState()));
    CHECK_FALSE(verifyModule(*M));
}
