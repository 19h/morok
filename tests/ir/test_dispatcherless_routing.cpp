// SPDX-License-Identifier: MIT
//
// Tests for DispatcherlessRouting — rewrites direct branch/switch terminators
// into data-derived indirectbr routing through a shared block-address table.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/DispatcherlessRouting.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;
using namespace morok::test;

namespace {

// Multiple eligible terminators (entry conditional br + two unconditional
// brs), no PHI nodes: three routable sites.
const char *kBranchy = R"ir(
define i32 @branchy(i32 %a, i32 %b) {
entry:
  %c = icmp slt i32 %a, %b
  br i1 %c, label %then, label %else
then:
  br label %join
else:
  br label %join
join:
  %r = add i32 %a, %b
  ret i32 %r
}
)ir";

// Exactly one eligible terminator (the entry conditional branch); both
// successors return, so the pass transforms a single site.
const char *kDiamond = R"ir(
define i32 @diamond(i32 %a, i32 %b) {
entry:
  %c = icmp slt i32 %a, %b
  br i1 %c, label %then, label %else
then:
  ret i32 %a
else:
  ret i32 %b
}
)ir";

const char *kSingleBlock = R"ir(
define i32 @trivial(i32 %x) {
entry:
  ret i32 %x
}
)ir";

const char *kDecl = R"ir(
declare i32 @external(i32)
)ir";

// Switch whose case/default blocks all return, so the switch is the only
// eligible terminator. Pinned to the x86_64-linux triple where the pass holds
// switch lowering back regardless of the CI host.
const char *kSwitchLinux = R"ir(
target triple = "x86_64-unknown-linux-gnu"
define i32 @swfn(i32 %x) {
entry:
  switch i32 %x, label %def [
    i32 1, label %c1
    i32 2, label %c2
  ]
c1:
  ret i32 11
c2:
  ret i32 22
def:
  ret i32 0
}
)ir";

// Same shape, but on a non-x86_64-linux triple where switch routing is enabled.
const char *kSwitchMac = R"ir(
target triple = "arm64-apple-macosx"
define i32 @swfn(i32 %x) {
entry:
  switch i32 %x, label %def [
    i32 1, label %c1
    i32 2, label %c2
  ]
c1:
  ret i32 11
c2:
  ret i32 22
def:
  ret i32 0
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

std::size_t instructionCount(Function &F) {
    std::size_t n = 0;
    for (Instruction &I : instructions(F)) {
        (void)I;
        ++n;
    }
    return n;
}

std::string printModule(Module &M) {
    std::string out;
    raw_string_ostream os(out);
    M.print(os, nullptr);
    return out;
}

} // namespace

TEST_CASE("dispatcherlessRoutingFunction grows the function and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kBranchy);
    Function *F = M->getFunction("branchy");
    REQUIRE(F);
    const std::size_t beforeInsts = instructionCount(*F);
    const std::size_t beforeGlobals = countGlobals(*M, "morok.dlf.");

    auto rng = makeRng(0x1001);
    CHECK(morok::passes::dispatcherlessRoutingFunction(
        *F, {/*probability=*/100, /*max_routes=*/32, /*max_terms=*/4}, rng));

    // No new blocks are created; the terminators are rewritten in place, but
    // instruction and global counts grow.
    CHECK(instructionCount(*F) > beforeInsts);
    CHECK(countGlobals(*M, "morok.dlf.") > beforeGlobals);
    CHECK(countOpcode(*M, Instruction::IndirectBr) >= 1);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("dispatcherlessRoutingFunction respects probability=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kBranchy);
    Function *F = M->getFunction("branchy");
    REQUIRE(F);
    const std::size_t beforeInsts = instructionCount(*F);

    auto rng = makeRng(0x1002);
    CHECK_FALSE(morok::passes::dispatcherlessRoutingFunction(
        *F, {/*probability=*/0, /*max_routes=*/32, /*max_terms=*/4}, rng));

    CHECK(instructionCount(*F) == beforeInsts);
    CHECK(countGlobals(*M, "morok.dlf.") == 0);
    CHECK(countOpcode(*M, Instruction::IndirectBr) == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("dispatcherlessRoutingFunction respects max_routes=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kBranchy);
    Function *F = M->getFunction("branchy");
    REQUIRE(F);
    const std::size_t beforeInsts = instructionCount(*F);

    auto rng = makeRng(0x1003);
    CHECK_FALSE(morok::passes::dispatcherlessRoutingFunction(
        *F, {/*probability=*/100, /*max_routes=*/0, /*max_terms=*/4}, rng));

    CHECK(instructionCount(*F) == beforeInsts);
    CHECK(countGlobals(*M, "morok.dlf.") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("dispatcherlessRoutingFunction is safe on declarations") {
    LLVMContext ctx;
    auto M = parse(ctx, kDecl);
    Function *F = M->getFunction("external");
    REQUIRE(F);

    auto rng = makeRng(0x1004);
    CHECK_FALSE(morok::passes::dispatcherlessRoutingFunction(
        *F, {/*probability=*/100, /*max_routes=*/32, /*max_terms=*/4}, rng));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("dispatcherlessRoutingFunction is a no-op on trivial single-block "
          "functions") {
    LLVMContext ctx;
    auto M = parse(ctx, kSingleBlock);
    Function *F = M->getFunction("trivial");
    REQUIRE(F);
    const std::size_t beforeInsts = instructionCount(*F);

    // A lone `ret` terminator is not an eligible branch/switch site.
    auto rng = makeRng(0x1005);
    CHECK_FALSE(morok::passes::dispatcherlessRoutingFunction(
        *F, {/*probability=*/100, /*max_routes=*/32, /*max_terms=*/4}, rng));

    CHECK(instructionCount(*F) == beforeInsts);
    CHECK(countGlobals(*M, "morok.dlf.") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("dispatcherlessRoutingFunction emits a private block-address table "
          "with state and volatile shadow slots") {
    LLVMContext ctx;
    auto M = parse(ctx, kDiamond);
    Function *F = M->getFunction("diamond");
    REQUIRE(F);

    auto rng = makeRng(0x1006);
    CHECK(morok::passes::dispatcherlessRoutingFunction(
        *F, {/*probability=*/100, /*max_routes=*/32, /*max_terms=*/4}, rng));

    // Exactly one shared routing table, one state slot, one shadow slot for the
    // single transformed site.
    CHECK(countGlobals(*M, "morok.dlf.table") == 1);
    CHECK(countNamedAllocas(*F, "morok.dlf.state") == 1);
    CHECK(countNamedAllocas(*F, "morok.dlf.shadow") == 1);
    CHECK(countOpcode(*M, Instruction::IndirectBr) == 1);

    // The table is a private, constant array of pointers (block addresses),
    // one per unique successor (then/else => two entries).
    auto *Table = M->getGlobalVariable("morok.dlf.table", /*AllowInternal=*/true);
    REQUIRE(Table);
    CHECK(Table->isConstant());
    CHECK(Table->hasPrivateLinkage());
    auto *ArrTy = dyn_cast<ArrayType>(Table->getValueType());
    REQUIRE(ArrTy);
    CHECK(ArrTy->getElementType()->isPointerTy());
    CHECK(ArrTy->getNumElements() == 2u);

    // The route-state slot is an i32.
    auto *StateAlloca =
        dyn_cast<AllocaInst>(findNamedInstruction(*F, "morok.dlf.state"));
    REQUIRE(StateAlloca);
    CHECK(StateAlloca->getAllocatedType()->isIntegerTy(32));

    // The shadow read is a volatile load (the counterfeit-cancel channel).
    auto *ShadowLoad =
        dyn_cast<LoadInst>(findNamedInstruction(*F, "morok.dlf.shadow.a"));
    REQUIRE(ShadowLoad);
    CHECK(ShadowLoad->isVolatile());

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("dispatcherlessRoutingFunction is deterministic for a fixed seed") {
    LLVMContext ctxA;
    LLVMContext ctxB;
    auto MA = parse(ctxA, kBranchy);
    auto MB = parse(ctxB, kBranchy);

    // Two independent engines seeded identically produce identical streams,
    // unlike the shared static makeRng engine.
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0x2024u);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0x2024u);
    morok::ir::IRRandom rngA(engineA);
    morok::ir::IRRandom rngB(engineB);

    const bool changedA = morok::passes::dispatcherlessRoutingFunction(
        *MA->getFunction("branchy"),
        {/*probability=*/100, /*max_routes=*/32, /*max_terms=*/4}, rngA);
    const bool changedB = morok::passes::dispatcherlessRoutingFunction(
        *MB->getFunction("branchy"),
        {/*probability=*/100, /*max_routes=*/32, /*max_terms=*/4}, rngB);

    CHECK(changedA);
    CHECK(changedB);
    CHECK(printModule(*MA) == printModule(*MB));
    CHECK_FALSE(verifyModule(*MA));
    CHECK_FALSE(verifyModule(*MB));
}

TEST_CASE("dispatcherlessRoutingFunction holds back switch routing on "
          "x86_64-linux targets") {
    LLVMContext ctx;
    auto M = parse(ctx, kSwitchLinux);
    Function *F = M->getFunction("swfn");
    REQUIRE(F);
    const std::size_t beforeInsts = instructionCount(*F);

    // The module triple (not the host) drives the gate, so this holds on every
    // CI platform: the switch is the only eligible site and it is skipped.
    auto rng = makeRng(0x1008);
    CHECK_FALSE(morok::passes::dispatcherlessRoutingFunction(
        *F, {/*probability=*/100, /*max_routes=*/32, /*max_terms=*/4}, rng));

    CHECK(instructionCount(*F) == beforeInsts);
    CHECK(countGlobals(*M, "morok.dlf.") == 0);
    CHECK(countOpcode(*M, Instruction::IndirectBr) == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("dispatcherlessRoutingFunction routes switch terminators on "
          "non-x86_64-linux targets") {
    LLVMContext ctx;
    auto M = parse(ctx, kSwitchMac);
    Function *F = M->getFunction("swfn");
    REQUIRE(F);

    auto rng = makeRng(0x1009);
    CHECK(morok::passes::dispatcherlessRoutingFunction(
        *F, {/*probability=*/100, /*max_routes=*/32, /*max_terms=*/4}, rng));

    // Switch lowering emits one per-case equality compare feeding the index
    // select, plus the shared table and an indirectbr.
    CHECK(countNamedInstructions(*F, "morok.dlf.case") > 0);
    CHECK(countGlobals(*M, "morok.dlf.table") == 1);
    CHECK(countOpcode(*M, Instruction::IndirectBr) == 1);
    CHECK_FALSE(verifyModule(*M));
}
