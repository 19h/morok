// SPDX-License-Identifier: MIT
//
// Tests for InterproceduralFsm — split flattened dispatcher state updates
// across shared mutually-recursive helper functions.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/InterproceduralFsm.hpp"

#include "llvm/IR/Attributes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// A flattened-dispatcher shape: an i32 `fla.state` slot, an entry-block seed
// store (never a candidate), and three transition stores in non-entry blocks
// (the only wrappable candidate sites the pass looks for).
const char *kFlattened = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @flat(i32 %n) {
entry:
  %fla.state = alloca i32, align 4
  store i32 0, ptr %fla.state, align 4
  br label %dispatch
dispatch:
  %s = load i32, ptr %fla.state, align 4
  switch i32 %s, label %done [
    i32 0, label %b0
    i32 1, label %b1
    i32 2, label %b2
  ]
b0:
  %x0 = add i32 %n, 7
  store i32 1, ptr %fla.state, align 4
  br label %dispatch
b1:
  %x1 = mul i32 %n, 3
  store i32 2, ptr %fla.state, align 4
  br label %dispatch
b2:
  %x2 = xor i32 %n, 5
  store i32 3, ptr %fla.state, align 4
  br label %dispatch
done:
  ret i32 %n
}
)ir";

// A multi-block function whose only `fla.state` store sits in the entry block:
// the pass explicitly skips entry-block stores, so there is nothing to wrap.
const char *kEntryOnly = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @entry_only(i32 %n) {
entry:
  %fla.state = alloca i32, align 4
  store i32 42, ptr %fla.state, align 4
  br label %tail
tail:
  %v = load i32, ptr %fla.state, align 4
  ret i32 %v
}
)ir";

// A branchy function with no flattened state slot at all: no candidate stores.
const char *kNoState = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @plain(i32 %a, i32 %b) {
entry:
  %c = icmp slt i32 %a, %b
  br i1 %c, label %then, label %else
then:
  %t = add i32 %a, 1
  ret i32 %t
else:
  %e = sub i32 %b, 1
  ret i32 %e
}
)ir";

const char *kDeclOnly = R"ir(
declare i32 @external(i32)
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

std::string moduleText(Module &M) {
    std::string out;
    raw_string_ostream os(out);
    M.print(os, nullptr);
    return os.str();
}

} // namespace

TEST_CASE("interproceduralFsmSplitModule grows the module and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kFlattened);
    Function *F = M->getFunction("flat");
    REQUIRE(F);

    const std::size_t functionsBefore = countFunctions(*M, "");
    CHECK(countNamedInstructions(*F, "morok.ifsm.") == 0);

    auto rng = makeRng(0x1001);
    CHECK(morok::passes::interproceduralFsmSplitModule(
        *M, morok::passes::InterproceduralFsmParams{}, rng));

    // Two shared helpers appear, plus the volatile thread slot global.
    CHECK(countFunctions(*M, "") > functionsBefore);
    CHECK(countGlobals(*M, "morok.ifsm.thread") == 1);
    // The dispatcher function now carries the pass's inserted instructions.
    CHECK(countNamedInstructions(*F, "morok.ifsm.") > 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("interproceduralFsmSplitModule emits mutually-recursive step helpers") {
    LLVMContext ctx;
    auto M = parse(ctx, kFlattened);

    auto rng = makeRng(0x1002);
    CHECK(morok::passes::interproceduralFsmSplitModule(
        *M, morok::passes::InterproceduralFsmParams{}, rng));

    Function *stepA = M->getFunction("morok.ifsm.step.a");
    Function *stepB = M->getFunction("morok.ifsm.step.b");
    REQUIRE(stepA);
    REQUIRE(stepB);

    // Each helper has the {entry, recurse, finish} skeleton and the fixed
    // (i32, i32, i32, ptr, i32) -> i32 shared signature.
    CHECK(stepA->size() == 3);
    CHECK(stepB->size() == 3);
    CHECK(stepA->arg_size() == 5);
    CHECK(stepB->arg_size() == 5);
    CHECK(stepA->getReturnType()->isIntegerTy(32));
    CHECK(stepB->getReturnType()->isIntegerTy(32));

    // Helpers are pinned so the interprocedural step cannot be inlined away.
    CHECK(stepA->hasFnAttribute(Attribute::NoInline));
    CHECK(stepB->hasFnAttribute(Attribute::NoInline));

    // The one-step recursion: A calls B and B calls A.
    CHECK(countCallsTo(*stepA, "morok.ifsm.step.b") == 1);
    CHECK(countCallsTo(*stepB, "morok.ifsm.step.a") == 1);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("interproceduralFsmSplitModule threads state through a volatile slot") {
    LLVMContext ctx;
    auto M = parse(ctx, kFlattened);

    auto rng = makeRng(0x1003);
    CHECK(morok::passes::interproceduralFsmSplitModule(
        *M, morok::passes::InterproceduralFsmParams{}, rng));

    // The thread global is a private i32 shared state slot.
    GlobalVariable *thread = M->getGlobalVariable("morok.ifsm.thread", true);
    REQUIRE(thread);
    CHECK(thread->hasPrivateLinkage());

    // The helper entry block stores the current state to the slot volatilely.
    Function *stepA = M->getFunction("morok.ifsm.step.a");
    REQUIRE(stepA);
    bool sawVolatileStore = false;
    bool sawVolatileLoad = false;
    for (Instruction &I : instructions(*stepA)) {
        if (auto *SI = dyn_cast<StoreInst>(&I))
            sawVolatileStore = sawVolatileStore || SI->isVolatile();
        if (auto *LI = dyn_cast<LoadInst>(&I))
            sawVolatileLoad = sawVolatileLoad || LI->isVolatile();
    }
    CHECK(sawVolatileStore);
    CHECK(sawVolatileLoad);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("interproceduralFsmSplitFunction rewrites the state store into a call") {
    LLVMContext ctx;
    auto M = parse(ctx, kFlattened);
    Function *F = M->getFunction("flat");
    REQUIRE(F);

    auto rng = makeRng(0x1004);
    CHECK(morok::passes::interproceduralFsmSplitFunction(
        *F, morok::passes::InterproceduralFsmParams{}, rng));

    // The wrapped transition store now stores the result of a helper call.
    CHECK(countCallsToPrefix(*F, "morok.ifsm.step") >= 1);
    // The load of current state and the token seed are the inserted glue.
    CHECK(countNamedInstructions(*F, "morok.ifsm.current") >= 1);
    CHECK(countNamedInstructions(*F, "morok.ifsm.next") >= 1);

    // Every wrapped store's value operand is exactly a helper call.
    std::size_t wrappedStores = 0;
    for (Instruction &I : instructions(*F)) {
        auto *SI = dyn_cast<StoreInst>(&I);
        if (!SI)
            continue;
        if (auto *CI = dyn_cast<CallInst>(SI->getValueOperand())) {
            Function *callee = CI->getCalledFunction();
            if (callee && callee->getName().starts_with("morok.ifsm.step"))
                ++wrappedStores;
        }
    }
    CHECK(wrappedStores >= 1);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("interproceduralFsmSplitModule caps wrapped sites at max_sites") {
    LLVMContext ctx;
    auto M = parse(ctx, kFlattened);
    Function *F = M->getFunction("flat");
    REQUIRE(F);

    // Three candidate stores exist; force selection of exactly one.
    morok::passes::InterproceduralFsmParams params;
    params.probability = 100;
    params.max_sites = 1;

    auto rng = makeRng(0x1005);
    CHECK(morok::passes::interproceduralFsmSplitModule(*M, params, rng));

    // At most one store may be wrapped, so at most one helper call is inserted.
    CHECK(countCallsToPrefix(*F, "morok.ifsm.step") == 1);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("interproceduralFsmSplitModule respects probability=0 as a no-op") {
    LLVMContext ctx;
    auto M = parse(ctx, kFlattened);

    morok::passes::InterproceduralFsmParams params;
    params.probability = 0;

    const std::size_t functionsBefore = countFunctions(*M, "");
    auto rng = makeRng(0x1006);
    CHECK_FALSE(morok::passes::interproceduralFsmSplitModule(*M, params, rng));

    // Nothing was created: no helpers, no thread slot, function count intact.
    CHECK(countFunctions(*M, "") == functionsBefore);
    CHECK(countFunctions(*M, "morok.ifsm.") == 0);
    CHECK(countGlobals(*M, "morok.ifsm.thread") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("interproceduralFsmSplitModule respects max_sites=0 as a no-op") {
    LLVMContext ctx;
    auto M = parse(ctx, kFlattened);

    morok::passes::InterproceduralFsmParams params;
    params.max_sites = 0;

    auto rng = makeRng(0x1007);
    CHECK_FALSE(morok::passes::interproceduralFsmSplitModule(*M, params, rng));
    CHECK(countFunctions(*M, "morok.ifsm.") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("interproceduralFsmSplitModule skips declarations and unflattened code") {
    LLVMContext ctx;
    auto Mdecl = parse(ctx, kDeclOnly);
    auto rngDecl = makeRng(0x1008);
    CHECK_FALSE(morok::passes::interproceduralFsmSplitModule(
        *Mdecl, morok::passes::InterproceduralFsmParams{}, rngDecl));
    CHECK(countFunctions(*Mdecl, "morok.ifsm.") == 0);
    CHECK_FALSE(verifyModule(*Mdecl));

    // A branchy function without any `fla.state` slot has no candidate sites.
    auto Mplain = parse(ctx, kNoState);
    auto rngPlain = makeRng(0x1009);
    CHECK_FALSE(morok::passes::interproceduralFsmSplitModule(
        *Mplain, morok::passes::InterproceduralFsmParams{}, rngPlain));
    CHECK(countFunctions(*Mplain, "morok.ifsm.") == 0);
    CHECK_FALSE(verifyModule(*Mplain));
}

TEST_CASE("interproceduralFsmSplitModule ignores entry-block state stores") {
    LLVMContext ctx;
    auto M = parse(ctx, kEntryOnly);
    Function *F = M->getFunction("entry_only");
    REQUIRE(F);

    auto rng = makeRng(0x100A);
    // The single `fla.state` store lives in the entry block, which the pass
    // never wraps, so there is no candidate and the pass reports no change.
    CHECK_FALSE(morok::passes::interproceduralFsmSplitModule(
        *M, morok::passes::InterproceduralFsmParams{}, rng));
    CHECK(countFunctions(*M, "morok.ifsm.") == 0);
    CHECK(countNamedInstructions(*F, "morok.ifsm.") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("interproceduralFsmSplitModule is deterministic for a fixed seed") {
    LLVMContext ctxA;
    LLVMContext ctxB;
    auto Ma = parse(ctxA, kFlattened);
    auto Mb = parse(ctxB, kFlattened);

    // Two independent engines seeded identically must drive identical output.
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0xC0FFEE);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0xC0FFEE);
    morok::ir::IRRandom rngA(engineA);
    morok::ir::IRRandom rngB(engineB);

    CHECK(morok::passes::interproceduralFsmSplitModule(
        *Ma, morok::passes::InterproceduralFsmParams{}, rngA));
    CHECK(morok::passes::interproceduralFsmSplitModule(
        *Mb, morok::passes::InterproceduralFsmParams{}, rngB));

    CHECK(moduleText(*Ma) == moduleText(*Mb));
    CHECK_FALSE(verifyModule(*Ma));
    CHECK_FALSE(verifyModule(*Mb));
}
