// SPDX-License-Identifier: MIT
//
// Tests for FunctionWrapper — call-site proxying via internal forwarders.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/FunctionWrapper.hpp"

#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// A defined function that directly calls another defined function.
const char *kCallModule = R"ir(
define i32 @helper(i32 %x) {
entry:
  ret i32 %x
}

define i32 @main(i32 %a) {
entry:
  %r = call i32 @helper(i32 %a)
  ret i32 %r
}
)ir";

// No wrappable call sites: a leaf function plus an external declaration.
const char *kNoCallModule = R"ir(
define i32 @leaf(i32 %x) {
entry:
  %y = add i32 %x, 1
  ret i32 %y
}

declare void @ext()
)ir";

// Five identical wrappable call sites so the wrapper cap is observable.
const char *kManyCallsModule = R"ir(
define i32 @helper(i32 %x) {
entry:
  ret i32 %x
}

define i32 @main() {
entry:
  %a = call i32 @helper(i32 1)
  %b = call i32 @helper(i32 2)
  %c = call i32 @helper(i32 3)
  %d = call i32 @helper(i32 4)
  %e = call i32 @helper(i32 5)
  %s1 = add i32 %a, %b
  %s2 = add i32 %s1, %c
  %s3 = add i32 %s2, %d
  %s4 = add i32 %s3, %e
  ret i32 %s4
}
)ir";

// Only an intrinsic call site — must be left alone.
const char *kIntrinsicModule = R"ir(
declare void @llvm.donothing()

define void @main() {
entry:
  call void @llvm.donothing()
  ret void
}
)ir";

// A variadic callee: the forwarder must use the concrete argument list.
const char *kVariadicModule = R"ir(
declare i32 @printf(ptr, ...)

define void @main() {
entry:
  %c = call i32 (ptr, ...) @printf(ptr null, i32 42)
  ret void
}
)ir";

// A musttail call site — must be left alone.
const char *kMustTailModule = R"ir(
define i32 @helper(i32 %x) {
entry:
  ret i32 %x
}

define i32 @main(i32 %x) {
entry:
  %r = musttail call i32 @helper(i32 %x)
  ret i32 %r
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

// The pass names every generated forwarder "morok.wrap" (LLVM uniquifies with a
// numeric suffix); return the first one, or null if none exist.
llvm::Function *firstWrapperFunction(llvm::Module &M) {
    for (llvm::Function &F : M)
        if (F.getName().starts_with("morok.wrap"))
            return &F;
    return nullptr;
}

} // namespace

TEST_CASE("functionWrapModule grows the module and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kCallModule);

    const std::size_t before = countFunctions(*M, "");

    auto rng = makeRng(0xF001);
    morok::passes::FuncWrapParams p;
    p.probability = 100;

    CHECK(morok::passes::functionWrapModule(*M, p, rng));
    // The pass emits a fresh forwarder, so the module grew.
    CHECK(countFunctions(*M, "") > before);
    CHECK(countFunctions(*M, "morok.wrap") >= 1);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("functionWrapModule does nothing when probability is zero") {
    LLVMContext ctx;
    auto M = parse(ctx, kCallModule);

    const std::size_t before = countFunctions(*M, "");

    auto rng = makeRng(0xF002);
    morok::passes::FuncWrapParams p;
    p.probability = 0;

    CHECK_FALSE(morok::passes::functionWrapModule(*M, p, rng));
    CHECK(countFunctions(*M, "") == before);
    CHECK(countFunctions(*M, "morok.wrap") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("functionWrapModule does nothing when max_wrappers is zero") {
    LLVMContext ctx;
    auto M = parse(ctx, kCallModule);

    const std::size_t before = countFunctions(*M, "");

    auto rng = makeRng(0xF003);
    morok::passes::FuncWrapParams p;
    p.probability = 100;
    p.max_wrappers = 0;

    CHECK_FALSE(morok::passes::functionWrapModule(*M, p, rng));
    CHECK(countFunctions(*M, "") == before);
    CHECK(countFunctions(*M, "morok.wrap") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("functionWrapModule is safe on call-free and declaration-only input") {
    LLVMContext ctx;
    auto M = parse(ctx, kNoCallModule);

    auto rng = makeRng(0xF004);
    morok::passes::FuncWrapParams p;
    p.probability = 100;

    // No eligible call sites: no change, no crash.
    CHECK_FALSE(morok::passes::functionWrapModule(*M, p, rng));
    CHECK(countFunctions(*M, "morok.wrap") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("functionWrapModule is deterministic for a fixed seed") {
    LLVMContext ctxA;
    LLVMContext ctxB;
    auto MA = parse(ctxA, kManyCallsModule);
    auto MB = parse(ctxB, kManyCallsModule);

    auto engineA = morok::core::Xoshiro256pp::fromSeed(0xC0FFEE);
    morok::ir::IRRandom rngA(engineA);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0xC0FFEE);
    morok::ir::IRRandom rngB(engineB);

    morok::passes::FuncWrapParams p;
    p.probability = 100;

    CHECK(morok::passes::functionWrapModule(*MA, p, rngA));
    CHECK(morok::passes::functionWrapModule(*MB, p, rngB));

    std::string textA;
    std::string textB;
    raw_string_ostream osA(textA);
    raw_string_ostream osB(textB);
    MA->print(osA, nullptr);
    MB->print(osB, nullptr);
    osA.flush();
    osB.flush();

    // Same seed + same input => byte-identical IR.
    CHECK(textA == textB);
    CHECK_FALSE(verifyModule(*MA));
    CHECK_FALSE(verifyModule(*MB));
}

TEST_CASE("functionWrapModule respects the max_wrappers cap") {
    LLVMContext ctx;
    auto M = parse(ctx, kManyCallsModule);

    auto rng = makeRng(0xF006);
    morok::passes::FuncWrapParams p;
    p.probability = 100; // every site is eligible
    p.max_wrappers = 2;  // but the cap stops at two forwarders

    CHECK(morok::passes::functionWrapModule(*M, p, rng));
    CHECK(countFunctions(*M, "morok.wrap") == 2);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("functionWrapModule redirects the call site to an internal forwarder") {
    LLVMContext ctx;
    auto M = parse(ctx, kCallModule);

    auto rng = makeRng(0xF007);
    morok::passes::FuncWrapParams p;
    p.probability = 100;

    CHECK(morok::passes::functionWrapModule(*M, p, rng));

    Function *mainF = M->getFunction("main");
    REQUIRE(mainF != nullptr);
    // main now reaches helper only through the forwarder.
    CHECK(countCallsTo(*mainF, "helper") == 0);
    CHECK(countCallsToPrefix(*mainF, "morok.wrap") == 1);

    Function *fwd = firstWrapperFunction(*M);
    REQUIRE(fwd != nullptr);
    CHECK(fwd->hasInternalLinkage());
    // The forwarder forwards to the original callee and returns.
    CHECK(countCallsTo(*fwd, "helper") == 1);
    REQUIRE_FALSE(fwd->empty());
    CHECK(isa<ReturnInst>(fwd->getEntryBlock().getTerminator()));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("functionWrapModule leaves intrinsic calls alone") {
    LLVMContext ctx;
    auto M = parse(ctx, kIntrinsicModule);

    auto rng = makeRng(0xF008);
    morok::passes::FuncWrapParams p;
    p.probability = 100;

    CHECK_FALSE(morok::passes::functionWrapModule(*M, p, rng));
    CHECK(countFunctions(*M, "morok.wrap") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("functionWrapModule builds a non-variadic wrapper for a variadic callee") {
    LLVMContext ctx;
    auto M = parse(ctx, kVariadicModule);

    auto rng = makeRng(0xF009);
    morok::passes::FuncWrapParams p;
    p.probability = 100;

    CHECK(morok::passes::functionWrapModule(*M, p, rng));

    Function *fwd = firstWrapperFunction(*M);
    REQUIRE(fwd != nullptr);
    FunctionType *fty = fwd->getFunctionType();
    // The forwarder pins the concrete argument list: (ptr, i32) -> i32, no "...".
    CHECK_FALSE(fty->isVarArg());
    CHECK(fty->getNumParams() == 2);
    CHECK(fty->getReturnType()->isIntegerTy(32));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("functionWrapModule leaves musttail calls alone") {
    LLVMContext ctx;
    auto M = parse(ctx, kMustTailModule);
    // Confirm the crafted musttail input is well-formed before running the pass.
    REQUIRE_FALSE(verifyModule(*M));

    auto rng = makeRng(0xF00A);
    morok::passes::FuncWrapParams p;
    p.probability = 100;

    CHECK_FALSE(morok::passes::functionWrapModule(*M, p, rng));
    CHECK(countFunctions(*M, "morok.wrap") == 0);

    Function *mainF = M->getFunction("main");
    REQUIRE(mainF != nullptr);
    CHECK(countCallsTo(*mainF, "helper") == 1);
    CHECK_FALSE(verifyModule(*M));
}
