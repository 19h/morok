// SPDX-License-Identifier: AGPL-3.0-or-later
//
// LLVM-linked tests for the IR-emitting passes: they must grow the IR and keep
// it well-formed.  Semantic preservation across the whole pipeline is verified
// separately by the end-to-end differential tests (tests/e2e); here we check
// structural validity and that the transformation actually fires.

#include "doctest.h"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/AntiAnalysis.hpp"
#include "morok/passes/BogusControlFlow.hpp"
#include "morok/passes/ChaosStateMachine.hpp"
#include "morok/passes/ConstantEncryption.hpp"
#include "morok/passes/Flattening.hpp"
#include "morok/passes/FunctionCallObfuscate.hpp"
#include "morok/passes/FunctionWrapper.hpp"
#include "morok/passes/IndirectBranch.hpp"
#include "morok/passes/Mba.hpp"
#include "morok/passes/SplitBasicBlocks.hpp"
#include "morok/passes/StringEncryption.hpp"
#include "morok/passes/Substitution.hpp"
#include "morok/passes/VectorObfuscation.hpp"

#include "llvm/AsmParser/Parser.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"

#include <memory>

using namespace llvm;

namespace {

const char *kArith = R"ir(
define i32 @arith(i32 %a, i32 %b) {
entry:
  %0 = add i32 %a, %b
  %1 = mul i32 %a, %b
  %2 = xor i32 %0, %1
  %3 = and i32 %0, %2
  %4 = or  i32 %1, %3
  %5 = sub i32 %4, %a
  ret i32 %5
}
)ir";

const char *kShifts = R"ir(
define i32 @shifts(i32 %a) {
entry:
  %0 = shl  i32 %a, 7
  %1 = lshr i32 %a, 3
  %2 = ashr i32 %a, 5
  %3 = xor  i32 %0, %1
  %4 = xor  i32 %3, %2
  ret i32 %4
}
)ir";

std::unique_ptr<Module> parse(LLVMContext &ctx, const char *ir) {
    SMDiagnostic err;
    auto m = parseAssemblyString(ir, err, ctx);
    REQUIRE(m != nullptr);
    return m;
}

std::size_t countBinops(Function &F) {
    std::size_t n = 0;
    for (Instruction &I : instructions(F))
        if (isa<BinaryOperator>(&I))
            ++n;
    return n;
}

} // namespace

TEST_CASE("substituteFunction grows the IR and preserves validity") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = countBinops(*F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(1);
    morok::ir::IRRandom rng(engine);
    const bool changed =
        morok::passes::substituteFunction(*F, {/*prob=*/100, /*iters=*/2}, rng);

    CHECK(changed);
    CHECK(countBinops(*F) > before);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("substituteFunction handles constant shifts and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kShifts);
    Function *F = M->getFunction("shifts");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(7);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::substituteFunction(*F, {100, 1}, rng));
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("mbaFunction grows the IR and preserves validity") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = countBinops(*F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(2);
    morok::ir::IRRandom rng(engine);
    const bool changed = morok::passes::mbaFunction(
        *F, {/*prob=*/100, /*layers=*/2, /*heuristic=*/true}, rng);

    CHECK(changed);
    CHECK(countBinops(*F) > before);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("constantEncryptFunction hides literals behind XOR shares") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @withconst(i32 %a) {
entry:
  %0 = add i32 %a, 305419896
  %1 = xor i32 %0, -559038737
  ret i32 %1
}
)ir");
    Function *F = M->getFunction("withconst");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(5);
    morok::ir::IRRandom rng(engine);
    const bool changed = morok::passes::constantEncryptFunction(
        *F, {/*prob=*/100, /*k=*/4, 1}, rng);
    CHECK(changed);
    CHECK_FALSE(verifyModule(*M, &errs()));
    // The shares must have been materialised as private globals.
    std::size_t shares = 0;
    for (GlobalVariable &gv : M->globals())
        if (gv.getName().starts_with("morok.share"))
            ++shares;
    CHECK(shares >= 4);
}

TEST_CASE("splitBlocksFunction multiplies blocks and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = F->size();
    auto engine = morok::core::Xoshiro256pp::fromSeed(11);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::splitBlocksFunction(*F, {/*splits=*/3}, rng));
    CHECK(F->size() > before);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("bogusControlFlowFunction adds guarded edges and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = F->size();
    auto engine = morok::core::Xoshiro256pp::fromSeed(13);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::bogusControlFlowFunction(*F, {/*prob=*/100, 1}, rng));
    CHECK(F->size() > before); // junk blocks were added
    CHECK_FALSE(verifyModule(*M, &errs()));
    // The opaque-predicate global must exist.
    CHECK(M->getGlobalVariable("morok.bcf.opaque", true) != nullptr);
}

TEST_CASE("flattenFunction collapses a branchy function into a dispatcher") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
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
  %loopcond = icmp sgt i32 %p, 0
  br i1 %loopcond, label %then, label %done
done:
  ret i32 %p
}
)ir");
    Function *F = M->getFunction("branchy");
    REQUIRE(F);
    const std::size_t before = F->size();
    auto engine = morok::core::Xoshiro256pp::fromSeed(17);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::flattenFunction(*F, rng));
    CHECK(F->size() > before); // dispatcher/back-edge/default blocks added
    // A switch-based dispatcher must now exist, and the IR must be valid.
    bool hasSwitch = false;
    for (Instruction &I : instructions(*F))
        if (isa<SwitchInst>(&I))
            hasSwitch = true;
    CHECK(hasSwitch);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("chaosStateMachineFunction flattens via the logistic map") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @branchy2(i32 %a, i32 %b) {
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
)ir");
    Function *F = M->getFunction("branchy2");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(19);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::chaosStateMachineFunction(*F, rng));
    bool hasSwitch = false;
    for (Instruction &I : instructions(*F))
        if (isa<SwitchInst>(&I))
            hasSwitch = true;
    CHECK(hasSwitch);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("vectorObfuscateFunction lifts scalar ops to SIMD and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(21);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::vectorObfuscateFunction(*F, {/*prob=*/100}, rng));
    bool hasVectorOp = false;
    for (Instruction &I : instructions(*F))
        if (I.getType()->isVectorTy())
            hasVectorOp = true;
    CHECK(hasVectorOp);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE(
    "indirectBranchFunction replaces conditional branches with indirectbr") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @cond(i32 %a, i32 %b) {
entry:
  %c = icmp slt i32 %a, %b
  br i1 %c, label %t, label %f
t:
  ret i32 %a
f:
  ret i32 %b
}
)ir");
    Function *F = M->getFunction("cond");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(23);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::indirectBranchFunction(*F, {/*prob=*/100}, rng));
    bool hasIndirectBr = false;
    for (Instruction &I : instructions(*F))
        if (isa<IndirectBrInst>(&I))
            hasIndirectBr = true;
    CHECK(hasIndirectBr);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("functionWrapModule proxies a call and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare i32 @ext(i32)
define i32 @caller(i32 %x) {
  %r = call i32 @ext(i32 %x)
  ret i32 %r
}
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(25);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::functionWrapModule(*M, {/*prob=*/100, /*times=*/1},
                                            rng));
    CHECK(M->getFunction("morok.wrap") != nullptr);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("functionCallObfuscateModule redirects an external call via dlsym") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare i32 @puts(ptr)
@.s = private constant [3 x i8] c"hi\00"
define i32 @caller() {
  %r = call i32 @puts(ptr @.s)
  ret i32 %r
}
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(27);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::functionCallObfuscateModule(*M, {/*prob=*/100}, rng));
    CHECK(M->getFunction("dlsym") != nullptr);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("anti-analysis passes inject valid startup code") {
    LLVMContext ctx;
    auto M = parse(ctx, "define i32 @main() { ret i32 0 }\n");
    CHECK(morok::passes::antiDebuggingModule(*M));
    CHECK(morok::passes::antiHookingModule(*M));
    CHECK_FALSE(morok::passes::antiClassDumpModule(*M)); // no ObjC → no-op
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("probability 0 is a no-op") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    const std::size_t before = countBinops(*F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(3);
    morok::ir::IRRandom rng(engine);
    CHECK_FALSE(morok::passes::substituteFunction(*F, {0, 1}, rng));
    CHECK(countBinops(*F) == before);
}

TEST_CASE("passes leave declarations untouched") {
    LLVMContext ctx;
    auto M = parse(ctx, "declare i32 @ext(i32)\n");
    // No defined functions → nothing to do, and no crash.
    for (Function &F : *M) {
        auto engine = morok::core::Xoshiro256pp::fromSeed(4);
        morok::ir::IRRandom rng(engine);
        CHECK_FALSE(morok::passes::substituteFunction(F, {100, 1}, rng));
    }
}
