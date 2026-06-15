// SPDX-License-Identifier: MIT
//
// LLVM-linked tests for the IR-emitting passes: they must grow the IR and keep
// it well-formed.  Semantic preservation across the whole pipeline is verified
// separately by the end-to-end differential tests (tests/e2e); here we check
// structural validity and that the transformation actually fires.

#include "doctest.h"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/AliasOpaquePredicates.hpp"
#include "morok/passes/AntiAnalysis.hpp"
#include "morok/passes/AdversarialFunctionMerging.hpp"
#include "morok/passes/ArithmeticTables.hpp"
#include "morok/passes/BogusControlFlow.hpp"
#include "morok/passes/ChaosStateMachine.hpp"
#include "morok/passes/CoherentDecoys.hpp"
#include "morok/passes/ConstantEncryption.hpp"
#include "morok/passes/DataEntangledFlattening.hpp"
#include "morok/passes/DataFlowIntegrity.hpp"
#include "morok/passes/DispatcherlessRouting.hpp"
#include "morok/passes/ExternalOpaquePredicates.hpp"
#include "morok/passes/Flattening.hpp"
#include "morok/passes/FunctionCallObfuscate.hpp"
#include "morok/passes/FunctionWrapper.hpp"
#include "morok/passes/HashGatedSelfDecrypt.hpp"
#include "morok/passes/IndirectBranch.hpp"
#include "morok/passes/InterproceduralFsm.hpp"
#include "morok/passes/Mba.hpp"
#include "morok/passes/MutualGuardGraph.hpp"
#include "morok/passes/NonInvertibleState.hpp"
#include "morok/passes/OptimizerAmplification.hpp"
#include "morok/passes/PathExplosion.hpp"
#include "morok/passes/PerBuildPolymorphism.hpp"
#include "morok/passes/PhiTangling.hpp"
#include "morok/passes/PointerLaundering.hpp"
#include "morok/passes/SelfChecksumConstants.hpp"
#include "morok/passes/SplitBasicBlocks.hpp"
#include "morok/passes/StackCoalescing.hpp"
#include "morok/passes/StateOpaquePredicates.hpp"
#include "morok/passes/StringEncryption.hpp"
#include "morok/passes/SubThresholdPersistence.hpp"
#include "morok/passes/Substitution.hpp"
#include "morok/passes/TraceKeying.hpp"
#include "morok/passes/TypePunning.hpp"
#include "morok/passes/UniformPrimitiveLowering.hpp"
#include "morok/passes/Virtualization.hpp"
#include "morok/passes/VectorObfuscation.hpp"

#include "llvm/AsmParser/Parser.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

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

std::size_t countNamedAllocas(Function &F, StringRef prefix) {
    std::size_t n = 0;
    for (Instruction &I : instructions(F))
        if (auto *ai = dyn_cast<AllocaInst>(&I))
            if (ai->getName().starts_with(prefix))
                ++n;
    return n;
}

std::size_t countPhis(Function &F) {
    std::size_t n = 0;
    for (Instruction &I : instructions(F))
        if (isa<PHINode>(&I))
            ++n;
    return n;
}

std::size_t countVolatileAccesses(Function &F) {
    std::size_t n = 0;
    for (Instruction &I : instructions(F)) {
        if (auto *LI = dyn_cast<LoadInst>(&I)) {
            if (LI->isVolatile())
                ++n;
            continue;
        }
        if (auto *SI = dyn_cast<StoreInst>(&I))
            if (SI->isVolatile())
                ++n;
    }
    return n;
}

std::size_t countGlobals(Module &M, StringRef prefix) {
    std::size_t n = 0;
    for (GlobalVariable &GV : M.globals())
        if (GV.getName().starts_with(prefix))
            ++n;
    return n;
}

std::size_t countFunctions(Module &M, StringRef prefix) {
    std::size_t n = 0;
    for (Function &F : M)
        if (F.getName().starts_with(prefix))
            ++n;
    return n;
}

std::vector<std::string> functionOrder(Module &M) {
    std::vector<std::string> Names;
    for (Function &F : M)
        if (!F.isDeclaration())
            Names.push_back(F.getName().str());
    return Names;
}

std::vector<std::string> blockOrder(Function &F) {
    std::vector<std::string> Names;
    for (BasicBlock &BB : F)
        Names.push_back(BB.getName().str());
    return Names;
}

bool hasPlainI8Arithmetic(Function &F) {
    for (Instruction &I : instructions(F)) {
        auto *BO = dyn_cast<BinaryOperator>(&I);
        if (!BO || !BO->getType()->isIntegerTy(8))
            continue;
        switch (BO->getOpcode()) {
        case Instruction::Add:
        case Instruction::Sub:
        case Instruction::Mul:
        case Instruction::And:
        case Instruction::Or:
        case Instruction::Xor:
            return true;
        default:
            break;
        }
    }
    return false;
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

TEST_CASE("optimizerAmplifyFunction builds input-selected equivalent forms") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @optamp(i32 %a, i32 %b) {
entry:
  %sum = add i32 %a, %b
  ret i32 %sum
}
)ir");
    Function *F = M->getFunction("optamp");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(13);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::optimizerAmplifyFunction(
        *F, {/*probability=*/100, /*max_forms=*/3}, rng));

    std::size_t bases = 0;
    std::size_t guards = 0;
    std::size_t selects = 0;
    std::size_t volatiles = 0;
    for (Instruction &I : instructions(*F)) {
        if (I.getName().starts_with("morok.optamp.base"))
            ++bases;
        if (auto *Cmp = dyn_cast<ICmpInst>(&I))
            if (Cmp->getName().starts_with("morok.optamp.guard"))
            ++guards;
        if (auto *SI = dyn_cast<SelectInst>(&I))
            if (SI->getName().starts_with("morok.optamp.select"))
                ++selects;
        if (auto *LI = dyn_cast<LoadInst>(&I))
            volatiles += LI->isVolatile() ? 1u : 0u;
        if (auto *SI = dyn_cast<StoreInst>(&I))
            volatiles += SI->isVolatile() ? 1u : 0u;
    }
    CHECK(bases == 1u);
    CHECK(guards == 3u);
    CHECK(selects == 3u);
    CHECK(volatiles == 0u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("optimizerAmplifyFunction honors probability and skips flags") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @optamp_skip(i32 %a, i32 %b) {
entry:
  %sum = add nsw i32 %a, %b
  ret i32 %sum
}
)ir");
    Function *F = M->getFunction("optamp_skip");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(14);
    morok::ir::IRRandom rng(engine);
    CHECK_FALSE(morok::passes::optimizerAmplifyFunction(
        *F, {/*probability=*/100, /*max_forms=*/3}, rng));
    for (Instruction &I : instructions(*F))
        CHECK_FALSE(I.getName().starts_with("morok.optamp"));
    CHECK_FALSE(verifyModule(*M, &errs()));

    auto M2 = parse(ctx, R"ir(
define i32 @optamp_zero(i32 %a, i32 %b) {
entry:
  %sum = xor i32 %a, %b
  ret i32 %sum
}
)ir");
    Function *F2 = M2->getFunction("optamp_zero");
    REQUIRE(F2);
    CHECK_FALSE(morok::passes::optimizerAmplifyFunction(
        *F2, {/*probability=*/0, /*max_forms=*/3}, rng));
    for (Instruction &I : instructions(*F2))
        CHECK_FALSE(I.getName().starts_with("morok.optamp"));
    CHECK_FALSE(verifyModule(*M2, &errs()));
}

TEST_CASE("subThresholdPersistFunction adds bounded volatile zero terms") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @threshold(i32 %a, i32 %b) {
entry:
  %sum = add i32 %a, %b
  ret i32 %sum
}
)ir");
    Function *F = M->getFunction("threshold");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(11);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::subThresholdPersistFunction(
        *F, {/*probability=*/100, /*max_terms=*/2}, rng));

    CHECK(countNamedAllocas(*F, "morok.threshold.seed") == 1u);

    std::size_t volatileLoads = 0;
    std::size_t zeroTerms = 0;
    std::size_t combinedTerms = 0;
    for (Instruction &I : instructions(*F)) {
        if (auto *LI = dyn_cast<LoadInst>(&I))
            if (LI->isVolatile() &&
                LI->getName().starts_with("morok.threshold.load"))
                ++volatileLoads;
        if (I.getName().starts_with("morok.threshold.zero"))
            ++zeroTerms;
        if (I.getName().starts_with("morok.threshold.keep"))
            ++combinedTerms;
    }
    CHECK(volatileLoads == 4u);
    CHECK(zeroTerms == 2u);
    CHECK(combinedTerms == 2u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("subThresholdPersistFunction honors probability and skips flags") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @threshold_skip(i32 %a, i32 %b) {
entry:
  %sum = add nuw i32 %a, %b
  ret i32 %sum
}
)ir");
    Function *F = M->getFunction("threshold_skip");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(12);
    morok::ir::IRRandom rng(engine);
    CHECK_FALSE(morok::passes::subThresholdPersistFunction(
        *F, {/*probability=*/100, /*max_terms=*/2}, rng));
    CHECK(countNamedAllocas(*F, "morok.threshold.seed") == 0u);
    CHECK_FALSE(verifyModule(*M, &errs()));

    auto M2 = parse(ctx, R"ir(
define i32 @threshold_zero(i32 %a, i32 %b) {
entry:
  %sum = add i32 %a, %b
  ret i32 %sum
}
)ir");
    Function *F2 = M2->getFunction("threshold_zero");
    REQUIRE(F2);
    CHECK_FALSE(morok::passes::subThresholdPersistFunction(
        *F2, {/*probability=*/0, /*max_terms=*/2}, rng));
    CHECK(countNamedAllocas(*F2, "morok.threshold.seed") == 0u);
    CHECK_FALSE(verifyModule(*M2, &errs()));
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

TEST_CASE("stackCoalesceFunction folds static allocas into one byte buffer") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @locals(i32 %x, ptr %sink) {
entry:
  %a = alloca i32, align 4
  %b = alloca i64, align 8
  store i32 %x, ptr %a, align 4
  %wide = zext i32 %x to i64
  store i64 %wide, ptr %b, align 8
  call void @llvm.lifetime.start.p0(i64 4, ptr %a)
  %av = load i32, ptr %a, align 4
  %bv = load i64, ptr %b, align 8
  %bt = trunc i64 %bv to i32
  %r = add i32 %av, %bt
  ret i32 %r
}
declare void @llvm.lifetime.start.p0(i64 immarg, ptr nocapture)
)ir");
    Function *F = M->getFunction("locals");
    REQUIRE(F);
    CHECK(countNamedAllocas(*F, "a") == 1);
    CHECK(countNamedAllocas(*F, "b") == 1);

    auto engine = morok::core::Xoshiro256pp::fromSeed(29);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::stackCoalesceFunction(
        *F, {/*probability=*/100, /*opaque_offsets=*/true}, rng));

    CHECK(countNamedAllocas(*F, "morok.stack") == 1);
    CHECK(countNamedAllocas(*F, "a") == 0);
    CHECK(countNamedAllocas(*F, "b") == 0);

    bool hasI8Gep = false;
    bool hasRuntimeOffsetMix = false;
    for (Instruction &I : instructions(*F)) {
        if (auto *gep = dyn_cast<GetElementPtrInst>(&I)) {
            hasI8Gep |= gep->getSourceElementType()->isIntegerTy(8);
        } else if (auto *bo = dyn_cast<BinaryOperator>(&I)) {
            hasRuntimeOffsetMix |= bo->getOpcode() == Instruction::And ||
                                   bo->getOpcode() == Instruction::Xor;
        }
    }
    CHECK(hasI8Gep);
    CHECK(hasRuntimeOffsetMix);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("stackCoalesceFunction leaves dynamic allocas untouched") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define ptr @dynamic(i64 %n) {
entry:
  %buf = alloca i8, i64 %n, align 1
  ret ptr %buf
}
)ir");
    Function *F = M->getFunction("dynamic");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(31);
    morok::ir::IRRandom rng(engine);
    CHECK_FALSE(morok::passes::stackCoalesceFunction(
        *F, {/*probability=*/100, /*opaque_offsets=*/true}, rng));
    CHECK(countNamedAllocas(*F, "buf") == 1);
    CHECK(countNamedAllocas(*F, "morok.stack") == 0);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("stackCoalesceFunction skips allocas whose address escapes") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define void @escape(ptr %sink) {
entry:
  %local = alloca i32, align 4
  store ptr %local, ptr %sink, align 8
  ret void
}
)ir");
    Function *F = M->getFunction("escape");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(33);
    morok::ir::IRRandom rng(engine);
    CHECK_FALSE(morok::passes::stackCoalesceFunction(
        *F, {/*probability=*/100, /*opaque_offsets=*/true}, rng));
    CHECK(countNamedAllocas(*F, "local") == 1);
    CHECK(countNamedAllocas(*F, "morok.stack") == 0);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("pointerLaunderFunction launders memory pointer operands") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
target datalayout = "e-p:64:64"
define i32 @mem(ptr %p, i32 %x) {
entry:
  store i32 %x, ptr %p, align 4
  %q = getelementptr i32, ptr %p, i32 1
  %v = load i32, ptr %q, align 4
  ret i32 %v
}
)ir");
    Function *F = M->getFunction("mem");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(35);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::pointerLaunderFunction(
        *F, {/*pointer_probability=*/100, /*integer_probability=*/0}, rng));

    bool hasPtrToInt = false;
    bool hasIntToPtr = false;
    bool hasI8Gep = false;
    bool hasVolatileKeyLoad = false;
    for (Instruction &I : instructions(*F)) {
        hasPtrToInt |= isa<PtrToIntInst>(&I);
        hasIntToPtr |= isa<IntToPtrInst>(&I);
        if (auto *gep = dyn_cast<GetElementPtrInst>(&I))
            hasI8Gep |= gep->getSourceElementType()->isIntegerTy(8);
        if (auto *load = dyn_cast<LoadInst>(&I))
            hasVolatileKeyLoad |=
                load->isVolatile() && load->getName().starts_with("morok.ptr");
    }
    CHECK(hasPtrToInt);
    CHECK(hasIntToPtr);
    CHECK(hasI8Gep);
    CHECK(hasVolatileKeyLoad);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("pointerLaunderFunction launders integer SSA through bitcasts") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @ints(i32 %a, i32 %b) {
entry:
  %sum = add i32 %a, %b
  %mix = xor i32 %sum, 305419896
  ret i32 %mix
}
)ir");
    Function *F = M->getFunction("ints");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(37);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::pointerLaunderFunction(
        *F, {/*pointer_probability=*/0, /*integer_probability=*/100}, rng));

    bool hasVectorBitcast = false;
    bool hasShuffle = false;
    for (Instruction &I : instructions(*F)) {
        if (auto *cast = dyn_cast<BitCastInst>(&I)) {
            hasVectorBitcast |= cast->getSrcTy()->isVectorTy() ||
                                cast->getDestTy()->isVectorTy();
        }
        hasShuffle |= isa<ShuffleVectorInst>(&I);
    }
    CHECK(hasVectorBitcast);
    CHECK(hasShuffle);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("pointerLaunderFunction skips non-integral pointer address spaces") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
target datalayout = "e-p:64:64-p1:64:64-ni:1"
define i32 @nonintegral(ptr addrspace(1) %p) {
entry:
  %v = load i32, ptr addrspace(1) %p, align 4
  ret i32 %v
}
)ir");
    Function *F = M->getFunction("nonintegral");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(39);
    morok::ir::IRRandom rng(engine);
    CHECK_FALSE(morok::passes::pointerLaunderFunction(
        *F, {/*pointer_probability=*/100, /*integer_probability=*/0}, rng));

    for (Instruction &I : instructions(*F)) {
        CHECK_FALSE(isa<PtrToIntInst>(&I));
        CHECK_FALSE(isa<IntToPtrInst>(&I));
    }
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("coherentDecoysFunction adds plausible dead return alternatives") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @score(i32 %a, i32 %b, i32 %salt) {
entry:
  %x = add i32 %a, %b
  %y = xor i32 %x, %salt
  %z = mul i32 %y, 17
  ret i32 %z
}
)ir");
    Function *F = M->getFunction("score");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(131);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::coherentDecoysFunction(
        *F, {/*probability=*/100, /*max_blocks=*/4, /*depth=*/4}, rng));

    CHECK(M->getGlobalVariable("morok.decoy.opaque", true) != nullptr);
    bool hasPredicate = false;
    bool hasDecoyBlock = false;
    bool hasDecoyReturn = false;
    bool hasAltArithmetic = false;
    bool hasVolatileLoad = false;
    for (BasicBlock &BB : *F) {
        if (BB.getName().starts_with("morok.decoy.alt")) {
            hasDecoyBlock = true;
            if (isa<ReturnInst>(BB.getTerminator()))
                hasDecoyReturn = true;
        }
        for (Instruction &I : BB) {
            if (I.getName().starts_with("morok.decoy.pred"))
                hasPredicate = true;
            if (I.getName().starts_with("morok.decoy.alt"))
                hasAltArithmetic = true;
            if (auto *LI = dyn_cast<LoadInst>(&I))
                hasVolatileLoad |= LI->isVolatile();
        }
    }
    CHECK(hasPredicate);
    CHECK(hasDecoyBlock);
    CHECK(hasDecoyReturn);
    CHECK(hasAltArithmetic);
    CHECK(hasVolatileLoad);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("coherentDecoysFunction honors zero probability") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(132);
    morok::ir::IRRandom rng(engine);

    CHECK_FALSE(morok::passes::coherentDecoysFunction(
        *F, {/*probability=*/0, /*max_blocks=*/4, /*depth=*/4}, rng));
    CHECK(M->getGlobalVariable("morok.decoy.opaque", true) == nullptr);
    for (BasicBlock &BB : *F)
        CHECK_FALSE(BB.getName().starts_with("morok.decoy"));
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("typePunFunction round-trips integers through a byte-vector view") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
target datalayout = "e-p:64:64"
define i32 @pun_i32(i32 %a, i32 %b) {
entry:
  %sum = add i32 %a, %b
  %mix = xor i32 %sum, 305419896
  ret i32 %mix
}
)ir");
    Function *F = M->getFunction("pun_i32");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(41);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::typePunFunction(*F,
                                         {/*probability=*/100,
                                          /*include_floating=*/true,
                                          /*max_targets=*/64},
                                         rng));

    CHECK(countNamedAllocas(*F, "morok.pun") >= 1);
    bool hasVolatileStore = false;
    bool hasVolatileVectorLoad = false;
    bool hasVectorBitcast = false;
    for (Instruction &I : instructions(*F)) {
        if (auto *store = dyn_cast<StoreInst>(&I))
            hasVolatileStore |= store->isVolatile();
        if (auto *load = dyn_cast<LoadInst>(&I))
            hasVolatileVectorLoad |=
                load->isVolatile() && load->getType()->isVectorTy();
        if (auto *cast = dyn_cast<BitCastInst>(&I))
            hasVectorBitcast |= cast->getSrcTy()->isVectorTy() ||
                                cast->getDestTy()->isVectorTy();
    }
    CHECK(hasVolatileStore);
    CHECK(hasVolatileVectorLoad);
    CHECK(hasVectorBitcast);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("typePunFunction round-trips floating scalars through integers") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
target datalayout = "e-p:64:64"
define double @pun_f64(double %a, double %b) {
entry:
  %sum = fadd double %a, %b
  %mix = fmul double %sum, 3.000000e+00
  ret double %mix
}
)ir");
    Function *F = M->getFunction("pun_f64");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(43);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::typePunFunction(*F,
                                         {/*probability=*/100,
                                          /*include_floating=*/true,
                                          /*max_targets=*/64},
                                         rng));

    bool hasIntegerLoad = false;
    bool hasIntToDoubleBitcast = false;
    for (Instruction &I : instructions(*F)) {
        if (auto *load = dyn_cast<LoadInst>(&I))
            hasIntegerLoad |=
                load->isVolatile() && load->getType()->isIntegerTy(64);
        if (auto *cast = dyn_cast<BitCastInst>(&I))
            hasIntToDoubleBitcast |= cast->getSrcTy()->isIntegerTy(64) &&
                                     cast->getDestTy()->isDoubleTy();
    }
    CHECK(hasIntegerLoad);
    CHECK(hasIntToDoubleBitcast);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("typePunFunction skips unsupported narrow scalar widths") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i1 @pun_i1(i1 %a, i1 %b) {
entry:
  %x = xor i1 %a, %b
  ret i1 %x
}
)ir");
    Function *F = M->getFunction("pun_i1");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(45);
    morok::ir::IRRandom rng(engine);
    CHECK_FALSE(morok::passes::typePunFunction(*F,
                                               {/*probability=*/100,
                                                /*include_floating=*/true,
                                                /*max_targets=*/64},
                                               rng));
    CHECK(countNamedAllocas(*F, "morok.pun") == 0);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("typePunFunction respects its per-function target cap") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
target datalayout = "e-p:64:64"
define i32 @many(i32 %a, i32 %b) {
entry:
  %v0 = add i32 %a, %b
  %v1 = xor i32 %v0, %a
  %v2 = add i32 %v1, %b
  %v3 = xor i32 %v2, %v0
  %v4 = add i32 %v3, %v1
  ret i32 %v4
}
)ir");
    Function *F = M->getFunction("many");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(47);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::typePunFunction(*F,
                                         {/*probability=*/100,
                                          /*include_floating=*/true,
                                          /*max_targets=*/2},
                                         rng));
    CHECK(countNamedAllocas(*F, "morok.pun") == 2);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("phiTangleFunction builds redundant integer phi webs") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @join(i32 %a, i32 %b, i1 %c) {
entry:
  br i1 %c, label %left, label %right
left:
  %l = add i32 %a, 7
  br label %merge
right:
  %r = sub i32 %b, 3
  br label %merge
merge:
  %p = phi i32 [ %l, %left ], [ %r, %right ]
  %out = xor i32 %p, 85
  ret i32 %out
}
)ir");
    Function *F = M->getFunction("join");
    REQUIRE(F);
    const std::size_t before = countPhis(*F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(49);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::phiTangleFunction(
        *F, {/*probability=*/100, /*layers=*/2, /*max_phis=*/8}, rng));

    CHECK(countPhis(*F) >= before + 4);
    bool hasEdgeCopies = false;
    bool hasTangleExpr = false;
    bool xorUsesTangle = false;
    for (Instruction &I : instructions(*F)) {
        hasEdgeCopies |= I.getName().starts_with("morok.phi.edge");
        hasTangleExpr |= I.getName().starts_with("morok.phi.value");
        if (auto *bo = dyn_cast<BinaryOperator>(&I)) {
            if (bo->getOpcode() == Instruction::Xor && bo->getName() == "out") {
                xorUsesTangle =
                    bo->getOperand(0)->getName().starts_with("morok.phi");
            }
        }
    }
    CHECK(hasEdgeCopies);
    CHECK(hasTangleExpr);
    CHECK(xorUsesTangle);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("phiTangleFunction skips non-integer phis") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define double @joinf(double %a, double %b, i1 %c) {
entry:
  br i1 %c, label %left, label %right
left:
  %l = fadd double %a, 1.000000e+00
  br label %merge
right:
  %r = fsub double %b, 2.000000e+00
  br label %merge
merge:
  %p = phi double [ %l, %left ], [ %r, %right ]
  ret double %p
}
)ir");
    Function *F = M->getFunction("joinf");
    REQUIRE(F);
    const std::size_t before = countPhis(*F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(51);
    morok::ir::IRRandom rng(engine);
    CHECK_FALSE(morok::passes::phiTangleFunction(
        *F, {/*probability=*/100, /*layers=*/2, /*max_phis=*/8}, rng));
    CHECK(countPhis(*F) == before);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("phiTangleFunction respects its selected phi cap") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @twop(i32 %a, i32 %b, i1 %c) {
entry:
  br i1 %c, label %left, label %right
left:
  %l0 = add i32 %a, 1
  %l1 = add i32 %a, 2
  br label %merge
right:
  %r0 = sub i32 %b, 1
  %r1 = sub i32 %b, 2
  br label %merge
merge:
  %p0 = phi i32 [ %l0, %left ], [ %r0, %right ]
  %p1 = phi i32 [ %l1, %left ], [ %r1, %right ]
  %s = add i32 %p0, %p1
  ret i32 %s
}
)ir");
    Function *F = M->getFunction("twop");
    REQUIRE(F);
    const std::size_t before = countPhis(*F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(53);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::phiTangleFunction(
        *F, {/*probability=*/100, /*layers=*/1, /*max_phis=*/1}, rng));
    CHECK(countPhis(*F) == before + 2);
    CHECK_FALSE(verifyModule(*M, &errs()));
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

TEST_CASE("aliasOpaquePredicatesFunction builds alias-invariant guards") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t beforeBlocks = F->size();
    auto engine = morok::core::Xoshiro256pp::fromSeed(61);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::aliasOpaquePredicatesFunction(
        *F, {/*probability=*/100, /*iterations=*/1}, rng));

    CHECK(F->size() > beforeBlocks);
    CHECK(countNamedAllocas(*F, "morok.aliasop.cell") == 1u);
    CHECK(countVolatileAccesses(*F) >= 5u);

    bool hasJunk = false;
    bool hasPtrToInt = false;
    bool hasIntToPtr = false;
    bool hasInvariantCompare = false;
    for (BasicBlock &BB : *F) {
        if (BB.getName().starts_with("morok.aliasop.junk"))
            hasJunk = true;
        for (Instruction &I : BB) {
            if (isa<PtrToIntInst>(&I))
                hasPtrToInt = true;
            if (isa<IntToPtrInst>(&I))
                hasIntToPtr = true;
            if (I.getName().starts_with("morok.aliasop.pred"))
                hasInvariantCompare = true;
        }
    }
    CHECK(hasJunk);
    CHECK(hasPtrToInt);
    CHECK(hasIntToPtr);
    CHECK(hasInvariantCompare);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("aliasOpaquePredicatesFunction honors zero probability") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t beforeBlocks = F->size();
    auto engine = morok::core::Xoshiro256pp::fromSeed(62);
    morok::ir::IRRandom rng(engine);

    CHECK_FALSE(morok::passes::aliasOpaquePredicatesFunction(
        *F, {/*probability=*/0, /*iterations=*/1}, rng));
    CHECK(F->size() == beforeBlocks);
    CHECK(countNamedAllocas(*F, "morok.aliasop.cell") == 0u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE(
    "externalOpaquePredicatesFunction builds IPO-blocked volatile guards") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @extop_target(i32 %x) {
entry:
  %c = icmp sgt i32 %x, 4
  br i1 %c, label %left, label %right
left:
  %l = add i32 %x, 7
  br label %merge
right:
  %r = sub i32 %x, 3
  br label %merge
merge:
  %p = phi i32 [ %l, %left ], [ %r, %right ]
  ret i32 %p
}
)ir");
    Function *F = M->getFunction("extop_target");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(98);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::externalOpaquePredicatesFunction(
        *F, {/*probability=*/100, /*max_blocks=*/3, /*decoy_stores=*/2}, rng));

    Function *Context = M->getFunction("morok.extop.context");
    REQUIRE(Context);
    CHECK(Context->hasFnAttribute(Attribute::NoInline));
    CHECK(Context->hasFnAttribute(Attribute::OptimizeNone));
    CHECK(countGlobals(*M, "morok.extop.seed") == 1u);
    CHECK(countGlobals(*M, "morok.extop.scratch") == 1u);

    unsigned contextCalls = 0;
    unsigned decoyBlocks = 0;
    bool hasPredicate = false;
    bool branchesToDecoy = false;
    bool decoyHasVolatileStore = false;
    for (BasicBlock &BB : *F) {
        const bool isDecoy = BB.getName().starts_with("morok.extop.decoy");
        if (isDecoy)
            ++decoyBlocks;
        for (Instruction &I : BB) {
            hasPredicate |= I.getName().starts_with("morok.extop.pred");
            if (auto *CI = dyn_cast<CallInst>(&I))
                if (CI->getCalledFunction() == Context)
                    ++contextCalls;
            if (auto *BI = dyn_cast<BranchInst>(&I))
                if (BI->isConditional())
                    for (unsigned Succ = 0; Succ != BI->getNumSuccessors();
                         ++Succ)
                        branchesToDecoy |= BI->getSuccessor(Succ)
                                               ->getName()
                                               .starts_with(
                                                   "morok.extop.decoy");
            if (isDecoy)
                if (auto *SI = dyn_cast<StoreInst>(&I))
                    decoyHasVolatileStore |= SI->isVolatile();
        }
    }

    bool helperHasVolatileLoad = false;
    for (Instruction &I : instructions(*Context))
        if (auto *LI = dyn_cast<LoadInst>(&I))
            helperHasVolatileLoad |= LI->isVolatile();

    CHECK(contextCalls >= 2u);
    CHECK(decoyBlocks >= 1u);
    CHECK(hasPredicate);
    CHECK(branchesToDecoy);
    CHECK(decoyHasVolatileStore);
    CHECK(helperHasVolatileLoad);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("externalOpaquePredicatesFunction honors zero probability") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @extop_off(i32 %x) {
entry:
  %y = add i32 %x, 1
  ret i32 %y
}
)ir");
    Function *F = M->getFunction("extop_off");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(99);
    morok::ir::IRRandom rng(engine);

    CHECK_FALSE(morok::passes::externalOpaquePredicatesFunction(
        *F, {/*probability=*/0, /*max_blocks=*/3, /*decoy_stores=*/2}, rng));
    CHECK(M->getFunction("morok.extop.context") == nullptr);
    CHECK(countGlobals(*M, "morok.extop.") == 0u);
    CHECK_FALSE(verifyModule(*M, &errs()));
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

TEST_CASE("dataEntangledFlattenFunction fuses state with live data") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @entangled(i32 %a, i32 %b, i1 %flag) {
entry:
  %seed = xor i32 %a, 305419896
  br i1 %flag, label %left, label %right
left:
  %l0 = add i32 %seed, %b
  %l1 = xor i32 %l0, %a
  br label %join
right:
  %r0 = sub i32 %seed, %b
  %r1 = or i32 %r0, %a
  br label %join
join:
  %p = phi i32 [ %l1, %left ], [ %r1, %right ]
  %out = add i32 %p, 7
  ret i32 %out
}
)ir");
    Function *F = M->getFunction("entangled");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(71);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::dataEntangledFlattenFunction(*F, {/*max_terms=*/4},
                                                      rng));

    bool hasSwitch = false;
    bool hasShadow = false;
    bool hasToken = false;
    bool hasNext = false;
    std::size_t volatileAccesses = 0;
    for (Instruction &I : instructions(*F)) {
        if (isa<SwitchInst>(&I))
            hasSwitch = true;
        if (auto *AI = dyn_cast<AllocaInst>(&I))
            if (AI->getName().starts_with("entfla.shadow"))
                hasShadow = true;
        if (I.getName().starts_with("entfla.token"))
            hasToken = true;
        if (I.getName().starts_with("entfla.next"))
            hasNext = true;
        if (auto *LI = dyn_cast<LoadInst>(&I)) {
            if (LI->isVolatile() && LI->getName().starts_with("entfla.shadow"))
                ++volatileAccesses;
        } else if (auto *SI = dyn_cast<StoreInst>(&I)) {
            if (SI->isVolatile())
                ++volatileAccesses;
        }
    }

    CHECK(hasSwitch);
    CHECK(hasShadow);
    CHECK(hasToken);
    CHECK(hasNext);
    CHECK(volatileAccesses >= 4u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("dataEntangledFlattenFunction skips single-block functions") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(72);
    morok::ir::IRRandom rng(engine);

    CHECK_FALSE(morok::passes::dataEntangledFlattenFunction(
        *F, {/*max_terms=*/4}, rng));
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE(
    "nonInvertibleStateFunction hashes entangled next states before dispatch") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @noninv(i32 %a, i32 %b, i32 %cmd) {
entry:
  %seed = xor i32 %a, 1431655765
  %cond = icmp slt i32 %seed, %b
  br i1 %cond, label %left, label %right
left:
  %l = add i32 %seed, %cmd
  br label %join
right:
  %r = sub i32 %b, %cmd
  br label %join
join:
  %p = phi i32 [ %l, %left ], [ %r, %right ]
  switch i32 %cmd, label %done [
    i32 0, label %case0
    i32 1, label %case1
  ]
case0:
  %x = xor i32 %p, %a
  ret i32 %x
case1:
  %y = or i32 %p, %b
  ret i32 %y
done:
  ret i32 %p
}
)ir");
    Function *F = M->getFunction("noninv");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(111);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::nonInvertibleStateFunction(
        *F, {/*max_terms=*/4, /*rounds=*/3}, rng));

    bool hasSwitch = false;
    bool hasToken = false;
    bool hasLossyHash = false;
    bool hasHashInput = false;
    bool hasNextStore = false;
    std::vector<std::uint64_t> switchCases;
    std::vector<std::uint64_t> rawTargets;
    std::size_t volatileAccesses = 0;
    for (Instruction &I : instructions(*F)) {
        if (auto *SW = dyn_cast<SwitchInst>(&I)) {
            hasSwitch = true;
            for (const auto &Case : SW->cases())
                switchCases.push_back(Case.getCaseValue()->getZExtValue());
        }
        if (I.getName().starts_with("nistate.token"))
            hasToken = true;
        if (I.getName().starts_with("nistate.hash.loss"))
            hasLossyHash = true;
        if (I.getName().starts_with("nistate.hash.input"))
            hasHashInput = true;
        if (auto *SI = dyn_cast<StoreInst>(&I)) {
            if (SI->isVolatile())
                ++volatileAccesses;
            if (SI->getValueOperand()->getName().starts_with("nistate.next"))
                hasNextStore = true;
        } else if (auto *LI = dyn_cast<LoadInst>(&I)) {
            if (LI->isVolatile())
                ++volatileAccesses;
        }
        if (auto *Sel = dyn_cast<SelectInst>(&I)) {
            if (!Sel->getName().starts_with("nistate.target.raw"))
                continue;
            if (auto *C = dyn_cast<ConstantInt>(Sel->getTrueValue()))
                rawTargets.push_back(C->getZExtValue());
            if (auto *C = dyn_cast<ConstantInt>(Sel->getFalseValue()))
                rawTargets.push_back(C->getZExtValue());
        }
    }

    bool rawStateLeakedAsCase = false;
    for (std::uint64_t Raw : rawTargets)
        if (std::find(switchCases.begin(), switchCases.end(), Raw) !=
            switchCases.end())
            rawStateLeakedAsCase = true;

    CHECK(hasSwitch);
    CHECK(countNamedAllocas(*F, "nistate.shadow") == 1u);
    CHECK(hasToken);
    CHECK(hasHashInput);
    CHECK(hasLossyHash);
    CHECK(hasNextStore);
    CHECK_FALSE(switchCases.empty());
    CHECK_FALSE(rawTargets.empty());
    CHECK_FALSE(rawStateLeakedAsCase);
    CHECK(volatileAccesses >= 4u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("nonInvertibleStateFunction skips single-block functions") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(112);
    morok::ir::IRRandom rng(engine);

    CHECK_FALSE(morok::passes::nonInvertibleStateFunction(
        *F, {/*max_terms=*/4, /*rounds=*/3}, rng));
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("stateOpaquePredicatesFunction guards flattened blocks with MBA state") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @stateful(i32 %a, i32 %b, i32 %cmd) {
entry:
  %seed = xor i32 %a, 610839776
  %cond = icmp ult i32 %seed, %b
  br i1 %cond, label %left, label %right
left:
  %l = add i32 %seed, %cmd
  br label %join
right:
  %r = sub i32 %b, %cmd
  br label %join
join:
  %p = phi i32 [ %l, %left ], [ %r, %right ]
  %out = xor i32 %p, %a
  ret i32 %out
}
)ir");
    Function *F = M->getFunction("stateful");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(141);
    morok::ir::IRRandom rng(engine);
    REQUIRE(morok::passes::nonInvertibleStateFunction(
        *F, {/*max_terms=*/4, /*rounds=*/3}, rng));

    CHECK(morok::passes::stateOpaquePredicatesFunction(
        *F, {/*probability=*/100, /*max_blocks=*/8, /*max_terms=*/4}, rng));

    CHECK(countNamedAllocas(*F, "morok.stateop.shadow") == 1u);
    bool hasFalseBlock = false;
    bool hasPredicate = false;
    bool hasStateLoad = false;
    bool hasMba = false;
    std::size_t volatileAccesses = 0;
    for (BasicBlock &BB : *F) {
        if (BB.getName().starts_with("morok.stateop.false"))
            hasFalseBlock = true;
        for (Instruction &I : BB) {
            if (I.getName().starts_with("morok.stateop.pred"))
                hasPredicate = true;
            if (I.getName().starts_with("morok.stateop.state"))
                hasStateLoad = true;
            if (I.getName().starts_with("morok.stateop.mba"))
                hasMba = true;
            if (auto *LI = dyn_cast<LoadInst>(&I))
                volatileAccesses += LI->isVolatile() ? 1u : 0u;
            if (auto *SI = dyn_cast<StoreInst>(&I))
                volatileAccesses += SI->isVolatile() ? 1u : 0u;
        }
    }
    CHECK(hasFalseBlock);
    CHECK(hasPredicate);
    CHECK(hasStateLoad);
    CHECK(hasMba);
    CHECK(volatileAccesses >= 4u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("stateOpaquePredicatesFunction honors zero probability") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @stateful_zero(i32 %x) {
entry:
  %c = icmp eq i32 %x, 0
  br i1 %c, label %a, label %b
a:
  %y = add i32 %x, 1
  ret i32 %y
b:
  %z = sub i32 %x, 1
  ret i32 %z
}
)ir");
    Function *F = M->getFunction("stateful_zero");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(142);
    morok::ir::IRRandom rng(engine);
    REQUIRE(morok::passes::nonInvertibleStateFunction(
        *F, {/*max_terms=*/2, /*rounds=*/2}, rng));

    CHECK_FALSE(morok::passes::stateOpaquePredicatesFunction(
        *F, {/*probability=*/0, /*max_blocks=*/8, /*max_terms=*/4}, rng));
    CHECK(countNamedAllocas(*F, "morok.stateop.shadow") == 0u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE(
    "interproceduralFsmSplitModule hoists flattened state updates to helpers") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @splitfsm(i32 %a, i32 %b, i32 %cmd) {
entry:
  %seed = xor i32 %a, 324508639
  %cond = icmp ugt i32 %seed, %b
  br i1 %cond, label %left, label %right
left:
  %l = add i32 %seed, %cmd
  br label %join
right:
  %r = sub i32 %b, %cmd
  br label %join
join:
  %p = phi i32 [ %l, %left ], [ %r, %right ]
  switch i32 %cmd, label %done [
    i32 0, label %case0
    i32 1, label %case1
  ]
case0:
  %x = xor i32 %p, %a
  ret i32 %x
case1:
  %y = or i32 %p, %b
  ret i32 %y
done:
  ret i32 %p
}
)ir");
    Function *F = M->getFunction("splitfsm");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(121);
    morok::ir::IRRandom rng(engine);
    REQUIRE(morok::passes::nonInvertibleStateFunction(
        *F, {/*max_terms=*/4, /*rounds=*/3}, rng));

    CHECK(morok::passes::interproceduralFsmSplitModule(
        *M, {/*probability=*/100, /*max_sites=*/32, /*max_terms=*/4}, rng));

    Function *StepA = M->getFunction("morok.ifsm.step.a");
    Function *StepB = M->getFunction("morok.ifsm.step.b");
    REQUIRE(StepA);
    REQUIRE(StepB);
    CHECK(M->getGlobalVariable("morok.ifsm.thread", true) != nullptr);

    bool aCallsB = false;
    bool bCallsA = false;
    for (Instruction &I : instructions(StepA))
        if (auto *CI = dyn_cast<CallInst>(&I))
            aCallsB |= CI->getCalledFunction() == StepB;
    for (Instruction &I : instructions(StepB))
        if (auto *CI = dyn_cast<CallInst>(&I))
            bCallsA |= CI->getCalledFunction() == StepA;
    CHECK(aCallsB);
    CHECK(bCallsA);

    bool callsA = false;
    bool callsB = false;
    std::size_t wrappedStores = 0;
    bool directTransitionStore = false;
    for (Instruction &I : instructions(*F)) {
        auto *SI = dyn_cast<StoreInst>(&I);
        if (!SI || SI->getParent() == &F->getEntryBlock())
            continue;
        auto *AI =
            dyn_cast<AllocaInst>(SI->getPointerOperand()->stripPointerCasts());
        if (!AI || !AI->getName().starts_with("fla.state"))
            continue;

        auto *CI = dyn_cast<CallInst>(SI->getValueOperand());
        if (!CI || !CI->getCalledFunction() ||
            !CI->getCalledFunction()->getName().starts_with("morok.ifsm")) {
            directTransitionStore = true;
            continue;
        }
        ++wrappedStores;
        callsA |= CI->getCalledFunction() == StepA;
        callsB |= CI->getCalledFunction() == StepB;
    }

    CHECK(wrappedStores >= 3u);
    CHECK(callsA);
    CHECK(callsB);
    CHECK_FALSE(directTransitionStore);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("interproceduralFsmSplitModule honors zero probability") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @plainfsm(i32 %x) {
entry:
  %c = icmp eq i32 %x, 0
  br i1 %c, label %a, label %b
a:
  %y = add i32 %x, 1
  ret i32 %y
b:
  %z = sub i32 %x, 1
  ret i32 %z
}
)ir");
    Function *F = M->getFunction("plainfsm");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(122);
    morok::ir::IRRandom rng(engine);
    REQUIRE(morok::passes::nonInvertibleStateFunction(
        *F, {/*max_terms=*/2, /*rounds=*/2}, rng));

    CHECK_FALSE(morok::passes::interproceduralFsmSplitModule(
        *M, {/*probability=*/0, /*max_sites=*/32, /*max_terms=*/4}, rng));
    CHECK(M->getFunction("morok.ifsm.step.a") == nullptr);
    CHECK(M->getFunction("morok.ifsm.step.b") == nullptr);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("vectorObfuscateFunction honors width, shuffles, and comparisons") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @vecshape(i32 %a, i32 %b) {
entry:
  %sum = add i32 %a, %b
  %mix = xor i32 %sum, 305419896
  %cmp = icmp ugt i32 %mix, %a
  %sel = select i1 %cmp, i32 %mix, i32 %b
  ret i32 %sel
}
)ir");
    Function *F = M->getFunction("vecshape");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(21);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::vectorObfuscateFunction(
        *F, {/*probability=*/100, /*width=*/128, /*shuffle=*/true,
             /*lift_comparisons=*/true},
        rng));
    bool hasVectorOp = false;
    bool hasFourLaneVector = false;
    bool hasShuffle = false;
    bool hasVectorCompare = false;
    for (Instruction &I : instructions(*F)) {
        if (I.getType()->isVectorTy())
            hasVectorOp = true;
        if (auto *VT = dyn_cast<FixedVectorType>(I.getType()))
            hasFourLaneVector |= VT->getNumElements() == 4u;
        hasShuffle |= isa<ShuffleVectorInst>(&I);
        if (auto *Cmp = dyn_cast<ICmpInst>(&I))
            hasVectorCompare |= Cmp->getType()->isVectorTy();
    }
    CHECK(hasVectorOp);
    CHECK(hasFourLaneVector);
    CHECK(hasShuffle);
    CHECK(hasVectorCompare);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("tableArithmeticFunction lowers i8 ops to encrypted lookup tables") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i8 @bytes(i8 %a, i8 %b) {
entry:
  %x = xor i8 %a, %b
  %y = add i8 %x, 7
  ret i8 %y
}
)ir");
    Function *F = M->getFunction("bytes");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(81);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::tableArithmeticFunction(
        *F, {/*probability=*/100, /*max_tables=*/2}, rng));

    CHECK(countGlobals(*M, "morok.tablearith.table") == 2u);
    CHECK(M->getFunction("morok.tablearith.ensure") != nullptr);
    CHECK_FALSE(hasPlainI8Arithmetic(*F));

    bool hasEnsureCall = false;
    bool hasValueLoad = false;
    for (Instruction &I : instructions(*F)) {
        if (auto *CI = dyn_cast<CallInst>(&I))
            if (Function *Callee = CI->getCalledFunction())
                if (Callee->getName().starts_with("morok.tablearith.ensure"))
                    hasEnsureCall = true;
        if (auto *LI = dyn_cast<LoadInst>(&I))
            if (LI->getName().starts_with("morok.tablearith.value"))
                hasValueLoad = true;
    }
    CHECK(hasEnsureCall);
    CHECK(hasValueLoad);

    bool encryptedDiffersFromPlain = false;
    for (GlobalVariable &GV : M->globals()) {
        if (!GV.getName().starts_with("morok.tablearith.table"))
            continue;
        auto *CDA = dyn_cast<ConstantDataArray>(GV.getInitializer());
        REQUIRE(CDA);
        for (unsigned idx = 0; idx < 256; ++idx) {
            const auto lhs = static_cast<std::uint8_t>(idx >> 8);
            const auto rhs = static_cast<std::uint8_t>(idx & 0xFFu);
            const auto plain = static_cast<std::uint8_t>(lhs ^ rhs);
            if (CDA->getElementAsInteger(idx) != plain) {
                encryptedDiffersFromPlain = true;
                break;
            }
        }
    }
    CHECK(encryptedDiffersFromPlain);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("tableArithmeticFunction honors zero probability") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i8 @bytes(i8 %a, i8 %b) {
entry:
  %x = xor i8 %a, %b
  ret i8 %x
}
)ir");
    Function *F = M->getFunction("bytes");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(82);
    morok::ir::IRRandom rng(engine);

    CHECK_FALSE(morok::passes::tableArithmeticFunction(
        *F, {/*probability=*/0, /*max_tables=*/2}, rng));
    CHECK(hasPlainI8Arithmetic(*F));
    CHECK(countGlobals(*M, "morok.tablearith.table") == 0u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("tableArithmeticFunction skips non-byte arithmetic") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(83);
    morok::ir::IRRandom rng(engine);

    CHECK_FALSE(morok::passes::tableArithmeticFunction(
        *F, {/*probability=*/100, /*max_tables=*/8}, rng));
    CHECK(countGlobals(*M, "morok.tablearith.table") == 0u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("dataFlowIntegrityFunction derives table values from integrity hash") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i8 @dfi(i8 %a, i8 %b) {
entry:
  %x = xor i8 %a, %b
  ret i8 %x
}
)ir");
    Function *F = M->getFunction("dfi");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(84);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::dataFlowIntegrityFunction(
        *F, {/*probability=*/100, /*max_tables=*/1, /*region_bytes=*/32},
        rng));

    CHECK(countGlobals(*M, "morok.dfi.table") == 1u);
    CHECK(countGlobals(*M, "morok.dfi.region") == 1u);
    CHECK(countGlobals(*M, "morok.dfi.expected") == 1u);

    Function *Hash = M->getFunction("morok.dfi.hash.dfi");
    REQUIRE(Hash);

    bool callsHash = false;
    bool hasTableLoad = false;
    bool hasDecodedValue = false;
    for (Instruction &I : instructions(*F)) {
        if (auto *CI = dyn_cast<CallInst>(&I))
            callsHash |= CI->getCalledFunction() == Hash;
        if (auto *LI = dyn_cast<LoadInst>(&I))
            hasTableLoad |=
                LI->isVolatile() &&
                LI->getPointerOperand()->getName().starts_with(
                    "morok.dfi.cell");
        hasDecodedValue |= I.getName().starts_with("morok.dfi.value");
    }

    bool hasVolatileRegionLoad = false;
    bool hasVolatileExpectedLoad = false;
    for (Instruction &I : instructions(*Hash)) {
        if (auto *LI = dyn_cast<LoadInst>(&I)) {
            hasVolatileRegionLoad |=
                LI->isVolatile() &&
                LI->getPointerOperand()->getName().starts_with(
                    "morok.dfi.region.ptr");
            hasVolatileExpectedLoad |=
                LI->isVolatile() &&
                LI->getPointerOperand()->getName().starts_with(
                    "morok.dfi.expected");
        }
    }

    bool encryptedDiffersFromPlain = false;
    for (GlobalVariable &GV : M->globals()) {
        if (!GV.getName().starts_with("morok.dfi.table"))
            continue;
        auto *CDA = dyn_cast<ConstantDataArray>(GV.getInitializer());
        REQUIRE(CDA);
        for (unsigned idx = 0; idx < 256; ++idx) {
            const auto lhs = static_cast<std::uint8_t>(idx >> 8);
            const auto rhs = static_cast<std::uint8_t>(idx & 0xFFu);
            const auto plain = static_cast<std::uint8_t>(lhs ^ rhs);
            if (CDA->getElementAsInteger(idx) != plain) {
                encryptedDiffersFromPlain = true;
                break;
            }
        }
    }

    CHECK(callsHash);
    CHECK(hasTableLoad);
    CHECK(hasDecodedValue);
    CHECK(hasVolatileRegionLoad);
    CHECK(hasVolatileExpectedLoad);
    CHECK(encryptedDiffersFromPlain);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("dataFlowIntegrityFunction honors zero probability") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i8 @dfi_zero(i8 %a, i8 %b) {
entry:
  %x = xor i8 %a, %b
  ret i8 %x
}
)ir");
    Function *F = M->getFunction("dfi_zero");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(85);
    morok::ir::IRRandom rng(engine);

    CHECK_FALSE(morok::passes::dataFlowIntegrityFunction(
        *F, {/*probability=*/0, /*max_tables=*/1, /*region_bytes=*/32},
        rng));
    CHECK(hasPlainI8Arithmetic(*F));
    CHECK(countGlobals(*M, "morok.dfi.table") == 0u);
    CHECK(M->getFunction("morok.dfi.hash.dfi_zero") == nullptr);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("uniformPrimitiveLowerFunction table-lowers ops and branch dispatch") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i8 @uniform(i8 %a, i8 %b, i1 %c) {
entry:
  %x = xor i8 %a, %b
  br i1 %c, label %left, label %right
left:
  %l = add i8 %x, 7
  ret i8 %l
right:
  %r = sub i8 %x, 3
  ret i8 %r
}
)ir");
    Function *F = M->getFunction("uniform");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(141);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::uniformPrimitiveLowerFunction(
        *F,
        {/*op_probability=*/100, /*branch_probability=*/100,
         /*max_tables=*/2, /*max_branches=*/1},
        rng));

    CHECK(countGlobals(*M, "morok.tablearith.table") == 2u);
    CHECK(countGlobals(*M, "morok.uniform.table") == 1u);
    CHECK(M->getFunction("morok.tablearith.ensure") != nullptr);

    std::size_t branches = 0;
    std::size_t indirects = 0;
    bool hasIndexSelect = false;
    bool hasTargetLoad = false;
    for (Instruction &I : instructions(*F)) {
        branches += isa<BranchInst>(&I) ? 1u : 0u;
        indirects += isa<IndirectBrInst>(&I) ? 1u : 0u;
        if (auto *SI = dyn_cast<SelectInst>(&I))
            hasIndexSelect |= SI->getName().starts_with("morok.uniform.index");
        if (auto *LI = dyn_cast<LoadInst>(&I))
            hasTargetLoad |= LI->getName().starts_with("morok.uniform.target");
    }
    CHECK(branches == 0u);
    CHECK(indirects == 1u);
    CHECK(hasIndexSelect);
    CHECK(hasTargetLoad);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("uniformPrimitiveLowerFunction honors zero probabilities") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i8 @uniform_zero(i8 %a, i8 %b, i1 %c) {
entry:
  %x = xor i8 %a, %b
  br i1 %c, label %left, label %right
left:
  ret i8 %x
right:
  ret i8 %b
}
)ir");
    Function *F = M->getFunction("uniform_zero");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(142);
    morok::ir::IRRandom rng(engine);

    CHECK_FALSE(morok::passes::uniformPrimitiveLowerFunction(
        *F,
        {/*op_probability=*/0, /*branch_probability=*/0,
         /*max_tables=*/2, /*max_branches=*/2},
        rng));
    CHECK(countGlobals(*M, "morok.tablearith.table") == 0u);
    CHECK(countGlobals(*M, "morok.uniform.table") == 0u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("virtualizeModule lifts simple arithmetic to encrypted threaded VM") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @vm_arith(i32 %a, i32 %b) {
entry:
  %x = add i32 %a, %b
  %y = xor i32 %x, 1515870810
  %z = mul i32 %y, %a
  ret i32 %z
}
)ir");
    Function *F = M->getFunction("vm_arith");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(151);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::virtualizeModule(
        *M,
        {/*probability=*/100, /*max_functions=*/1,
         /*max_instructions=*/16, /*max_registers=*/32},
        rng));

    Function *Helper = M->getFunction("morok.vm.vm_arith.exec");
    REQUIRE(Helper);
    CHECK(countGlobals(*M, "morok.vm.bytecode") == 1u);
    CHECK(countGlobals(*M, "morok.vm.targets") == 1u);

    GlobalVariable *Bytecode = nullptr;
    for (GlobalVariable &GV : M->globals())
        if (GV.getName().starts_with("morok.vm.bytecode"))
            Bytecode = &GV;
    REQUIRE(Bytecode);
    REQUIRE(Bytecode->isConstant());
    auto *Data = dyn_cast<ConstantDataArray>(Bytecode->getInitializer());
    REQUIRE(Data);
    bool controlBytesAreEncrypted = false;
    for (unsigned I = 0; I < 4 && I < Data->getNumElements(); ++I)
        controlBytesAreEncrypted |= Data->getElementAsInteger(I) > 63u;
    CHECK(controlBytesAreEncrypted);

    std::size_t wrapperCalls = 0;
    std::size_t wrapperBinops = 0;
    for (Instruction &I : instructions(*F)) {
        wrapperCalls += isa<CallInst>(&I) ? 1u : 0u;
        wrapperBinops += isa<BinaryOperator>(&I) ? 1u : 0u;
    }
    CHECK(wrapperCalls == 1u);
    CHECK(wrapperBinops == 0u);

    std::size_t indirects = 0;
    std::size_t switches = 0;
    std::size_t addHandlers = 0;
    std::size_t xorHandlers = 0;
    bool hasBytecodeDecrypt = false;
    for (BasicBlock &BB : *Helper) {
        addHandlers += BB.getName().starts_with("morok.vm.h.add") ? 1u : 0u;
        xorHandlers += BB.getName().starts_with("morok.vm.h.xor") ? 1u : 0u;
        for (Instruction &I : BB) {
            indirects += isa<IndirectBrInst>(&I) ? 1u : 0u;
            switches += isa<SwitchInst>(&I) ? 1u : 0u;
            hasBytecodeDecrypt |= I.getName().starts_with("morok.vm.bc.dec");
        }
    }
    CHECK(indirects == 1u);
    CHECK(switches == 0u);
    CHECK(addHandlers >= 2u);
    CHECK(xorHandlers >= 2u);
    CHECK(hasBytecodeDecrypt);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("virtualizeModule skips unsupported control flow") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @branchy(i32 %a, i32 %b, i1 %c) {
entry:
  br i1 %c, label %left, label %right
left:
  ret i32 %a
right:
  ret i32 %b
}
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(152);
    morok::ir::IRRandom rng(engine);

    CHECK_FALSE(morok::passes::virtualizeModule(
        *M,
        {/*probability=*/100, /*max_functions=*/1,
         /*max_instructions=*/16, /*max_registers=*/32},
        rng));
    CHECK(countGlobals(*M, "morok.vm.bytecode") == 0u);
    CHECK(M->getFunction("morok.vm.branchy.exec") == nullptr);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("hashGatedSelfDecryptModule wraps VM bytecode in lazy decryptor") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @vm_secret(i32 %a, i32 %b) {
entry:
  %x = add i32 %a, %b
  %y = xor i32 %x, 1515870810
  %z = mul i32 %y, %a
  ret i32 %z
}
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(171);
    morok::ir::IRRandom rng(engine);

    REQUIRE(morok::passes::virtualizeModule(
        *M,
        {/*probability=*/100, /*max_functions=*/1,
         /*max_instructions=*/16, /*max_registers=*/32},
        rng));

    GlobalVariable *Bytecode = nullptr;
    for (GlobalVariable &GV : M->globals())
        if (GV.getName().starts_with("morok.vm.bytecode"))
            Bytecode = &GV;
    REQUIRE(Bytecode);
    REQUIRE(Bytecode->isConstant());
    auto *BeforeData = dyn_cast<ConstantDataArray>(Bytecode->getInitializer());
    REQUIRE(BeforeData);
    std::vector<std::uint8_t> Before;
    for (unsigned I = 0; I < BeforeData->getNumElements(); ++I)
        Before.push_back(
            static_cast<std::uint8_t>(BeforeData->getElementAsInteger(I)));

    CHECK(morok::passes::hashGatedSelfDecryptModule(
        *M, {/*probability=*/100, /*max_payloads=*/4}, rng));

    CHECK_FALSE(Bytecode->isConstant());
    CHECK(countGlobals(*M, "morok.sdb.ready") == 1u);
    Function *Ensure = M->getFunction("morok.sdb.ensure.vm_secret");
    REQUIRE(Ensure);
    Function *Helper = M->getFunction("morok.vm.vm_secret.exec");
    REQUIRE(Helper);

    auto *AfterData = dyn_cast<ConstantDataArray>(Bytecode->getInitializer());
    REQUIRE(AfterData);
    bool payloadChanged = false;
    for (unsigned I = 0; I < AfterData->getNumElements() && I < Before.size();
         ++I)
        payloadChanged |=
            Before[I] !=
            static_cast<std::uint8_t>(AfterData->getElementAsInteger(I));
    CHECK(payloadChanged);

    bool helperCallsEnsure = false;
    bool hasGate = false;
    bool hasTrap = false;
    bool hasVolatileReadyLoad = false;
    bool hasVolatileReadyStore = false;
    bool storesPayload = false;
    for (Instruction &I : instructions(*Helper))
        if (auto *CI = dyn_cast<CallInst>(&I))
            helperCallsEnsure |= CI->getCalledFunction() == Ensure;
    for (Instruction &I : instructions(*Ensure)) {
        if (I.getName().starts_with("morok.sdb.gate"))
            hasGate = true;
        if (auto *CI = dyn_cast<CallInst>(&I))
            if (Function *Callee = CI->getCalledFunction())
                hasTrap |= Callee->getName() == "llvm.trap";
        if (auto *LI = dyn_cast<LoadInst>(&I))
            hasVolatileReadyLoad |=
                LI->isVolatile() &&
                LI->getPointerOperand()->getName().starts_with(
                    "morok.sdb.ready");
        if (auto *SI = dyn_cast<StoreInst>(&I)) {
            hasVolatileReadyStore |=
                SI->isVolatile() &&
                SI->getPointerOperand()->getName().starts_with(
                    "morok.sdb.ready");
            storesPayload |=
                SI->getPointerOperand()->getName().starts_with(
                    "morok.sdb.payload.ptr");
        }
    }
    CHECK(helperCallsEnsure);
    CHECK(hasGate);
    CHECK(hasTrap);
    CHECK(hasVolatileReadyLoad);
    CHECK(hasVolatileReadyStore);
    CHECK(storesPayload);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("hashGatedSelfDecryptModule honors zero probability") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @vm_zero(i32 %a, i32 %b) {
entry:
  %x = add i32 %a, %b
  ret i32 %x
}
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(172);
    morok::ir::IRRandom rng(engine);

    REQUIRE(morok::passes::virtualizeModule(
        *M,
        {/*probability=*/100, /*max_functions=*/1,
         /*max_instructions=*/16, /*max_registers=*/32},
        rng));
    CHECK_FALSE(morok::passes::hashGatedSelfDecryptModule(
        *M, {/*probability=*/0, /*max_payloads=*/4}, rng));
    CHECK(countGlobals(*M, "morok.sdb.ready") == 0u);
    CHECK(M->getFunction("morok.sdb.ensure.vm_zero") == nullptr);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("selfChecksumConstantsFunction fuses constants with checksum data") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @selfcheck(i32 %a) {
entry:
  %x = xor i32 %a, 305419896
  %y = add i32 %x, 17
  ret i32 %y
}
)ir");
    Function *F = M->getFunction("selfcheck");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(181);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::selfChecksumConstantsFunction(
        *F, {/*probability=*/100, /*max_constants=*/8, /*region_bytes=*/32},
        rng));

    CHECK(countGlobals(*M, "morok.sc.region") == 1u);
    CHECK(countGlobals(*M, "morok.sc.expected") == 1u);
    CHECK(countGlobals(*M, "morok.sc.mask") == 2u);

    Function *Diff = M->getFunction("morok.sc.diff.selfcheck");
    REQUIRE(Diff);

    bool callsDiff = false;
    bool hasConstMix = false;
    bool hasTrap = false;
    bool hasVolatileMaskLoad = false;
    for (Instruction &I : instructions(*F)) {
        if (auto *CI = dyn_cast<CallInst>(&I))
            callsDiff |= CI->getCalledFunction() == Diff;
        hasConstMix |= I.getName().starts_with("morok.sc.const");
        if (auto *LI = dyn_cast<LoadInst>(&I))
            hasVolatileMaskLoad |=
                LI->isVolatile() &&
                LI->getPointerOperand()->getName().starts_with(
                    "morok.sc.mask");
    }

    bool hasVolatileRegionLoad = false;
    bool hasVolatileExpectedLoad = false;
    bool hasDiffValue = false;
    for (Instruction &I : instructions(*Diff)) {
        hasDiffValue |= I.getName().starts_with("morok.sc.diff");
        if (auto *CI = dyn_cast<CallInst>(&I))
            if (Function *Callee = CI->getCalledFunction())
                hasTrap |= Callee->getName() == "llvm.trap";
        if (auto *LI = dyn_cast<LoadInst>(&I)) {
            hasVolatileRegionLoad |=
                LI->isVolatile() &&
                LI->getPointerOperand()->getName().starts_with(
                    "morok.sc.region.ptr");
            hasVolatileExpectedLoad |=
                LI->isVolatile() &&
                LI->getPointerOperand()->getName().starts_with(
                    "morok.sc.expected");
        }
    }

    CHECK(callsDiff);
    CHECK(hasConstMix);
    CHECK(hasVolatileMaskLoad);
    CHECK(hasVolatileRegionLoad);
    CHECK(hasVolatileExpectedLoad);
    CHECK(hasDiffValue);
    CHECK_FALSE(hasTrap);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("selfChecksumConstantsFunction honors zero probability") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @selfcheck_zero(i32 %a) {
entry:
  %x = add i32 %a, 99
  ret i32 %x
}
)ir");
    Function *F = M->getFunction("selfcheck_zero");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(182);
    morok::ir::IRRandom rng(engine);

    CHECK_FALSE(morok::passes::selfChecksumConstantsFunction(
        *F, {/*probability=*/0, /*max_constants=*/8, /*region_bytes=*/32},
        rng));
    CHECK(countGlobals(*M, "morok.sc.region") == 0u);
    CHECK(M->getFunction("morok.sc.diff.selfcheck_zero") == nullptr);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("mutualGuardGraphFunction emits overlapping integrity nodes") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @mutual(i32 %a, i32 %b) {
entry:
  %x = xor i32 %a, %b
  %y = add i32 %x, 7
  ret i32 %y
}
)ir");
    Function *F = M->getFunction("mutual");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(201);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::mutualGuardGraphFunction(
        *F, {/*probability=*/100, /*nodes=*/3, /*region_bytes=*/32,
             /*max_returns=*/1},
        rng));

    CHECK(countGlobals(*M, "morok.mg.region") == 3u);
    CHECK(countGlobals(*M, "morok.mg.expected") == 3u);

    Function *Diff = M->getFunction("morok.mg.diff.mutual");
    REQUIRE(Diff);

    std::vector<Function *> nodes;
    for (unsigned i = 0; i != 3; ++i) {
        Function *Node =
            M->getFunction("morok.mg.node.mutual." + std::to_string(i));
        REQUIRE(Node);
        nodes.push_back(Node);
    }

    bool callsDiff = false;
    bool hasReturnPoison = false;
    bool hasTrap = false;
    for (Instruction &I : instructions(*F)) {
        if (auto *CI = dyn_cast<CallInst>(&I)) {
            callsDiff |= CI->getCalledFunction() == Diff;
            if (Function *Callee = CI->getCalledFunction())
                hasTrap |= Callee->getName() == "llvm.trap";
        }
        hasReturnPoison |= I.getName().starts_with("morok.mg.value");
    }

    unsigned nodeCalls = 0;
    bool hasGraphDiff = false;
    for (Instruction &I : instructions(*Diff)) {
        hasGraphDiff |= I.getName().starts_with("morok.mg.diff");
        if (auto *CI = dyn_cast<CallInst>(&I)) {
            if (Function *Callee = CI->getCalledFunction()) {
                hasTrap |= Callee->getName() == "llvm.trap";
                if (std::find(nodes.begin(), nodes.end(), Callee) !=
                    nodes.end())
                    ++nodeCalls;
            }
        }
    }

    for (Function *Node : nodes) {
        bool hasRegionLoad = false;
        unsigned expectedLoads = 0;
        bool hasPeerMix = false;
        bool hasNodeDiff = false;
        for (Instruction &I : instructions(*Node)) {
            hasPeerMix |= I.getName().starts_with("morok.mg.peer");
            hasNodeDiff |= I.getName().starts_with("morok.mg.node.diff");
            if (auto *CI = dyn_cast<CallInst>(&I))
                if (Function *Callee = CI->getCalledFunction())
                    hasTrap |= Callee->getName() == "llvm.trap";
            if (auto *LI = dyn_cast<LoadInst>(&I)) {
                hasRegionLoad |=
                    LI->isVolatile() &&
                    LI->getPointerOperand()->getName().starts_with(
                        "morok.mg.region.ptr");
                if (LI->isVolatile() &&
                    LI->getPointerOperand()->getName().starts_with(
                        "morok.mg.expected"))
                    ++expectedLoads;
            }
        }
        CHECK(hasRegionLoad);
        CHECK(expectedLoads >= 3u);
        CHECK(hasPeerMix);
        CHECK(hasNodeDiff);
    }

    CHECK(callsDiff);
    CHECK(hasReturnPoison);
    CHECK(nodeCalls == 3u);
    CHECK(hasGraphDiff);
    CHECK_FALSE(hasTrap);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("mutualGuardGraphFunction honors zero probability") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @mutual_zero(i32 %a, i32 %b) {
entry:
  %x = add i32 %a, %b
  ret i32 %x
}
)ir");
    Function *F = M->getFunction("mutual_zero");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(202);
    morok::ir::IRRandom rng(engine);

    CHECK_FALSE(morok::passes::mutualGuardGraphFunction(
        *F, {/*probability=*/0, /*nodes=*/3, /*region_bytes=*/32,
             /*max_returns=*/1},
        rng));
    CHECK(countGlobals(*M, "morok.mg.region") == 0u);
    CHECK(countGlobals(*M, "morok.mg.expected") == 0u);
    CHECK(M->getFunction("morok.mg.diff.mutual_zero") == nullptr);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("pathExplosionFunction injects input-driven decoy loops") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @guarded(i32 %a, i32 %b) {
entry:
  %x = add i32 %a, %b
  %y = xor i32 %x, %a
  ret i32 %y
}
)ir");
    Function *F = M->getFunction("guarded");
    REQUIRE(F);
    const std::size_t beforeBlocks = F->size();
    auto engine = morok::core::Xoshiro256pp::fromSeed(91);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::pathExplosionFunction(
        *F, {/*probability=*/100, /*max_blocks=*/1, /*max_iterations=*/8},
        rng));

    CHECK(F->size() > beforeBlocks);
    CHECK(countNamedAllocas(*F, "morok.path.scratch") == 1u);
    CHECK(M->getGlobalVariable("morok.path.opaque", true) != nullptr);

    bool hasIndirectBr = false;
    bool hasDecoyLoop = false;
    bool hasVolatileStore = false;
    bool hasInputSeed = false;
    for (BasicBlock &BB : *F) {
        if (BB.getName().starts_with("morok.path.loop"))
            hasDecoyLoop = true;
        for (Instruction &I : BB) {
            if (isa<IndirectBrInst>(&I))
                hasIndirectBr = true;
            if (auto *SI = dyn_cast<StoreInst>(&I))
                if (SI->isVolatile())
                    hasVolatileStore = true;
            if (I.getName().starts_with("morok.path.seed"))
                hasInputSeed = true;
        }
    }
    CHECK(hasIndirectBr);
    CHECK(hasDecoyLoop);
    CHECK(hasVolatileStore);
    CHECK(hasInputSeed);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("pathExplosionFunction honors zero probability") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t beforeBlocks = F->size();
    auto engine = morok::core::Xoshiro256pp::fromSeed(92);
    morok::ir::IRRandom rng(engine);

    CHECK_FALSE(morok::passes::pathExplosionFunction(
        *F, {/*probability=*/0, /*max_blocks=*/4, /*max_iterations=*/16}, rng));
    CHECK(F->size() == beforeBlocks);
    CHECK(countNamedAllocas(*F, "morok.path.scratch") == 0u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("traceKeyFunction builds rolling accumulator guards") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @trace(i32 %a, i32 %b) {
entry:
  %c = icmp slt i32 %a, %b
  br i1 %c, label %left, label %right
left:
  %l = add i32 %a, 7
  br label %join
right:
  %r = sub i32 %b, 3
  br label %join
join:
  %p = phi i32 [ %l, %left ], [ %r, %right ]
  %d = icmp eq i32 %p, %a
  br i1 %d, label %yes, label %no
yes:
  ret i32 %p
no:
  %x = xor i32 %p, %b
  ret i32 %x
}
)ir");
    Function *F = M->getFunction("trace");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(161);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::traceKeyFunction(
        *F, {/*probability=*/100, /*max_blocks=*/8}, rng));

    CHECK(countNamedAllocas(*F, "morok.trace.state") == 1u);
    CHECK(M->getGlobalVariable("morok.trace.seed", true) != nullptr);
    CHECK(M->getFunction("llvm.trap") != nullptr);

    std::size_t guards = 0;
    std::size_t expectedPhis = 0;
    std::size_t volatileLoads = 0;
    std::size_t volatileStores = 0;
    std::size_t failBlocks = 0;
    std::size_t branchKeys = 0;
    std::size_t returnKeys = 0;
    std::size_t edgeMixes = 0;
    for (BasicBlock &BB : *F) {
        failBlocks += BB.getName().starts_with("morok.trace.fail") ? 1u : 0u;
        for (Instruction &I : BB) {
            if (I.getName().starts_with("morok.trace.guard"))
                ++guards;
            if (I.getName().starts_with("morok.trace.expected"))
                ++expectedPhis;
            if (I.getName().starts_with("morok.trace.edge.mix"))
                ++edgeMixes;
            if (auto *LI = dyn_cast<LoadInst>(&I))
                volatileLoads += LI->isVolatile() ? 1u : 0u;
            if (auto *SI = dyn_cast<StoreInst>(&I))
                volatileStores += SI->isVolatile() ? 1u : 0u;
            if (auto *BI = dyn_cast<BranchInst>(&I))
                if (BI->isConditional() &&
                    BI->getCondition()->getName().starts_with(
                        "morok.trace.branch.cond"))
                    ++branchKeys;
            if (auto *RI = dyn_cast<ReturnInst>(&I))
                if (RI->getReturnValue() &&
                    RI->getReturnValue()->getName().starts_with(
                        "morok.trace.ret"))
                    ++returnKeys;
        }
    }
    CHECK(guards >= 4u);
    CHECK(expectedPhis >= 4u);
    CHECK(volatileLoads >= 4u);
    CHECK(volatileStores >= 4u);
    CHECK(failBlocks >= 4u);
    CHECK(branchKeys >= 1u);
    CHECK(returnKeys >= 1u);
    CHECK(edgeMixes >= 3u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("traceKeyFunction honors zero probability") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @trace_zero(i32 %a, i32 %b) {
entry:
  %c = icmp slt i32 %a, %b
  br i1 %c, label %left, label %right
left:
  ret i32 %a
right:
  ret i32 %b
}
)ir");
    Function *F = M->getFunction("trace_zero");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(162);
    morok::ir::IRRandom rng(engine);

    CHECK_FALSE(morok::passes::traceKeyFunction(
        *F, {/*probability=*/0, /*max_blocks=*/8}, rng));
    CHECK(countNamedAllocas(*F, "morok.trace.state") == 0u);
    CHECK(M->getGlobalVariable("morok.trace.seed", true) == nullptr);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("dispatcherlessRoutingFunction replaces branch/switch dispatch") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @threaded(i32 %a, i32 %b, i32 %cmd) {
entry:
  %c = icmp slt i32 %a, %b
  br i1 %c, label %left, label %right
left:
  %l = add i32 %a, %cmd
  br label %join
right:
  %r = sub i32 %b, %cmd
  br label %join
join:
  %p = phi i32 [ %l, %left ], [ %r, %right ]
  switch i32 %cmd, label %done [
    i32 0, label %case0
    i32 1, label %case1
  ]
case0:
  %x = xor i32 %p, %a
  ret i32 %x
case1:
  %y = or i32 %p, %b
  ret i32 %y
done:
  ret i32 %p
}
)ir");
    Function *F = M->getFunction("threaded");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(101);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::dispatcherlessRoutingFunction(
        *F, {/*probability=*/100, /*max_routes=*/8, /*max_terms=*/4}, rng));

    CHECK(countNamedAllocas(*F, "morok.dlf.state") == 1u);
    CHECK(countNamedAllocas(*F, "morok.dlf.shadow") == 1u);
    CHECK(M->getGlobalVariable("morok.dlf.table", true) != nullptr);

    std::size_t indirects = 0;
    std::size_t switches = 0;
    bool hasToken = false;
    bool hasNext = false;
    bool hasVolatileLoad = false;
    for (Instruction &I : instructions(*F)) {
        if (isa<IndirectBrInst>(&I))
            ++indirects;
        if (isa<SwitchInst>(&I))
            ++switches;
        if (I.getName().starts_with("morok.dlf.token"))
            hasToken = true;
        if (I.getName().starts_with("morok.dlf.next"))
            hasNext = true;
        if (auto *LI = dyn_cast<LoadInst>(&I))
            if (LI->isVolatile() &&
                LI->getName().starts_with("morok.dlf.shadow"))
                hasVolatileLoad = true;
    }
    CHECK(indirects >= 4u);
    CHECK(switches == 0u);
    CHECK(hasToken);
    CHECK(hasNext);
    CHECK(hasVolatileLoad);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("dispatcherlessRoutingFunction honors zero probability") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @direct(i32 %a, i32 %b) {
entry:
  %c = icmp eq i32 %a, %b
  br i1 %c, label %t, label %f
t:
  ret i32 %a
f:
  ret i32 %b
}
)ir");
    Function *F = M->getFunction("direct");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(102);
    morok::ir::IRRandom rng(engine);

    CHECK_FALSE(morok::passes::dispatcherlessRoutingFunction(
        *F, {/*probability=*/0, /*max_routes=*/8, /*max_terms=*/4}, rng));
    CHECK(countNamedAllocas(*F, "morok.dlf.state") == 0u);
    CHECK(M->getGlobalVariable("morok.dlf.table", true) == nullptr);
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

TEST_CASE("adversarialFunctionMergingModule fuses functions behind a selector") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @alpha(i32 %a, i32 %b) {
entry:
  %sum = add i32 %a, %b
  %mix = xor i32 %sum, 7
  ret i32 %mix
}

define i32 @beta(i32 %a, i32 %b) {
entry:
  %prod = mul i32 %a, %b
  %mix = sub i32 %prod, 3
  ret i32 %mix
}

define i32 @caller(i32 %x) {
entry:
  %a = call i32 @alpha(i32 %x, i32 5)
  %b = call i32 @beta(i32 %x, i32 3)
  %r = add i32 %a, %b
  ret i32 %r
}
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(221);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::adversarialFunctionMergingModule(
        *M, {/*probability=*/100, /*max_groups=*/1, /*max_functions=*/2,
             /*outline_probability=*/100, /*max_outlines=*/4},
        rng));

    Function *Alpha = M->getFunction("alpha");
    Function *Beta = M->getFunction("beta");
    REQUIRE(Alpha);
    REQUIRE(Beta);
    CHECK(Alpha->hasFnAttribute(Attribute::NoInline));
    CHECK(Beta->hasFnAttribute(Attribute::NoInline));

    CHECK(countFunctions(*M, "morok.afm.dispatch") == 1u);
    CHECK(countFunctions(*M, "morok.afm.impl") == 2u);
    CHECK(countFunctions(*M, "morok.afm.outline") >= 1u);
    CHECK(countGlobals(*M, "morok.afm.selector") == 2u);
    CHECK(countGlobals(*M, "morok.afm.key") >= 2u);

    Function *Dispatch = nullptr;
    for (Function &F : *M)
        if (F.getName().starts_with("morok.afm.dispatch"))
            Dispatch = &F;
    REQUIRE(Dispatch);
    CHECK(Dispatch->hasFnAttribute(Attribute::NoInline));
    CHECK(Dispatch->hasFnAttribute(Attribute::OptimizeNone));

    bool dispatchHasSwitch = false;
    unsigned dispatchImplCalls = 0;
    for (Instruction &I : instructions(*Dispatch)) {
        dispatchHasSwitch |= isa<SwitchInst>(&I);
        if (auto *CI = dyn_cast<CallInst>(&I))
            if (Function *Callee = CI->getCalledFunction())
                if (Callee->getName().starts_with("morok.afm.impl"))
                    ++dispatchImplCalls;
    }

    bool wrappersCallDispatch = false;
    bool wrappersLoadSelectors = false;
    for (Function *F : {Alpha, Beta}) {
        bool callsDispatch = false;
        bool loadsSelector = false;
        for (Instruction &I : instructions(*F)) {
            if (auto *CI = dyn_cast<CallInst>(&I))
                callsDispatch |= CI->getCalledFunction() == Dispatch;
            if (auto *LI = dyn_cast<LoadInst>(&I))
                loadsSelector |=
                    LI->isVolatile() &&
                    LI->getPointerOperand()->getName().starts_with(
                        "morok.afm.selector");
        }
        wrappersCallDispatch |= callsDispatch;
        wrappersLoadSelectors |= loadsSelector;
        CHECK(callsDispatch);
        CHECK(loadsSelector);
    }

    bool outlineHelperHasVolatileKey = false;
    bool implCallsOutline = false;
    for (Function &F : *M) {
        if (F.getName().starts_with("morok.afm.outline")) {
            CHECK(F.hasFnAttribute(Attribute::NoInline));
            CHECK(F.hasFnAttribute(Attribute::OptimizeNone));
            for (Instruction &I : instructions(F))
                if (auto *LI = dyn_cast<LoadInst>(&I))
                    outlineHelperHasVolatileKey |=
                        LI->isVolatile() &&
                        LI->getPointerOperand()->getName().starts_with(
                            "morok.afm.key");
        }
        if (!F.getName().starts_with("morok.afm.impl"))
            continue;
        for (Instruction &I : instructions(F))
            if (auto *CI = dyn_cast<CallInst>(&I))
                if (Function *Callee = CI->getCalledFunction())
                    implCallsOutline |=
                        Callee->getName().starts_with("morok.afm.outline");
    }

    CHECK(dispatchHasSwitch);
    CHECK(dispatchImplCalls == 2u);
    CHECK(wrappersCallDispatch);
    CHECK(wrappersLoadSelectors);
    CHECK(outlineHelperHasVolatileKey);
    CHECK(implCallsOutline);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("adversarialFunctionMergingModule honors zero probability") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @afm_a(i32 %a, i32 %b) {
entry:
  %x = add i32 %a, %b
  ret i32 %x
}

define i32 @afm_b(i32 %a, i32 %b) {
entry:
  %x = xor i32 %a, %b
  ret i32 %x
}
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(222);
    morok::ir::IRRandom rng(engine);

    CHECK_FALSE(morok::passes::adversarialFunctionMergingModule(
        *M, {/*probability=*/0, /*max_groups=*/1, /*max_functions=*/2,
             /*outline_probability=*/100, /*max_outlines=*/4},
        rng));
    CHECK(countFunctions(*M, "morok.afm.dispatch") == 0u);
    CHECK(countFunctions(*M, "morok.afm.impl") == 0u);
    CHECK(countGlobals(*M, "morok.afm.selector") == 0u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("perBuildPolymorphismModule diversifies layout and anchors returns") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @poly_a(i32 %x) {
entry:
  %c = icmp ult i32 %x, 10
  br i1 %c, label %left, label %right
left:
  %l = add i32 %x, 3
  br label %merge
right:
  %r = xor i32 %x, 7
  br label %merge
merge:
  %p = phi i32 [ %l, %left ], [ %r, %right ]
  ret i32 %p
}

define i32 @poly_b(i32 %x) {
entry:
  %y = mul i32 %x, 5
  ret i32 %y
}

define i32 @poly_c(i32 %x) {
entry:
  %y = sub i32 %x, 11
  ret i32 %y
}
)ir");
    Function *A = M->getFunction("poly_a");
    REQUIRE(A);
    const auto BeforeFunctions = functionOrder(*M);
    const auto BeforeBlocks = blockOrder(*A);

    auto engine = morok::core::Xoshiro256pp::fromSeed(301);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::perBuildPolymorphismModule(
        *M, {/*function_order=*/true, /*block_order=*/true,
             /*anchor_probability=*/100, /*max_anchors=*/8},
        rng));

    CHECK(functionOrder(*M) != BeforeFunctions);
    const auto AfterBlocks = blockOrder(*A);
    REQUIRE_FALSE(AfterBlocks.empty());
    CHECK(AfterBlocks.front() == "entry");
    CHECK(AfterBlocks != BeforeBlocks);
    CHECK(countGlobals(*M, "morok.poly.salt") == 3u);

    bool hasVolatileSalt = false;
    bool hasAnchoredReturn = false;
    for (Function &F : *M) {
        if (F.isDeclaration() || F.getName().starts_with("morok."))
            continue;
        for (Instruction &I : instructions(F)) {
            hasAnchoredReturn |= I.getName().starts_with("morok.poly.value");
            if (auto *LI = dyn_cast<LoadInst>(&I))
                hasVolatileSalt |=
                    LI->isVolatile() &&
                    LI->getPointerOperand()->getName().starts_with(
                        "morok.poly.salt");
        }
    }

    CHECK(hasVolatileSalt);
    CHECK(hasAnchoredReturn);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("perBuildPolymorphismModule is reproducible and seed-diverse") {
    constexpr const char *IR = R"ir(
define i32 @poly_seed_a(i32 %x) {
entry:
  %y = add i32 %x, 1
  ret i32 %y
}

define i32 @poly_seed_b(i32 %x) {
entry:
  %y = xor i32 %x, 9
  ret i32 %y
}

define i32 @poly_seed_c(i32 %x) {
entry:
  %y = mul i32 %x, 3
  ret i32 %y
}
)ir";

    auto render = [&](std::uint64_t Seed) {
        LLVMContext ctx;
        auto M = parse(ctx, IR);
        auto engine = morok::core::Xoshiro256pp::fromSeed(Seed);
        morok::ir::IRRandom rng(engine);
        CHECK(morok::passes::perBuildPolymorphismModule(
            *M, {/*function_order=*/true, /*block_order=*/true,
                 /*anchor_probability=*/100, /*max_anchors=*/8},
            rng));
        std::string Text;
        raw_string_ostream OS(Text);
        M->print(OS, nullptr);
        return OS.str();
    };

    const std::string A = render(302);
    const std::string B = render(302);
    const std::string C = render(303);
    CHECK(A == B);
    CHECK(A != C);
}

TEST_CASE("perBuildPolymorphismModule honors disabled knobs") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @poly_off_a(i32 %x) {
entry:
  %y = add i32 %x, 1
  ret i32 %y
}

define i32 @poly_off_b(i32 %x) {
entry:
  %y = sub i32 %x, 1
  ret i32 %y
}
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(304);
    morok::ir::IRRandom rng(engine);

    CHECK_FALSE(morok::passes::perBuildPolymorphismModule(
        *M, {/*function_order=*/false, /*block_order=*/false,
             /*anchor_probability=*/0, /*max_anchors=*/0},
        rng));
    CHECK(countGlobals(*M, "morok.poly.salt") == 0u);
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
