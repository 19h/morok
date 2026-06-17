// SPDX-License-Identifier: MIT
//
// LLVM-linked tests for the IR-emitting passes: they must grow the IR and keep
// it well-formed.  Semantic preservation across the whole pipeline is verified
// separately by the end-to-end differential tests (tests/e2e); here we check
// structural validity and that the transformation actually fires.

#include "doctest.h"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/Annotations.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/AdversarialFunctionMerging.hpp"
#include "morok/passes/AdversarialSelfTuning.hpp"
#include "morok/passes/AliasOpaquePredicates.hpp"
#include "morok/passes/AntiAnalysis.hpp"
#include "morok/passes/ArithmeticTables.hpp"
#include "morok/passes/BogusControlFlow.hpp"
#include "morok/passes/ChaosStateMachine.hpp"
#include "morok/passes/CoherentDecoys.hpp"
#include "morok/passes/ConstantEncryption.hpp"
#include "morok/passes/DataEntangledFlattening.hpp"
#include "morok/passes/DataFlowIntegrity.hpp"
#include "morok/passes/DecoyStrings.hpp"
#include "morok/passes/DispatcherlessRouting.hpp"
#include "morok/passes/ExternalOpaquePredicates.hpp"
#include "morok/passes/Flattening.hpp"
#include "morok/passes/FunctionCallObfuscate.hpp"
#include "morok/passes/FunctionWrapper.hpp"
#include "morok/passes/HashGatedSelfDecrypt.hpp"
#include "morok/passes/IndirectBranch.hpp"
#include "morok/passes/InterproceduralFsm.hpp"
#include "morok/passes/Mba.hpp"
#include "morok/passes/MicrocodeStress.hpp"
#include "morok/passes/MisleadingMetadata.hpp"
#include "morok/passes/MqGate.hpp"
#include "morok/passes/MutualGuardGraph.hpp"
#include "morok/passes/NonInvertibleState.hpp"
#include "morok/passes/OptimizerAmplification.hpp"
#include "morok/passes/PathExplosion.hpp"
#include "morok/passes/PerBuildPolymorphism.hpp"
#include "morok/passes/PhiTangling.hpp"
#include "morok/passes/PointerLaundering.hpp"
#include "morok/passes/SelfChecksumConstants.hpp"
#include "morok/passes/ShamirShare.hpp"
#include "morok/passes/SplitBasicBlocks.hpp"
#include "morok/passes/StackCoalescing.hpp"
#include "morok/passes/StackDeltaGames.hpp"
#include "morok/passes/StateOpaquePredicates.hpp"
#include "morok/passes/StringEncryption.hpp"
#include "morok/passes/SubThresholdPersistence.hpp"
#include "morok/passes/Substitution.hpp"
#include "morok/passes/TraceKeying.hpp"
#include "morok/passes/TypePunning.hpp"
#include "morok/passes/UniformPrimitiveLowering.hpp"
#include "morok/passes/VTableIntegrity.hpp"
#include "morok/passes/VectorObfuscation.hpp"
#include "morok/passes/Virtualization.hpp"
#include "morok/pipeline/Scheduler.hpp"

#include "llvm/ADT/Twine.h"
#include "llvm/AsmParser/Parser.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/ModRef.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Triple.h"

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

std::size_t countNamedInstructions(Function &F, StringRef prefix) {
    std::size_t n = 0;
    for (Instruction &I : instructions(F))
        if (I.getName().starts_with(prefix))
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

std::size_t countOpcode(Module &M, unsigned opcode) {
    std::size_t n = 0;
    for (Function &F : M)
        if (!F.isDeclaration())
            for (Instruction &I : instructions(F))
                if (I.getOpcode() == opcode)
                    ++n;
    return n;
}

std::size_t countGlobals(Module &M, StringRef prefix) {
    std::size_t n = 0;
    for (GlobalVariable &GV : M.globals())
        if (GV.getName().starts_with(prefix))
            ++n;
    return n;
}

bool constantReferencesGlobal(const Constant *C, const GlobalValue *GV) {
    if (!C || !GV)
        return false;
    if (C == GV)
        return true;
    for (const Use &U : C->operands()) {
        if (U.get() == GV)
            return true;
        if (auto *Child = dyn_cast<Constant>(U.get()))
            if (constantReferencesGlobal(Child, GV))
                return true;
    }
    return false;
}

bool instructionReferencesGlobal(const Instruction &I, const GlobalValue *GV) {
    for (const Use &U : I.operands()) {
        if (U.get() == GV)
            return true;
        if (auto *C = dyn_cast<Constant>(U.get()))
            if (constantReferencesGlobal(C, GV))
                return true;
    }
    return false;
}

std::size_t countFunctions(Module &M, StringRef prefix) {
    std::size_t n = 0;
    for (Function &F : M)
        if (F.getName().starts_with(prefix))
            ++n;
    return n;
}

std::size_t countAliases(Module &M) {
    return static_cast<std::size_t>(
        std::distance(M.alias_begin(), M.alias_end()));
}

std::size_t countCallsTo(Function &F, StringRef name) {
    std::size_t n = 0;
    for (Instruction &I : instructions(F))
        if (auto *CB = dyn_cast<CallBase>(&I))
            if (Function *Callee = CB->getCalledFunction())
                if (Callee->getName() == name)
                    ++n;
    return n;
}

std::size_t countUserCallsTo(Module &M, StringRef name) {
    std::size_t n = 0;
    for (Function &F : M)
        if (!F.isDeclaration() && !F.getName().starts_with("morok."))
            n += countCallsTo(F, name);
    return n;
}

std::size_t countUserCallsToPrefix(Module &M, StringRef prefix) {
    std::size_t n = 0;
    for (Function &F : M) {
        if (F.isDeclaration() || F.getName().starts_with("morok."))
            continue;
        for (Instruction &I : instructions(F))
            if (auto *CB = dyn_cast<CallBase>(&I))
                if (Function *Callee = CB->getCalledFunction())
                    if (Callee->getName().starts_with(prefix))
                        ++n;
    }
    return n;
}

bool hasInlineAsmCall(Function &F) {
    for (Instruction &I : instructions(F))
        if (auto *CB = dyn_cast<CallBase>(&I))
            if (CB->isInlineAsm())
                return true;
    return false;
}

std::size_t countInlineAsmCalls(Function &F) {
    std::size_t n = 0;
    for (Instruction &I : instructions(F))
        if (auto *CB = dyn_cast<CallBase>(&I))
            if (CB->isInlineAsm())
                ++n;
    return n;
}

bool hasReadableByteString(Module &M, StringRef needle) {
    for (GlobalVariable &GV : M.globals()) {
        if (!GV.hasInitializer())
            continue;
        if (auto *CDA = dyn_cast<ConstantDataArray>(GV.getInitializer()))
            if (CDA->getElementType()->isIntegerTy(8))
                if (CDA->getRawDataValues().find(needle) != StringRef::npos)
                    return true;
    }
    return false;
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

bool hasPlainNarrowArithmetic(Function &F) {
    for (Instruction &I : instructions(F)) {
        if (I.getName().starts_with("morok."))
            continue;
        auto *BO = dyn_cast<BinaryOperator>(&I);
        if (!BO)
            continue;
        auto *Ty = dyn_cast<IntegerType>(BO->getType());
        if (!Ty || Ty->getBitWidth() == 0 || Ty->getBitWidth() > 8)
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

bool hasPlainNarrowShift(Function &F) {
    for (Instruction &I : instructions(F)) {
        if (I.getName().starts_with("morok."))
            continue;
        auto *BO = dyn_cast<BinaryOperator>(&I);
        if (!BO)
            continue;
        auto *Ty = dyn_cast<IntegerType>(BO->getType());
        if (!Ty || Ty->getBitWidth() == 0 || Ty->getBitWidth() > 8)
            continue;
        switch (BO->getOpcode()) {
        case Instruction::Shl:
        case Instruction::LShr:
        case Instruction::AShr:
            return true;
        default:
            break;
        }
    }
    return false;
}

bool hasPlainNarrowICmp(Function &F) {
    for (Instruction &I : instructions(F)) {
        if (I.getName().starts_with("morok."))
            continue;
        auto *CI = dyn_cast<ICmpInst>(&I);
        if (!CI)
            continue;
        auto *Ty = dyn_cast<IntegerType>(CI->getOperand(0)->getType());
        if (Ty && Ty == CI->getOperand(1)->getType() &&
            Ty->getBitWidth() > 0 && Ty->getBitWidth() <= 8)
            return true;
    }
    return false;
}

Function *makeLargeLinearFunction(Module &M, unsigned Adds) {
    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *FT = FunctionType::get(I32, {I32}, false);
    auto *F =
        Function::Create(FT, GlobalValue::ExternalLinkage, "large_linear", M);
    F->arg_begin()->setName("x");

    IRBuilder<> B(BasicBlock::Create(Ctx, "entry", F));
    Value *V = &*F->arg_begin();
    for (unsigned I = 0; I < Adds; ++I)
        V = B.CreateAdd(V, B.getInt32(I + 1), "step");
    B.CreateRet(V);
    return F;
}

Function *makeI8OpChain(Module &M, unsigned Ops, StringRef Name) {
    LLVMContext &Ctx = M.getContext();
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *FT = FunctionType::get(I8, {I8, I8}, false);
    auto *F = Function::Create(FT, GlobalValue::ExternalLinkage, Name, M);
    auto ArgIt = F->arg_begin();
    Value *A = &*ArgIt++;
    A->setName("a");
    Value *Bv = &*ArgIt;
    Bv->setName("b");

    IRBuilder<> B(BasicBlock::Create(Ctx, "entry", F));
    Value *V = A;
    for (unsigned I = 0; I < Ops; ++I)
        V = B.CreateXor(V, Bv, "byte");
    B.CreateRet(V);
    return F;
}

Function *makeTinyAddFunction(Module &M, StringRef Name) {
    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *FT = FunctionType::get(I32, {I32}, false);
    auto *F = Function::Create(FT, GlobalValue::ExternalLinkage, Name, M);
    F->arg_begin()->setName("x");

    IRBuilder<> B(BasicBlock::Create(Ctx, "entry", F));
    Value *X = &*F->arg_begin();
    Value *Y = B.CreateAdd(X, B.getInt32(1), "y");
    B.CreateRet(Y);
    return F;
}

Function *makeBranchChainFunction(Module &M, unsigned Branches,
                                  StringRef Name) {
    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *FT = FunctionType::get(I32, {I32}, false);
    auto *F = Function::Create(FT, GlobalValue::ExternalLinkage, Name, M);
    Value *X = &*F->arg_begin();
    X->setName("x");

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", F);
    BasicBlock *Done = BasicBlock::Create(Ctx, "done", F);
    std::vector<BasicBlock *> Tests;
    std::vector<BasicBlock *> Returns;
    Tests.reserve(Branches);
    Returns.reserve(Branches);
    for (unsigned I = 0; I < Branches; ++I) {
        Tests.push_back(
            BasicBlock::Create(Ctx, (Twine("test") + Twine(I)).str(), F));
        Returns.push_back(
            BasicBlock::Create(Ctx, (Twine("ret") + Twine(I)).str(), F));
    }

    IRBuilder<> B(Entry);
    if (Branches == 0) {
        B.CreateRet(X);
        return F;
    }
    B.CreateBr(Tests.front());

    for (unsigned I = 0; I < Branches; ++I) {
        B.SetInsertPoint(Tests[I]);
        Value *Cond = B.CreateICmpEQ(X, B.getInt32(I), "match");
        BasicBlock *Next = (I + 1 < Branches) ? Tests[I + 1] : Done;
        B.CreateCondBr(Cond, Returns[I], Next);

        B.SetInsertPoint(Returns[I]);
        B.CreateRet(B.getInt32(I));
    }

    B.SetInsertPoint(Done);
    B.CreateRet(X);
    return F;
}

GlobalVariable *makePrivateString(Module &M, StringRef Name, StringRef Text) {
    Constant *Init = ConstantDataArray::getString(M.getContext(), Text, true);
    return new GlobalVariable(M, Init->getType(), /*isConstant=*/true,
                              GlobalValue::PrivateLinkage, Init, Name);
}

Function *makeExternalCallFunction(Module &M, GlobalVariable *Text) {
    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);
    auto *PutsTy = FunctionType::get(I32, {Ptr}, false);
    Function *Puts =
        Function::Create(PutsTy, GlobalValue::ExternalLinkage, "puts", M);
    Puts->addParamAttr(
        0, Attribute::getWithCaptureInfo(Ctx, CaptureInfo::none()));

    auto *FT = FunctionType::get(I32, false);
    auto *F =
        Function::Create(FT, GlobalValue::ExternalLinkage, "call_external", M);

    IRBuilder<> B(BasicBlock::Create(Ctx, "entry", F));
    Value *Msg = B.CreateConstInBoundsGEP2_64(Text->getValueType(), Text, 0, 0);
    Value *Result = B.CreateCall(Puts, {Msg});
    B.CreateRet(Result);
    return F;
}

Function *makeRepeatedVoidCalls(Module &M, unsigned Calls) {
    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *VoidTy = Type::getVoidTy(Ctx);
    auto *CalleeTy = FunctionType::get(VoidTy, {I32}, false);
    Function *Sink =
        Function::Create(CalleeTy, GlobalValue::ExternalLinkage, "sink", M);

    auto *CallerTy = FunctionType::get(VoidTy, {I32}, false);
    auto *Caller =
        Function::Create(CallerTy, GlobalValue::ExternalLinkage, "caller", M);
    Value *X = &*Caller->arg_begin();
    X->setName("x");

    IRBuilder<> B(BasicBlock::Create(Ctx, "entry", Caller));
    for (unsigned I = 0; I < Calls; ++I)
        B.CreateCall(Sink, {X});
    B.CreateRetVoid();
    return Caller;
}

Function *makePointerStoreFunction(Module &M, unsigned Stores) {
    M.setDataLayout("e-p:64:64");
    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);
    auto *FT = FunctionType::get(Type::getVoidTy(Ctx), {Ptr, I32}, false);
    auto *F =
        Function::Create(FT, GlobalValue::ExternalLinkage, "ptr_stress", M);
    auto ArgIt = F->arg_begin();
    Value *P = &*ArgIt++;
    P->setName("p");
    Value *X = &*ArgIt;
    X->setName("x");

    IRBuilder<> B(BasicBlock::Create(Ctx, "entry", F));
    for (unsigned I = 0; I < Stores; ++I) {
        Value *Slot = B.CreateGEP(I32, P, B.getInt32(I), "slot");
        B.CreateStore(X, Slot);
    }
    B.CreateRetVoid();
    return F;
}

} // namespace

TEST_CASE("MorokPass skips configured growth passes on oversized functions") {
    LLVMContext ctx;
    auto M = std::make_unique<Module>("large-module", ctx);
    Function *F = makeLargeLinearFunction(*M, 3000);
    REQUIRE(F);

    morok::config::Config cfg;
    cfg.seed = 101;
    cfg.passes.split.enabled = true;
    cfg.passes.split.splits = 5;

    ModuleAnalysisManager AM;
    morok::pipeline::MorokPass(std::move(cfg)).run(*M, AM);

    CHECK(F->size() == 1u);
    CHECK(countFunctions(*M, "morok.") == 0u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("MorokPass stops per-function growth on oversized modules") {
    LLVMContext ctx;
    auto M = std::make_unique<Module>("many-functions", ctx);
    Function *First = makeTinyAddFunction(*M, "tiny_0");
    for (unsigned I = 1; I < 1601; ++I)
        makeTinyAddFunction(*M, (Twine("tiny_") + Twine(I)).str());
    GlobalVariable *Text = makePrivateString(*M, "plain.str", "oversized");
    makeExternalCallFunction(*M, Text);

    morok::config::Config cfg;
    cfg.seed = 102;
    cfg.passes.sub.enabled = true;
    cfg.passes.sub.probability = 100;
    cfg.passes.sub.iterations = 1;
    cfg.passes.str_enc.enabled = true;
    cfg.passes.str_enc.probability = 100;
    cfg.passes.fco.enabled = true;

    ModuleAnalysisManager AM;
    morok::pipeline::MorokPass(std::move(cfg)).run(*M, AM);

    CHECK(countBinops(*First) == 1u);
    CHECK(countFunctions(*M, "morok.") == 0u);
    CHECK(M->getFunction("dlsym") == nullptr);
    CHECK(M->getFunction("morok.strdec") == nullptr);
    CHECK(countGlobals(*M, "morok.cloak") == 0u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("MorokPass caps eligible function visits on wide modules") {
    LLVMContext ctx;
    auto M = std::make_unique<Module>("wide-module", ctx);
    Function *First = makeTinyAddFunction(*M, "wide_0");
    Function *Tail = nullptr;
    for (unsigned I = 1; I < 320; ++I)
        Tail = makeTinyAddFunction(*M, (Twine("wide_") + Twine(I)).str());
    REQUIRE(Tail);

    morok::config::Config cfg;
    cfg.seed = 103;
    cfg.passes.sub.enabled = true;
    cfg.passes.sub.probability = 100;
    cfg.passes.sub.iterations = 1;

    ModuleAnalysisManager AM;
    morok::pipeline::MorokPass(std::move(cfg)).run(*M, AM);

    CHECK(countBinops(*First) > 1u);
    CHECK(countBinops(*Tail) == 1u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("MorokPass demotes generated symbols to private linkage") {
    LLVMContext ctx;
    auto M = std::make_unique<Module>("strip-symbols", ctx);
    GlobalVariable *Text = makePrivateString(*M, "plain.str", "hello-symbol");
    makeExternalCallFunction(*M, Text);

    morok::config::Config cfg;
    cfg.seed = 909;
    cfg.passes.str_enc.enabled = true;
    cfg.passes.str_enc.probability = 100;
    cfg.passes.fco.enabled = true;

    ModuleAnalysisManager AM;
    morok::pipeline::MorokPass(std::move(cfg)).run(*M, AM);

    // Generated helpers exist (e.g. morok.strdec) but must carry private
    // linkage, so their descriptive names never reach the binary's symbol table.
    std::size_t morokSyms = 0;
    for (Function &F : *M) {
        if (!F.getName().starts_with("morok."))
            continue;
        ++morokSyms;
        CHECK(F.hasPrivateLinkage());
    }
    for (GlobalVariable &GV : M->globals()) {
        if (!GV.getName().starts_with("morok."))
            continue;
        ++morokSyms;
        CHECK(GV.hasPrivateLinkage());
    }
    CHECK(morokSyms >= 1u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("misleadingMetadataModule plants retained fake analysis anchors") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
target triple = "arm64-apple-macosx13.0.0"

define i32 @main(i32 %x) {
entry:
  %y = add i32 %x, 1
  ret i32 %y
}
)ir");

    auto engine = morok::core::Xoshiro256pp::fromSeed(0x5EED);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::misleadingMetadataModule(*M, rng));

    std::vector<Function *> decoys;
    for (Function &F : *M) {
        if (F.getName() == "main")
            continue;
        decoys.push_back(&F);
        CHECK(F.hasInternalLinkage());
        CHECK(F.hasFnAttribute(Attribute::OptimizeNone));
        REQUIRE(F.getSubprogram() != nullptr);
        CHECK(F.getSubprogram()->getName() != F.getName());
    }

    CHECK(decoys.size() == 5u);
    CHECK(countAliases(*M) == 5u);
    CHECK(M->getNamedMetadata("llvm.dbg.cu") != nullptr);
    GlobalVariable *DebugStr = M->getGlobalVariable("morok.md.debug.str", true);
    REQUIRE(DebugStr);
    CHECK(DebugStr->getSection() == "__TEXT,__debug_str");

    GlobalVariable *Used = M->getGlobalVariable("llvm.compiler.used");
    REQUIRE(Used);
    REQUIRE(Used->hasInitializer());
    for (Function *F : decoys)
        CHECK(constantReferencesGlobal(Used->getInitializer(), F));
    for (GlobalAlias &Alias : M->aliases())
        CHECK(constantReferencesGlobal(Used->getInitializer(), &Alias));
    CHECK(constantReferencesGlobal(Used->getInitializer(), DebugStr));

    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("MorokPass boosts MBA and opaque predicates on sensitive functions") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @hot_path(i32 %x, i32 %y) {
entry:
  %s = add i32 %x, %y
  %c = icmp sgt i32 %s, 7
  br i1 %c, label %left, label %right
left:
  %l = xor i32 %s, %x
  br label %merge
right:
  %r = sub i32 %s, %y
  br label %merge
merge:
  %p = phi i32 [ %l, %left ], [ %r, %right ]
  ret i32 %p
}
)ir");
    Function *F = M->getFunction("hot_path");
    REQUIRE(F);
    morok::ir::addAnnotation(*F, "sensitive");
    const std::size_t beforeBlocks = F->size();
    const std::size_t beforeBinops = countBinops(*F);

    morok::config::Config cfg;
    cfg.seed = 710;

    ModuleAnalysisManager AM;
    morok::pipeline::MorokPass(std::move(cfg)).run(*M, AM);

    CHECK(F->size() > beforeBlocks);
    CHECK(countBinops(*F) > beforeBinops);
    CHECK(M->getGlobalVariable("morok.bcf.opaque", true) != nullptr);
    CHECK(M->getFunction("morok.extop.context") != nullptr);
    CHECK(countNamedInstructions(*F, "morok.extop.pred") >= 1u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("MorokPass hardens sensitive generated decryptor helpers") {
    LLVMContext ctx;
    auto M = std::make_unique<Module>("helper-density", ctx);
    makePrivateString(*M, "secret.str", "generated-secret");

    morok::config::Config cfg;
    cfg.seed = 711;
    cfg.passes.str_enc.enabled = true;
    cfg.passes.str_enc.probability = 100;
    cfg.passes.bcf.enabled = true;
    cfg.passes.bcf.probability = 0;
    cfg.passes.bcf.iterations = 1;
    cfg.passes.mba.enabled = true;
    cfg.passes.mba.probability = 0;
    cfg.passes.mba.layers = 1;
    cfg.passes.mba.heuristic = false;
    cfg.passes.external_op.enabled = true;
    cfg.passes.external_op.probability = 0;
    cfg.passes.external_op.max_blocks = 0;
    cfg.passes.external_op.decoy_stores = 0;

    ModuleAnalysisManager AM;
    morok::pipeline::MorokPass(std::move(cfg)).run(*M, AM);

    Function *Dec = nullptr;
    for (Function &F : *M)
        if (F.getName().starts_with("morok.strdec")) {
            Dec = &F;
            break;
        }
    REQUIRE(Dec);

    bool hasBcfJunk = false;
    for (BasicBlock &BB : *Dec)
        hasBcfJunk |= BB.getName().starts_with("morok.bcf.junk");
    CHECK(hasBcfJunk);
    CHECK(countNamedInstructions(*Dec, "morok.extop.pred") >= 1u);
    CHECK(M->getFunction("morok.extop.context") != nullptr);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("decoyStringsModule emits volatile decoy logging infrastructure") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @main(i32 %x) {
entry:
  %y = add i32 %x, 1
  ret i32 %y
}

define void @worker() {
entry:
  ret void
}
)ir");

    auto engine = morok::core::Xoshiro256pp::fromSeed(0xDEC0);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::decoyStringsModule(*M, rng));

    const std::size_t decoyGlobals = countGlobals(*M, "morok.decoy.str.");
    CHECK(decoyGlobals >= 6u);
    CHECK(countFunctions(*M, "morok.dbglog.") == 5u);
    CHECK(countGlobals(*M, "morok.dbglog.state.") == 5u);
    CHECK(countUserCallsToPrefix(*M, "morok.dbglog.") == decoyGlobals);
    CHECK_FALSE(hasReadableByteString(*M, "__TARGET_TRIPLE__"));

    for (Function &F : *M)
        if (F.getName().starts_with("morok.dbglog."))
            CHECK(countVolatileAccesses(F) == 2u);

    for (GlobalVariable &GV : M->globals()) {
        if (!GV.getName().starts_with("morok.dbglog.state."))
            continue;
        auto *StateTy = dyn_cast<StructType>(GV.getValueType());
        REQUIRE(StateTy != nullptr);
        REQUIRE(StateTy->getNumElements() == 2u);
        CHECK(StateTy->getElementType(0)->isPointerTy());
        CHECK(StateTy->getElementType(1)->isIntegerTy(32));
    }

    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("decoyStringsModule skips modules without user bodies") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare void @puts(ptr)
)ir");

    auto engine = morok::core::Xoshiro256pp::fromSeed(0xDEC1);
    morok::ir::IRRandom rng(engine);
    CHECK_FALSE(morok::passes::decoyStringsModule(*M, rng));
    CHECK(countFunctions(*M, "morok.dbglog.") == 0u);
    CHECK(countGlobals(*M, "morok.decoy.str.") == 0u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

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

TEST_CASE("substituteFunction handles one-bit arithmetic without poison shifts") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i1 @sub_bool(i1 %a, i1 %b) {
entry:
  %x = add i1 %a, %b
  %y = xor i1 %x, %a
  ret i1 %y
}
)ir");
    Function *F = M->getFunction("sub_bool");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(17);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::substituteFunction(*F, {100, 3}, rng));

    for (Instruction &I : instructions(*F)) {
        auto *BO = dyn_cast<BinaryOperator>(&I);
        if (!BO || BO->getOpcode() != Instruction::Shl ||
            !BO->getType()->isIntegerTy(1))
            continue;
        auto *Shift = dyn_cast<ConstantInt>(BO->getOperand(1));
        const bool invalidShift = Shift && Shift->getZExtValue() >= 1u;
        CHECK_FALSE(invalidShift);
    }
    CHECK(countBinops(*F) > 2u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("substituteFunction caps selected operators per iteration") {
    LLVMContext ctx;
    auto M = std::make_unique<Module>("sub-cap", ctx);
    Function *F = makeLargeLinearFunction(*M, 400);
    REQUIRE(F);
    CHECK(countNamedInstructions(*F, "step") == 400u);

    auto engine = morok::core::Xoshiro256pp::fromSeed(71);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::substituteFunction(*F, {100, 1}, rng));

    CHECK(countNamedInstructions(*F, "step") == 144u);
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

TEST_CASE("mbaFunction caps selected operators per layer") {
    LLVMContext ctx;
    auto M = std::make_unique<Module>("mba-cap", ctx);
    Function *F = makeLargeLinearFunction(*M, 400);
    REQUIRE(F);
    CHECK(countNamedInstructions(*F, "step") == 400u);

    auto engine = morok::core::Xoshiro256pp::fromSeed(72);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::mbaFunction(
        *F, {/*prob=*/100, /*layers=*/1, /*heuristic=*/true}, rng));

    CHECK(countNamedInstructions(*F, "step") == 144u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("mbaFunction rewrites constant shift operators") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @mba_shift(i32 %a) {
entry:
  %0 = shl  i32 %a, 3
  %1 = lshr i32 %0, 2
  %2 = ashr i32 %1, 1
  ret i32 %2
}
)ir");
    Function *F = M->getFunction("mba_shift");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(73);
    morok::ir::IRRandom rng(engine);
    // Shifts used to be skipped entirely (emitMba returned nullptr); the pass
    // must now report a change and emit the multiply form for `shl`.
    CHECK(morok::passes::mbaFunction(
        *F, {/*prob=*/100, /*layers=*/1, /*heuristic=*/false}, rng));
    CHECK(countOpcode(*M, Instruction::Mul) >= 1u);
    // The constant `shl a, 3` is gone — it became `a * 8`.
    bool hasPlainShlByThree = false;
    for (Instruction &I : instructions(*F))
        if (auto *BO = dyn_cast<BinaryOperator>(&I))
            if (BO->getOpcode() == Instruction::Shl)
                if (auto *K = dyn_cast<ConstantInt>(BO->getOperand(1)))
                    hasPlainShlByThree |= K->getZExtValue() == 3;
    CHECK_FALSE(hasPlainShlByThree);
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

TEST_CASE("optimizerAmplifyFunction amplifies poison-flagged ops via a "
          "flag-free base") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @optamp_flagged(i32 %a, i32 %b) {
entry:
  %sum = add nsw i32 %a, %b
  ret i32 %sum
}
)ir");
    Function *F = M->getFunction("optamp_flagged");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(14);
    morok::ir::IRRandom rng(engine);
    // `add nsw` used to be skipped; it must now amplify, and the generated base
    // op must NOT carry nsw/nuw (the replacement is the flag-free refinement).
    CHECK(morok::passes::optimizerAmplifyFunction(
        *F, {/*probability=*/100, /*max_forms=*/3}, rng));
    bool hasBase = false;
    for (Instruction &I : instructions(*F)) {
        if (!I.getName().starts_with("morok.optamp.base"))
            continue;
        hasBase = true;
        if (auto *OBO = dyn_cast<OverflowingBinaryOperator>(&I)) {
            CHECK_FALSE(OBO->hasNoSignedWrap());
            CHECK_FALSE(OBO->hasNoUnsignedWrap());
        }
    }
    CHECK(hasBase);
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

TEST_CASE("optimizerAmplifyFunction supports sub-byte integer ops") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i1 @optamp_bool(i1 %a, i1 %b) {
entry:
  %sum = add i1 %a, %b
  ret i1 %sum
}

define i4 @optamp_nibble(i4 %a, i4 %b) {
entry:
  %x = xor i4 %a, %b
  ret i4 %x
}
)ir");
    Function *BoolF = M->getFunction("optamp_bool");
    Function *NibbleF = M->getFunction("optamp_nibble");
    REQUIRE(BoolF);
    REQUIRE(NibbleF);

    auto engine = morok::core::Xoshiro256pp::fromSeed(141);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::optimizerAmplifyFunction(
        *BoolF, {/*probability=*/100, /*max_forms=*/3}, rng));
    CHECK(morok::passes::optimizerAmplifyFunction(
        *NibbleF, {/*probability=*/100, /*max_forms=*/3}, rng));

    std::size_t boolSelects = 0;
    bool boolHasShiftForm = false;
    for (Instruction &I : instructions(*BoolF)) {
        if (auto *SI = dyn_cast<SelectInst>(&I))
            if (SI->getName().starts_with("morok.optamp.select") &&
                SI->getType()->isIntegerTy(1))
                ++boolSelects;
        boolHasShiftForm |= I.getName().starts_with("morok.optamp.twice");
    }
    CHECK(boolSelects == 3u);
    CHECK_FALSE(boolHasShiftForm);

    std::size_t nibbleSelects = 0;
    for (Instruction &I : instructions(*NibbleF))
        if (auto *SI = dyn_cast<SelectInst>(&I))
            if (SI->getName().starts_with("morok.optamp.select") &&
                SI->getType()->isIntegerTy(4))
                ++nibbleSelects;
    CHECK(nibbleSelects == 3u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("optimizerAmplifyFunction builds equivalent integer comparisons") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i1 @optamp_cmp_eq(i8 %a, i8 %b) {
entry:
  %cmp = icmp eq i8 %a, %b
  ret i1 %cmp
}

define i1 @optamp_cmp_signed(i8 %a, i8 %b) {
entry:
  %cmp = icmp sge i8 %a, %b
  ret i1 %cmp
}
)ir");
    Function *EqF = M->getFunction("optamp_cmp_eq");
    Function *SignedF = M->getFunction("optamp_cmp_signed");
    REQUIRE(EqF);
    REQUIRE(SignedF);

    auto engine = morok::core::Xoshiro256pp::fromSeed(142);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::optimizerAmplifyFunction(
        *EqF, {/*probability=*/100, /*max_forms=*/4}, rng));
    CHECK(morok::passes::optimizerAmplifyFunction(
        *SignedF, {/*probability=*/100, /*max_forms=*/4}, rng));

    std::size_t eqBases = 0;
    std::size_t eqSelects = 0;
    bool hasEqXorZeroForm = false;
    for (Instruction &I : instructions(*EqF)) {
        if (I.getName().starts_with("morok.optamp.base") &&
            I.getType()->isIntegerTy(1))
            ++eqBases;
        if (auto *SI = dyn_cast<SelectInst>(&I))
            if (SI->getName().starts_with("morok.optamp.select") &&
                SI->getType()->isIntegerTy(1))
                ++eqSelects;
        hasEqXorZeroForm |= I.getName().starts_with("morok.optamp.cmp.xor");
    }
    CHECK(eqBases == 1u);
    CHECK(eqSelects == 4u);
    CHECK(hasEqXorZeroForm);

    std::size_t signedSelects = 0;
    bool hasSignedInverse = false;
    for (Instruction &I : instructions(*SignedF)) {
        if (auto *SI = dyn_cast<SelectInst>(&I))
            if (SI->getName().starts_with("morok.optamp.select") &&
                SI->getType()->isIntegerTy(1))
                ++signedSelects;
        hasSignedInverse |=
            I.getName().starts_with("morok.optamp.cmp.inverse");
    }
    CHECK(signedSelects == 4u);
    CHECK(hasSignedInverse);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("optimizerAmplifyFunction builds equivalent floating comparisons") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i1 @optamp_fcmp_ordered(float %a, float %b) {
entry:
  %cmp = fcmp olt float %a, %b
  ret i1 %cmp
}

define i1 @optamp_fcmp_unordered(double %a, double %b) {
entry:
  %cmp = fcmp uno double %a, %b
  ret i1 %cmp
}
)ir");
    Function *OrderedF = M->getFunction("optamp_fcmp_ordered");
    Function *UnorderedF = M->getFunction("optamp_fcmp_unordered");
    REQUIRE(OrderedF);
    REQUIRE(UnorderedF);

    auto engine = morok::core::Xoshiro256pp::fromSeed(143);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::optimizerAmplifyFunction(
        *OrderedF, {/*probability=*/100, /*max_forms=*/4}, rng));
    CHECK(morok::passes::optimizerAmplifyFunction(
        *UnorderedF, {/*probability=*/100, /*max_forms=*/4}, rng));

    std::size_t orderedBases = 0;
    std::size_t orderedSelects = 0;
    bool hasOrderedInverse = false;
    bool hasFloatGuardBits = false;
    for (Instruction &I : instructions(*OrderedF)) {
        if (I.getName().starts_with("morok.optamp.base") &&
            I.getType()->isIntegerTy(1))
            ++orderedBases;
        if (auto *SI = dyn_cast<SelectInst>(&I))
            if (SI->getName().starts_with("morok.optamp.select") &&
                SI->getType()->isIntegerTy(1))
                ++orderedSelects;
        hasOrderedInverse |=
            I.getName().starts_with("morok.optamp.fcmp.inverse");
        if (auto *BC = dyn_cast<BitCastInst>(&I))
            hasFloatGuardBits |=
                BC->getSrcTy()->isFloatTy() && BC->getDestTy()->isIntegerTy(32);
    }
    CHECK(orderedBases == 1u);
    CHECK(orderedSelects == 4u);
    CHECK(hasOrderedInverse);
    CHECK(hasFloatGuardBits);

    std::size_t unorderedSelects = 0;
    bool hasDoubleGuardBits = false;
    for (Instruction &I : instructions(*UnorderedF)) {
        if (auto *SI = dyn_cast<SelectInst>(&I))
            if (SI->getName().starts_with("morok.optamp.select") &&
                SI->getType()->isIntegerTy(1))
                ++unorderedSelects;
        if (auto *BC = dyn_cast<BitCastInst>(&I))
            hasDoubleGuardBits |= BC->getSrcTy()->isDoubleTy() &&
                                  BC->getDestTy()->isIntegerTy(64);
    }
    CHECK(unorderedSelects == 4u);
    CHECK(hasDoubleGuardBits);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("optimizerAmplifyFunction skips fast-math floating comparisons") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i1 @optamp_fcmp_fast(float %a, float %b) {
entry:
  %cmp = fcmp nnan olt float %a, %b
  ret i1 %cmp
}
)ir");
    Function *F = M->getFunction("optamp_fcmp_fast");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(144);
    morok::ir::IRRandom rng(engine);
    CHECK_FALSE(morok::passes::optimizerAmplifyFunction(
        *F, {/*probability=*/100, /*max_forms=*/4}, rng));
    for (Instruction &I : instructions(*F))
        CHECK_FALSE(I.getName().starts_with("morok.optamp"));
    CHECK_FALSE(verifyModule(*M, &errs()));
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

TEST_CASE("subThresholdPersistFunction wraps poison-flagged ops via a "
          "flag-free base") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @threshold_flagged(i32 %a, i32 %b) {
entry:
  %sum = add nuw i32 %a, %b
  ret i32 %sum
}
)ir");
    Function *F = M->getFunction("threshold_flagged");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(12);
    morok::ir::IRRandom rng(engine);
    // `add nuw` used to be skipped; it must now wrap through a flag-free base
    // op (cloneBaseOp drops the nuw, a sound refinement).
    CHECK(morok::passes::subThresholdPersistFunction(
        *F, {/*probability=*/100, /*max_terms=*/2}, rng));
    CHECK(countNamedAllocas(*F, "morok.threshold.seed") == 1u);
    bool hasBase = false;
    for (Instruction &I : instructions(*F)) {
        if (!I.getName().starts_with("morok.threshold.base"))
            continue;
        hasBase = true;
        if (auto *OBO = dyn_cast<OverflowingBinaryOperator>(&I)) {
            CHECK_FALSE(OBO->hasNoSignedWrap());
            CHECK_FALSE(OBO->hasNoUnsignedWrap());
        }
    }
    CHECK(hasBase);
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

TEST_CASE("subThresholdPersistFunction preserves floating ops through bit carriers") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define float @threshold_float(float %a, float %b) {
entry:
  %sum = fadd float %a, %b
  ret float %sum
}

define double @threshold_double(double %a, double %b) {
entry:
  %prod = fmul double %a, %b
  ret double %prod
}
)ir");
    Function *FloatF = M->getFunction("threshold_float");
    Function *DoubleF = M->getFunction("threshold_double");
    REQUIRE(FloatF);
    REQUIRE(DoubleF);

    auto engine = morok::core::Xoshiro256pp::fromSeed(122);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::subThresholdPersistFunction(
        *FloatF, {/*probability=*/100, /*max_terms=*/2}, rng));
    CHECK(morok::passes::subThresholdPersistFunction(
        *DoubleF, {/*probability=*/100, /*max_terms=*/2}, rng));

    bool hasFloatKeep = false;
    bool hasFloatCarrier = false;
    for (Instruction &I : instructions(*FloatF)) {
        hasFloatKeep |= I.getName().starts_with("morok.threshold.keep") &&
                        I.getType()->isFloatTy();
        if (auto *BC = dyn_cast<BitCastInst>(&I))
            hasFloatCarrier |=
                BC->getSrcTy()->isFloatTy() && BC->getDestTy()->isIntegerTy(32);
    }
    CHECK(hasFloatKeep);
    CHECK(hasFloatCarrier);

    bool hasDoubleKeep = false;
    bool hasDoubleCarrier = false;
    for (Instruction &I : instructions(*DoubleF)) {
        hasDoubleKeep |= I.getName().starts_with("morok.threshold.keep") &&
                         I.getType()->isDoubleTy();
        if (auto *BC = dyn_cast<BitCastInst>(&I))
            hasDoubleCarrier |= BC->getSrcTy()->isDoubleTy() &&
                                BC->getDestTy()->isIntegerTy(64);
    }
    CHECK(hasDoubleKeep);
    CHECK(hasDoubleCarrier);
    CHECK(countNamedAllocas(*FloatF, "morok.threshold.seed") == 1u);
    CHECK(countNamedAllocas(*DoubleF, "morok.threshold.seed") == 1u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("subThresholdPersistFunction skips fast-math floating ops") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define float @threshold_fast(float %a, float %b) {
entry:
  %sum = fadd nnan float %a, %b
  ret float %sum
}
)ir");
    Function *F = M->getFunction("threshold_fast");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(123);
    morok::ir::IRRandom rng(engine);
    CHECK_FALSE(morok::passes::subThresholdPersistFunction(
        *F, {/*probability=*/100, /*max_terms=*/2}, rng));
    CHECK(countNamedAllocas(*F, "morok.threshold.seed") == 0u);
    for (Instruction &I : instructions(*F))
        CHECK_FALSE(I.getName().starts_with("morok.threshold"));
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("subThresholdPersistFunction supports sub-byte integer ops") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i1 @threshold_bool(i1 %a, i1 %b) {
entry:
  %x = xor i1 %a, %b
  ret i1 %x
}

define i4 @threshold_nibble(i4 %a, i4 %b) {
entry:
  %x = add i4 %a, %b
  ret i4 %x
}
)ir");
    Function *BoolF = M->getFunction("threshold_bool");
    Function *NibbleF = M->getFunction("threshold_nibble");
    REQUIRE(BoolF);
    REQUIRE(NibbleF);

    auto engine = morok::core::Xoshiro256pp::fromSeed(121);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::subThresholdPersistFunction(
        *BoolF, {/*probability=*/100, /*max_terms=*/2}, rng));
    CHECK(morok::passes::subThresholdPersistFunction(
        *NibbleF, {/*probability=*/100, /*max_terms=*/2}, rng));

    bool hasI1Zero = false;
    bool hasI1Keep = false;
    for (Instruction &I : instructions(*BoolF)) {
        hasI1Zero |= I.getName().starts_with("morok.threshold.zero") &&
                     I.getType()->isIntegerTy(1);
        hasI1Keep |= I.getName().starts_with("morok.threshold.keep") &&
                     I.getType()->isIntegerTy(1);
    }
    CHECK(hasI1Zero);
    CHECK(hasI1Keep);

    bool hasI4Zero = false;
    bool hasI4Keep = false;
    for (Instruction &I : instructions(*NibbleF)) {
        hasI4Zero |= I.getName().starts_with("morok.threshold.zero") &&
                     I.getType()->isIntegerTy(4);
        hasI4Keep |= I.getName().starts_with("morok.threshold.keep") &&
                     I.getType()->isIntegerTy(4);
    }
    CHECK(hasI4Zero);
    CHECK(hasI4Keep);
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

TEST_CASE("constantEncryptFunction supports sub-byte and odd-width literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i1 @const_bool(i1 %a) {
entry:
  %x = xor i1 %a, true
  ret i1 %x
}

define i12 @const_i12(i12 %a) {
entry:
  %x = add i12 %a, 291
  ret i12 %x
}
)ir");
    Function *BoolF = M->getFunction("const_bool");
    Function *I12F = M->getFunction("const_i12");
    REQUIRE(BoolF);
    REQUIRE(I12F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(501);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::constantEncryptFunction(
        *BoolF, {/*prob=*/100, /*k=*/3, /*iterations=*/1}, rng));
    CHECK(morok::passes::constantEncryptFunction(
        *I12F, {/*prob=*/100, /*k=*/3, /*iterations=*/1}, rng));

    CHECK(countGlobals(*M, "morok.share") == 6u);
    bool hasI1Load = false;
    bool hasI12Load = false;
    for (Instruction &I : instructions(*BoolF))
        if (auto *LI = dyn_cast<LoadInst>(&I))
            hasI1Load |= LI->isVolatile() && LI->getType()->isIntegerTy(1);
    for (Instruction &I : instructions(*I12F))
        if (auto *LI = dyn_cast<LoadInst>(&I))
            hasI12Load |= LI->isVolatile() && LI->getType()->isIntegerTy(12);
    CHECK(hasI1Load);
    CHECK(hasI12Load);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("constantEncryptFunction rewrites integer select literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @const_select(i1 %flag) {
entry:
  %x = select i1 %flag, i32 11, i32 29
  ret i32 %x
}
)ir");
    Function *F = M->getFunction("const_select");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(502);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::constantEncryptFunction(
        *F, {/*prob=*/100, /*k=*/3, /*iterations=*/1}, rng));

    SelectInst *Sel = nullptr;
    for (Instruction &I : instructions(*F))
        if (auto *SI = dyn_cast<SelectInst>(&I))
            Sel = SI;
    REQUIRE(Sel);
    CHECK_FALSE(isa<ConstantInt>(Sel->getTrueValue()));
    CHECK_FALSE(isa<ConstantInt>(Sel->getFalseValue()));
    CHECK(countGlobals(*M, "morok.share") == 6u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("constantEncryptFunction rewrites cast and return literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @const_cast_ret() {
entry:
  %x = zext i8 7 to i32
  ret i32 42
}
)ir");
    Function *F = M->getFunction("const_cast_ret");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(503);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::constantEncryptFunction(
        *F, {/*prob=*/100, /*k=*/3, /*iterations=*/1}, rng));

    CastInst *Cast = nullptr;
    ReturnInst *Ret = nullptr;
    for (Instruction &I : instructions(*F)) {
        if (auto *CI = dyn_cast<CastInst>(&I))
            Cast = CI;
        if (auto *RI = dyn_cast<ReturnInst>(&I))
            Ret = RI;
    }
    REQUIRE(Cast);
    REQUIRE(Ret);
    CHECK_FALSE(isa<ConstantInt>(Cast->getOperand(0)));
    CHECK_FALSE(isa<ConstantInt>(Ret->getReturnValue()));
    CHECK(countGlobals(*M, "morok.share") == 6u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("constantEncryptFunction rewrites floating value literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare void @const_fp_arg(float)

define float @const_fp_values(float %a, double %d, ptr %p) {
entry:
  %x = fadd float %a, 1.500000e+00
  %cmp = fcmp olt double %d, 2.500000e+00
  store float 3.500000e+00, ptr %p, align 4
  call void @const_fp_arg(float 4.500000e+00)
  ret float 5.500000e+00
}
)ir");
    Function *F = M->getFunction("const_fp_values");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(508);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::constantEncryptFunction(
        *F, {/*prob=*/100, /*k=*/3, /*iterations=*/1}, rng));

    std::size_t fpBitcasts = 0;
    for (Instruction &I : instructions(*F)) {
        if (auto *BC = dyn_cast<BitCastInst>(&I))
            if (BC->getName().starts_with("morok.share.fp"))
                ++fpBitcasts;
        if (isa<BinaryOperator>(I) || isa<FCmpInst>(I) ||
            isa<ReturnInst>(I) || isa<StoreInst>(I) || isa<CallInst>(I)) {
            for (Use &Op : I.operands())
                CHECK_FALSE(isa<ConstantFP>(Op.get()));
        }
    }
    CHECK(fpBitcasts >= 5u);
    CHECK(countGlobals(*M, "morok.share") == 15u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("constantEncryptFunction rewrites floating PHI incoming literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define float @const_fp_phi(i1 %flag) {
entry:
  br i1 %flag, label %left, label %right
left:
  br label %merge
right:
  br label %merge
merge:
  %p = phi float [ 1.250000e+00, %left ], [ 2.750000e+00, %right ]
  ret float %p
}
)ir");
    Function *F = M->getFunction("const_fp_phi");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(509);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::constantEncryptFunction(
        *F, {/*prob=*/100, /*k=*/3, /*iterations=*/1}, rng));

    PHINode *Phi = nullptr;
    for (Instruction &I : instructions(*F))
        if (auto *PN = dyn_cast<PHINode>(&I))
            Phi = PN;
    REQUIRE(Phi);
    for (Value *Incoming : Phi->incoming_values())
        CHECK_FALSE(isa<ConstantFP>(Incoming));
    CHECK(countGlobals(*M, "morok.share") == 6u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("constantEncryptFunction rewrites ordinary call argument literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare i32 @const_arg_callee(i32, i8)

define i32 @const_call_args() {
entry:
  %x = call i32 @const_arg_callee(i32 11, i8 29)
  ret i32 %x
}
)ir");
    Function *F = M->getFunction("const_call_args");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(504);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::constantEncryptFunction(
        *F, {/*prob=*/100, /*k=*/3, /*iterations=*/1}, rng));

    CallInst *Call = nullptr;
    for (Instruction &I : instructions(*F))
        if (auto *CI = dyn_cast<CallInst>(&I))
            if (CI->getCalledFunction() &&
                CI->getCalledFunction()->getName() == "const_arg_callee")
                Call = CI;
    REQUIRE(Call);
    CHECK_FALSE(isa<ConstantInt>(Call->getArgOperand(0)));
    CHECK_FALSE(isa<ConstantInt>(Call->getArgOperand(1)));
    CHECK(countGlobals(*M, "morok.share") == 6u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("constantEncryptFunction rewrites store value literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define void @const_store(ptr %p) {
entry:
  store i32 12345, ptr %p, align 4
  ret void
}
)ir");
    Function *F = M->getFunction("const_store");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(505);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::constantEncryptFunction(
        *F, {/*prob=*/100, /*k=*/3, /*iterations=*/1}, rng));

    StoreInst *Store = nullptr;
    for (Instruction &I : instructions(*F))
        if (auto *SI = dyn_cast<StoreInst>(&I))
            Store = SI;
    REQUIRE(Store);
    CHECK_FALSE(isa<ConstantInt>(Store->getValueOperand()));
    CHECK(Store->getPointerOperand()->getName() == "p");
    CHECK(countGlobals(*M, "morok.share") == 3u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("constantEncryptFunction rewrites conditional branch literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define void @const_branch() {
entry:
  br i1 true, label %left, label %right
left:
  ret void
right:
  ret void
}
)ir");
    Function *F = M->getFunction("const_branch");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(506);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::constantEncryptFunction(
        *F, {/*prob=*/100, /*k=*/3, /*iterations=*/1}, rng));

    auto *BI = dyn_cast<BranchInst>(F->getEntryBlock().getTerminator());
    REQUIRE(BI);
    REQUIRE(BI->isConditional());
    CHECK_FALSE(isa<ConstantInt>(BI->getCondition()));
    CHECK(countGlobals(*M, "morok.share") == 3u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("constantEncryptFunction rewrites switch condition literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define void @const_switch() {
entry:
  switch i32 7, label %default [
    i32 7, label %hit
    i32 9, label %miss
  ]
hit:
  ret void
miss:
  ret void
default:
  ret void
}
)ir");
    Function *F = M->getFunction("const_switch");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(507);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::constantEncryptFunction(
        *F, {/*prob=*/100, /*k=*/3, /*iterations=*/1}, rng));

    auto *SW = dyn_cast<SwitchInst>(F->getEntryBlock().getTerminator());
    REQUIRE(SW);
    CHECK_FALSE(isa<ConstantInt>(SW->getCondition()));
    for (auto &Case : SW->cases())
        CHECK(isa<ConstantInt>(Case.getCaseValue()));
    CHECK(countGlobals(*M, "morok.share") == 3u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("constantEncryptFunction rewrites PHI incoming literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i8 @const_phi(i1 %flag) {
entry:
  br i1 %flag, label %join, label %right
right:
  br label %join
join:
  %x = phi i8 [ 11, %entry ], [ 29, %right ]
  ret i8 %x
}
)ir");
    Function *F = M->getFunction("const_phi");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(508);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::constantEncryptFunction(
        *F, {/*prob=*/100, /*k=*/3, /*iterations=*/1}, rng));

    PHINode *Phi = nullptr;
    bool hasSplitEdge = false;
    for (BasicBlock &BB : *F) {
        hasSplitEdge |= BB.getName().starts_with("morok.const.phi.edge");
        for (Instruction &I : BB)
            if (auto *PN = dyn_cast<PHINode>(&I))
                Phi = PN;
    }
    REQUIRE(Phi);
    for (unsigned I = 0; I < Phi->getNumIncomingValues(); ++I)
        CHECK_FALSE(isa<ConstantInt>(Phi->getIncomingValue(I)));
    CHECK(hasSplitEdge);
    CHECK(countGlobals(*M, "morok.share") == 6u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("constantEncryptFunction caps literal rewrites") {
    LLVMContext ctx;
    auto M = std::make_unique<Module>("const-cap", ctx);
    Function *F = makeLargeLinearFunction(*M, 200);
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(73);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::constantEncryptFunction(
        *F, {/*prob=*/100, /*k=*/2, /*iterations=*/1}, rng));

    CHECK(countGlobals(*M, "morok.share") == 256u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("shamirShareFunction reconstructs literals from threshold shares") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @shamir_lit(i32 %a) {
entry:
  %x = add i32 %a, 305419896
  %y = xor i32 %x, 90
  ret i32 %y
}
)ir");
    Function *F = M->getFunction("shamir_lit");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(0x5348);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::shamirShareFunction(*F,
                                             {/*probability=*/100,
                                              /*threshold=*/3, /*shares=*/5,
                                              /*max_secrets=*/1},
                                             rng));

    Function *Gf8Mul = M->getFunction("morok.gf8mul");
    REQUIRE(Gf8Mul);
    bool gf8MulHasBranch = false;
    for (BasicBlock &BB : *Gf8Mul)
        gf8MulHasBranch |= isa<BranchInst>(BB.getTerminator());
    CHECK_FALSE(gf8MulHasBranch);
    CHECK(countGlobals(*M, "morok.shamir.share") == 12u);
    CHECK(countGlobals(*M, "morok.shamir.cell") == 12u);
    CHECK(countCallsTo(*F, "morok.gf8mul") == 12u);

    std::size_t volatileShareLoads = 0;
    std::size_t volatileCellLoads = 0;
    std::size_t volatileCellStores = 0;
    bool hasByteReconstruction = false;
    bool hasWideReconstruction = false;
    for (Instruction &I : instructions(*F)) {
        hasByteReconstruction |= I.getName().starts_with("morok.shamir.byte");
        hasWideReconstruction |= I.getName().starts_with("morok.shamir.value");
        if (auto *LI = dyn_cast<LoadInst>(&I))
            if (LI->isVolatile() &&
                LI->getPointerOperand()->getName().starts_with(
                    "morok.shamir.share"))
                ++volatileShareLoads;
        if (auto *LI = dyn_cast<LoadInst>(&I))
            if (LI->isVolatile() &&
                LI->getPointerOperand()->getName().starts_with(
                    "morok.shamir.cell"))
                ++volatileCellLoads;
        if (auto *SI = dyn_cast<StoreInst>(&I))
            if (SI->isVolatile() &&
                SI->getPointerOperand()->getName().starts_with(
                    "morok.shamir.cell"))
                ++volatileCellStores;
    }
    CHECK(volatileShareLoads == 12u);
    CHECK(volatileCellLoads == 12u);
    CHECK(volatileCellStores == 12u);
    CHECK(hasByteReconstruction);
    CHECK(hasWideReconstruction);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("shamirShareFunction supports sub-byte and odd-width literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i1 @shamir_bool(i1 %a) {
entry:
  %x = xor i1 %a, true
  ret i1 %x
}

define i12 @shamir_i12(i12 %a) {
entry:
  %x = add i12 %a, 291
  ret i12 %x
}
)ir");
    Function *BoolF = M->getFunction("shamir_bool");
    Function *I12F = M->getFunction("shamir_i12");
    REQUIRE(BoolF);
    REQUIRE(I12F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(0x5350);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::shamirShareFunction(
        *BoolF,
        {/*probability=*/100, /*threshold=*/3, /*shares=*/5,
         /*max_secrets=*/1},
        rng));
    CHECK(morok::passes::shamirShareFunction(
        *I12F,
        {/*probability=*/100, /*threshold=*/3, /*shares=*/5,
         /*max_secrets=*/1},
        rng));

    CHECK(M->getFunction("morok.gf8mul") != nullptr);
    CHECK(countGlobals(*M, "morok.shamir.share") == 9u);
    CHECK(countGlobals(*M, "morok.shamir.cell") == 9u);
    CHECK(countCallsTo(*BoolF, "morok.gf8mul") == 3u);
    CHECK(countCallsTo(*I12F, "morok.gf8mul") == 6u);

    bool hasI1Trunc = false;
    bool hasI12Trunc = false;
    for (Instruction &I : instructions(*BoolF))
        hasI1Trunc |= I.getName().starts_with("morok.shamir.value.trunc") &&
                      I.getType()->isIntegerTy(1);
    for (Instruction &I : instructions(*I12F))
        hasI12Trunc |= I.getName().starts_with("morok.shamir.value.trunc") &&
                       I.getType()->isIntegerTy(12);
    CHECK(hasI1Trunc);
    CHECK(hasI12Trunc);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("shamirShareFunction reconstructs integer select literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i8 @shamir_select(i1 %flag) {
entry:
  %x = select i1 %flag, i8 11, i8 29
  ret i8 %x
}
)ir");
    Function *F = M->getFunction("shamir_select");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(0x5351);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::shamirShareFunction(
        *F,
        {/*probability=*/100, /*threshold=*/2, /*shares=*/3,
         /*max_secrets=*/2},
        rng));

    SelectInst *Sel = nullptr;
    for (Instruction &I : instructions(*F))
        if (auto *SI = dyn_cast<SelectInst>(&I))
            Sel = SI;
    REQUIRE(Sel);
    CHECK_FALSE(isa<ConstantInt>(Sel->getTrueValue()));
    CHECK_FALSE(isa<ConstantInt>(Sel->getFalseValue()));
    CHECK(countGlobals(*M, "morok.shamir.share") == 4u);
    CHECK(countGlobals(*M, "morok.shamir.cell") == 4u);
    CHECK(countCallsTo(*F, "morok.gf8mul") == 4u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("shamirShareFunction reconstructs cast and return literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i8 @shamir_cast_ret() {
entry:
  %x = zext i4 7 to i8
  ret i8 42
}
)ir");
    Function *F = M->getFunction("shamir_cast_ret");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(0x5352);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::shamirShareFunction(
        *F,
        {/*probability=*/100, /*threshold=*/2, /*shares=*/3,
         /*max_secrets=*/2},
        rng));

    CastInst *Cast = nullptr;
    ReturnInst *Ret = nullptr;
    for (Instruction &I : instructions(*F)) {
        if (auto *CI = dyn_cast<CastInst>(&I))
            Cast = CI;
        if (auto *RI = dyn_cast<ReturnInst>(&I))
            Ret = RI;
    }
    REQUIRE(Cast);
    REQUIRE(Ret);
    CHECK_FALSE(isa<ConstantInt>(Cast->getOperand(0)));
    CHECK_FALSE(isa<ConstantInt>(Ret->getReturnValue()));
    CHECK(countGlobals(*M, "morok.shamir.share") == 4u);
    CHECK(countGlobals(*M, "morok.shamir.cell") == 4u);
    CHECK(countCallsTo(*F, "morok.gf8mul") == 4u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("shamirShareFunction reconstructs ordinary call argument literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare i8 @shamir_arg_callee(i8, i8)

define i8 @shamir_call_args() {
entry:
  %x = call i8 @shamir_arg_callee(i8 11, i8 29)
  ret i8 %x
}
)ir");
    Function *F = M->getFunction("shamir_call_args");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(0x5353);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::shamirShareFunction(
        *F,
        {/*probability=*/100, /*threshold=*/2, /*shares=*/3,
         /*max_secrets=*/2},
        rng));

    CallInst *Call = nullptr;
    for (Instruction &I : instructions(*F))
        if (auto *CI = dyn_cast<CallInst>(&I))
            if (CI->getCalledFunction() &&
                CI->getCalledFunction()->getName() == "shamir_arg_callee")
                Call = CI;
    REQUIRE(Call);
    CHECK_FALSE(isa<ConstantInt>(Call->getArgOperand(0)));
    CHECK_FALSE(isa<ConstantInt>(Call->getArgOperand(1)));
    CHECK(countGlobals(*M, "morok.shamir.share") == 4u);
    CHECK(countGlobals(*M, "morok.shamir.cell") == 4u);
    CHECK(countCallsTo(*F, "morok.gf8mul") == 4u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("shamirShareFunction reconstructs floating value literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare void @shamir_fp_arg(float)

define float @shamir_fp_values(float %a, double %d, ptr %p) {
entry:
  %x = fadd float %a, 1.500000e+00
  %cmp = fcmp olt double %d, 2.500000e+00
  store float 3.500000e+00, ptr %p, align 4
  call void @shamir_fp_arg(float 4.500000e+00)
  ret float 5.500000e+00
}
)ir");
    Function *F = M->getFunction("shamir_fp_values");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(0x5358);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::shamirShareFunction(
        *F,
        {/*probability=*/100, /*threshold=*/2, /*shares=*/3,
         /*max_secrets=*/5},
        rng));

    std::size_t fpBitcasts = 0;
    for (Instruction &I : instructions(*F)) {
        if (auto *BC = dyn_cast<BitCastInst>(&I))
            if (BC->getName().starts_with("morok.shamir.value.fp"))
                ++fpBitcasts;
        if (isa<BinaryOperator>(I) || isa<FCmpInst>(I) ||
            isa<ReturnInst>(I) || isa<StoreInst>(I) || isa<CallInst>(I)) {
            for (Use &Op : I.operands())
                CHECK_FALSE(isa<ConstantFP>(Op.get()));
        }
    }
    CHECK(fpBitcasts >= 5u);
    CHECK(countGlobals(*M, "morok.shamir.share") == 48u);
    CHECK(countGlobals(*M, "morok.shamir.cell") == 48u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("shamirShareFunction reconstructs floating PHI incoming literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define float @shamir_fp_phi(i1 %flag) {
entry:
  br i1 %flag, label %join, label %right
right:
  br label %join
join:
  %p = phi float [ 1.250000e+00, %entry ], [ 2.750000e+00, %right ]
  ret float %p
}
)ir");
    Function *F = M->getFunction("shamir_fp_phi");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(0x5359);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::shamirShareFunction(
        *F,
        {/*probability=*/100, /*threshold=*/2, /*shares=*/3,
         /*max_secrets=*/2},
        rng));

    PHINode *Phi = nullptr;
    bool hasSplitEdge = false;
    for (BasicBlock &BB : *F) {
        hasSplitEdge |= BB.getName().starts_with("morok.shamir.phi.edge");
        for (Instruction &I : BB)
            if (auto *PN = dyn_cast<PHINode>(&I))
                Phi = PN;
    }
    REQUIRE(Phi);
    for (Value *Incoming : Phi->incoming_values())
        CHECK_FALSE(isa<ConstantFP>(Incoming));
    CHECK(hasSplitEdge);
    CHECK(countGlobals(*M, "morok.shamir.share") == 16u);
    CHECK(countGlobals(*M, "morok.shamir.cell") == 16u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("shamirShareFunction reconstructs store value literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define void @shamir_store(ptr %p) {
entry:
  store i8 37, ptr %p, align 1
  ret void
}
)ir");
    Function *F = M->getFunction("shamir_store");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(0x5354);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::shamirShareFunction(
        *F,
        {/*probability=*/100, /*threshold=*/2, /*shares=*/3,
         /*max_secrets=*/1},
        rng));

    StoreInst *Store = nullptr;
    for (Instruction &I : instructions(*F))
        if (auto *SI = dyn_cast<StoreInst>(&I))
            if (SI->getPointerOperand()->getName() == "p")
                Store = SI;
    REQUIRE(Store);
    CHECK_FALSE(isa<ConstantInt>(Store->getValueOperand()));
    CHECK(countGlobals(*M, "morok.shamir.share") == 2u);
    CHECK(countGlobals(*M, "morok.shamir.cell") == 2u);
    CHECK(countCallsTo(*F, "morok.gf8mul") == 2u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("shamirShareFunction reconstructs conditional branch literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define void @shamir_branch() {
entry:
  br i1 false, label %left, label %right
left:
  ret void
right:
  ret void
}
)ir");
    Function *F = M->getFunction("shamir_branch");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(0x5355);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::shamirShareFunction(
        *F,
        {/*probability=*/100, /*threshold=*/2, /*shares=*/3,
         /*max_secrets=*/1},
        rng));

    auto *BI = dyn_cast<BranchInst>(F->getEntryBlock().getTerminator());
    REQUIRE(BI);
    REQUIRE(BI->isConditional());
    CHECK_FALSE(isa<ConstantInt>(BI->getCondition()));
    CHECK(countGlobals(*M, "morok.shamir.share") == 2u);
    CHECK(countGlobals(*M, "morok.shamir.cell") == 2u);
    CHECK(countCallsTo(*F, "morok.gf8mul") == 2u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("shamirShareFunction reconstructs switch condition literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define void @shamir_switch() {
entry:
  switch i8 5, label %default [
    i8 5, label %hit
    i8 7, label %miss
  ]
hit:
  ret void
miss:
  ret void
default:
  ret void
}
)ir");
    Function *F = M->getFunction("shamir_switch");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(0x5356);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::shamirShareFunction(
        *F,
        {/*probability=*/100, /*threshold=*/2, /*shares=*/3,
         /*max_secrets=*/1},
        rng));

    auto *SW = dyn_cast<SwitchInst>(F->getEntryBlock().getTerminator());
    REQUIRE(SW);
    CHECK_FALSE(isa<ConstantInt>(SW->getCondition()));
    for (auto &Case : SW->cases())
        CHECK(isa<ConstantInt>(Case.getCaseValue()));
    CHECK(countGlobals(*M, "morok.shamir.share") == 2u);
    CHECK(countGlobals(*M, "morok.shamir.cell") == 2u);
    CHECK(countCallsTo(*F, "morok.gf8mul") == 2u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("shamirShareFunction reconstructs PHI incoming literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i8 @shamir_phi(i1 %flag) {
entry:
  br i1 %flag, label %join, label %right
right:
  br label %join
join:
  %x = phi i8 [ 11, %entry ], [ 29, %right ]
  ret i8 %x
}
)ir");
    Function *F = M->getFunction("shamir_phi");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(0x5357);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::shamirShareFunction(
        *F,
        {/*probability=*/100, /*threshold=*/2, /*shares=*/3,
         /*max_secrets=*/2},
        rng));

    PHINode *Phi = nullptr;
    bool hasSplitEdge = false;
    for (BasicBlock &BB : *F) {
        hasSplitEdge |= BB.getName().starts_with("morok.shamir.phi.edge");
        for (Instruction &I : BB)
            if (auto *PN = dyn_cast<PHINode>(&I))
                Phi = PN;
    }
    REQUIRE(Phi);
    for (unsigned I = 0; I < Phi->getNumIncomingValues(); ++I)
        CHECK_FALSE(isa<ConstantInt>(Phi->getIncomingValue(I)));
    CHECK(hasSplitEdge);
    CHECK(countGlobals(*M, "morok.shamir.share") == 4u);
    CHECK(countGlobals(*M, "morok.shamir.cell") == 4u);
    CHECK(countCallsTo(*F, "morok.gf8mul") == 4u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("shamirShareFunction honors probability and max secret caps") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @shamir_off(i32 %a) {
entry:
  %x = add i32 %a, 305419896
  ret i32 %x
}
)ir");
    Function *F = M->getFunction("shamir_off");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(0x5349);
    morok::ir::IRRandom rng(engine);

    CHECK_FALSE(morok::passes::shamirShareFunction(
        *F,
        {/*probability=*/0, /*threshold=*/3, /*shares=*/5,
         /*max_secrets=*/1},
        rng));
    CHECK(countGlobals(*M, "morok.shamir.share") == 0u);
    CHECK_FALSE(verifyModule(*M, &errs()));

    auto M2 = parse(ctx, R"ir(
define i32 @shamir_cap(i32 %a) {
entry:
  %x = add i32 %a, 305419896
  ret i32 %x
}
)ir");
    Function *F2 = M2->getFunction("shamir_cap");
    REQUIRE(F2);
    CHECK_FALSE(morok::passes::shamirShareFunction(
        *F2,
        {/*probability=*/100, /*threshold=*/3, /*shares=*/5,
         /*max_secrets=*/0},
        rng));
    CHECK(countGlobals(*M2, "morok.shamir.share") == 0u);
    CHECK_FALSE(verifyModule(*M2, &errs()));
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

TEST_CASE("stackDeltaGamesFunction emits dynamic stack-pointer deltas") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @stackdelta(i32 %x, i32 %y) {
entry:
  %seed = add i32 %x, %y
  %c = icmp sgt i32 %seed, 10
  br i1 %c, label %left, label %right
left:
  %l = xor i32 %seed, %x
  br label %join
right:
  %r = sub i32 %seed, %y
  br label %join
join:
  %p = phi i32 [ %l, %left ], [ %r, %right ]
  ret i32 %p
}
)ir");
    Function *F = M->getFunction("stackdelta");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(66);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::stackDeltaGamesFunction(
        *F,
        {/*probability=*/100, /*max_blocks=*/3, /*min_bytes=*/17,
         /*max_extra_bytes=*/32, /*touches=*/2},
        rng));

    CHECK(countGlobals(*M, "morok.stackdelta.seed") == 1u);

    bool hasDynamicAlloca = false;
    bool hasStackSave = false;
    bool hasStackRestore = false;
    bool hasOddSize = false;
    bool hasOverlapStore = false;
    unsigned volatileStores = 0;
    for (Instruction &I : instructions(*F)) {
        if (auto *AI = dyn_cast<AllocaInst>(&I))
            if (AI->getName().starts_with("morok.stackdelta.frame"))
                hasDynamicAlloca |= !AI->isStaticAlloca();
        if (auto *CI = dyn_cast<CallInst>(&I)) {
            if (Function *Callee = CI->getCalledFunction()) {
                hasStackSave |= Callee->getName().starts_with("llvm.stacksave");
                hasStackRestore |=
                    Callee->getName().starts_with("llvm.stackrestore");
            }
        }
        hasOddSize |= I.getName().starts_with("morok.stackdelta.size");
        if (auto *SI = dyn_cast<StoreInst>(&I)) {
            if (SI->isVolatile())
                ++volatileStores;
            hasOverlapStore |= SI->getPointerOperand()->getName().starts_with(
                "morok.stackdelta.overlap");
        }
    }

    CHECK(hasDynamicAlloca);
    CHECK(hasStackSave);
    CHECK(hasStackRestore);
    CHECK(hasOddSize);
    CHECK(hasOverlapStore);
    CHECK(volatileStores >= 2u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("stackDeltaGamesFunction mixes floating live terms") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @stackdelta_fp(float %a, double %b, i1 %flag) {
entry:
  %b32 = fptrunc double %b to float
  %sum = fadd float %a, %b32
  %cmp = fcmp ogt float %sum, %a
  br i1 %flag, label %body, label %alt
body:
  %out = select i1 %cmp, i32 1, i32 2
  ret i32 %out
alt:
  ret i32 0
}
)ir");
    Function *F = M->getFunction("stackdelta_fp");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(9211);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::stackDeltaGamesFunction(
        *F,
        {/*probability=*/100, /*max_blocks=*/4, /*min_bytes=*/17,
         /*max_extra_bytes=*/64, /*touches=*/3},
        rng));

    bool hasFpTerm = false;
    bool hasMix = false;
    bool hasFrame = false;
    for (Instruction &I : instructions(*F)) {
        if (auto *BC = dyn_cast<BitCastInst>(&I))
            hasFpTerm |= BC->getName().starts_with(
                             "morok.stackdelta.term.fp") &&
                         (BC->getSrcTy()->isFloatTy() ||
                          BC->getSrcTy()->isDoubleTy()) &&
                         BC->getDestTy()->isIntegerTy();
        hasMix |= I.getName().starts_with("morok.stackdelta.mix.term");
        if (auto *AI = dyn_cast<AllocaInst>(&I))
            hasFrame |= AI->getName().starts_with("morok.stackdelta.frame");
    }

    CHECK(hasFpTerm);
    CHECK(hasMix);
    CHECK(hasFrame);
    CHECK(countGlobals(*M, "morok.stackdelta.seed") == 1u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("stackDeltaGamesFunction honors zero probability") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @stackdelta_off(i32 %x) {
entry:
  %y = add i32 %x, 1
  ret i32 %y
}
)ir");
    Function *F = M->getFunction("stackdelta_off");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(67);
    morok::ir::IRRandom rng(engine);

    CHECK_FALSE(morok::passes::stackDeltaGamesFunction(
        *F,
        {/*probability=*/0, /*max_blocks=*/3, /*min_bytes=*/17,
         /*max_extra_bytes=*/32, /*touches=*/2},
        rng));
    CHECK(countGlobals(*M, "morok.stackdelta.seed") == 0u);
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

TEST_CASE("pointerLaunderFunction launders call and return pointer operands") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
target datalayout = "e-p:64:64"
declare void @sink(ptr)

define ptr @callret(ptr %p) {
entry:
  call void @sink(ptr %p)
  ret ptr %p
}
)ir");
    Function *F = M->getFunction("callret");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(36);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::pointerLaunderFunction(
        *F, {/*pointer_probability=*/100, /*integer_probability=*/0}, rng));

    CallInst *Call = nullptr;
    ReturnInst *Ret = nullptr;
    unsigned ptrToIntCount = 0;
    unsigned intToPtrCount = 0;
    for (Instruction &I : instructions(*F)) {
        ptrToIntCount += isa<PtrToIntInst>(&I);
        intToPtrCount += isa<IntToPtrInst>(&I);
        if (auto *CI = dyn_cast<CallInst>(&I))
            if (CI->getCalledFunction() &&
                CI->getCalledFunction()->getName() == "sink")
                Call = CI;
        if (auto *RI = dyn_cast<ReturnInst>(&I))
            Ret = RI;
    }

    REQUIRE(Call);
    REQUIRE(Ret);
    CHECK(Call->getArgOperand(0)->getName().starts_with("morok.ptr.gep"));
    CHECK(Ret->getReturnValue()->getName().starts_with("morok.ptr.gep"));
    CHECK(ptrToIntCount == 2u);
    CHECK(intToPtrCount == 2u);
    CHECK(countGlobals(*M, "morok.ptr.key") == 4u);
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

TEST_CASE("pointerLaunderFunction launders floating SSA through bit carriers") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define float @fp_launder(float %a, float %b) {
entry:
  %sum = fadd float %a, %b
  %prod = fmul float %sum, %a
  ret float %prod
}

define double @fp_launder_d(double %a, double %b) {
entry:
  %sum = fadd double %a, %b
  ret double %sum
}
)ir");
    Function *FloatF = M->getFunction("fp_launder");
    Function *DoubleF = M->getFunction("fp_launder_d");
    REQUIRE(FloatF);
    REQUIRE(DoubleF);

    auto engine = morok::core::Xoshiro256pp::fromSeed(371);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::pointerLaunderFunction(
        *FloatF, {/*pointer_probability=*/0, /*integer_probability=*/100},
        rng));
    CHECK(morok::passes::pointerLaunderFunction(
        *DoubleF, {/*pointer_probability=*/0, /*integer_probability=*/100},
        rng));

    bool hasFloatBits = false;
    bool hasFloatBack = false;
    bool hasFloatShuffle = false;
    for (Instruction &I : instructions(*FloatF)) {
        if (auto *cast = dyn_cast<BitCastInst>(&I)) {
            hasFloatBits |= I.getName().starts_with("morok.int.fpbits") &&
                            cast->getSrcTy()->isFloatTy() &&
                            cast->getDestTy()->isIntegerTy(32);
            hasFloatBack |= I.getName().starts_with("morok.int.fpvalue") &&
                            cast->getSrcTy()->isIntegerTy(32) &&
                            cast->getDestTy()->isFloatTy();
        }
        hasFloatShuffle |= isa<ShuffleVectorInst>(&I);
    }

    bool hasDoubleBits = false;
    bool hasDoubleBack = false;
    bool hasDoubleShuffle = false;
    for (Instruction &I : instructions(*DoubleF)) {
        if (auto *cast = dyn_cast<BitCastInst>(&I)) {
            hasDoubleBits |= I.getName().starts_with("morok.int.fpbits") &&
                             cast->getSrcTy()->isDoubleTy() &&
                             cast->getDestTy()->isIntegerTy(64);
            hasDoubleBack |= I.getName().starts_with("morok.int.fpvalue") &&
                             cast->getSrcTy()->isIntegerTy(64) &&
                             cast->getDestTy()->isDoubleTy();
        }
        hasDoubleShuffle |= isa<ShuffleVectorInst>(&I);
    }

    CHECK(hasFloatBits);
    CHECK(hasFloatBack);
    CHECK(hasFloatShuffle);
    CHECK(hasDoubleBits);
    CHECK(hasDoubleBack);
    CHECK(hasDoubleShuffle);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("pointerLaunderFunction launders sub-byte and odd-width integers") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i1 @ints_bool(i1 %a, i1 %b) {
entry:
  %x = xor i1 %a, %b
  ret i1 %x
}

define i12 @ints_i12(i12 %a, i12 %b) {
entry:
  %x = add i12 %a, %b
  ret i12 %x
}
)ir");
    Function *BoolF = M->getFunction("ints_bool");
    Function *I12F = M->getFunction("ints_i12");
    REQUIRE(BoolF);
    REQUIRE(I12F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(38);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::pointerLaunderFunction(
        *BoolF, {/*pointer_probability=*/0, /*integer_probability=*/100},
        rng));
    CHECK(morok::passes::pointerLaunderFunction(
        *I12F, {/*pointer_probability=*/0, /*integer_probability=*/100},
        rng));

    bool boolWide = false;
    bool boolTrunc = false;
    bool boolShuffle = false;
    for (Instruction &I : instructions(*BoolF)) {
        if (auto *ZExt = dyn_cast<ZExtInst>(&I))
            boolWide |= ZExt->getDestTy()->isIntegerTy(8) &&
                        I.getName().starts_with("morok.int.wide");
        if (auto *Trunc = dyn_cast<TruncInst>(&I))
            boolTrunc |= Trunc->getDestTy()->isIntegerTy(1) &&
                         I.getName().starts_with("morok.int.value");
        boolShuffle |= isa<ShuffleVectorInst>(&I);
    }
    CHECK(boolWide);
    CHECK(boolTrunc);
    CHECK(boolShuffle);

    bool i12Wide = false;
    bool i12Trunc = false;
    bool i12Shuffle = false;
    for (Instruction &I : instructions(*I12F)) {
        if (auto *ZExt = dyn_cast<ZExtInst>(&I))
            i12Wide |= ZExt->getDestTy()->isIntegerTy(16) &&
                       I.getName().starts_with("morok.int.wide");
        if (auto *Trunc = dyn_cast<TruncInst>(&I))
            i12Trunc |= Trunc->getDestTy()->isIntegerTy(12) &&
                        I.getName().starts_with("morok.int.value");
        i12Shuffle |= isa<ShuffleVectorInst>(&I);
    }
    CHECK(i12Wide);
    CHECK(i12Trunc);
    CHECK(i12Shuffle);
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

TEST_CASE("pointerLaunderFunction caps selected pointer operands") {
    LLVMContext ctx;
    auto M = std::make_unique<Module>("ptr-cap", ctx);
    Function *F = makePointerStoreFunction(*M, 100);
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(74);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::pointerLaunderFunction(
        *F, {/*pointer_probability=*/100, /*integer_probability=*/0}, rng));

    CHECK(countGlobals(*M, "morok.ptr.key") == 256u);
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
    CHECK(M->getGlobalVariable("morok.decoy.state", true) != nullptr);
    bool hasPredicate = false;
    bool hasDecoyBlock = false;
    bool hasDecoyReturn = false;
    bool hasAltArithmetic = false;
    bool hasVolatileLoad = false;
    bool hasHiddenStateStore = false;
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
            if (auto *SI = dyn_cast<StoreInst>(&I))
                hasHiddenStateStore |=
                    SI->isVolatile() &&
                    SI->getPointerOperand()->getName().starts_with(
                        "morok.decoy.state");
        }
    }
    CHECK(hasPredicate);
    CHECK(hasDecoyBlock);
    CHECK(hasDecoyReturn);
    CHECK(hasAltArithmetic);
    CHECK(hasVolatileLoad);
    CHECK(hasHiddenStateStore);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("coherentDecoysFunction handles sub-byte integer returns") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i1 @score_bool(i1 %a, i1 %b) {
entry:
  %x = xor i1 %a, %b
  ret i1 %x
}

define i4 @score_nibble(i4 %a, i4 %b) {
entry:
  %x = add i4 %a, %b
  %y = xor i4 %x, 7
  ret i4 %y
}
)ir");
    Function *BoolF = M->getFunction("score_bool");
    Function *NibbleF = M->getFunction("score_nibble");
    REQUIRE(BoolF);
    REQUIRE(NibbleF);
    auto engine = morok::core::Xoshiro256pp::fromSeed(1311);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::coherentDecoysFunction(
        *BoolF, {/*probability=*/100, /*max_blocks=*/4, /*depth=*/4}, rng));
    CHECK(morok::passes::coherentDecoysFunction(
        *NibbleF, {/*probability=*/100, /*max_blocks=*/4, /*depth=*/4}, rng));

    CHECK(M->getGlobalVariable("morok.decoy.opaque", true) != nullptr);
    bool hasI1Alt = false;
    bool hasI4Alt = false;
    for (BasicBlock &BB : *BoolF)
        if (BB.getName().starts_with("morok.decoy.alt"))
            if (auto *RI = dyn_cast<ReturnInst>(BB.getTerminator()))
                hasI1Alt |= RI->getReturnValue()->getType()->isIntegerTy(1);
    for (BasicBlock &BB : *NibbleF)
        if (BB.getName().starts_with("morok.decoy.alt"))
            if (auto *RI = dyn_cast<ReturnInst>(BB.getTerminator()))
                hasI4Alt |= RI->getReturnValue()->getType()->isIntegerTy(4);
    CHECK(hasI1Alt);
    CHECK(hasI4Alt);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("coherentDecoysFunction mixes floating terms into integer returns") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @score_mixed(float %a, double %b, i32 %salt) {
entry:
  %b32 = fptrunc double %b to float
  %sum = fadd float %a, %b32
  %bits = bitcast float %sum to i32
  %out = xor i32 %bits, %salt
  ret i32 %out
}
)ir");
    Function *F = M->getFunction("score_mixed");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(1313);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::coherentDecoysFunction(
        *F, {/*probability=*/100, /*max_blocks=*/4, /*depth=*/16}, rng));

    bool hasFloatBits = false;
    bool hasDoubleBits = false;
    bool hasIntAlt = false;
    for (BasicBlock &BB : *F) {
        if (!BB.getName().starts_with("morok.decoy.alt"))
            continue;
        if (auto *RI = dyn_cast<ReturnInst>(BB.getTerminator()))
            hasIntAlt |= RI->getReturnValue()->getType()->isIntegerTy(32);
        for (Instruction &I : BB) {
            if (auto *BC = dyn_cast<BitCastInst>(&I)) {
                hasFloatBits |= BC->getName().starts_with(
                                    "morok.decoy.alt.fpbits") &&
                                BC->getSrcTy()->isFloatTy() &&
                                BC->getDestTy()->isIntegerTy(32);
                hasDoubleBits |= BC->getName().starts_with(
                                     "morok.decoy.alt.fpbits") &&
                                 BC->getSrcTy()->isDoubleTy() &&
                                 BC->getDestTy()->isIntegerTy(64);
            }
        }
    }

    CHECK(hasFloatBits);
    CHECK(hasDoubleBits);
    CHECK(hasIntAlt);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("coherentDecoysFunction adds floating scalar return alternatives") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define float @score_float(float %a, float %b, i32 %n) {
entry:
  %i = sitofp i32 %n to float
  %x = fadd float %a, %b
  %y = fmul float %x, %i
  ret float %y
}

define double @score_double(double %a, double %b, i64 %n) {
entry:
  %i = sitofp i64 %n to double
  %x = fsub double %a, %b
  %y = fmul double %x, %i
  ret double %y
}
)ir");
    Function *FloatF = M->getFunction("score_float");
    Function *DoubleF = M->getFunction("score_double");
    REQUIRE(FloatF);
    REQUIRE(DoubleF);
    auto engine = morok::core::Xoshiro256pp::fromSeed(1312);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::coherentDecoysFunction(
        *FloatF, {/*probability=*/100, /*max_blocks=*/4, /*depth=*/8}, rng));
    CHECK(morok::passes::coherentDecoysFunction(
        *DoubleF, {/*probability=*/100, /*max_blocks=*/4, /*depth=*/8}, rng));

    bool hasFloatAlt = false;
    bool hasDoubleAlt = false;
    bool hasFpAltArithmetic = false;
    for (BasicBlock &BB : *FloatF) {
        if (!BB.getName().starts_with("morok.decoy.alt"))
            continue;
        if (auto *RI = dyn_cast<ReturnInst>(BB.getTerminator()))
            hasFloatAlt |= RI->getReturnValue()->getType()->isFloatTy();
        for (Instruction &I : BB)
            hasFpAltArithmetic |= I.getName().starts_with("morok.decoy.alt") &&
                                  I.getType()->isFloatingPointTy();
    }
    for (BasicBlock &BB : *DoubleF) {
        if (!BB.getName().starts_with("morok.decoy.alt"))
            continue;
        if (auto *RI = dyn_cast<ReturnInst>(BB.getTerminator()))
            hasDoubleAlt |= RI->getReturnValue()->getType()->isDoubleTy();
        for (Instruction &I : BB)
            hasFpAltArithmetic |= I.getName().starts_with("morok.decoy.alt") &&
                                  I.getType()->isFloatingPointTy();
    }

    CHECK(hasFloatAlt);
    CHECK(hasDoubleAlt);
    CHECK(hasFpAltArithmetic);
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

TEST_CASE("typePunFunction handles sub-byte and odd-width integer scalars") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i1 @pun_i1(i1 %a, i1 %b) {
entry:
  %x = xor i1 %a, %b
  ret i1 %x
}

define i12 @pun_i12(i12 %a, i12 %b) {
entry:
  %x = add i12 %a, %b
  ret i12 %x
}
)ir");
    Function *BoolF = M->getFunction("pun_i1");
    Function *I12F = M->getFunction("pun_i12");
    REQUIRE(BoolF);
    REQUIRE(I12F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(45);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::typePunFunction(*BoolF,
                                         {/*probability=*/100,
                                          /*include_floating=*/true,
                                          /*max_targets=*/64},
                                         rng));
    CHECK(morok::passes::typePunFunction(*I12F,
                                         {/*probability=*/100,
                                          /*include_floating=*/true,
                                          /*max_targets=*/64},
                                         rng));

    CHECK(countNamedAllocas(*BoolF, "morok.pun") >= 1);
    CHECK(countNamedAllocas(*I12F, "morok.pun") >= 1);
    bool hasI1Widen = false;
    bool hasI1Trunc = false;
    bool hasI12Widen = false;
    bool hasI12Trunc = false;
    for (Instruction &I : instructions(*BoolF)) {
        hasI1Widen |= I.getName().starts_with("morok.pun.widen") &&
                      I.getType()->isIntegerTy(8);
        hasI1Trunc |= I.getName().starts_with("morok.pun.value") &&
                      I.getType()->isIntegerTy(1);
    }
    for (Instruction &I : instructions(*I12F)) {
        hasI12Widen |= I.getName().starts_with("morok.pun.widen") &&
                       I.getType()->isIntegerTy(16);
        hasI12Trunc |= I.getName().starts_with("morok.pun.value") &&
                       I.getType()->isIntegerTy(12);
    }
    CHECK(hasI1Widen);
    CHECK(hasI1Trunc);
    CHECK(hasI12Widen);
    CHECK(hasI12Trunc);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("typePunFunction round-trips PHI values after the PHI cluster") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
target datalayout = "e-p:64:64"
define i32 @pun_phi(i1 %flag, i32 %a, i32 %b) {
entry:
  br i1 %flag, label %join, label %right
right:
  br label %join
join:
  %x = phi i32 [ %a, %entry ], [ %b, %right ]
  ret i32 %x
}
)ir");
    Function *F = M->getFunction("pun_phi");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(46);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::typePunFunction(*F,
                                         {/*probability=*/100,
                                          /*include_floating=*/true,
                                          /*max_targets=*/1},
                                         rng));

    CHECK(countNamedAllocas(*F, "morok.pun") == 1);
    PHINode *Phi = nullptr;
    bool hasVolatileStore = false;
    bool hasVolatileVectorLoad = false;
    bool retUsesPunnedValue = false;
    for (Instruction &I : instructions(*F)) {
        if (auto *PN = dyn_cast<PHINode>(&I))
            Phi = PN;
        if (auto *SI = dyn_cast<StoreInst>(&I))
            hasVolatileStore |= SI->isVolatile();
        if (auto *LI = dyn_cast<LoadInst>(&I))
            hasVolatileVectorLoad |=
                LI->isVolatile() && LI->getType()->isVectorTy();
        if (auto *RI = dyn_cast<ReturnInst>(&I))
            retUsesPunnedValue =
                RI->getReturnValue()->getName().starts_with("morok.pun.value");
    }
    REQUIRE(Phi);
    CHECK(Phi->getNextNode() != nullptr);
    CHECK(!isa<PHINode>(Phi->getNextNode()));
    CHECK(hasVolatileStore);
    CHECK(hasVolatileVectorLoad);
    CHECK(retUsesPunnedValue);
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

TEST_CASE("phiTangleFunction handles sub-byte integer phis") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i1 @join_bool(i1 %a, i1 %b, i1 %c) {
entry:
  br i1 %c, label %left, label %right
left:
  br label %merge
right:
  br label %merge
merge:
  %p = phi i1 [ %a, %left ], [ %b, %right ]
  %out = xor i1 %p, true
  ret i1 %out
}

define i4 @join_nibble(i4 %a, i4 %b, i1 %c) {
entry:
  br i1 %c, label %left, label %right
left:
  %l = add i4 %a, 3
  br label %merge
right:
  %r = sub i4 %b, 5
  br label %merge
merge:
  %p = phi i4 [ %l, %left ], [ %r, %right ]
  %out = xor i4 %p, 9
  ret i4 %out
}
)ir");
    Function *BoolF = M->getFunction("join_bool");
    Function *NibbleF = M->getFunction("join_nibble");
    REQUIRE(BoolF);
    REQUIRE(NibbleF);
    const std::size_t before = countPhis(*BoolF) + countPhis(*NibbleF);

    auto engine = morok::core::Xoshiro256pp::fromSeed(491);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::phiTangleFunction(
        *BoolF, {/*probability=*/100, /*layers=*/1, /*max_phis=*/8}, rng));
    CHECK(morok::passes::phiTangleFunction(
        *NibbleF, {/*probability=*/100, /*layers=*/1, /*max_phis=*/8}, rng));

    CHECK(countPhis(*BoolF) + countPhis(*NibbleF) >= before + 4);
    bool hasI1Tangle = false;
    bool hasI4Tangle = false;
    for (Instruction &I : instructions(*BoolF))
        hasI1Tangle |= I.getName().starts_with("morok.phi.value") &&
                       I.getType()->isIntegerTy(1);
    for (Instruction &I : instructions(*NibbleF))
        hasI4Tangle |= I.getName().starts_with("morok.phi.value") &&
                       I.getType()->isIntegerTy(4);
    CHECK(hasI1Tangle);
    CHECK(hasI4Tangle);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("phiTangleFunction handles floating phis through bit carriers") {
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
    CHECK(morok::passes::phiTangleFunction(
        *F, {/*probability=*/100, /*layers=*/1, /*max_phis=*/8}, rng));
    CHECK(countPhis(*F) >= before + 2);

    bool hasFpValue = false;
    bool hasBitCarrier = false;
    bool retUsesTangle = false;
    for (Instruction &I : instructions(*F)) {
        hasFpValue |= I.getName().starts_with("morok.phi.value") &&
                      I.getType()->isDoubleTy();
        if (auto *BC = dyn_cast<BitCastInst>(&I))
            hasBitCarrier |=
                BC->getName().starts_with("morok.phi") &&
                ((BC->getSrcTy()->isDoubleTy() &&
                  BC->getDestTy()->isIntegerTy(64)) ||
                 (BC->getSrcTy()->isIntegerTy(64) &&
                  BC->getDestTy()->isDoubleTy()));
        if (auto *RI = dyn_cast<ReturnInst>(&I))
            retUsesTangle =
                RI->getReturnValue()->getName().starts_with("morok.phi.value");
    }

    CHECK(hasFpValue);
    CHECK(hasBitCarrier);
    CHECK(retUsesTangle);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("phiTangleFunction skips unsupported pointer phis") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define ptr @join_ptr(ptr %a, ptr %b, i1 %c) {
entry:
  br i1 %c, label %left, label %right
left:
  br label %merge
right:
  br label %merge
merge:
  %p = phi ptr [ %a, %left ], [ %b, %right ]
  ret ptr %p
}
)ir");
    Function *F = M->getFunction("join_ptr");
    REQUIRE(F);
    const std::size_t before = countPhis(*F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(511);
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
                        branchesToDecoy |=
                            BI->getSuccessor(Succ)->getName().starts_with(
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
    morok::passes::CsmParams params;
    params.generator = morok::passes::CsmGenerator::Logistic;
    CHECK(morok::passes::chaosStateMachineFunction(*F, params, rng));
    bool hasSwitch = false;
    bool hasLogisticShift = false;
    for (Instruction &I : instructions(*F))
        if (isa<SwitchInst>(&I)) {
            hasSwitch = true;
        } else if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
            if (BO->getOpcode() == Instruction::LShr &&
                isa<ConstantInt>(BO->getOperand(1)) &&
                cast<ConstantInt>(BO->getOperand(1))->getZExtValue() == 30u)
                hasLogisticShift = true;
        }
    CHECK(hasSwitch);
    CHECK(hasLogisticShift);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("chaosStateMachineFunction can use a single-cycle T-function") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @branchy_tf(i32 %a, i32 %b) {
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
    Function *F = M->getFunction("branchy_tf");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(20);
    morok::ir::IRRandom rng(engine);
    morok::passes::CsmParams params;
    params.generator = morok::passes::CsmGenerator::TFunction;
    params.tf_const = 5;
    CHECK(morok::passes::chaosStateMachineFunction(*F, params, rng));

    bool hasSwitch = false;
    bool hasTfMul = false;
    bool hasTfOr = false;
    bool hasTfAdd = false;
    bool hasLogisticShift = false;
    for (Instruction &I : instructions(*F)) {
        hasSwitch |= isa<SwitchInst>(&I);
        hasTfMul |= I.getName().starts_with("csm.tf.mul");
        hasTfOr |= I.getName().starts_with("csm.tf.or");
        hasTfAdd |= I.getName().starts_with("csm.tf.next");
        if (auto *BO = dyn_cast<BinaryOperator>(&I))
            if (BO->getOpcode() == Instruction::LShr &&
                isa<ConstantInt>(BO->getOperand(1)) &&
                cast<ConstantInt>(BO->getOperand(1))->getZExtValue() == 30u)
                hasLogisticShift = true;
    }
    CHECK(hasSwitch);
    CHECK(hasTfMul);
    CHECK(hasTfOr);
    CHECK(hasTfAdd);
    CHECK_FALSE(hasLogisticShift);
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
    bool hasTermZExt = false;
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
        if (I.getName().starts_with("entfla.term.zext"))
            hasTermZExt = true;
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
    CHECK(hasTermZExt);
    CHECK(hasNext);
    CHECK(volatileAccesses >= 4u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("dataEntangledFlattenFunction mixes floating live terms") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @entangled_fp(float %a, double %b, i1 %flag) {
entry:
  br i1 %flag, label %left, label %right
left:
  %b32 = fptrunc double %b to float
  %sum = fadd float %a, %b32
  %cmp = fcmp ogt float %sum, %a
  br i1 %cmp, label %done, label %right
right:
  ret i32 0
done:
  ret i32 1
}
)ir");
    Function *F = M->getFunction("entangled_fp");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(711);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::dataEntangledFlattenFunction(*F, {/*max_terms=*/8},
                                                      rng));

    bool hasFpTerm = false;
    bool hasTokenMix = false;
    for (Instruction &I : instructions(*F)) {
        if (auto *BC = dyn_cast<BitCastInst>(&I))
            hasFpTerm |= BC->getName().starts_with("entfla.term.fp") &&
                         (BC->getSrcTy()->isFloatTy() ||
                          BC->getSrcTy()->isDoubleTy()) &&
                         BC->getDestTy()->isIntegerTy();
        hasTokenMix |= I.getName().starts_with("entfla.token.mix");
    }

    CHECK(hasFpTerm);
    CHECK(hasTokenMix);
    CHECK(countNamedAllocas(*F, "entfla.shadow") == 1u);
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
    bool hasTermZExt = false;
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
        if (I.getName().starts_with("nistate.term.zext"))
            hasTermZExt = true;
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
    CHECK(hasTermZExt);
    CHECK(hasHashInput);
    CHECK(hasLossyHash);
    CHECK(hasNextStore);
    CHECK_FALSE(switchCases.empty());
    CHECK_FALSE(rawTargets.empty());
    CHECK_FALSE(rawStateLeakedAsCase);
    CHECK(volatileAccesses >= 4u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("nonInvertibleStateFunction mixes floating live terms") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @noninv_fp(float %a, double %b, i1 %flag) {
entry:
  br i1 %flag, label %left, label %right
left:
  %b32 = fptrunc double %b to float
  %sum = fadd float %a, %b32
  %cmp = fcmp ole float %sum, %a
  br i1 %cmp, label %done, label %right
right:
  ret i32 0
done:
  ret i32 1
}
)ir");
    Function *F = M->getFunction("noninv_fp");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(1111);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::nonInvertibleStateFunction(
        *F, {/*max_terms=*/8, /*rounds=*/3}, rng));

    bool hasFpTerm = false;
    bool hasTokenMix = false;
    bool hasHashInput = false;
    for (Instruction &I : instructions(*F)) {
        if (auto *BC = dyn_cast<BitCastInst>(&I))
            hasFpTerm |= BC->getName().starts_with("nistate.term.fp") &&
                         (BC->getSrcTy()->isFloatTy() ||
                          BC->getSrcTy()->isDoubleTy()) &&
                         BC->getDestTy()->isIntegerTy();
        hasTokenMix |= I.getName().starts_with("nistate.token.mix");
        hasHashInput |= I.getName().starts_with("nistate.hash.input");
    }

    CHECK(hasFpTerm);
    CHECK(hasTokenMix);
    CHECK(hasHashInput);
    CHECK(countNamedAllocas(*F, "nistate.shadow") == 1u);
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

TEST_CASE(
    "stateOpaquePredicatesFunction guards flattened blocks with MBA state") {
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

TEST_CASE("stateOpaquePredicatesFunction mixes floating live terms") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @stateful_fp(float %a, double %b, i1 %flag) {
entry:
  %fla.state = alloca i32, align 4
  store i32 7, ptr %fla.state, align 4
  br i1 %flag, label %body, label %alt
body:
  %b32 = fptrunc double %b to float
  %sum = fadd float %a, %b32
  %cmp = fcmp ogt float %sum, %a
  %out = select i1 %cmp, i32 1, i32 2
  ret i32 %out
alt:
  ret i32 0
}
)ir");
    Function *F = M->getFunction("stateful_fp");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(1411);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::stateOpaquePredicatesFunction(
        *F, {/*probability=*/100, /*max_blocks=*/4, /*max_terms=*/4}, rng));

    bool hasFpTerm = false;
    bool hasTokenMix = false;
    bool hasPredicate = false;
    for (Instruction &I : instructions(*F)) {
        if (auto *BC = dyn_cast<BitCastInst>(&I))
            hasFpTerm |= BC->getName().starts_with("morok.stateop.term.fp") &&
                         (BC->getSrcTy()->isFloatTy() ||
                          BC->getSrcTy()->isDoubleTy()) &&
                         BC->getDestTy()->isIntegerTy();
        hasTokenMix |= I.getName().starts_with("morok.stateop.token.mix");
        hasPredicate |= I.getName().starts_with("morok.stateop.pred");
    }

    CHECK(hasFpTerm);
    CHECK(hasTokenMix);
    CHECK(hasPredicate);
    CHECK(countNamedAllocas(*F, "morok.stateop.shadow") == 1u);
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

TEST_CASE("interproceduralFsmSplitModule mixes floating live terms") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @ifsm_fp(float %a, double %b, i1 %flag) {
entry:
  %fla.state = alloca i32, align 4
  store i32 0, ptr %fla.state, align 4
  br i1 %flag, label %body, label %done
body:
  %b32 = fptrunc double %b to float
  %sum = fadd float %a, %b32
  %cmp = fcmp ogt float %sum, %a
  %next = select i1 %cmp, i32 11, i32 13
  store i32 %next, ptr %fla.state, align 4
  br label %done
done:
  %cur = load i32, ptr %fla.state, align 4
  ret i32 %cur
}
)ir");
    Function *F = M->getFunction("ifsm_fp");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(1211);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::interproceduralFsmSplitModule(
        *M, {/*probability=*/100, /*max_sites=*/4, /*max_terms=*/8}, rng));

    bool hasFpTerm = false;
    bool hasTokenMix = false;
    bool hasWrappedStore = false;
    for (Instruction &I : instructions(*F)) {
        if (auto *BC = dyn_cast<BitCastInst>(&I))
            hasFpTerm |= BC->getName().starts_with("morok.ifsm.term.fp") &&
                         (BC->getSrcTy()->isFloatTy() ||
                          BC->getSrcTy()->isDoubleTy()) &&
                         BC->getDestTy()->isIntegerTy();
        hasTokenMix |= I.getName().starts_with("morok.ifsm.token.mix");
        if (auto *SI = dyn_cast<StoreInst>(&I)) {
            auto *CI = dyn_cast<CallInst>(SI->getValueOperand());
            hasWrappedStore |=
                CI && CI->getCalledFunction() &&
                CI->getCalledFunction()->getName().starts_with("morok.ifsm.");
        }
    }

    CHECK(hasFpTerm);
    CHECK(hasTokenMix);
    CHECK(hasWrappedStore);
    CHECK(M->getFunction("morok.ifsm.step.a") != nullptr);
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
        *F,
        {/*probability=*/100, /*width=*/128, /*shuffle=*/true,
         /*lift_comparisons=*/true},
        rng));
    bool hasVectorOp = false;
    bool hasFourLaneVector = false;
    bool hasShuffle = false;
    bool hasVectorCompare = false;
    bool hasVectorSelect = false;
    for (Instruction &I : instructions(*F)) {
        if (I.getType()->isVectorTy())
            hasVectorOp = true;
        if (auto *VT = dyn_cast<FixedVectorType>(I.getType()))
            hasFourLaneVector |= VT->getNumElements() == 4u;
        hasShuffle |= isa<ShuffleVectorInst>(&I);
        if (auto *Cmp = dyn_cast<ICmpInst>(&I))
            hasVectorCompare |= Cmp->getType()->isVectorTy();
        if (auto *Sel = dyn_cast<SelectInst>(&I))
            hasVectorSelect |= Sel->getType()->isVectorTy();
    }
    CHECK(hasVectorOp);
    CHECK(hasFourLaneVector);
    CHECK(hasShuffle);
    CHECK(hasVectorCompare);
    CHECK(hasVectorSelect);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("vectorObfuscateFunction lifts floating ops, compares, and selects") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define float @vecfloat(float %a, float %b) {
entry:
  %sum = fadd float %a, %b
  %mix = fmul float %sum, %b
  %cmp = fcmp olt float %mix, %a
  %sel = select i1 %cmp, float %mix, float %b
  ret float %sel
}
)ir");
    Function *F = M->getFunction("vecfloat");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(2121);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::vectorObfuscateFunction(
        *F,
        {/*probability=*/100, /*width=*/128, /*shuffle=*/true,
         /*lift_comparisons=*/true},
        rng));

    bool hasFloatVector = false;
    bool hasVectorFAddOrFMul = false;
    bool hasVectorFCmp = false;
    bool hasVectorSelect = false;
    bool hasShuffle = false;
    for (Instruction &I : instructions(*F)) {
        if (auto *VT = dyn_cast<FixedVectorType>(I.getType()))
            hasFloatVector |= VT->getElementType()->isFloatTy() &&
                              VT->getNumElements() == 4u;
        if (auto *BO = dyn_cast<BinaryOperator>(&I))
            hasVectorFAddOrFMul |=
                (BO->getOpcode() == Instruction::FAdd ||
                 BO->getOpcode() == Instruction::FMul) &&
                BO->getType()->isVectorTy();
        if (auto *Cmp = dyn_cast<FCmpInst>(&I))
            hasVectorFCmp |= Cmp->getType()->isVectorTy();
        if (auto *Sel = dyn_cast<SelectInst>(&I))
            hasVectorSelect |= Sel->getType()->isVectorTy();
        hasShuffle |= isa<ShuffleVectorInst>(&I);
    }
    CHECK(hasFloatVector);
    CHECK(hasVectorFAddOrFMul);
    CHECK(hasVectorFCmp);
    CHECK(hasVectorSelect);
    CHECK(hasShuffle);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("vectorObfuscateFunction lifts fast-math floating ops and compares") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define float @vecfast(float %a, float %b) {
entry:
  %sum = fadd fast float %a, %b
  %mul = fmul nnan ninf float %sum, %b
  %cmp = fcmp nnan olt float %mul, %a
  %sel = select i1 %cmp, float %mul, float %b
  ret float %sel
}
)ir");
    Function *F = M->getFunction("vecfast");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(2122);
    morok::ir::IRRandom rng(engine);
    // Fast-math FP ops/compares used to be skipped (liftable returned false);
    // they must now lift and carry their fast-math flags onto the vector op.
    CHECK(morok::passes::vectorObfuscateFunction(
        *F,
        {/*probability=*/100, /*width=*/128, /*shuffle=*/false,
         /*lift_comparisons=*/true},
        rng));

    bool hasFastVectorFP = false;
    bool hasFastVectorFCmp = false;
    for (Instruction &I : instructions(*F)) {
        if (auto *BO = dyn_cast<BinaryOperator>(&I))
            if (BO->getType()->isVectorTy() &&
                (BO->getOpcode() == Instruction::FAdd ||
                 BO->getOpcode() == Instruction::FMul))
                hasFastVectorFP |= BO->getFastMathFlags().any();
        if (auto *Cmp = dyn_cast<FCmpInst>(&I))
            if (Cmp->getType()->isVectorTy())
                hasFastVectorFCmp |= Cmp->getFastMathFlags().any();
    }
    CHECK(hasFastVectorFP);
    CHECK(hasFastVectorFCmp);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("vectorObfuscateFunction lifts scalar casts") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i64 @veccasts(i32 %a, float %f) {
entry:
  %wide = zext i32 %a to i64
  %narrow = trunc i64 %wide to i16
  %double = fpext float %f to double
  %bits = bitcast double %double to i64
  %narrow64 = zext i16 %narrow to i64
  %out = xor i64 %bits, %narrow64
  ret i64 %out
}
)ir");
    Function *F = M->getFunction("veccasts");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(2122);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::vectorObfuscateFunction(
        *F,
        {/*probability=*/100, /*width=*/128, /*shuffle=*/true,
         /*lift_comparisons=*/true},
        rng));

    bool hasVectorZExt = false;
    bool hasVectorTrunc = false;
    bool hasVectorFPExt = false;
    bool hasVectorBitCast = false;
    bool hasCastExtract = false;
    for (Instruction &I : instructions(*F)) {
        auto *Cast = dyn_cast<CastInst>(&I);
        if (!Cast)
            continue;
        const bool vectorCast =
            Cast->getSrcTy()->isVectorTy() && Cast->getDestTy()->isVectorTy();
        hasVectorZExt |= vectorCast && Cast->getOpcode() == Instruction::ZExt;
        hasVectorTrunc |= vectorCast && Cast->getOpcode() == Instruction::Trunc;
        hasVectorFPExt |= vectorCast && Cast->getOpcode() == Instruction::FPExt;
        hasVectorBitCast |=
            vectorCast && Cast->getOpcode() == Instruction::BitCast;
    }
    for (Instruction &I : instructions(*F))
        if (auto *Extract = dyn_cast<ExtractElementInst>(&I))
            hasCastExtract |=
                Extract->getName().starts_with("morok.vec.cast.value");

    CHECK(hasVectorZExt);
    CHECK(hasVectorTrunc);
    CHECK(hasVectorFPExt);
    CHECK(hasVectorBitCast);
    CHECK(hasCastExtract);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("vectorObfuscateFunction lifts sub-byte and odd-width selects") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i1 @vec_bool(i1 %a, i1 %b, i1 %c) {
entry:
  %x = xor i1 %a, %b
  %s = select i1 %c, i1 %x, i1 %a
  ret i1 %s
}

define i12 @vec_i12(i12 %a, i12 %b) {
entry:
  %sum = add i12 %a, %b
  %cmp = icmp ult i12 %sum, %a
  %s = select i1 %cmp, i12 %sum, i12 %b
  ret i12 %s
}
)ir");
    Function *BoolF = M->getFunction("vec_bool");
    Function *I12F = M->getFunction("vec_i12");
    REQUIRE(BoolF);
    REQUIRE(I12F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(2112);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::vectorObfuscateFunction(
        *BoolF,
        {/*probability=*/100, /*width=*/128, /*shuffle=*/true,
         /*lift_comparisons=*/true},
        rng));
    CHECK(morok::passes::vectorObfuscateFunction(
        *I12F,
        {/*probability=*/100, /*width=*/128, /*shuffle=*/true,
         /*lift_comparisons=*/true},
        rng));

    bool hasI1Vector = false;
    bool hasI1Select = false;
    for (Instruction &I : instructions(*BoolF)) {
        if (auto *VT = dyn_cast<FixedVectorType>(I.getType()))
            hasI1Vector |= VT->getElementType()->isIntegerTy(1) &&
                           VT->getNumElements() >= 2u;
        if (auto *Sel = dyn_cast<SelectInst>(&I))
            hasI1Select |= Sel->getType()->isVectorTy();
    }
    CHECK(hasI1Vector);
    CHECK(hasI1Select);

    bool hasI12Vector = false;
    bool hasI12Compare = false;
    bool hasI12Select = false;
    for (Instruction &I : instructions(*I12F)) {
        if (auto *VT = dyn_cast<FixedVectorType>(I.getType()))
            hasI12Vector |= VT->getElementType()->isIntegerTy(12) &&
                            VT->getNumElements() >= 2u;
        if (auto *Cmp = dyn_cast<ICmpInst>(&I))
            hasI12Compare |= Cmp->getType()->isVectorTy();
        if (auto *Sel = dyn_cast<SelectInst>(&I))
            hasI12Select |= Sel->getType()->isVectorTy();
    }
    CHECK(hasI12Vector);
    CHECK(hasI12Compare);
    CHECK(hasI12Select);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("vectorObfuscateFunction caps selected operators") {
    LLVMContext ctx;
    auto M = std::make_unique<Module>("vec-cap", ctx);
    Function *F = makeLargeLinearFunction(*M, 200);
    REQUIRE(F);
    CHECK(countNamedInstructions(*F, "step") == 200u);

    auto engine = morok::core::Xoshiro256pp::fromSeed(75);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::vectorObfuscateFunction(
        *F,
        {/*probability=*/100, /*width=*/128, /*shuffle=*/false,
         /*lift_comparisons=*/false},
        rng));

    CHECK(countNamedInstructions(*F, "step") == 72u);
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

TEST_CASE(
    "tableArithmeticFunction lowers sub-byte ops to encrypted lookup tables") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i1 @bool_ops(i1 %a, i1 %b) {
entry:
  %x = xor i1 %a, %b
  ret i1 %x
}

define i4 @nibble_ops(i4 %a, i4 %b) {
entry:
  %x = add i4 %a, %b
  %y = and i4 %x, 13
  ret i4 %y
}
)ir");
    Function *BoolF = M->getFunction("bool_ops");
    Function *NibbleF = M->getFunction("nibble_ops");
    REQUIRE(BoolF);
    REQUIRE(NibbleF);
    auto engine = morok::core::Xoshiro256pp::fromSeed(811);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::tableArithmeticFunction(
        *BoolF, {/*probability=*/100, /*max_tables=*/1}, rng));
    CHECK(morok::passes::tableArithmeticFunction(
        *NibbleF, {/*probability=*/100, /*max_tables=*/2}, rng));

    CHECK(countGlobals(*M, "morok.tablearith.table") == 3u);
    CHECK(M->getFunction("morok.tablearith.ensure") != nullptr);
    CHECK_FALSE(hasPlainNarrowArithmetic(*BoolF));
    CHECK_FALSE(hasPlainNarrowArithmetic(*NibbleF));
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("tableArithmeticFunction lowers narrow comparisons to tables") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i1 @cmp8(i8 %a, i8 %b) {
entry:
  %x = icmp slt i8 %a, %b
  ret i1 %x
}

define i1 @cmp1(i1 %a, i1 %b) {
entry:
  %x = icmp uge i1 %a, %b
  ret i1 %x
}
)ir");
    Function *Cmp8 = M->getFunction("cmp8");
    Function *Cmp1 = M->getFunction("cmp1");
    REQUIRE(Cmp8);
    REQUIRE(Cmp1);
    auto engine = morok::core::Xoshiro256pp::fromSeed(812);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::tableArithmeticFunction(
        *Cmp8, {/*probability=*/100, /*max_tables=*/1}, rng));
    CHECK(morok::passes::tableArithmeticFunction(
        *Cmp1, {/*probability=*/100, /*max_tables=*/1}, rng));

    CHECK(countGlobals(*M, "morok.tablearith.table") == 2u);
    CHECK_FALSE(hasPlainNarrowICmp(*Cmp8));
    CHECK_FALSE(hasPlainNarrowICmp(*Cmp1));
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("tableArithmeticFunction lowers const-indexed i16 ops to tables") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i16 @wide_const_tables(i16 %a) {
entry:
  %x = add i16 %a, 4660
  %y = xor i16 21930, %x
  %z = ashr i16 %y, 3
  %c = icmp slt i16 %z, -17
  %out = select i1 %c, i16 %z, i16 %x
  ret i16 %out
}
)ir");
    Function *F = M->getFunction("wide_const_tables");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(8121);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::tableArithmeticFunction(
        *F, {/*probability=*/100, /*max_tables=*/4}, rng));

    CHECK(countGlobals(*M, "morok.tablearith.table") == 4u);
    bool hasI16Table = false;
    for (GlobalVariable &GV : M->globals()) {
        if (!GV.getName().starts_with("morok.tablearith.table"))
            continue;
        auto *ArrTy = dyn_cast<ArrayType>(GV.getValueType());
        hasI16Table |=
            ArrTy && ArrTy->getElementType()->isIntegerTy(16);
    }
    CHECK(hasI16Table);

    bool hasPlainWideOp = false;
    for (Instruction &I : instructions(*F)) {
        if (I.getName().starts_with("morok."))
            continue;
        if (auto *BO = dyn_cast<BinaryOperator>(&I))
            hasPlainWideOp |= BO->getType()->isIntegerTy(16);
        if (auto *CI = dyn_cast<ICmpInst>(&I)) {
            auto *Ty = dyn_cast<IntegerType>(CI->getOperand(0)->getType());
            hasPlainWideOp |= Ty && Ty->getBitWidth() == 16;
        }
    }
    CHECK_FALSE(hasPlainWideOp);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("tableArithmeticFunction lowers constant narrow shifts to tables") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i8 @shift8(i8 %a) {
entry:
  %x = shl i8 %a, 3
  %y = lshr i8 %x, 1
  %z = ashr i8 %y, 2
  ret i8 %z
}

define i4 @shift4(i4 %a) {
entry:
  %x = ashr i4 %a, 1
  ret i4 %x
}
)ir");
    Function *Shift8 = M->getFunction("shift8");
    Function *Shift4 = M->getFunction("shift4");
    REQUIRE(Shift8);
    REQUIRE(Shift4);
    auto engine = morok::core::Xoshiro256pp::fromSeed(813);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::tableArithmeticFunction(
        *Shift8, {/*probability=*/100, /*max_tables=*/3}, rng));
    CHECK(morok::passes::tableArithmeticFunction(
        *Shift4, {/*probability=*/100, /*max_tables=*/1}, rng));

    CHECK(countGlobals(*M, "morok.tablearith.table") == 4u);
    CHECK_FALSE(hasPlainNarrowShift(*Shift8));
    CHECK_FALSE(hasPlainNarrowShift(*Shift4));
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("tableArithmeticFunction skips unsafe narrow shifts") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i8 @bad_shifts(i8 %a, i8 %s) {
entry:
  %var = shl i8 %a, %s
  %wide = lshr i8 %var, 8
  %exact = ashr exact i8 %wide, 1
  %flagged = shl nuw i8 %exact, 1
  ret i8 %flagged
}
)ir");
    Function *F = M->getFunction("bad_shifts");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(814);
    morok::ir::IRRandom rng(engine);

    CHECK_FALSE(morok::passes::tableArithmeticFunction(
        *F, {/*probability=*/100, /*max_tables=*/8}, rng));
    CHECK(hasPlainNarrowShift(*F));
    CHECK(countGlobals(*M, "morok.tablearith.table") == 0u);
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

TEST_CASE("tableArithmeticFunction skips wide arithmetic") {
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

TEST_CASE("tableArithmeticFunction caps selected table count") {
    LLVMContext ctx;
    auto M = std::make_unique<Module>("table-cap", ctx);
    Function *F = makeI8OpChain(*M, 64, "many_bytes");

    auto engine = morok::core::Xoshiro256pp::fromSeed(831);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::tableArithmeticFunction(
        *F, {/*probability=*/100, /*max_tables=*/100}, rng));

    CHECK(countGlobals(*M, "morok.tablearith.table") == 16u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE(
    "dataFlowIntegrityFunction derives table values from integrity hash") {
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
        *F, {/*probability=*/100, /*max_tables=*/1, /*region_bytes=*/32}, rng));

    CHECK(countGlobals(*M, "morok.dfi.table") == 1u);
    CHECK(countGlobals(*M, "morok.dfi.region") == 1u);
    CHECK(countGlobals(*M, "morok.dfi.expected") == 1u);

    Function *Hash = M->getFunction("morok.dfi.hash.dfi");
    REQUIRE(Hash);

    bool callsHash = false;
    bool hasTableLoad = false;
    bool hasEntangledIndex = false;
    bool hasDecodedValue = false;
    for (Instruction &I : instructions(*F)) {
        if (auto *CI = dyn_cast<CallInst>(&I))
            callsHash |= CI->getCalledFunction() == Hash;
        if (auto *LI = dyn_cast<LoadInst>(&I))
            hasTableLoad |= LI->isVolatile() &&
                            LI->getPointerOperand()->getName().starts_with(
                                "morok.dfi.cell");
        hasEntangledIndex |=
            I.getName().starts_with("morok.dfi.idx.entangled");
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
    CHECK(hasEntangledIndex);
    CHECK(hasDecodedValue);
    CHECK(hasVolatileRegionLoad);
    CHECK(hasVolatileExpectedLoad);
    CHECK(encryptedDiffersFromPlain);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("dataFlowIntegrityFunction folds decoy hidden state into diff") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
@morok.decoy.state = private global i64 0, align 8

define i8 @dfi_decoy(i8 %a, i8 %b) {
entry:
  %x = xor i8 %a, %b
  ret i8 %x
}
)ir");
    Function *F = M->getFunction("dfi_decoy");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(841);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::dataFlowIntegrityFunction(
        *F, {/*probability=*/100, /*max_tables=*/1, /*region_bytes=*/32}, rng));

    bool hasDecoyStateLoad = false;
    bool hasDecoyDiff = false;
    for (Instruction &I : instructions(*F)) {
        if (auto *LI = dyn_cast<LoadInst>(&I)) {
            hasDecoyStateLoad |=
                LI->isVolatile() &&
                LI->getPointerOperand()->getName().starts_with(
                    "morok.decoy.state");
        }
        hasDecoyDiff |= I.getName().starts_with("morok.dfi.decoy.diff");
    }

    CHECK(hasDecoyStateLoad);
    CHECK(hasDecoyDiff);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("dataFlowIntegrityFunction supports sub-byte arithmetic") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i1 @dfi_bool(i1 %a, i1 %b) {
entry:
  %x = xor i1 %a, %b
  ret i1 %x
}

define i4 @dfi_nibble(i4 %a, i4 %b) {
entry:
  %x = add i4 %a, %b
  %y = xor i4 %x, 11
  ret i4 %y
}
)ir");
    Function *BoolF = M->getFunction("dfi_bool");
    Function *NibbleF = M->getFunction("dfi_nibble");
    REQUIRE(BoolF);
    REQUIRE(NibbleF);
    auto engine = morok::core::Xoshiro256pp::fromSeed(841);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::dataFlowIntegrityFunction(
        *BoolF, {/*probability=*/100, /*max_tables=*/1, /*region_bytes=*/32},
        rng));
    CHECK(morok::passes::dataFlowIntegrityFunction(
        *NibbleF, {/*probability=*/100, /*max_tables=*/2, /*region_bytes=*/32},
        rng));

    CHECK(countGlobals(*M, "morok.dfi.table") == 3u);
    CHECK(countGlobals(*M, "morok.dfi.region") == 2u);
    CHECK(countGlobals(*M, "morok.dfi.expected") == 2u);
    CHECK(M->getFunction("morok.dfi.hash.dfi_bool") != nullptr);
    CHECK(M->getFunction("morok.dfi.hash.dfi_nibble") != nullptr);
    CHECK_FALSE(hasPlainNarrowArithmetic(*BoolF));
    CHECK_FALSE(hasPlainNarrowArithmetic(*NibbleF));
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("dataFlowIntegrityFunction supports narrow comparisons") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i1 @dfi_cmp8(i8 %a, i8 %b) {
entry:
  %x = icmp ugt i8 %a, %b
  ret i1 %x
}

define i1 @dfi_cmp1(i1 %a, i1 %b) {
entry:
  %x = icmp sle i1 %a, %b
  ret i1 %x
}
)ir");
    Function *Cmp8 = M->getFunction("dfi_cmp8");
    Function *Cmp1 = M->getFunction("dfi_cmp1");
    REQUIRE(Cmp8);
    REQUIRE(Cmp1);
    auto engine = morok::core::Xoshiro256pp::fromSeed(842);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::dataFlowIntegrityFunction(
        *Cmp8, {/*probability=*/100, /*max_tables=*/1, /*region_bytes=*/32},
        rng));
    CHECK(morok::passes::dataFlowIntegrityFunction(
        *Cmp1, {/*probability=*/100, /*max_tables=*/1, /*region_bytes=*/32},
        rng));

    CHECK(countGlobals(*M, "morok.dfi.table") == 2u);
    CHECK(countGlobals(*M, "morok.dfi.region") == 2u);
    CHECK(countGlobals(*M, "morok.dfi.expected") == 2u);
    CHECK_FALSE(hasPlainNarrowICmp(*Cmp8));
    CHECK_FALSE(hasPlainNarrowICmp(*Cmp1));
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("dataFlowIntegrityFunction lowers const-indexed i16 ops to tables") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i16 @dfi_wide_const(i16 %a) {
entry:
  %x = add i16 %a, 4660
  %y = xor i16 21930, %x
  %z = ashr i16 %y, 3
  %c = icmp slt i16 %z, -17
  %out = select i1 %c, i16 %z, i16 %x
  ret i16 %out
}
)ir");
    Function *F = M->getFunction("dfi_wide_const");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(8421);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::dataFlowIntegrityFunction(
        *F, {/*probability=*/100, /*max_tables=*/4, /*region_bytes=*/32},
        rng));

    CHECK(countGlobals(*M, "morok.dfi.table") == 4u);
    CHECK(countGlobals(*M, "morok.dfi.region") == 1u);
    CHECK(countGlobals(*M, "morok.dfi.expected") == 1u);
    CHECK(M->getFunction("morok.dfi.hash.dfi_wide_const") != nullptr);

    bool hasI16Table = false;
    for (GlobalVariable &GV : M->globals()) {
        if (!GV.getName().starts_with("morok.dfi.table"))
            continue;
        auto *ArrTy = dyn_cast<ArrayType>(GV.getValueType());
        hasI16Table |= ArrTy && ArrTy->getElementType()->isIntegerTy(16);
    }
    CHECK(hasI16Table);

    bool hasPlainWideOp = false;
    for (Instruction &I : instructions(*F)) {
        if (I.getName().starts_with("morok."))
            continue;
        if (auto *BO = dyn_cast<BinaryOperator>(&I))
            hasPlainWideOp |= BO->getType()->isIntegerTy(16);
        if (auto *CI = dyn_cast<ICmpInst>(&I)) {
            auto *Ty = dyn_cast<IntegerType>(CI->getOperand(0)->getType());
            hasPlainWideOp |= Ty && Ty->getBitWidth() == 16;
        }
    }
    CHECK_FALSE(hasPlainWideOp);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("dataFlowIntegrityFunction supports constant narrow shifts") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i8 @dfi_shift8(i8 %a) {
entry:
  %x = shl i8 %a, 2
  %y = ashr i8 %x, 1
  ret i8 %y
}

define i4 @dfi_shift4(i4 %a) {
entry:
  %x = lshr i4 %a, 1
  ret i4 %x
}
)ir");
    Function *Shift8 = M->getFunction("dfi_shift8");
    Function *Shift4 = M->getFunction("dfi_shift4");
    REQUIRE(Shift8);
    REQUIRE(Shift4);
    auto engine = morok::core::Xoshiro256pp::fromSeed(843);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::dataFlowIntegrityFunction(
        *Shift8, {/*probability=*/100, /*max_tables=*/2, /*region_bytes=*/32},
        rng));
    CHECK(morok::passes::dataFlowIntegrityFunction(
        *Shift4, {/*probability=*/100, /*max_tables=*/1, /*region_bytes=*/32},
        rng));

    CHECK(countGlobals(*M, "morok.dfi.table") == 3u);
    CHECK(countGlobals(*M, "morok.dfi.region") == 2u);
    CHECK(countGlobals(*M, "morok.dfi.expected") == 2u);
    CHECK_FALSE(hasPlainNarrowShift(*Shift8));
    CHECK_FALSE(hasPlainNarrowShift(*Shift4));
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
        *F, {/*probability=*/0, /*max_tables=*/1, /*region_bytes=*/32}, rng));
    CHECK(hasPlainI8Arithmetic(*F));
    CHECK(countGlobals(*M, "morok.dfi.table") == 0u);
    CHECK(M->getFunction("morok.dfi.hash.dfi_zero") == nullptr);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("dataFlowIntegrityFunction caps selected table count") {
    LLVMContext ctx;
    auto M = std::make_unique<Module>("dfi-cap", ctx);
    Function *F = makeI8OpChain(*M, 32, "dfi_many");

    auto engine = morok::core::Xoshiro256pp::fromSeed(851);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::dataFlowIntegrityFunction(
        *F, {/*probability=*/100, /*max_tables=*/100, /*region_bytes=*/32},
        rng));

    CHECK(countGlobals(*M, "morok.dfi.table") == 8u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE(
    "uniformPrimitiveLowerFunction table-lowers ops and branch dispatch") {
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

TEST_CASE("uniformPrimitiveLowerFunction table-lowers comparisons") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i1 @uniform_cmp(i8 %a, i8 %b) {
entry:
  %x = icmp ult i8 %a, %b
  ret i1 %x
}
)ir");
    Function *F = M->getFunction("uniform_cmp");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(142);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::uniformPrimitiveLowerFunction(
        *F,
        {/*op_probability=*/100, /*branch_probability=*/0,
         /*max_tables=*/1, /*max_branches=*/0},
        rng));

    CHECK(countGlobals(*M, "morok.tablearith.table") == 1u);
    CHECK_FALSE(hasPlainNarrowICmp(*F));
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("uniformPrimitiveLowerFunction table-lowers const-indexed i16 ops") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i16 @uniform_wide_const(i16 %a) {
entry:
  %x = add i16 %a, 4660
  %y = xor i16 21930, %x
  %z = ashr i16 %y, 3
  %c = icmp slt i16 %z, -17
  %out = select i1 %c, i16 %z, i16 %x
  ret i16 %out
}
)ir");
    Function *F = M->getFunction("uniform_wide_const");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(1421);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::uniformPrimitiveLowerFunction(
        *F,
        {/*op_probability=*/100, /*branch_probability=*/0,
         /*max_tables=*/4, /*max_branches=*/0},
        rng));

    CHECK(countGlobals(*M, "morok.tablearith.table") == 4u);
    bool hasI16Table = false;
    for (GlobalVariable &GV : M->globals()) {
        if (!GV.getName().starts_with("morok.tablearith.table"))
            continue;
        auto *ArrTy = dyn_cast<ArrayType>(GV.getValueType());
        hasI16Table |= ArrTy && ArrTy->getElementType()->isIntegerTy(16);
    }
    CHECK(hasI16Table);

    bool hasPlainWideOp = false;
    for (Instruction &I : instructions(*F)) {
        if (I.getName().starts_with("morok."))
            continue;
        if (auto *BO = dyn_cast<BinaryOperator>(&I))
            hasPlainWideOp |= BO->getType()->isIntegerTy(16);
        if (auto *CI = dyn_cast<ICmpInst>(&I)) {
            auto *Ty = dyn_cast<IntegerType>(CI->getOperand(0)->getType());
            hasPlainWideOp |= Ty && Ty->getBitWidth() == 16;
        }
    }
    CHECK_FALSE(hasPlainWideOp);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("uniformPrimitiveLowerFunction table-lowers constant shifts") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i8 @uniform_shift(i8 %a) {
entry:
  %x = lshr i8 %a, 3
  ret i8 %x
}
)ir");
    Function *F = M->getFunction("uniform_shift");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(143);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::uniformPrimitiveLowerFunction(
        *F,
        {/*op_probability=*/100, /*branch_probability=*/0,
         /*max_tables=*/1, /*max_branches=*/0},
        rng));

    CHECK(countGlobals(*M, "morok.tablearith.table") == 1u);
    CHECK_FALSE(hasPlainNarrowShift(*F));
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

TEST_CASE("uniformPrimitiveLowerFunction caps branch lowering") {
    LLVMContext ctx;
    auto M = std::make_unique<Module>("uniform-cap", ctx);
    Function *F = makeBranchChainFunction(*M, 40, "uniform_many");

    auto engine = morok::core::Xoshiro256pp::fromSeed(1421);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::uniformPrimitiveLowerFunction(
        *F,
        {/*op_probability=*/0, /*branch_probability=*/100,
         /*max_tables=*/0, /*max_branches=*/100},
        rng));

    std::size_t indirects = 0;
    for (Instruction &I : instructions(*F))
        indirects += isa<IndirectBrInst>(&I) ? 1u : 0u;
    CHECK(indirects == 16u);
    CHECK(countGlobals(*M, "morok.uniform.table") == 1u);
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

TEST_CASE("virtualizeModule lifts integer comparisons, zext, and select idioms") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @vm_cmp(i32 %a, i32 %b) {
entry:
  %lt = icmp slt i32 %a, %b
  %eq = icmp eq i32 %a, 7
  %zl = zext i1 %lt to i32
  %ze = zext i1 %eq to i32
  %sel = select i1 %lt, i32 %a, i32 %b
  %flags = add i32 %zl, %ze
  %sum = add i32 %sel, %flags
  ret i32 %sum
}
)ir");
    Function *F = M->getFunction("vm_cmp");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(155);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::virtualizeModule(
        *M,
        {/*probability=*/100, /*max_functions=*/1,
         /*max_instructions=*/16, /*max_registers=*/32},
        rng));

    Function *Helper = M->getFunction("morok.vm.vm_cmp.exec");
    REQUIRE(Helper);
    CHECK(countGlobals(*M, "morok.vm.bytecode") == 1u);
    CHECK(countGlobals(*M, "morok.vm.targets") == 1u);

    std::size_t wrapperCalls = 0;
    std::size_t wrapperCmps = 0;
    for (Instruction &I : instructions(*F)) {
        wrapperCalls += isa<CallInst>(&I) ? 1u : 0u;
        wrapperCmps += isa<ICmpInst>(&I) ? 1u : 0u;
    }
    CHECK(wrapperCalls == 1u);
    CHECK(wrapperCmps == 0u);

    bool hasSignedCompareHandler = false;
    bool hasEqCompareHandler = false;
    bool hasSelectHandler = false;
    bool hasIndirectDispatch = false;
    for (BasicBlock &BB : *Helper) {
        hasSignedCompareHandler |= BB.getName().starts_with("morok.vm.h.icmp.slt");
        hasEqCompareHandler |= BB.getName().starts_with("morok.vm.h.icmp.eq");
        hasSelectHandler |= BB.getName().starts_with("morok.vm.h.select");
        for (Instruction &I : BB)
            hasIndirectDispatch |= isa<IndirectBrInst>(&I);
    }
    CHECK(hasSignedCompareHandler);
    CHECK(hasEqCompareHandler);
    CHECK(hasSelectHandler);
    CHECK(hasIndirectDispatch);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("virtualizeModule lifts branchless boolean predicates and masks") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @vm_predicate_mask(i32 %a, i32 %b, i32 %c) {
entry:
  %lt = icmp slt i32 %a, %b
  %gt = icmp sgt i32 %b, %c
  %both = and i1 %lt, %gt
  %either = or i1 %lt, %gt
  %flip = xor i1 %both, %either
  %mask = sext i1 %flip to i32
  %sel = select i1 %both, i32 %mask, i32 %a
  %out = xor i32 %sel, %mask
  ret i32 %out
}
)ir");
    Function *F = M->getFunction("vm_predicate_mask");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(1551);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::virtualizeModule(
        *M,
        {/*probability=*/100, /*max_functions=*/1,
         /*max_instructions=*/32, /*max_registers=*/48},
        rng));

    Function *Helper = M->getFunction("morok.vm.vm_predicate_mask.exec");
    REQUIRE(Helper);
    CHECK(countGlobals(*M, "morok.vm.bytecode") == 1u);
    CHECK(countGlobals(*M, "morok.vm.targets") == 1u);

    std::size_t wrapperCalls = 0;
    std::size_t wrapperBinops = 0;
    std::size_t wrapperCmps = 0;
    std::size_t wrapperSelects = 0;
    std::size_t wrapperSexts = 0;
    for (Instruction &I : instructions(*F)) {
        wrapperCalls += isa<CallInst>(&I) ? 1u : 0u;
        wrapperBinops += isa<BinaryOperator>(&I) ? 1u : 0u;
        wrapperCmps += isa<ICmpInst>(&I) ? 1u : 0u;
        wrapperSelects += isa<SelectInst>(&I) ? 1u : 0u;
        wrapperSexts += isa<SExtInst>(&I) ? 1u : 0u;
    }
    CHECK(wrapperCalls == 1u);
    CHECK(wrapperBinops == 0u);
    CHECK(wrapperCmps == 0u);
    CHECK(wrapperSelects == 0u);
    CHECK(wrapperSexts == 0u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("virtualizeModule lifts mixed-width integer casts and narrow ops") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @vm_mixed_width(i8 %a, i16 %b, i32 %c) {
entry:
  %az = zext i8 %a to i32
  %bs = sext i16 %b to i32
  %low = trunc i32 %c to i8
  %n0 = add i8 %a, %low
  %n1 = mul i8 %n0, 3
  %n2 = ashr i8 %n1, 2
  %cmp = icmp slt i8 %n2, %a
  %nz = zext i8 %n2 to i32
  %sel = select i1 %cmp, i32 %bs, i32 %az
  %sum = add i32 %sel, %nz
  ret i32 %sum
}
)ir");
    Function *F = M->getFunction("vm_mixed_width");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(1552);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::virtualizeModule(
        *M,
        {/*probability=*/100, /*max_functions=*/1,
         /*max_instructions=*/64, /*max_registers=*/96},
        rng));

    Function *Helper = M->getFunction("morok.vm.vm_mixed_width.exec");
    REQUIRE(Helper);
    CHECK(countGlobals(*M, "morok.vm.bytecode") == 1u);
    CHECK(countGlobals(*M, "morok.vm.targets") == 1u);

    std::size_t wrapperCalls = 0;
    std::size_t wrapperBinops = 0;
    std::size_t wrapperCasts = 0;
    std::size_t wrapperCmps = 0;
    for (Instruction &I : instructions(*F)) {
        wrapperCalls += isa<CallInst>(&I) ? 1u : 0u;
        wrapperBinops += isa<BinaryOperator>(&I) ? 1u : 0u;
        wrapperCasts += isa<CastInst>(&I) ? 1u : 0u;
        wrapperCmps += isa<ICmpInst>(&I) ? 1u : 0u;
    }
    CHECK(wrapperCalls == 1u);
    CHECK(wrapperBinops == 0u);
    CHECK(wrapperCasts == 0u);
    CHECK(wrapperCmps == 0u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("virtualizeModule lifts one-bit integer functions") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i1 @vm_bool(i1 %a, i1 %b) {
entry:
  %x = xor i1 %a, %b
  %y = and i1 %x, %a
  ret i1 %y
}
)ir");
    Function *F = M->getFunction("vm_bool");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(156);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::virtualizeModule(
        *M,
        {/*probability=*/100, /*max_functions=*/1,
         /*max_instructions=*/16, /*max_registers=*/16},
        rng));

    Function *Helper = M->getFunction("morok.vm.vm_bool.exec");
    REQUIRE(Helper);
    CHECK(countGlobals(*M, "morok.vm.bytecode") == 1u);

    std::size_t wrapperCalls = 0;
    std::size_t wrapperBinops = 0;
    for (Instruction &I : instructions(*F)) {
        wrapperCalls += isa<CallInst>(&I) ? 1u : 0u;
        wrapperBinops += isa<BinaryOperator>(&I) ? 1u : 0u;
    }
    CHECK(wrapperCalls == 1u);
    CHECK(wrapperBinops == 0u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("virtualizeModule lifts unused-vararg integer functions") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @vm_vararg(i32 %a, ...) {
entry:
  %x = add i32 %a, 5
  %y = xor i32 %x, 17
  ret i32 %y
}
)ir");
    Function *F = M->getFunction("vm_vararg");
    REQUIRE(F);
    REQUIRE(F->isVarArg());
    auto engine = morok::core::Xoshiro256pp::fromSeed(157);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::virtualizeModule(
        *M,
        {/*probability=*/100, /*max_functions=*/1,
         /*max_instructions=*/16, /*max_registers=*/16},
        rng));

    Function *Helper = M->getFunction("morok.vm.vm_vararg.exec");
    REQUIRE(Helper);
    CHECK_FALSE(Helper->isVarArg());
    CHECK(F->isVarArg());
    std::size_t wrapperCalls = 0;
    std::size_t wrapperBinops = 0;
    for (Instruction &I : instructions(*F)) {
        wrapperCalls += isa<CallInst>(&I) ? 1u : 0u;
        wrapperBinops += isa<BinaryOperator>(&I) ? 1u : 0u;
    }
    CHECK(wrapperCalls == 1u);
    CHECK(wrapperBinops == 0u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("virtualizeModule lifts integer division and remainder") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @vm_divrem(i32 %a, i32 %b) {
entry:
  %uq = udiv i32 %a, %b
  %ur = urem i32 %a, %b
  %sq = sdiv i32 %a, %b
  %sr = srem i32 %a, %b
  %t0 = xor i32 %uq, %ur
  %t1 = xor i32 %sq, %sr
  %r  = add i32 %t0, %t1
  ret i32 %r
}
)ir");
    Function *F = M->getFunction("vm_divrem");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(1771);
    morok::ir::IRRandom rng(engine);

    // udiv/urem/sdiv/srem used to make the whole function ineligible
    // (buildProgram returned nullopt).  A successful lift proves every one is
    // now accepted and encoded into the bytecode.
    CHECK(morok::passes::virtualizeModule(
        *M,
        {/*probability=*/100, /*max_functions=*/1,
         /*max_instructions=*/64, /*max_registers=*/96},
        rng));

    Function *Helper = M->getFunction("morok.vm.vm_divrem.exec");
    REQUIRE(Helper);
    CHECK(countOpcode(*M, Instruction::UDiv) >= 1u);
    CHECK(countOpcode(*M, Instruction::SDiv) >= 1u);
    CHECK(countOpcode(*M, Instruction::URem) >= 1u);
    CHECK(countOpcode(*M, Instruction::SRem) >= 1u);

    std::size_t wrapperCalls = 0;
    std::size_t wrapperBinops = 0;
    for (Instruction &I : instructions(*F)) {
        wrapperCalls += isa<CallInst>(&I) ? 1u : 0u;
        wrapperBinops += isa<BinaryOperator>(&I) ? 1u : 0u;
    }
    CHECK(wrapperCalls == 1u);
    CHECK(wrapperBinops == 0u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("virtualizeModule lifts narrow signed division and remainder") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @vm_narrow_div(i8 %a, i8 %b) {
entry:
  %sq = sdiv i8 %a, %b
  %sr = srem i8 %a, %b
  %uq = udiv i8 %a, %b
  %x0 = xor i8 %sq, %sr
  %x1 = xor i8 %x0, %uq
  %r  = sext i8 %x1 to i32
  ret i32 %r
}
)ir");
    Function *F = M->getFunction("vm_narrow_div");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(1772);
    morok::ir::IRRandom rng(engine);

    // Narrow signed div/rem must sign-extend both operands into the register
    // width; the lift must succeed and stay well-formed.
    CHECK(morok::passes::virtualizeModule(
        *M,
        {/*probability=*/100, /*max_functions=*/1,
         /*max_instructions=*/96, /*max_registers=*/128},
        rng));

    Function *Helper = M->getFunction("morok.vm.vm_narrow_div.exec");
    REQUIRE(Helper);
    std::size_t wrapperBinops = 0;
    for (Instruction &I : instructions(*F))
        wrapperBinops += isa<BinaryOperator>(&I) ? 1u : 0u;
    CHECK(wrapperBinops == 0u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("virtualizeModule lifts poison-flagged arithmetic") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @vm_flagged(i32 %a, i32 %b) {
entry:
  %p = mul nsw i32 %a, %b
  %q = add nuw i32 %p, %a
  %r = shl nuw nsw i32 %q, 3
  %s = ashr exact i32 %r, 1
  ret i32 %s
}
)ir");
    Function *F = M->getFunction("vm_flagged");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(1773);
    morok::ir::IRRandom rng(engine);

    // -O2 stamps nsw/nuw/exact onto essentially all arithmetic; the VM must
    // accept these (emitting the sound unflagged refinement) or it never fires
    // on optimized code.
    CHECK(morok::passes::virtualizeModule(
        *M,
        {/*probability=*/100, /*max_functions=*/1,
         /*max_instructions=*/64, /*max_registers=*/96},
        rng));
    Function *Helper = M->getFunction("morok.vm.vm_flagged.exec");
    REQUIRE(Helper);
    std::size_t wrapperBinops = 0;
    for (Instruction &I : instructions(*F))
        wrapperBinops += isa<BinaryOperator>(&I) ? 1u : 0u;
    CHECK(wrapperBinops == 0u);
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
    CHECK(Ensure->arg_size() == Helper->arg_size());

    auto *AfterData = dyn_cast<ConstantDataArray>(Bytecode->getInitializer());
    REQUIRE(AfterData);
    bool payloadChanged = false;
    for (unsigned I = 0; I < AfterData->getNumElements() && I < Before.size();
         ++I)
        payloadChanged |= Before[I] != static_cast<std::uint8_t>(
                                           AfterData->getElementAsInteger(I));
    CHECK(payloadChanged);

    bool helperCallsEnsure = false;
    bool hasGate = false;
    bool hasTrap = false;
    bool hasVolatileReadyLoad = false;
    bool hasVolatileReadyStore = false;
    bool hasVolatileContextLoad = false;
    bool hasVolatileContextStore = false;
    bool hasContextZero = false;
    bool keyUsesContext = false;
    bool storesPayload = false;
    bool gateFallsIntoDecrypt = false;
    bool decryptBranchesToDecide = false;
    bool hasPostDecryptGateDecision = false;
    for (Instruction &I : instructions(*Helper)) {
        if (auto *CI = dyn_cast<CallInst>(&I)) {
            if (CI->getCalledFunction() == Ensure) {
                helperCallsEnsure = true;
                CHECK(CI->arg_size() == Helper->arg_size());
            }
        }
    }
    for (Instruction &I : instructions(*Ensure)) {
        if (I.getName().starts_with("morok.sdb.gate"))
            hasGate = true;
        if (I.getName().starts_with("morok.sdb.context.zero"))
            hasContextZero = true;
        if (I.getName().starts_with("morok.sdb.key.context"))
            keyUsesContext = true;
        if (auto *CI = dyn_cast<CallInst>(&I))
            if (Function *Callee = CI->getCalledFunction())
                hasTrap |= Callee->getName() == "llvm.trap";
        if (auto *LI = dyn_cast<LoadInst>(&I))
            hasVolatileReadyLoad |=
                LI->isVolatile() &&
                LI->getPointerOperand()->getName().starts_with(
                    "morok.sdb.ready");
        if (auto *LI = dyn_cast<LoadInst>(&I))
            hasVolatileContextLoad |=
                LI->isVolatile() &&
                LI->getPointerOperand()->getName().starts_with(
                    "morok.sdb.context.slot");
        if (auto *SI = dyn_cast<StoreInst>(&I)) {
            hasVolatileReadyStore |=
                SI->isVolatile() &&
                SI->getPointerOperand()->getName().starts_with(
                    "morok.sdb.ready");
            hasVolatileContextStore |=
                SI->isVolatile() &&
                SI->getPointerOperand()->getName().starts_with(
                    "morok.sdb.context.slot");
            storesPayload |= SI->getPointerOperand()->getName().starts_with(
                "morok.sdb.payload.ptr");
        }
    }
    for (BasicBlock &BB : *Ensure) {
        bool blockHasGate = false;
        for (Instruction &I : BB)
            blockHasGate |= I.getName().starts_with("morok.sdb.gate");
        if (auto *BI = dyn_cast<BranchInst>(BB.getTerminator())) {
            if (blockHasGate)
                gateFallsIntoDecrypt =
                    BI->isUnconditional() &&
                    BI->getSuccessor(0)->getName() == "decrypt";
            if (BB.getName() == "decrypt")
                decryptBranchesToDecide =
                    BI->isConditional() &&
                    BI->getSuccessor(0)->getName() == "decide";
            if (BB.getName() == "decide")
                hasPostDecryptGateDecision =
                    BI->isConditional() &&
                    ((BI->getSuccessor(0)->getName() == "ready" &&
                      BI->getSuccessor(1)->getName() == "fail") ||
                     (BI->getSuccessor(0)->getName() == "fail" &&
                      BI->getSuccessor(1)->getName() == "ready"));
        }
    }
    CHECK(helperCallsEnsure);
    CHECK(hasGate);
    CHECK(hasTrap);
    CHECK(hasVolatileReadyLoad);
    CHECK(hasVolatileReadyStore);
    CHECK(hasVolatileContextLoad);
    CHECK(hasVolatileContextStore);
    CHECK(hasContextZero);
    CHECK(keyUsesContext);
    CHECK(storesPayload);
    CHECK(gateFallsIntoDecrypt);
    CHECK(decryptBranchesToDecide);
    CHECK(hasPostDecryptGateDecision);
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
    CHECK(countGlobals(*M, "morok.sc.code.size") == 1u);
    CHECK(countGlobals(*M, "morok.sc.mask") == 2u);
    CHECK(countGlobals(*M, "morok.postlink.sc") == 1u);

    GlobalVariable *Region = nullptr;
    GlobalVariable *Expected = nullptr;
    GlobalVariable *CodeSize = nullptr;
    GlobalVariable *Manifest = nullptr;
    for (GlobalVariable &GV : M->globals()) {
        if (GV.getName().starts_with("morok.sc.region"))
            Region = &GV;
        if (GV.getName().starts_with("morok.sc.expected"))
            Expected = &GV;
        if (GV.getName().starts_with("morok.sc.code.size"))
            CodeSize = &GV;
        if (GV.getName().starts_with("morok.postlink.sc"))
            Manifest = &GV;
    }
    REQUIRE(Region);
    REQUIRE(Expected);
    REQUIRE(CodeSize);
    REQUIRE(Manifest);
    REQUIRE(Manifest->hasInitializer());
    CHECK(constantReferencesGlobal(Manifest->getInitializer(), Region));
    CHECK(constantReferencesGlobal(Manifest->getInitializer(), Expected));
    CHECK(constantReferencesGlobal(Manifest->getInitializer(), CodeSize));
    CHECK(constantReferencesGlobal(Manifest->getInitializer(), F));
    GlobalVariable *Used = M->getGlobalVariable("llvm.compiler.used");
    REQUIRE(Used);
    REQUIRE(Used->hasInitializer());
    CHECK(constantReferencesGlobal(Used->getInitializer(), Manifest));

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
                LI->getPointerOperand()->getName().starts_with("morok.sc.mask");
    }

    bool hasVolatileRegionLoad = false;
    bool hasVolatileExpectedLoad = false;
    bool hasVolatileCodeSizeLoad = false;
    bool hasVolatileCodeByteLoad = false;
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
            hasVolatileCodeSizeLoad |=
                LI->isVolatile() &&
                LI->getPointerOperand()->getName().starts_with(
                    "morok.sc.code.size");
            hasVolatileCodeByteLoad |=
                LI->isVolatile() &&
                LI->getName().starts_with("morok.sc.code.byte");
        }
    }

    CHECK(callsDiff);
    CHECK(hasConstMix);
    CHECK(hasVolatileMaskLoad);
    CHECK(hasVolatileRegionLoad);
    CHECK(hasVolatileExpectedLoad);
    CHECK(hasVolatileCodeSizeLoad);
    CHECK(hasVolatileCodeByteLoad);
    CHECK(hasDiffValue);
    CHECK_FALSE(hasTrap);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE(
    "selfChecksumConstantsFunction supports sub-byte and odd-width literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i1 @selfcheck_bool(i1 %a) {
entry:
  %x = xor i1 %a, true
  ret i1 %x
}

define i12 @selfcheck_i12(i12 %a) {
entry:
  %x = add i12 %a, 291
  ret i12 %x
}
)ir");
    Function *BoolF = M->getFunction("selfcheck_bool");
    Function *I12F = M->getFunction("selfcheck_i12");
    REQUIRE(BoolF);
    REQUIRE(I12F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(1811);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::selfChecksumConstantsFunction(
        *BoolF, {/*probability=*/100, /*max_constants=*/1, /*region_bytes=*/32},
        rng));
    CHECK(morok::passes::selfChecksumConstantsFunction(
        *I12F, {/*probability=*/100, /*max_constants=*/1, /*region_bytes=*/32},
        rng));

    CHECK(countGlobals(*M, "morok.sc.region") == 2u);
    CHECK(countGlobals(*M, "morok.sc.expected") == 2u);
    CHECK(countGlobals(*M, "morok.sc.mask") == 2u);
    CHECK(countGlobals(*M, "morok.postlink.sc") == 2u);
    CHECK(M->getFunction("morok.sc.diff.selfcheck_bool") != nullptr);
    CHECK(M->getFunction("morok.sc.diff.selfcheck_i12") != nullptr);

    bool hasI12MaskAlignment = false;
    for (GlobalVariable &GV : M->globals())
        if (GV.getName().starts_with("morok.sc.mask") &&
            GV.getValueType()->isIntegerTy(12))
            hasI12MaskAlignment |= GV.getAlign().valueOrOne().value() >= 2u;

    bool hasI1Mix = false;
    bool hasI12Mix = false;
    for (Instruction &I : instructions(*BoolF))
        hasI1Mix |= I.getName().starts_with("morok.sc.const") &&
                    I.getType()->isIntegerTy(1);
    for (Instruction &I : instructions(*I12F))
        hasI12Mix |= I.getName().starts_with("morok.sc.const") &&
                     I.getType()->isIntegerTy(12);
    CHECK(hasI1Mix);
    CHECK(hasI12Mix);
    CHECK(hasI12MaskAlignment);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("selfChecksumConstantsFunction fuses integer select literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i12 @selfcheck_select(i1 %flag) {
entry:
  %x = select i1 %flag, i12 11, i12 291
  ret i12 %x
}
)ir");
    Function *F = M->getFunction("selfcheck_select");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(1812);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::selfChecksumConstantsFunction(
        *F, {/*probability=*/100, /*max_constants=*/2, /*region_bytes=*/32},
        rng));

    SelectInst *Sel = nullptr;
    for (Instruction &I : instructions(*F))
        if (auto *SI = dyn_cast<SelectInst>(&I))
            Sel = SI;
    REQUIRE(Sel);
    CHECK_FALSE(isa<ConstantInt>(Sel->getTrueValue()));
    CHECK_FALSE(isa<ConstantInt>(Sel->getFalseValue()));

    bool hasI12Mix = false;
    for (Instruction &I : instructions(*F))
        hasI12Mix |= I.getName().starts_with("morok.sc.const") &&
                     I.getType()->isIntegerTy(12);
    CHECK(hasI12Mix);
    CHECK(countGlobals(*M, "morok.sc.mask") == 2u);
    CHECK(M->getFunction("morok.sc.diff.selfcheck_select") != nullptr);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("selfChecksumConstantsFunction fuses cast and return literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i8 @selfcheck_cast_ret() {
entry:
  %x = zext i4 7 to i8
  ret i8 42
}
)ir");
    Function *F = M->getFunction("selfcheck_cast_ret");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(1813);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::selfChecksumConstantsFunction(
        *F, {/*probability=*/100, /*max_constants=*/2, /*region_bytes=*/32},
        rng));

    CastInst *Cast = nullptr;
    ReturnInst *Ret = nullptr;
    for (Instruction &I : instructions(*F)) {
        if (auto *CI = dyn_cast<CastInst>(&I))
            Cast = CI;
        if (auto *RI = dyn_cast<ReturnInst>(&I))
            Ret = RI;
    }
    REQUIRE(Cast);
    REQUIRE(Ret);
    CHECK_FALSE(isa<ConstantInt>(Cast->getOperand(0)));
    CHECK_FALSE(isa<ConstantInt>(Ret->getReturnValue()));
    CHECK(countGlobals(*M, "morok.sc.mask") == 2u);
    CHECK(M->getFunction("morok.sc.diff.selfcheck_cast_ret") != nullptr);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE(
    "selfChecksumConstantsFunction fuses ordinary call argument literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare i8 @selfcheck_arg_callee(i8, i8)

define i8 @selfcheck_call_args() {
entry:
  %x = call i8 @selfcheck_arg_callee(i8 11, i8 29)
  ret i8 %x
}
)ir");
    Function *F = M->getFunction("selfcheck_call_args");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(1814);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::selfChecksumConstantsFunction(
        *F, {/*probability=*/100, /*max_constants=*/2, /*region_bytes=*/32},
        rng));

    CallInst *Call = nullptr;
    for (Instruction &I : instructions(*F))
        if (auto *CI = dyn_cast<CallInst>(&I))
            if (CI->getCalledFunction() &&
                CI->getCalledFunction()->getName() == "selfcheck_arg_callee")
                Call = CI;
    REQUIRE(Call);
    CHECK_FALSE(isa<ConstantInt>(Call->getArgOperand(0)));
    CHECK_FALSE(isa<ConstantInt>(Call->getArgOperand(1)));
    CHECK(countGlobals(*M, "morok.sc.mask") == 2u);
    CHECK(M->getFunction("morok.sc.diff.selfcheck_call_args") != nullptr);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("selfChecksumConstantsFunction fuses floating value literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare void @selfcheck_fp_arg(float)

define float @selfcheck_fp_values(float %a, double %d, ptr %p) {
entry:
  %x = fadd float %a, 1.500000e+00
  %cmp = fcmp olt double %d, 2.500000e+00
  store float 3.500000e+00, ptr %p, align 4
  call void @selfcheck_fp_arg(float 4.500000e+00)
  ret float 5.500000e+00
}
)ir");
    Function *F = M->getFunction("selfcheck_fp_values");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(18141);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::selfChecksumConstantsFunction(
        *F, {/*probability=*/100, /*max_constants=*/8, /*region_bytes=*/32},
        rng));

    bool hasFpConst = false;
    unsigned fpConstBitcasts = 0;
    for (Instruction &I : instructions(*F)) {
        if (auto *BO = dyn_cast<BinaryOperator>(&I))
            for (Value *Op : BO->operands())
                hasFpConst |= isa<ConstantFP>(Op);
        if (auto *FC = dyn_cast<FCmpInst>(&I))
            for (Value *Op : FC->operands())
                hasFpConst |= isa<ConstantFP>(Op);
        if (auto *SI = dyn_cast<StoreInst>(&I))
            hasFpConst |= isa<ConstantFP>(SI->getValueOperand());
        if (auto *CI = dyn_cast<CallInst>(&I))
            if (CI->getCalledFunction() &&
                CI->getCalledFunction()->getName() == "selfcheck_fp_arg")
                for (Value *Arg : CI->args())
                    hasFpConst |= isa<ConstantFP>(Arg);
        if (auto *RI = dyn_cast<ReturnInst>(&I))
            hasFpConst |= isa<ConstantFP>(RI->getReturnValue());
        if (I.getName().starts_with("morok.sc.const.fp"))
            ++fpConstBitcasts;
    }

    CHECK_FALSE(hasFpConst);
    CHECK(fpConstBitcasts >= 5u);
    CHECK(countGlobals(*M, "morok.sc.mask") == 5u);
    CHECK(M->getFunction("morok.sc.diff.selfcheck_fp_values") != nullptr);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("selfChecksumConstantsFunction fuses store value literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define void @selfcheck_store(ptr %p) {
entry:
  store i8 37, ptr %p, align 1
  ret void
}
)ir");
    Function *F = M->getFunction("selfcheck_store");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(1815);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::selfChecksumConstantsFunction(
        *F, {/*probability=*/100, /*max_constants=*/1, /*region_bytes=*/32},
        rng));

    StoreInst *Store = nullptr;
    for (Instruction &I : instructions(*F))
        if (auto *SI = dyn_cast<StoreInst>(&I))
            if (SI->getPointerOperand()->getName() == "p")
                Store = SI;
    REQUIRE(Store);
    CHECK_FALSE(isa<ConstantInt>(Store->getValueOperand()));
    CHECK(Store->getValueOperand()->getName().starts_with("morok.sc.const"));
    CHECK(countGlobals(*M, "morok.sc.region") == 1u);
    CHECK(countGlobals(*M, "morok.sc.expected") == 1u);
    CHECK(countGlobals(*M, "morok.sc.mask") == 1u);
    CHECK(countGlobals(*M, "morok.postlink.sc") == 1u);
    CHECK(M->getFunction("morok.sc.diff.selfcheck_store") != nullptr);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("selfChecksumConstantsFunction fuses conditional branch literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define void @selfcheck_branch() {
entry:
  br i1 true, label %left, label %right
left:
  ret void
right:
  ret void
}
)ir");
    Function *F = M->getFunction("selfcheck_branch");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(1816);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::selfChecksumConstantsFunction(
        *F, {/*probability=*/100, /*max_constants=*/1, /*region_bytes=*/32},
        rng));

    auto *BI = dyn_cast<BranchInst>(F->getEntryBlock().getTerminator());
    REQUIRE(BI);
    REQUIRE(BI->isConditional());
    CHECK_FALSE(isa<ConstantInt>(BI->getCondition()));
    CHECK(BI->getCondition()->getName().starts_with("morok.sc.const"));
    CHECK(BI->getSuccessor(0)->getName() == "left");
    CHECK(BI->getSuccessor(1)->getName() == "right");
    CHECK(countGlobals(*M, "morok.sc.region") == 1u);
    CHECK(countGlobals(*M, "morok.sc.expected") == 1u);
    CHECK(countGlobals(*M, "morok.sc.mask") == 1u);
    CHECK(countGlobals(*M, "morok.postlink.sc") == 1u);
    CHECK(M->getFunction("morok.sc.diff.selfcheck_branch") != nullptr);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("selfChecksumConstantsFunction fuses switch condition literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define void @selfcheck_switch() {
entry:
  switch i8 5, label %default [
    i8 5, label %hit
    i8 7, label %miss
  ]
hit:
  ret void
miss:
  ret void
default:
  ret void
}
)ir");
    Function *F = M->getFunction("selfcheck_switch");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(1817);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::selfChecksumConstantsFunction(
        *F, {/*probability=*/100, /*max_constants=*/1, /*region_bytes=*/32},
        rng));

    auto *SW = dyn_cast<SwitchInst>(F->getEntryBlock().getTerminator());
    REQUIRE(SW);
    CHECK_FALSE(isa<ConstantInt>(SW->getCondition()));
    CHECK(SW->getCondition()->getName().starts_with("morok.sc.const"));
    for (auto &Case : SW->cases())
        CHECK(isa<ConstantInt>(Case.getCaseValue()));
    CHECK(countGlobals(*M, "morok.sc.region") == 1u);
    CHECK(countGlobals(*M, "morok.sc.expected") == 1u);
    CHECK(countGlobals(*M, "morok.sc.mask") == 1u);
    CHECK(countGlobals(*M, "morok.postlink.sc") == 1u);
    CHECK(M->getFunction("morok.sc.diff.selfcheck_switch") != nullptr);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("selfChecksumConstantsFunction fuses PHI incoming literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i8 @selfcheck_phi(i1 %flag) {
entry:
  br i1 %flag, label %join, label %right
right:
  br label %join
join:
  %x = phi i8 [ 11, %entry ], [ 29, %right ]
  ret i8 %x
}
)ir");
    Function *F = M->getFunction("selfcheck_phi");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(1818);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::selfChecksumConstantsFunction(
        *F, {/*probability=*/100, /*max_constants=*/2, /*region_bytes=*/32},
        rng));

    PHINode *Phi = nullptr;
    bool hasSplitEdge = false;
    for (BasicBlock &BB : *F) {
        hasSplitEdge |= BB.getName().starts_with("morok.sc.phi.edge");
        for (Instruction &I : BB)
            if (auto *PN = dyn_cast<PHINode>(&I))
                Phi = PN;
    }
    REQUIRE(Phi);
    for (unsigned I = 0; I < Phi->getNumIncomingValues(); ++I) {
        CHECK_FALSE(isa<ConstantInt>(Phi->getIncomingValue(I)));
        CHECK(Phi->getIncomingValue(I)->getName().starts_with("morok.sc.const"));
    }
    CHECK(hasSplitEdge);
    CHECK(countGlobals(*M, "morok.sc.region") == 1u);
    CHECK(countGlobals(*M, "morok.sc.expected") == 1u);
    CHECK(countGlobals(*M, "morok.sc.mask") == 2u);
    CHECK(countGlobals(*M, "morok.postlink.sc") == 1u);
    CHECK(M->getFunction("morok.sc.diff.selfcheck_phi") != nullptr);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("selfChecksumConstantsFunction fuses floating PHI incoming literals") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define float @selfcheck_fp_phi(i1 %flag) {
entry:
  br i1 %flag, label %join, label %right
right:
  br label %join
join:
  %p = phi float [ 1.250000e+00, %entry ], [ 2.750000e+00, %right ]
  ret float %p
}
)ir");
    Function *F = M->getFunction("selfcheck_fp_phi");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(18181);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::selfChecksumConstantsFunction(
        *F, {/*probability=*/100, /*max_constants=*/2, /*region_bytes=*/32},
        rng));

    PHINode *Phi = nullptr;
    bool hasSplitEdge = false;
    for (BasicBlock &BB : *F) {
        hasSplitEdge |= BB.getName().starts_with("morok.sc.phi.edge");
        for (Instruction &I : BB)
            if (auto *PN = dyn_cast<PHINode>(&I))
                Phi = PN;
    }
    REQUIRE(Phi);
    for (unsigned I = 0; I < Phi->getNumIncomingValues(); ++I) {
        CHECK_FALSE(isa<ConstantFP>(Phi->getIncomingValue(I)));
        CHECK(Phi->getIncomingValue(I)
                  ->getName()
                  .starts_with("morok.sc.const"));
    }
    CHECK(hasSplitEdge);
    CHECK(countGlobals(*M, "morok.sc.mask") == 2u);
    CHECK(M->getFunction("morok.sc.diff.selfcheck_fp_phi") != nullptr);
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
        *F,
        {/*probability=*/100, /*nodes=*/3, /*region_bytes=*/32,
         /*max_returns=*/1},
        rng));

    CHECK(countGlobals(*M, "morok.mg.region") == 3u);
    CHECK(countGlobals(*M, "morok.mg.expected") == 3u);
    CHECK(countGlobals(*M, "morok.postlink.mg") == 1u);

    GlobalVariable *Manifest = nullptr;
    for (GlobalVariable &GV : M->globals())
        if (GV.getName().starts_with("morok.postlink.mg"))
            Manifest = &GV;
    REQUIRE(Manifest);
    REQUIRE(Manifest->hasInitializer());

    Function *Diff = M->getFunction("morok.mg.diff.mutual");
    REQUIRE(Diff);

    std::vector<Function *> nodes;
    std::vector<GlobalVariable *> regions;
    std::vector<GlobalVariable *> expected;
    for (unsigned i = 0; i != 3; ++i) {
        Function *Node =
            M->getFunction("morok.mg.node.mutual." + std::to_string(i));
        REQUIRE(Node);
        nodes.push_back(Node);
        GlobalVariable *Region = M->getGlobalVariable(
            "morok.mg.region.mutual." + std::to_string(i), true);
        GlobalVariable *Expected = M->getGlobalVariable(
            "morok.mg.expected.mutual." + std::to_string(i), true);
        REQUIRE(Region);
        REQUIRE(Expected);
        regions.push_back(Region);
        expected.push_back(Expected);
    }
    for (GlobalVariable *Region : regions)
        CHECK(constantReferencesGlobal(Manifest->getInitializer(), Region));
    for (GlobalVariable *Expected : expected)
        CHECK(constantReferencesGlobal(Manifest->getInitializer(), Expected));
    GlobalVariable *Used = M->getGlobalVariable("llvm.compiler.used");
    REQUIRE(Used);
    REQUIRE(Used->hasInitializer());
    CHECK(constantReferencesGlobal(Used->getInitializer(), Manifest));

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

    std::vector<unsigned> regionCoverage(regions.size(), 0);
    for (Function *Node : nodes) {
        unsigned regionLoads = 0;
        unsigned expectedLoads = 0;
        bool hasPeerMix = false;
        bool hasNodeDiff = false;
        std::vector<bool> nodeCovers(regions.size(), false);
        for (Instruction &I : instructions(*Node)) {
            hasPeerMix |= I.getName().starts_with("morok.mg.peer");
            hasNodeDiff |= I.getName().starts_with("morok.mg.node.diff");
            if (auto *CI = dyn_cast<CallInst>(&I))
                if (Function *Callee = CI->getCalledFunction())
                    hasTrap |= Callee->getName() == "llvm.trap";
            if (auto *LI = dyn_cast<LoadInst>(&I)) {
                if (LI->isVolatile() &&
                    LI->getPointerOperand()->getName().starts_with(
                        "morok.mg.region.ptr"))
                    ++regionLoads;
                if (LI->isVolatile() &&
                    LI->getPointerOperand()->getName().starts_with(
                        "morok.mg.expected"))
                    ++expectedLoads;
            }
            for (std::size_t R = 0; R != regions.size(); ++R)
                nodeCovers[R] = nodeCovers[R] ||
                                instructionReferencesGlobal(I, regions[R]);
        }
        for (std::size_t R = 0; R != nodeCovers.size(); ++R)
            if (nodeCovers[R])
                ++regionCoverage[R];
        CHECK(regionLoads >= 3u);
        CHECK(expectedLoads >= 3u);
        CHECK(hasPeerMix);
        CHECK(hasNodeDiff);
    }
    for (unsigned Coverage : regionCoverage)
        CHECK(Coverage >= 3u);

    CHECK(callsDiff);
    CHECK(hasReturnPoison);
    CHECK(nodeCalls == 3u);
    CHECK(hasGraphDiff);
    CHECK_FALSE(hasTrap);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("mutualGuardGraphFunction poisons sub-byte integer returns") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i1 @mg_bool(i1 %a, i1 %b) {
entry:
  %x = xor i1 %a, %b
  ret i1 %x
}

define i4 @mg_nibble(i4 %a, i4 %b) {
entry:
  %x = add i4 %a, %b
  ret i4 %x
}
)ir");
    Function *Bool = M->getFunction("mg_bool");
    Function *Nibble = M->getFunction("mg_nibble");
    REQUIRE(Bool);
    REQUIRE(Nibble);

    auto engine = morok::core::Xoshiro256pp::fromSeed(203);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::mutualGuardGraphFunction(
        *Bool,
        {/*probability=*/100, /*nodes=*/2, /*region_bytes=*/16,
         /*max_returns=*/1},
        rng));
    CHECK(morok::passes::mutualGuardGraphFunction(
        *Nibble,
        {/*probability=*/100, /*nodes=*/2, /*region_bytes=*/16,
         /*max_returns=*/1},
        rng));

    bool hasI1Poison = false;
    bool hasI4Poison = false;
    for (Instruction &I : instructions(*Bool))
        hasI1Poison |= I.getName().starts_with("morok.mg.value") &&
                       I.getType()->isIntegerTy(1);
    for (Instruction &I : instructions(*Nibble))
        hasI4Poison |= I.getName().starts_with("morok.mg.value") &&
                       I.getType()->isIntegerTy(4);

    CHECK(hasI1Poison);
    CHECK(hasI4Poison);
    CHECK(M->getFunction("morok.mg.diff.mg_bool") != nullptr);
    CHECK(M->getFunction("morok.mg.diff.mg_nibble") != nullptr);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("mutualGuardGraphFunction poisons floating scalar returns") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define float @mg_float(float %a, float %b) {
entry:
  %x = fadd float %a, %b
  ret float %x
}

define double @mg_double(double %a, double %b) {
entry:
  %x = fsub double %a, %b
  ret double %x
}
)ir");
    Function *FloatFn = M->getFunction("mg_float");
    Function *DoubleFn = M->getFunction("mg_double");
    REQUIRE(FloatFn);
    REQUIRE(DoubleFn);

    auto engine = morok::core::Xoshiro256pp::fromSeed(204);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::mutualGuardGraphFunction(
        *FloatFn,
        {/*probability=*/100, /*nodes=*/2, /*region_bytes=*/16,
         /*max_returns=*/1},
        rng));
    CHECK(morok::passes::mutualGuardGraphFunction(
        *DoubleFn,
        {/*probability=*/100, /*nodes=*/2, /*region_bytes=*/16,
         /*max_returns=*/1},
        rng));

    bool hasFloatPoison = false;
    bool hasDoublePoison = false;
    bool hasFloatCarrier = false;
    bool hasDoubleCarrier = false;
    for (Instruction &I : instructions(*FloatFn)) {
        hasFloatPoison |= I.getName().starts_with("morok.mg.value") &&
                          I.getType()->isFloatTy();
        if (auto *BC = dyn_cast<BitCastInst>(&I))
            hasFloatCarrier |=
                BC->getSrcTy()->isFloatTy() && BC->getDestTy()->isIntegerTy(32);
    }
    for (Instruction &I : instructions(*DoubleFn)) {
        hasDoublePoison |= I.getName().starts_with("morok.mg.value") &&
                           I.getType()->isDoubleTy();
        if (auto *BC = dyn_cast<BitCastInst>(&I))
            hasDoubleCarrier |= BC->getSrcTy()->isDoubleTy() &&
                                BC->getDestTy()->isIntegerTy(64);
    }

    CHECK(hasFloatPoison);
    CHECK(hasDoublePoison);
    CHECK(hasFloatCarrier);
    CHECK(hasDoubleCarrier);
    CHECK(M->getFunction("morok.mg.diff.mg_float") != nullptr);
    CHECK(M->getFunction("morok.mg.diff.mg_double") != nullptr);
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
        *F,
        {/*probability=*/0, /*nodes=*/3, /*region_bytes=*/32,
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

TEST_CASE("pathExplosionFunction mixes floating inputs into decoy seed") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @guarded_fp(float %a, double %b, i32 %salt) {
entry:
  %b32 = fptrunc double %b to float
  %sum = fadd float %a, %b32
  %bits = bitcast float %sum to i32
  %y = xor i32 %bits, %salt
  ret i32 %y
}
)ir");
    Function *F = M->getFunction("guarded_fp");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(93);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::pathExplosionFunction(
        *F, {/*probability=*/100, /*max_blocks=*/1, /*max_iterations=*/8},
        rng));

    bool hasFloatTerm = false;
    bool hasDoubleTerm = false;
    bool hasSeedMix = false;
    bool hasIndirectBr = false;
    for (Instruction &I : instructions(*F)) {
        if (auto *BC = dyn_cast<BitCastInst>(&I)) {
            hasFloatTerm |= BC->getName().starts_with("morok.path.seed.fp") &&
                            BC->getSrcTy()->isFloatTy() &&
                            BC->getDestTy()->isIntegerTy(32);
            hasDoubleTerm |= BC->getName().starts_with("morok.path.seed.fp") &&
                             BC->getSrcTy()->isDoubleTy() &&
                             BC->getDestTy()->isIntegerTy(64);
        }
        hasSeedMix |= I.getName().starts_with("morok.path.seed.mix");
        hasIndirectBr |= isa<IndirectBrInst>(&I);
    }

    CHECK(hasFloatTerm);
    CHECK(hasDoubleTerm);
    CHECK(hasSeedMix);
    CHECK(hasIndirectBr);
    CHECK(countNamedAllocas(*F, "morok.path.scratch") == 1u);
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

TEST_CASE("mqGateFunction emits planted quadratic gate and decoy path") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @mq_branch(i32 %a, i32 %b) {
entry:
  %mix = xor i32 %a, %b
  %cond = icmp ult i32 %mix, 100
  br i1 %cond, label %then, label %else
then:
  %x = add i32 %mix, 7
  ret i32 %x
else:
  %y = sub i32 %mix, 3
  ret i32 %y
}
)ir");
    Function *F = M->getFunction("mq_branch");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(0x51f7);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::mqGateFunction(*F,
                                        {/*probability=*/100, /*vars=*/8,
                                         /*eqs=*/6, /*density=*/60,
                                         /*max_gates=*/1, /*fold_diff=*/true},
                                        rng));

    CHECK(countGlobals(*M, "morok.mq.sys") == 1u);

    bool hasGate = false;
    bool hasFail = false;
    bool hasDecoyStore = false;
    std::size_t mqAnds = 0;
    std::size_t mqXors = 0;
    std::size_t mqIcmps = 0;
    for (BasicBlock &BB : *F) {
        hasFail |= BB.getName().starts_with("morok.mq.fail");
        for (Instruction &I : BB) {
            if (I.getName().starts_with("morok.mq.gate"))
                hasGate = true;
            if (I.getName().starts_with("morok.mq.term"))
                ++mqAnds;
            if (I.getName().starts_with("morok.mq.form"))
                ++mqXors;
            if (auto *Cmp = dyn_cast<ICmpInst>(&I))
                if (Cmp->getName().starts_with("morok.mq.eq"))
                    ++mqIcmps;
            if (auto *Store = dyn_cast<StoreInst>(&I))
                hasDecoyStore |=
                    Store->isVolatile() &&
                    Store->getPointerOperand()->getName().starts_with(
                        "morok.mq.scratch");
        }
    }

    CHECK(hasGate);
    CHECK(hasFail);
    CHECK(hasDecoyStore);
    CHECK(mqAnds > 0u);
    CHECK(mqXors > 0u);
    CHECK(mqIcmps == 6u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("mqGateFunction extracts floating input bits") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @mq_float(float %a, double %b) {
entry:
  %b32 = fptrunc double %b to float
  %mix = fadd float %a, %b32
  %cond = fcmp olt float %mix, %a
  br i1 %cond, label %then, label %else
then:
  ret i32 1
else:
  ret i32 0
}
)ir");
    Function *F = M->getFunction("mq_float");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(0x51f71);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::mqGateFunction(*F,
                                        {/*probability=*/100, /*vars=*/8,
                                         /*eqs=*/6, /*density=*/60,
                                         /*max_gates=*/1, /*fold_diff=*/true},
                                        rng));

    bool hasGate = false;
    bool hasFpBitcast = false;
    bool hasInputBit = false;
    for (Instruction &I : instructions(*F)) {
        hasGate |= I.getName().starts_with("morok.mq.gate");
        hasInputBit |= I.getName().starts_with("morok.mq.input.bit");
        if (auto *BC = dyn_cast<BitCastInst>(&I))
            hasFpBitcast |= BC->getName().starts_with("morok.mq.arg.fp") &&
                            (BC->getSrcTy()->isFloatTy() ||
                             BC->getSrcTy()->isDoubleTy()) &&
                            BC->getDestTy()->isIntegerTy();
    }

    CHECK(hasGate);
    CHECK(hasFpBitcast);
    CHECK(hasInputBit);
    CHECK(countGlobals(*M, "morok.mq.sys") == 1u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("mqGateFunction honors probability and max gate caps") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @mq_off(i32 %a, i32 %b) {
entry:
  %cond = icmp eq i32 %a, %b
  br i1 %cond, label %t, label %f
t:
  ret i32 1
f:
  ret i32 0
}
)ir");
    Function *F = M->getFunction("mq_off");
    REQUIRE(F);

    auto engine = morok::core::Xoshiro256pp::fromSeed(0x51f8);
    morok::ir::IRRandom rng(engine);
    CHECK_FALSE(morok::passes::mqGateFunction(
        *F,
        {/*probability=*/0, /*vars=*/8, /*eqs=*/6, /*density=*/60,
         /*max_gates=*/1, /*fold_diff=*/true},
        rng));
    CHECK(countGlobals(*M, "morok.mq.sys") == 0u);
    CHECK_FALSE(verifyModule(*M, &errs()));

    auto M2 = parse(ctx, R"ir(
define i32 @mq_cap(i32 %a, i32 %b) {
entry:
  %cond = icmp eq i32 %a, %b
  br i1 %cond, label %t, label %f
t:
  ret i32 1
f:
  ret i32 0
}
)ir");
    Function *F2 = M2->getFunction("mq_cap");
    REQUIRE(F2);
    CHECK_FALSE(morok::passes::mqGateFunction(
        *F2,
        {/*probability=*/100, /*vars=*/8, /*eqs=*/6, /*density=*/60,
         /*max_gates=*/0, /*fold_diff=*/true},
        rng));
    CHECK(countGlobals(*M2, "morok.mq.sys") == 0u);
    CHECK_FALSE(verifyModule(*M2, &errs()));
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
    CHECK(M->getGlobalVariable("morok.trace.latent", true) != nullptr);
    CHECK(M->getFunction("llvm.trap") == nullptr);

    std::size_t guards = 0;
    std::size_t expectedPhis = 0;
    std::size_t volatileLoads = 0;
    std::size_t volatileStores = 0;
    std::size_t recordBlocks = 0;
    std::size_t delayedFires = 0;
    std::size_t delayedBranchKeys = 0;
    std::size_t delayedReturnKeys = 0;
    std::size_t delayedSwitchKeys = 0;
    std::size_t edgeMixes = 0;
    std::size_t valueTerms = 0;
    for (BasicBlock &BB : *F) {
        recordBlocks +=
            BB.getName().starts_with("morok.trace.record") ? 1u : 0u;
        for (Instruction &I : BB) {
            if (I.getName().starts_with("morok.trace.guard"))
                ++guards;
            if (I.getName().starts_with("morok.trace.expected"))
                ++expectedPhis;
            if (I.getName().starts_with("morok.trace.edge.mix"))
                ++edgeMixes;
            if (I.getName().starts_with("morok.trace.delay.fire"))
                ++delayedFires;
            if (I.getName().starts_with("morok.trace.value.bits"))
                ++valueTerms;
            if (auto *LI = dyn_cast<LoadInst>(&I))
                volatileLoads += LI->isVolatile() ? 1u : 0u;
            if (auto *SI = dyn_cast<StoreInst>(&I))
                volatileStores += SI->isVolatile() ? 1u : 0u;
            if (auto *BI = dyn_cast<BranchInst>(&I))
                if (BI->isConditional() &&
                    BI->getCondition()->getName().starts_with(
                        "morok.trace.delay.branch.cond"))
                    ++delayedBranchKeys;
            if (auto *RI = dyn_cast<ReturnInst>(&I))
                if (RI->getReturnValue() &&
                    RI->getReturnValue()->getName().starts_with(
                        "morok.trace.delay.ret"))
                    ++delayedReturnKeys;
            if (auto *SW = dyn_cast<SwitchInst>(&I))
                if (SW->getCondition()->getName().starts_with(
                        "morok.trace.delay.switch.cond"))
                    ++delayedSwitchKeys;
        }
    }
    CHECK(guards >= 4u);
    CHECK(expectedPhis >= 4u);
    CHECK(volatileLoads >= 4u);
    CHECK(volatileStores >= 4u);
    CHECK(recordBlocks >= 4u);
    CHECK(delayedFires >= 1u);
    CHECK(delayedBranchKeys + delayedReturnKeys + delayedSwitchKeys >= 1u);
    CHECK(edgeMixes >= 3u);
    CHECK(valueTerms >= 3u);
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
    CHECK(M->getGlobalVariable("morok.trace.latent", true) == nullptr);
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

TEST_CASE("dispatcherlessRoutingFunction mixes floating live terms") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @threaded_fp(float %a, double %b, i1 %flag) {
entry:
  br i1 %flag, label %body, label %alt
body:
  %b32 = fptrunc double %b to float
  %sum = fadd float %a, %b32
  %cmp = fcmp olt float %sum, %a
  br i1 %cmp, label %left, label %right
left:
  ret i32 1
right:
  ret i32 2
alt:
  ret i32 0
}
)ir");
    Function *F = M->getFunction("threaded_fp");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(1011);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::dispatcherlessRoutingFunction(
        *F, {/*probability=*/100, /*max_routes=*/8, /*max_terms=*/8}, rng));

    bool hasFpTerm = false;
    bool hasTokenMix = false;
    bool hasIndirect = false;
    for (Instruction &I : instructions(*F)) {
        if (auto *BC = dyn_cast<BitCastInst>(&I))
            hasFpTerm |= BC->getName().starts_with("morok.dlf.term.fp") &&
                         (BC->getSrcTy()->isFloatTy() ||
                          BC->getSrcTy()->isDoubleTy()) &&
                         BC->getDestTy()->isIntegerTy();
        hasTokenMix |= I.getName().starts_with("morok.dlf.token.mix");
        hasIndirect |= isa<IndirectBrInst>(&I);
    }

    CHECK(hasFpTerm);
    CHECK(hasTokenMix);
    CHECK(hasIndirect);
    CHECK(M->getGlobalVariable("morok.dlf.table", true) != nullptr);
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

TEST_CASE("dispatcherlessRoutingFunction caps route lowering") {
    LLVMContext ctx;
    auto M = std::make_unique<Module>("dispatch-cap", ctx);
    Function *F = makeBranchChainFunction(*M, 48, "dispatch_many");

    auto engine = morok::core::Xoshiro256pp::fromSeed(1021);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::dispatcherlessRoutingFunction(
        *F, {/*probability=*/100, /*max_routes=*/100, /*max_terms=*/100}, rng));

    std::size_t indirects = 0;
    std::size_t tokenFolds = 0;
    for (Instruction &I : instructions(*F)) {
        indirects += isa<IndirectBrInst>(&I) ? 1u : 0u;
        tokenFolds += I.getName().starts_with("morok.dlf.token.fold") ? 1u : 0u;
    }
    CHECK(indirects == 32u);
    CHECK(tokenFolds <= 32u * 8u);
    CHECK(M->getGlobalVariable("morok.dlf.table", true) != nullptr);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("microcodeStressFunction emits sparse aliased jump-table stress") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @microstress(i32 %a, i32 %b) {
entry:
  %x = add i32 %a, %b
  %c = icmp sgt i32 %x, 17
  br i1 %c, label %left, label %right
left:
  %l = xor i32 %x, %a
  br label %join
right:
  %r = sub i32 %x, %b
  br label %join
join:
  %p = phi i32 [ %l, %left ], [ %r, %right ]
  ret i32 %p
}
)ir");
    Function *F = M->getFunction("microstress");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(411);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::microcodeStressFunction(
        *F,
        {/*probability=*/100, /*max_sites=*/1, /*table_entries=*/16,
         /*decoy_blocks=*/4, /*alias_stores=*/2},
        rng));

    CHECK(countNamedAllocas(*F, "morok.micro.scratch") == 1u);
    CHECK(countGlobals(*M, "morok.micro.seed") == 1u);
    CHECK(countGlobals(*M, "morok.micro.table") == 1u);

    auto *Table = M->getGlobalVariable("morok.micro.table", true);
    REQUIRE(Table);
    auto *ArrTy = dyn_cast<ArrayType>(Table->getValueType());
    REQUIRE(ArrTy);
    CHECK(ArrTy->getNumElements() == 16u);

    unsigned decoys = 0;
    unsigned indirects = 0;
    unsigned destinations = 0;
    unsigned volatileStores = 0;
    bool hasPtrToInt = false;
    bool hasIntToPtr = false;
    bool hasIndex = false;
    for (BasicBlock &BB : *F) {
        const bool IsDecoy = BB.getName().starts_with("morok.micro.decoy");
        if (IsDecoy)
            ++decoys;
        for (Instruction &I : BB) {
            hasIndex |= I.getName().starts_with("morok.micro.index");
            hasPtrToInt |= isa<PtrToIntInst>(&I);
            hasIntToPtr |= isa<IntToPtrInst>(&I);
            if (auto *IB = dyn_cast<IndirectBrInst>(&I)) {
                ++indirects;
                destinations += IB->getNumDestinations();
            }
            if (IsDecoy)
                if (auto *SI = dyn_cast<StoreInst>(&I))
                    volatileStores += SI->isVolatile() ? 1u : 0u;
        }
    }

    CHECK(decoys == 4u);
    CHECK(indirects == 1u);
    CHECK(destinations >= 5u);
    CHECK(volatileStores >= 8u);
    CHECK(hasPtrToInt);
    CHECK(hasIntToPtr);
    CHECK(hasIndex);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("microcodeStressFunction mixes floating live terms") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @microstress_fp(float %a, double %b, i32 %salt) {
entry:
  %b32 = fptrunc double %b to float
  %sum = fadd float %a, %b32
  %bits = bitcast float %sum to i32
  %x = xor i32 %bits, %salt
  %c = icmp sgt i32 %x, 17
  br i1 %c, label %left, label %right
left:
  %l = add i32 %x, %salt
  br label %join
right:
  %r = sub i32 %x, %salt
  br label %join
join:
  %p = phi i32 [ %l, %left ], [ %r, %right ]
  ret i32 %p
}
)ir");
    Function *F = M->getFunction("microstress_fp");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(413);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::microcodeStressFunction(
        *F,
        {/*probability=*/100, /*max_sites=*/1, /*table_entries=*/16,
         /*decoy_blocks=*/4, /*alias_stores=*/2},
        rng));

    bool hasFpTerm = false;
    bool hasMixTerm = false;
    bool hasIndirect = false;
    for (Instruction &I : instructions(*F)) {
        if (auto *BC = dyn_cast<BitCastInst>(&I))
            hasFpTerm |=
                BC->getName().starts_with("morok.micro.term.fp") &&
                (BC->getSrcTy()->isFloatTy() || BC->getSrcTy()->isDoubleTy()) &&
                BC->getDestTy()->isIntegerTy();
        hasMixTerm |= I.getName().starts_with("morok.micro.mix.term");
        hasIndirect |= isa<IndirectBrInst>(&I);
    }

    CHECK(hasFpTerm);
    CHECK(hasMixTerm);
    CHECK(hasIndirect);
    CHECK(countGlobals(*M, "morok.micro.seed") == 1u);
    CHECK(countGlobals(*M, "morok.micro.table") == 1u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("microcodeStressFunction honors zero probability") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @microstress_off(i32 %a, i32 %b) {
entry:
  %x = add i32 %a, %b
  ret i32 %x
}
)ir");
    Function *F = M->getFunction("microstress_off");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(412);
    morok::ir::IRRandom rng(engine);

    CHECK_FALSE(morok::passes::microcodeStressFunction(
        *F,
        {/*probability=*/0, /*max_sites=*/1, /*table_entries=*/16,
         /*decoy_blocks=*/4, /*alias_stores=*/2},
        rng));
    CHECK(countNamedAllocas(*F, "morok.micro.scratch") == 0u);
    CHECK(countGlobals(*M, "morok.micro.table") == 0u);
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

TEST_CASE("indirectBranchFunction replaces switches with indirectbr") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @indirect_switch(i32 %x) {
entry:
  switch i32 %x, label %def [
    i32 1, label %one
    i32 2, label %two
    i32 3, label %one
  ]
one:
  ret i32 10
two:
  ret i32 20
def:
  ret i32 0
}
)ir");
    Function *F = M->getFunction("indirect_switch");
    REQUIRE(F);
    auto engine = morok::core::Xoshiro256pp::fromSeed(24);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::indirectBranchFunction(*F, {/*prob=*/100}, rng));
    CHECK(countGlobals(*M, "morok.ibtable") == 1u);
    unsigned switchCount = 0;
    unsigned indirectCount = 0;
    unsigned destinationCount = 0;
    for (Instruction &I : instructions(*F)) {
        if (isa<SwitchInst>(&I))
            ++switchCount;
        if (auto *IB = dyn_cast<IndirectBrInst>(&I)) {
            ++indirectCount;
            destinationCount = IB->getNumDestinations();
        }
    }
    CHECK(switchCount == 0u);
    CHECK(indirectCount == 1u);
    CHECK(destinationCount == 3u);
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

TEST_CASE("functionWrapModule proxies a variadic call with concrete args") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare i32 @printf(ptr, ...)
@.fmt = private constant [4 x i8] c"%d\0A\00"

define i32 @caller(i32 %x) {
  %r = call i32 (ptr, ...) @printf(ptr @.fmt, i32 %x)
  ret i32 %r
}
)ir");
    Function *Caller = M->getFunction("caller");
    REQUIRE(Caller);

    auto engine = morok::core::Xoshiro256pp::fromSeed(253);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::functionWrapModule(*M, {/*prob=*/100, /*times=*/1},
                                            rng));

    Function *Wrap = nullptr;
    for (Function &F : *M)
        if (F.getName().starts_with("morok.wrap"))
            Wrap = &F;

    REQUIRE(Wrap);
    CHECK_FALSE(Wrap->getFunctionType()->isVarArg());
    CHECK(Wrap->arg_size() == 2u);
    CHECK(countCallsTo(*Caller, "printf") == 0u);
    CHECK(countCallsTo(*Wrap, "printf") == 1u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("functionWrapModule proxies an invoke and preserves EH edges") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare i32 @may_throw(i32)
declare i32 @__gxx_personality_v0(...)

define i32 @caller(i32 %x) personality ptr @__gxx_personality_v0 {
entry:
  %r = invoke i32 @may_throw(i32 %x)
          to label %ok unwind label %lpad
ok:
  ret i32 %r
lpad:
  %lp = landingpad { ptr, i32 }
          cleanup
  ret i32 -1
}
)ir");
    Function *F = M->getFunction("caller");
    REQUIRE(F);
    BasicBlock *Ok = nullptr;
    BasicBlock *LPad = nullptr;
    for (BasicBlock &BB : *F) {
        if (BB.getName() == "ok")
            Ok = &BB;
        if (BB.getName() == "lpad")
            LPad = &BB;
    }
    REQUIRE(Ok);
    REQUIRE(LPad);

    auto engine = morok::core::Xoshiro256pp::fromSeed(252);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::functionWrapModule(*M, {/*prob=*/100, /*times=*/1},
                                            rng));

    InvokeInst *WrappedInvoke = nullptr;
    for (Instruction &I : instructions(*F))
        if (auto *II = dyn_cast<InvokeInst>(&I))
            WrappedInvoke = II;

    REQUIRE(WrappedInvoke);
    REQUIRE(WrappedInvoke->getCalledFunction());
    CHECK(WrappedInvoke->getCalledFunction()->getName().starts_with(
        "morok.wrap"));
    CHECK(WrappedInvoke->getNormalDest() == Ok);
    CHECK(WrappedInvoke->getUnwindDest() == LPad);
    CHECK(countFunctions(*M, "morok.wrap") == 1u);
    CHECK(countCallsTo(*F, "may_throw") == 0u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("functionWrapModule caps generated forwarders") {
    LLVMContext ctx;
    auto M = std::make_unique<Module>("wrap-cap", ctx);
    makeRepeatedVoidCalls(*M, 300);

    auto engine = morok::core::Xoshiro256pp::fromSeed(251);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::functionWrapModule(
        *M, {/*probability=*/100, /*times=*/1, /*max_wrappers=*/1000}, rng));

    CHECK(countFunctions(*M, "morok.wrap") == 256u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE(
    "adversarialFunctionMergingModule fuses functions behind a selector") {
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
        *M,
        {/*probability=*/100, /*max_groups=*/1, /*max_functions=*/2,
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
                loadsSelector |= LI->isVolatile() &&
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

TEST_CASE(
    "adversarialFunctionMergingModule outlines sub-byte integer fragments") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i1 @bool_a(i1 %a, i1 %b) {
entry:
  %x = xor i1 %a, %b
  %y = and i1 %x, %a
  ret i1 %y
}

define i1 @bool_b(i1 %a, i1 %b) {
entry:
  %x = or i1 %a, %b
  %y = xor i1 %x, %b
  ret i1 %y
}

define i4 @nib_a(i4 %a, i4 %b) {
entry:
  %x = add i4 %a, %b
  %y = xor i4 %x, 3
  ret i4 %y
}

define i4 @nib_b(i4 %a, i4 %b) {
entry:
  %x = mul i4 %a, %b
  %y = or i4 %x, 1
  ret i4 %y
}
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(223);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::adversarialFunctionMergingModule(
        *M,
        {/*probability=*/100, /*max_groups=*/2, /*max_functions=*/2,
         /*outline_probability=*/100, /*max_outlines=*/4},
        rng));

    CHECK(countFunctions(*M, "morok.afm.dispatch") == 2u);
    CHECK(countFunctions(*M, "morok.afm.impl") == 4u);

    bool hasI1Helper = false;
    bool hasI4Helper = false;
    unsigned implOutlineCalls = 0;
    for (Function &F : *M) {
        if (F.getName().starts_with("morok.afm.outline")) {
            auto *RetTy = dyn_cast<IntegerType>(F.getReturnType());
            REQUIRE(RetTy);
            hasI1Helper |= RetTy->getBitWidth() == 1;
            hasI4Helper |= RetTy->getBitWidth() == 4;
        }
        if (!F.getName().starts_with("morok.afm.impl"))
            continue;
        for (Instruction &I : instructions(F))
            if (auto *CI = dyn_cast<CallInst>(&I))
                if (Function *Callee = CI->getCalledFunction())
                    if (Callee->getName().starts_with("morok.afm.outline"))
                        ++implOutlineCalls;
    }

    CHECK(hasI1Helper);
    CHECK(hasI4Helper);
    CHECK(implOutlineCalls >= 4u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("adversarialFunctionMergingModule outlines shift and division ops") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @divshift_a(i32 %a, i32 %b) {
entry:
  %q = udiv i32 %a, %b
  %r = srem i32 %a, %b
  %s = shl i32 %q, 3
  %t = lshr i32 %r, 2
  %u = xor i32 %s, %t
  ret i32 %u
}

define i32 @divshift_b(i32 %a, i32 %b) {
entry:
  %q = sdiv i32 %a, %b
  %r = urem i32 %a, %b
  %s = ashr i32 %q, 1
  %t = add i32 %r, %s
  ret i32 %t
}
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(224);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::adversarialFunctionMergingModule(
        *M,
        {/*probability=*/100, /*max_groups=*/1, /*max_functions=*/2,
         /*outline_probability=*/100, /*max_outlines=*/8},
        rng));

    // Shift and division fragments are now outline-eligible: helper calls must
    // have been planted in the merged implementations, and the module stays
    // well-formed.
    unsigned implOutlineCalls = 0;
    for (Function &F : *M) {
        if (!F.getName().starts_with("morok.afm.impl"))
            continue;
        for (Instruction &I : instructions(F))
            if (auto *CI = dyn_cast<CallInst>(&I))
                if (Function *Callee = CI->getCalledFunction())
                    if (Callee->getName().starts_with("morok.afm.outline"))
                        ++implOutlineCalls;
    }
    CHECK(implOutlineCalls >= 1u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("adversarialFunctionMergingModule outlines integer comparisons") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i1 @cmp_a(i8 %a, i8 %b) {
entry:
  %x = icmp ult i8 %a, %b
  ret i1 %x
}

define i1 @cmp_b(i8 %a, i8 %b) {
entry:
  %x = icmp sge i8 %a, %b
  ret i1 %x
}
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(224);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::adversarialFunctionMergingModule(
        *M,
        {/*probability=*/100, /*max_groups=*/1, /*max_functions=*/2,
         /*outline_probability=*/100, /*max_outlines=*/2},
        rng));

    CHECK(countFunctions(*M, "morok.afm.dispatch") == 1u);
    CHECK(countFunctions(*M, "morok.afm.impl") == 2u);

    bool hasIcmpOutline = false;
    bool helperHasVolatileKey = false;
    unsigned implIcmpOutlineCalls = 0;
    for (Function &F : *M) {
        if (F.getName().starts_with("morok.afm.outline.icmp")) {
            hasIcmpOutline = true;
            auto *RetTy = dyn_cast<IntegerType>(F.getReturnType());
            REQUIRE(RetTy);
            CHECK(RetTy->getBitWidth() == 1);
            CHECK(F.arg_size() == 2u);
            for (Argument &A : F.args()) {
                auto *ArgTy = dyn_cast<IntegerType>(A.getType());
                REQUIRE(ArgTy);
                CHECK(ArgTy->getBitWidth() == 8);
            }
            for (Instruction &I : instructions(F))
                if (auto *LI = dyn_cast<LoadInst>(&I))
                    helperHasVolatileKey |=
                        LI->isVolatile() &&
                        LI->getPointerOperand()->getName().starts_with(
                            "morok.afm.key.outline.icmp");
        }

        if (!F.getName().starts_with("morok.afm.impl"))
            continue;
        for (Instruction &I : instructions(F))
            if (auto *CI = dyn_cast<CallInst>(&I))
                if (Function *Callee = CI->getCalledFunction())
                    if (Callee->getName().starts_with(
                            "morok.afm.outline.icmp"))
                        ++implIcmpOutlineCalls;
    }

    CHECK(hasIcmpOutline);
    CHECK(helperHasVolatileKey);
    CHECK(implIcmpOutlineCalls == 2u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("adversarialFunctionMergingModule outlines floating operations") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define float @fp_a(float %a, float %b) {
entry:
  %x = fadd float %a, %b
  %y = fmul float %x, %a
  ret float %y
}

define float @fp_b(float %a, float %b) {
entry:
  %x = fsub float %a, %b
  %y = fdiv float %x, %b
  ret float %y
}
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(225);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::adversarialFunctionMergingModule(
        *M,
        {/*probability=*/100, /*max_groups=*/1, /*max_functions=*/2,
         /*outline_probability=*/100, /*max_outlines=*/4},
        rng));

    CHECK(countFunctions(*M, "morok.afm.dispatch") == 1u);
    CHECK(countFunctions(*M, "morok.afm.impl") == 2u);

    bool hasFloatOutline = false;
    bool helperHasBitCarrier = false;
    unsigned implFloatOutlineCalls = 0;
    for (Function &F : *M) {
        if (F.getName().starts_with("morok.afm.outline.f")) {
            hasFloatOutline = true;
            CHECK(F.getReturnType()->isFloatTy());
            CHECK(F.arg_size() == 2u);
            for (Argument &A : F.args())
                CHECK(A.getType()->isFloatTy());
            for (Instruction &I : instructions(F))
                if (auto *BC = dyn_cast<BitCastInst>(&I))
                    helperHasBitCarrier |=
                        BC->getSrcTy()->isFloatTy() ||
                        BC->getDestTy()->isFloatTy();
        }

        if (!F.getName().starts_with("morok.afm.impl"))
            continue;
        for (Instruction &I : instructions(F))
            if (auto *CI = dyn_cast<CallInst>(&I))
                if (Function *Callee = CI->getCalledFunction())
                    if (Callee->getName().starts_with("morok.afm.outline.f"))
                        ++implFloatOutlineCalls;
    }

    CHECK(hasFloatOutline);
    CHECK(helperHasBitCarrier);
    CHECK(implFloatOutlineCalls == 4u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("adversarialFunctionMergingModule outlines floating comparisons") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i1 @fcmp_a(double %a, double %b) {
entry:
  %x = fcmp olt double %a, %b
  ret i1 %x
}

define i1 @fcmp_b(double %a, double %b) {
entry:
  %x = fcmp uno double %a, %b
  ret i1 %x
}
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(226);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::adversarialFunctionMergingModule(
        *M,
        {/*probability=*/100, /*max_groups=*/1, /*max_functions=*/2,
         /*outline_probability=*/100, /*max_outlines=*/2},
        rng));

    CHECK(countFunctions(*M, "morok.afm.dispatch") == 1u);
    CHECK(countFunctions(*M, "morok.afm.impl") == 2u);

    bool hasFcmpOutline = false;
    bool helperHasVolatileKey = false;
    unsigned implFcmpOutlineCalls = 0;
    for (Function &F : *M) {
        if (F.getName().starts_with("morok.afm.outline.fcmp")) {
            hasFcmpOutline = true;
            CHECK(F.getReturnType()->isIntegerTy(1));
            CHECK(F.arg_size() == 2u);
            for (Argument &A : F.args())
                CHECK(A.getType()->isDoubleTy());
            for (Instruction &I : instructions(F))
                if (auto *LI = dyn_cast<LoadInst>(&I))
                    helperHasVolatileKey |=
                        LI->isVolatile() &&
                        LI->getPointerOperand()->getName().starts_with(
                            "morok.afm.key.outline.fcmp");
        }

        if (!F.getName().starts_with("morok.afm.impl"))
            continue;
        for (Instruction &I : instructions(F))
            if (auto *CI = dyn_cast<CallInst>(&I))
                if (Function *Callee = CI->getCalledFunction())
                    if (Callee->getName().starts_with(
                            "morok.afm.outline.fcmp"))
                        ++implFcmpOutlineCalls;
    }

    CHECK(hasFcmpOutline);
    CHECK(helperHasVolatileKey);
    CHECK(implFcmpOutlineCalls == 2u);
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
        *M,
        {/*probability=*/0, /*max_groups=*/1, /*max_functions=*/2,
         /*outline_probability=*/100, /*max_outlines=*/4},
        rng));
    CHECK(countFunctions(*M, "morok.afm.dispatch") == 0u);
    CHECK(countFunctions(*M, "morok.afm.impl") == 0u);
    CHECK(countGlobals(*M, "morok.afm.selector") == 0u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("adversarialSelfTuneModule searches candidates and improves score") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @tune_target(i32 %x, i32 %y) {
entry:
  %slot = alloca i32, align 4
  %seed = add i32 %x, %y
  store i32 %seed, ptr %slot, align 4
  %live = load i32, ptr %slot, align 4
  %cmp = icmp ult i32 %live, 19
  br i1 %cmp, label %left, label %right
left:
  %a = mul i32 %live, 17
  %b = xor i32 %a, %y
  br label %merge
right:
  %c = sub i32 %live, %x
  %d = or i32 %c, 5
  br label %merge
merge:
  %p = phi i32 [ %b, %left ], [ %d, %right ]
  %r = add i32 %p, 11
  ret i32 %r
}

define i32 @tune_side(i32 %x) {
entry:
  %a = add i32 %x, 3
  %b = xor i32 %a, 9
  ret i32 %b
}
)ir");
    const auto Before = morok::passes::adversarialScoreModule(*M);
    const std::size_t IndirectBefore = countOpcode(*M, Instruction::IndirectBr);

    auto engine = morok::core::Xoshiro256pp::fromSeed(450);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::adversarialSelfTuneModule(
        *M,
        {/*max_candidates=*/4, /*max_candidate_passes=*/3,
         /*score_floor=*/1, /*emit_marker=*/true},
        rng));

    const auto After = morok::passes::adversarialScoreModule(*M);
    CHECK(After.total > Before.total);
    CHECK(After.cfg_recovery >= Before.cfg_recovery);
    CHECK(After.lvar_recovery >= Before.lvar_recovery);
    CHECK(countGlobals(*M, "morok.tune.choice") == 1u);
    CHECK(countGlobals(*M, "morok.tune.score") == 1u);
    CHECK(countOpcode(*M, Instruction::IndirectBr) >= IndirectBefore);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("adversarialSelfTuneModule honors disabled search") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i32 @tune_off(i32 %x, i32 %y) {
entry:
  %a = add i32 %x, %y
  ret i32 %a
}
)ir");
    const auto Before = morok::passes::adversarialScoreModule(*M);
    auto engine = morok::core::Xoshiro256pp::fromSeed(451);
    morok::ir::IRRandom rng(engine);

    CHECK_FALSE(morok::passes::adversarialSelfTuneModule(
        *M,
        {/*max_candidates=*/0, /*max_candidate_passes=*/3,
         /*score_floor=*/1, /*emit_marker=*/true},
        rng));
    const auto After = morok::passes::adversarialScoreModule(*M);
    CHECK(After.total == Before.total);
    CHECK(countGlobals(*M, "morok.tune.choice") == 0u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("adversarialSelfTuneModule refuses oversized modules") {
    LLVMContext ctx;
    auto M = std::make_unique<Module>("large-tune", ctx);
    makeLargeLinearFunction(*M, 25000);

    auto engine = morok::core::Xoshiro256pp::fromSeed(452);
    morok::ir::IRRandom rng(engine);
    CHECK_FALSE(morok::passes::adversarialSelfTuneModule(
        *M,
        {/*max_candidates=*/4, /*max_candidate_passes=*/3,
         /*score_floor=*/1, /*emit_marker=*/true},
        rng));
    CHECK(countGlobals(*M, "morok.tune.choice") == 0u);
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
        *M,
        {/*function_order=*/true, /*block_order=*/true,
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

TEST_CASE("perBuildPolymorphismModule anchors sub-byte integer returns") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define i1 @poly_bool(i1 %a, i1 %b) {
entry:
  %x = xor i1 %a, %b
  ret i1 %x
}

define i4 @poly_nibble(i4 %a, i4 %b) {
entry:
  %x = add i4 %a, %b
  ret i4 %x
}
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(305);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::perBuildPolymorphismModule(
        *M,
        {/*function_order=*/false, /*block_order=*/false,
         /*anchor_probability=*/100, /*max_anchors=*/4},
        rng));

    Function *Bool = M->getFunction("poly_bool");
    Function *Nibble = M->getFunction("poly_nibble");
    REQUIRE(Bool);
    REQUIRE(Nibble);

    bool hasI1Anchor = false;
    bool hasI4Anchor = false;
    for (Instruction &I : instructions(*Bool))
        hasI1Anchor |= I.getName().starts_with("morok.poly.value") &&
                       I.getType()->isIntegerTy(1);
    for (Instruction &I : instructions(*Nibble))
        hasI4Anchor |= I.getName().starts_with("morok.poly.value") &&
                       I.getType()->isIntegerTy(4);

    CHECK(hasI1Anchor);
    CHECK(hasI4Anchor);
    CHECK(countGlobals(*M, "morok.poly.salt") == 2u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("perBuildPolymorphismModule anchors floating scalar returns") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
define float @poly_float(float %a, float %b) {
entry:
  %x = fadd float %a, %b
  ret float %x
}

define double @poly_double(double %a, double %b) {
entry:
  %x = fmul double %a, %b
  ret double %x
}
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(306);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::perBuildPolymorphismModule(
        *M,
        {/*function_order=*/false, /*block_order=*/false,
         /*anchor_probability=*/100, /*max_anchors=*/4},
        rng));

    Function *FloatFn = M->getFunction("poly_float");
    Function *DoubleFn = M->getFunction("poly_double");
    REQUIRE(FloatFn);
    REQUIRE(DoubleFn);

    bool hasFloatAnchor = false;
    bool hasDoubleAnchor = false;
    bool hasFloatCarrier = false;
    bool hasDoubleCarrier = false;
    for (Instruction &I : instructions(*FloatFn)) {
        hasFloatAnchor |= I.getName().starts_with("morok.poly.value") &&
                          I.getType()->isFloatTy();
        if (auto *BC = dyn_cast<BitCastInst>(&I))
            hasFloatCarrier |=
                BC->getSrcTy()->isFloatTy() && BC->getDestTy()->isIntegerTy(32);
    }
    for (Instruction &I : instructions(*DoubleFn)) {
        hasDoubleAnchor |= I.getName().starts_with("morok.poly.value") &&
                           I.getType()->isDoubleTy();
        if (auto *BC = dyn_cast<BitCastInst>(&I))
            hasDoubleCarrier |= BC->getSrcTy()->isDoubleTy() &&
                                BC->getDestTy()->isIntegerTy(64);
    }

    CHECK(hasFloatAnchor);
    CHECK(hasDoubleAnchor);
    CHECK(hasFloatCarrier);
    CHECK(hasDoubleCarrier);
    CHECK(countGlobals(*M, "morok.poly.salt") == 2u);
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
            *M,
            {/*function_order=*/true, /*block_order=*/true,
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
        *M,
        {/*function_order=*/false, /*block_order=*/false,
         /*anchor_probability=*/0, /*max_anchors=*/0},
        rng));
    CHECK(countGlobals(*M, "morok.poly.salt") == 0u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("vtableIntegrityModule guards Itanium virtual dispatches") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
target datalayout = "e-p:64:64"
@_ZTV4Base = linkonce_odr unnamed_addr constant { [4 x ptr] } { [4 x ptr] [ptr null, ptr null, ptr @virt0, ptr @virt1] }

define i32 @virt0(ptr %this) {
entry:
  ret i32 7
}

define i32 @virt1(ptr %this) {
entry:
  ret i32 11
}

define void @ctor(ptr %obj) {
entry:
  store ptr getelementptr inbounds ({ [4 x ptr] }, ptr @_ZTV4Base, i64 0, i32 0, i64 2), ptr %obj
  ret void
}

define i32 @dispatch_ptr_gep(ptr %obj) {
entry:
  %vptr = load ptr, ptr %obj
  %slotp = getelementptr ptr, ptr %vptr, i64 1
  %fn = load ptr, ptr %slotp
  %r = call i32 %fn(ptr %obj)
  ret i32 %r
}

define i32 @dispatch_byte_gep(ptr %obj) {
entry:
  %vptr = load ptr, ptr %obj
  %slotp = getelementptr i8, ptr %vptr, i64 0
  %fn = load ptr, ptr %slotp
  %r = call i32 %fn(ptr %obj)
  ret i32 %r
}
)ir");

    CHECK(morok::passes::vtableIntegrityModule(*M));
    CHECK(M->getFunction("morok.vti.verify") != nullptr);
    CHECK(countUserCallsTo(*M, "morok.vti.verify") == 2u);
    CHECK(countGlobals(*M, "morok.vti.") == 4u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("vtableIntegrityModule ignores non-vptr indirect calls") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
target datalayout = "e-p:64:64"
define i32 @callback(ptr %slot) {
entry:
  %fn = load ptr, ptr %slot
  %r = call i32 %fn()
  ret i32 %r
}
)ir");

    CHECK_FALSE(morok::passes::vtableIntegrityModule(*M));
    CHECK(M->getFunction("morok.vti.verify") == nullptr);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("vtableIntegrityModule skips mismatched slot call types") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
target datalayout = "e-p:64:64"
@_ZTV4Base = linkonce_odr unnamed_addr constant { [3 x ptr] } { [3 x ptr] [ptr null, ptr null, ptr @virt0] }

define i32 @virt0(ptr %this) {
entry:
  ret i32 7
}

define i64 @callback_table(ptr %obj) {
entry:
  %tbl = load ptr, ptr %obj
  %slotp = getelementptr ptr, ptr %tbl, i64 0
  %fn = load ptr, ptr %slotp
  %r = call i64 %fn()
  ret i64 %r
}
)ir");

    CHECK_FALSE(morok::passes::vtableIntegrityModule(*M));
    CHECK(M->getFunction("morok.vti.verify") == nullptr);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("stringEncryptModule materializes used strings on the stack") {
    LLVMContext ctx;
    auto M = std::make_unique<Module>("stack-strings", ctx);
    M->setTargetTriple(Triple("x86_64-unknown-linux-gnu"));
    GlobalVariable *Text =
        makePrivateString(*M, "msg.str", "callsite-secret");
    Function *Caller = makeExternalCallFunction(*M, Text);

    auto engine = morok::core::Xoshiro256pp::fromSeed(305);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::stringEncryptModule(*M, {/*probability=*/100}, rng));

    GlobalVariable *Msg = M->getGlobalVariable("msg.str", true);
    REQUIRE(Msg);
    CHECK(Msg->isConstant());
    CHECK_FALSE(hasReadableByteString(*M, "callsite-secret"));
    CHECK(countFunctions(*M, "morok.strdec") == 0u);
    CHECK(countNamedAllocas(*Caller, "morok.str.stack.buf") >= 1u);
    CHECK(countNamedInstructions(*Caller, "morok.str.stack.ptr") >= 1u);
    bool stackHelperHasBarrier = false;
    bool stackHelperHasMixer = false;
    for (Function &F : *M)
        if (F.getName().starts_with("morok.strsite")) {
            stackHelperHasBarrier |= hasInlineAsmCall(F);
            stackHelperHasMixer |=
                countNamedAllocas(F, "morok.str.mix") >= 1u;
        }
    CHECK(stackHelperHasBarrier);
    CHECK(stackHelperHasMixer);

    bool callStillUsesGlobal = false;
    for (Instruction &I : instructions(*Caller))
        if (auto *CI = dyn_cast<CallInst>(&I))
            for (Value *Arg : CI->args())
                if (auto *C = dyn_cast<Constant>(Arg))
                    callStillUsesGlobal |= constantReferencesGlobal(C, Msg);
    CHECK_FALSE(callStillUsesGlobal);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("stringEncryptModule uses stack decrypt loops for long callsite strings") {
    LLVMContext ctx;
    auto M = std::make_unique<Module>("stack-long-strings", ctx);
    const std::string LargeText(256, 'z');
    GlobalVariable *Text = makePrivateString(*M, "long.str", LargeText);
    Function *Caller = makeExternalCallFunction(*M, Text);

    auto engine = morok::core::Xoshiro256pp::fromSeed(306);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::stringEncryptModule(*M, {/*probability=*/100}, rng));

    CHECK(countFunctions(*M, "morok.strdec") == 0u);
    CHECK(countFunctions(*M, "morok.strsite") >= 1u);
    bool sawStackLoop = false;
    bool sawStackPhi = false;
    bool sawStackMixer = false;
    (void)Caller;
    for (Function &F : *M)
        if (F.getName().starts_with("morok.strsite"))
            for (BasicBlock &BB : F) {
                sawStackLoop |= BB.getName().starts_with("morok.str.stack.loop");
                for (Instruction &I : BB)
                    sawStackPhi |=
                        I.getName().starts_with("morok.str.stack.i");
                sawStackMixer |=
                    countNamedAllocas(F, "morok.str.stack.mix") >= 1u;
            }
    CHECK(sawStackLoop);
    CHECK(sawStackPhi);
    CHECK(sawStackMixer);
    CHECK_FALSE(hasReadableByteString(*M, LargeText));
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("stringEncryptModule falls back to per-string decryptors") {
    LLVMContext ctx;
    auto M = std::make_unique<Module>("strings", ctx);
    M->setTargetTriple(Triple("x86_64-unknown-linux-gnu"));
    makePrivateString(*M, "small.str", "small");
    const std::string LargeText(2048, 'x');
    makePrivateString(*M, "large.str", LargeText);

    auto engine = morok::core::Xoshiro256pp::fromSeed(307);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::stringEncryptModule(*M, {/*probability=*/100}, rng));

    // Length-hiding may replace the globals with padded ones; re-fetch by name.
    GlobalVariable *Small = M->getGlobalVariable("small.str", true);
    GlobalVariable *Large = M->getGlobalVariable("large.str", true);
    REQUIRE(Small);
    REQUIRE(Large);

    // EVERY string is encrypted — readable strings are toxic.  With no safe
    // instruction use to rewrite, the pass keeps the per-string constructor
    // fallback: the small one unrolled, the long one loop-based.
    CHECK_FALSE(Small->isConstant());
    CHECK_FALSE(Large->isConstant());
    // The small string's stored size is padded past its true length (6).
    CHECK(cast<ArrayType>(Small->getValueType())->getNumElements() > 6u);

    // The plaintext is gone, and the encryption is driven by the runtime-opaque
    // module seed plus dedicated decryptors (no shared gf8mul / key globals).
    if (auto *CDA = dyn_cast<ConstantDataArray>(Small->getInitializer()))
        CHECK(CDA->getRawDataValues().find("small") == StringRef::npos);
    CHECK(countGlobals(*M, "morok.cloak.seed") == 1u);
    CHECK(countGlobals(*M, "morok.k1") == 0u);
    CHECK(M->getFunction("morok.gf8mul") == nullptr);
    CHECK(countFunctions(*M, "morok.strdec") == 2u);

    // The long string's decryptor is a loop (has a PHI induction variable),
    // not a fully unrolled chain.
    bool sawLoopDecryptor = false;
    bool sawStaticAnalysisBarrier = false;
    bool sawDecryptorMixer = false;
    for (Function &F : *M)
        if (F.getName().starts_with("morok.strdec")) {
            sawStaticAnalysisBarrier |= hasInlineAsmCall(F);
            sawDecryptorMixer |=
                countNamedAllocas(F, "morok.str.mix") >= 1u ||
                countNamedAllocas(F, "morok.str.loop.mix") >= 1u;
            for (Instruction &I : instructions(F))
                sawLoopDecryptor |= isa<PHINode>(&I);
        }
    CHECK(sawLoopDecryptor);
    CHECK(sawStaticAnalysisBarrier);
    CHECK(sawDecryptorMixer);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("stringEncryptModule leaves generated decoy strings as plaintext bait") {
    LLVMContext ctx;
    auto M = std::make_unique<Module>("decoy-strings", ctx);
    M->setTargetTriple(Triple("x86_64-unknown-linux-gnu"));
    makePrivateString(*M, "morok.decoy.str.test", "decoy-visible");

    auto engine = morok::core::Xoshiro256pp::fromSeed(308);
    morok::ir::IRRandom rng(engine);
    CHECK_FALSE(
        morok::passes::stringEncryptModule(*M, {/*probability=*/100}, rng));

    GlobalVariable *Decoy = M->getGlobalVariable("morok.decoy.str.test", true);
    REQUIRE(Decoy);
    CHECK(Decoy->isConstant());
    CHECK(hasReadableByteString(*M, "decoy-visible"));
    CHECK(countFunctions(*M, "morok.strdec") == 0u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("stringEncryptModule gives each string its own cipher") {
    LLVMContext ctx;
    auto M = std::make_unique<Module>("multi-strings", ctx);
    // Two identical plaintexts must encrypt to DIFFERENT ciphertext (per-string
    // keys) and get DISTINCT decryptors (not one shared routine).
    makePrivateString(*M, "a.str", "duplicate-content");
    makePrivateString(*M, "b.str", "duplicate-content");

    auto engine = morok::core::Xoshiro256pp::fromSeed(77);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::stringEncryptModule(*M, {/*probability=*/100}, rng));

    GlobalVariable *A = M->getGlobalVariable("a.str", true);
    GlobalVariable *B = M->getGlobalVariable("b.str", true);
    REQUIRE(A);
    REQUIRE(B);
    auto *CA = dyn_cast<ConstantDataArray>(A->getInitializer());
    auto *CB = dyn_cast<ConstantDataArray>(B->getInitializer());
    REQUIRE(CA);
    REQUIRE(CB);
    CHECK(CA->getRawDataValues() != CB->getRawDataValues());
    // Two separate decryptor constructors, not one.
    CHECK(countFunctions(*M, "morok.strdec") == 2u);
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
    M->setTargetTriple(Triple("x86_64-unknown-linux-gnu"));
    auto engine = morok::core::Xoshiro256pp::fromSeed(27);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::functionCallObfuscateModule(*M, {/*prob=*/100}, rng));
    CHECK(M->getFunction("dlsym") != nullptr);
    Function *Caller = M->getFunction("caller");
    REQUIRE(Caller);
    CHECK(hasInlineAsmCall(*Caller));
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("functionCallObfuscateModule redirects an external invoke via dlsym") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare i32 @may_throw()
declare i32 @__gxx_personality_v0(...)

define i32 @caller() personality ptr @__gxx_personality_v0 {
entry:
  %r = invoke i32 @may_throw()
          to label %ok unwind label %lpad
ok:
  ret i32 %r
lpad:
  %lp = landingpad { ptr, i32 }
          cleanup
  ret i32 -1
}
)ir");
    Function *F = M->getFunction("caller");
    REQUIRE(F);
    BasicBlock *Ok = nullptr;
    BasicBlock *LPad = nullptr;
    for (BasicBlock &BB : *F) {
        if (BB.getName() == "ok")
            Ok = &BB;
        if (BB.getName() == "lpad")
            LPad = &BB;
    }
    REQUIRE(Ok);
    REQUIRE(LPad);

    auto engine = morok::core::Xoshiro256pp::fromSeed(272);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::functionCallObfuscateModule(*M, {/*prob=*/100}, rng));

    InvokeInst *IndirectInvoke = nullptr;
    for (Instruction &I : instructions(*F))
        if (auto *II = dyn_cast<InvokeInst>(&I))
            IndirectInvoke = II;

    REQUIRE(IndirectInvoke);
    CHECK(IndirectInvoke->getCalledFunction() == nullptr);
    CHECK(IndirectInvoke->getNormalDest() == Ok);
    CHECK(IndirectInvoke->getUnwindDest() == LPad);
    CHECK(countCallsTo(*F, "may_throw") == 0u);
    CHECK(countCallsTo(*F, "dlsym") == 1u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("functionCallObfuscateModule caps redirected call sites") {
    LLVMContext ctx;
    auto M = std::make_unique<Module>("fco-cap", ctx);
    Function *Caller = makeRepeatedVoidCalls(*M, 300);

    auto engine = morok::core::Xoshiro256pp::fromSeed(271);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::functionCallObfuscateModule(
        *M, {/*probability=*/100, /*max_calls=*/1000}, rng));

    CHECK(countGlobals(*M, "morok.cloak.c") == 256u);
    CHECK(countCallsTo(*Caller, "dlsym") == 256u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("functionCallObfuscateModule never leaves the symbol name readable") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare i32 @puts(ptr)
@.s = private constant [3 x i8] c"hi\00"
define i32 @caller() {
  %r = call i32 @puts(ptr @.s)
  ret i32 %r
}
)ir");
    M->setTargetTriple(Triple("x86_64-unknown-linux-gnu"));
    auto engine = morok::core::Xoshiro256pp::fromSeed(4242);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::functionCallObfuscateModule(*M, {/*prob=*/100}, rng));

    // No byte-array global may carry the readable symbol name "puts".
    for (GlobalVariable &GV : M->globals()) {
        if (!GV.hasInitializer())
            continue;
        if (auto *CDA = dyn_cast<ConstantDataArray>(GV.getInitializer()))
            if (CDA->getElementType()->isIntegerTy(8))
                CHECK(CDA->getRawDataValues().find("puts") == StringRef::npos);
    }
    // A per-site cipher global and the volatile module seed exist.
    CHECK(countGlobals(*M, "morok.cloak.c") == 1u);
    CHECK(countGlobals(*M, "morok.cloak.seed") == 1u);

    // The seed is read with a volatile load, and the symbol passed to dlsym is
    // a computed stack pointer (an alloca), not a direct global string.
    Function *Caller = M->getFunction("caller");
    REQUIRE(Caller);
    CallInst *DlsymCall = nullptr;
    bool hasVolatileLoad = false;
    bool dlsymTakesAlloca = false;
    bool indirectUsesDecodedPointer = false;
    for (Instruction &I : instructions(*Caller)) {
        if (auto *LI = dyn_cast<LoadInst>(&I))
            hasVolatileLoad |= LI->isVolatile();
        if (auto *CI = dyn_cast<CallInst>(&I)) {
            if (Function *Cee = CI->getCalledFunction()) {
                if (Cee->getName() == "dlsym") {
                    DlsymCall = CI;
                    dlsymTakesAlloca |= isa<AllocaInst>(
                        CI->getArgOperand(1)->stripInBoundsOffsets());
                }
            } else if (auto *I2P =
                           dyn_cast<IntToPtrInst>(CI->getCalledOperand())) {
                indirectUsesDecodedPointer =
                    I2P->getName().starts_with("morok.fco.ptr.dec");
            }
        }
    }
    REQUIRE(DlsymCall != nullptr);
    for (User *U : DlsymCall->users())
        CHECK(isa<PtrToIntInst>(U));
    CHECK(hasVolatileLoad);
    CHECK(dlsymTakesAlloca);
    CHECK(indirectUsesDecodedPointer);
    CHECK(countInlineAsmCalls(*Caller) >= 2u);
    CHECK(countNamedAllocas(*Caller, "morok.cloak.mix") >= 1u);
    CHECK(countNamedAllocas(*Caller, "morok.fco.ptr.slot") == 1u);
    CHECK(countNamedInstructions(*Caller, "morok.fco.ptr.enc") >= 1u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("functionCallObfuscateModule strips the asm-name escape for dlsym") {
    LLVMContext ctx;
    // macOS libc symbols carry a `\01`-escaped asm name (`\01_fwrite`); dlsym
    // needs the plain C name "fwrite", else it returns null and the redirected
    // call jumps to address 0.
    auto M = parse(ctx, R"ir(
target triple = "arm64-apple-macosx13.0.0"
declare i64 @"\01_fwrite"(ptr, i64, i64, ptr)
@.d = private constant [3 x i8] c"hi\00"
define i64 @caller(ptr %f) {
  %r = call i64 @"\01_fwrite"(ptr @.d, i64 1, i64 2, ptr %f)
  ret i64 %r
}
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(55);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::functionCallObfuscateModule(*M, {/*prob=*/100}, rng));

    // The cloaked symbol must be the plain C name "fwrite" (6 + NUL = 7 bytes),
    // not the raw "\01_fwrite" (10 bytes).
    bool hasStrippedCipher = false;
    for (GlobalVariable &GV : M->globals())
        if (GV.getName().starts_with("morok.cloak.c"))
            if (auto *AT = dyn_cast<ArrayType>(GV.getValueType()))
                hasStrippedCipher |= AT->getNumElements() == 7u;
    CHECK(hasStrippedCipher);
    CHECK(M->getFunction("dlsym") != nullptr);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("anti-analysis passes inject valid startup code") {
    LLVMContext ctx;
    auto M = parse(ctx, "define i32 @main() { ret i32 0 }\n");
    auto engine = morok::core::Xoshiro256pp::fromSeed(88);
    morok::ir::IRRandom rng(engine);
    CHECK(morok::passes::antiDebuggingModule(*M));
    CHECK(morok::passes::antiHookingModule(*M, rng));
    CHECK_FALSE(morok::passes::antiClassDumpModule(*M)); // no ObjC → no-op

    // The probed framework name must never appear as a readable string.
    for (GlobalVariable &GV : M->globals())
        if (GV.hasInitializer())
            if (auto *CDA = dyn_cast<ConstantDataArray>(GV.getInitializer()))
                if (CDA->getElementType()->isIntegerTy(8))
                    CHECK(CDA->getRawDataValues().find("MSHookFunction") ==
                          StringRef::npos);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("antiHookingModule emits Linux clean-copy byte diff with direct "
          "syscalls") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
target triple = "x86_64-unknown-linux-gnu"
define i32 @work(i32 %x) {
entry:
  %y = add i32 %x, 3
  ret i32 %y
}
define i32 @main() {
entry:
  %v = call i32 @work(i32 39)
  ret i32 %v
}
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(8801);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::antiHookingModule(*M, rng));

    Function *Clean = M->getFunction("morok.antihook.clean.elf");
    REQUIRE(Clean != nullptr);
    Function *Got = M->getFunction("morok.antihook.got.plt");
    REQUIRE(Got != nullptr);
    Function *Rx = M->getFunction("morok.antihook.elf.rx");
    REQUIRE(Rx != nullptr);
    Function *Maps = M->getFunction("morok.antihook.maps.linux");
    REQUIRE(Maps != nullptr);
    Function *Wx = M->getFunction("morok.antihook.wxorx.linux");
    REQUIRE(Wx != nullptr);
    Function *Stack = M->getFunction("morok.antihook.stack.linux");
    REQUIRE(Stack != nullptr);
    Function *Diverge = M->getFunction("morok.antihook.diverge.posix");
    REQUIRE(Diverge != nullptr);
    Function *Sandbox = M->getFunction("morok.antihook.sandbox");
    REQUIRE(Sandbox != nullptr);
    Function *Dbi = M->getFunction("morok.antihook.dbi.linux");
    REQUIRE(Dbi != nullptr);
    Function *Smc = M->getFunction("morok.antihook.dbi.smc");
    REQUIRE(Smc != nullptr);
    Function *NegativeTiming = M->getFunction("morok.negative.timing");
    REQUIRE(NegativeTiming != nullptr);
    Function *Work = M->getFunction("work");
    REQUIRE(Work != nullptr);
    CHECK(M->getGlobalVariable("morok.antihook.state", true) != nullptr);
    CHECK(M->getGlobalVariable("morok.antihook.mac.targets", true) != nullptr);
    CHECK(hasInlineAsmCall(*Clean));
    CHECK(hasInlineAsmCall(*Got));
    CHECK(hasInlineAsmCall(*Maps));
    CHECK(hasInlineAsmCall(*Wx));
    CHECK(M->getFunction("dlsym") != nullptr);
    CHECK(M->getFunction("getenv") != nullptr);
    CHECK(M->getFunction("readlink") == nullptr);
    CHECK(M->getFunction("open") == nullptr);
    CHECK(M->getFunction("lseek") == nullptr);
    CHECK(M->getFunction("mmap") == nullptr);
    CHECK(M->getFunction("munmap") == nullptr);
    CHECK(M->getFunction("mprotect") == nullptr);
    CHECK(M->getFunction("close") == nullptr);
    CHECK(M->getFunction("syscall") == nullptr);
    CHECK(M->getFunction("getpid") != nullptr);
    CHECK(M->getFunction("getppid") != nullptr);
    CHECK(M->getFunction("sysconf") != nullptr);
    CHECK(M->getFunction("clock_gettime") != nullptr);
    CHECK(M->getFunction("nanosleep") != nullptr);
    CHECK(countNamedInstructions(*Clean, "morok.antihook.mac.mem.mix") >= 1u);
    CHECK(countNamedInstructions(*Clean, "morok.antihook.mac.file.mix") >=
          1u);
    CHECK(countNamedInstructions(*Clean, "morok.negative.text.int3") >= 1u);
    CHECK(countNamedInstructions(*Got, "morok.antihook.got.rel.offset") >= 1u);
    CHECK(countNamedInstructions(*Got, "morok.antihook.got.mprotect") >= 1u);
    CHECK(countNamedInstructions(*Got, "morok.antihook.got.rx") >= 1u);
    CHECK(countNamedInstructions(*Rx, "morok.antihook.got.map.seg.hit") >= 1u);
    CHECK(countNamedInstructions(*Wx, "morok.antihook.wxorx.mprotect") >= 1u);
    CHECK(countNamedInstructions(*Stack, "morok.antihook.stack.rx") >= 1u);
    CHECK(hasInlineAsmCall(*Diverge));
    CHECK(hasInlineAsmCall(*Sandbox));
    CHECK(countNamedInstructions(*Diverge,
                                 "morok.antihook.diverge.getpid.direct") >=
          1u);
    CHECK(countNamedInstructions(*Diverge,
                                 "morok.antihook.diverge.getppid.wrapper") >=
          1u);
    CHECK(countNamedInstructions(
              *Sandbox, "morok.antihook.sandbox.cpuid.hypervisor") >= 1u);
    CHECK(countNamedInstructions(*Sandbox,
                                 "morok.antihook.sandbox.cpuid.vendor") >=
          1u);
    CHECK(countNamedInstructions(*Sandbox,
                                 "morok.antihook.sandbox.vmware.vendor") >=
          1u);
    CHECK(countNamedInstructions(*Sandbox,
                                 "morok.antihook.sandbox.vmware.backdoor") >=
          1u);
    CHECK(countNamedInstructions(*Sandbox,
                                 "morok.antihook.sandbox.sidt.base") >= 1u);
    CHECK(countNamedInstructions(*Sandbox,
                                 "morok.antihook.sandbox.sgdt.base") >= 1u);
    CHECK(countNamedInstructions(*Sandbox, "morok.antihook.sandbox.cpu.low") >=
          1u);
    CHECK(countNamedInstructions(*Sandbox,
                                 "morok.antihook.sandbox.uptime.flag") >= 1u);
    CHECK(countNamedInstructions(*Sandbox,
                                 "morok.antihook.sandbox.sleep.skip") >= 1u);
    CHECK(countNamedInstructions(*Dbi, "morok.antihook.dbi.maps.sig") >= 1u);
    CHECK(countNamedInstructions(*Dbi, "morok.antihook.dbi.thread.sig") >= 1u);
    CHECK(countNamedInstructions(*Dbi, "morok.antihook.dbi.port.sig0") >= 1u);
    CHECK(countNamedInstructions(*Smc,
                                 "morok.antihook.dbi.smc.mprotect.rwx") >=
          1u);
    CHECK(countNamedInstructions(*Smc, "morok.antihook.dbi.smc.trip") >= 1u);
    CHECK(countNamedInstructions(*NegativeTiming,
                                 "morok.negative.timing.slow") >= 1u);
    CHECK(countNamedInstructions(*M->getFunction("morok.antihook"),
                                 "morok.corroborate.score.final") >= 1u);
    CHECK(countNamedInstructions(*M->getFunction("morok.antihook"),
                                 "morok.corroborate.confirmed") >= 1u);
    CHECK(countNamedInstructions(*M->getFunction("morok.antihook"),
                                 "morok.corroborate.aggressive") >= 1u);
    CHECK(countNamedInstructions(*M->getFunction("morok.antihook"),
                                 "morok.negative.modules.extra") >= 1u);
    CHECK(countNamedInstructions(*Work, "morok.antihook.stack.ra") >= 1u);
    CHECK(countNamedInstructions(*Work, "morok.antihook.stack.bad") >= 1u);
    CHECK(countNamedInstructions(*Maps, "morok.antihook.maps.rwx") >= 1u);
    CHECK(countNamedInstructions(*Maps, "morok.antihook.maps.anonymous.exec") >=
          1u);
    CHECK(countNamedInstructions(*Maps, "morok.antihook.maps.preload") >= 1u);
    CHECK(countNamedInstructions(*M->getFunction("morok.antihook"),
                                 "morok.antihook.prologue.x86.hit") >= 1u);
    CHECK_FALSE(hasReadableByteString(*M, "/proc/self/exe"));
    CHECK_FALSE(hasReadableByteString(*M, "/proc/self/maps"));
    CHECK_FALSE(hasReadableByteString(*M, "LD_PRELOAD"));
    CHECK_FALSE(hasReadableByteString(*M, "MSHookFunction"));
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("antiHookingModule emits Darwin clean-copy checker without dlsym") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
target triple = "x86_64-apple-macosx13.0.0"
define i32 @work(i32 %x) {
entry:
  %y = add i32 %x, 5
  ret i32 %y
}
define i32 @main() {
entry:
  %v = call i32 @work(i32 37)
  ret i32 %v
}
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(8802);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::antiHookingModule(*M, rng));

    Function *Clean = M->getFunction("morok.antihook.clean.macho");
    REQUIRE(Clean != nullptr);
    Function *Fixups = M->getFunction("morok.antihook.macho.fixups");
    REQUIRE(Fixups != nullptr);
    Function *Text = M->getFunction("morok.antihook.macho.text");
    REQUIRE(Text != nullptr);
    Function *Vm = M->getFunction("morok.antihook.vm.darwin");
    REQUIRE(Vm != nullptr);
    Function *Wx = M->getFunction("morok.antihook.wxorx.darwin");
    REQUIRE(Wx != nullptr);
    Function *Stack = M->getFunction("morok.antihook.stack.darwin");
    REQUIRE(Stack != nullptr);
    Function *Diverge = M->getFunction("morok.antihook.diverge.posix");
    REQUIRE(Diverge != nullptr);
    Function *Sandbox = M->getFunction("morok.antihook.sandbox");
    REQUIRE(Sandbox != nullptr);
    Function *Smc = M->getFunction("morok.antihook.dbi.smc");
    REQUIRE(Smc != nullptr);
    Function *NegativeTiming = M->getFunction("morok.negative.timing");
    REQUIRE(NegativeTiming != nullptr);
    Function *Work = M->getFunction("work");
    REQUIRE(Work != nullptr);
    CHECK(M->getGlobalVariable("morok.antihook.state", true) != nullptr);
    CHECK(M->getGlobalVariable("morok.antihook.mac.targets", true) != nullptr);
    CHECK(M->getFunction("morok.antihook.got.plt") == nullptr);
    CHECK(hasInlineAsmCall(*Clean));
    CHECK(hasInlineAsmCall(*Sandbox));
    CHECK(M->getFunction("dlsym") == nullptr);
    CHECK(M->getFunction("open") == nullptr);
    CHECK(M->getFunction("lseek") == nullptr);
    CHECK(M->getFunction("mmap") == nullptr);
    CHECK(M->getFunction("munmap") == nullptr);
    CHECK(M->getFunction("close") == nullptr);
    CHECK(M->getFunction("syscall") == nullptr);
    CHECK(M->getFunction("getpid") != nullptr);
    CHECK(M->getFunction("getppid") != nullptr);
    CHECK(countNamedInstructions(*Clean, "morok.antihook.mac.mem.mix") >= 1u);
    CHECK(countNamedInstructions(*Clean, "morok.antihook.mac.file.mix") >=
          1u);
    CHECK(countNamedInstructions(*Clean, "morok.negative.text.int3") >= 1u);
    CHECK(countNamedInstructions(*Fixups,
                                 "morok.antihook.fixup.section.got") >= 1u);
    CHECK(countNamedInstructions(*Fixups,
                                 "morok.antihook.fixup.section.lazy") >= 1u);
    CHECK(countNamedInstructions(*Fixups, "morok.antihook.fixup.text") >= 1u);
    CHECK(countNamedInstructions(*Text, "morok.antihook.macho.text.hit") >=
          1u);
    CHECK(countNamedInstructions(*Wx, "morok.antihook.wxorx.mprotect") >= 1u);
    CHECK(countNamedInstructions(*Stack, "morok.antihook.stack.text") >= 1u);
    CHECK(hasInlineAsmCall(*Diverge));
    CHECK(countNamedInstructions(*Diverge,
                                 "morok.antihook.diverge.getpid.direct") >=
          1u);
    CHECK(countNamedInstructions(*Diverge,
                                 "morok.antihook.diverge.getppid.wrapper") >=
          1u);
    CHECK(countNamedInstructions(
              *Sandbox, "morok.antihook.sandbox.cpuid.hypervisor") >= 1u);
    CHECK(countNamedInstructions(*Sandbox,
                                 "morok.antihook.sandbox.vmware.backdoor") >=
          1u);
    CHECK(countNamedInstructions(*Sandbox,
                                 "morok.antihook.sandbox.sidt.base") >= 1u);
    CHECK(countNamedInstructions(*Smc,
                                 "morok.antihook.dbi.smc.mprotect.rwx") >=
          1u);
    CHECK(countNamedInstructions(*Smc, "morok.antihook.dbi.smc.trip") >= 1u);
    CHECK(countNamedInstructions(*NegativeTiming,
                                 "morok.negative.timing.slow") >= 1u);
    CHECK(countNamedInstructions(*M->getFunction("morok.antihook"),
                                 "morok.negative.modules.extra") >= 1u);
    CHECK(countNamedInstructions(*Work, "morok.antihook.stack.ra") >= 1u);
    CHECK(countNamedInstructions(*Work, "morok.antihook.stack.bad") >= 1u);
    CHECK(countNamedInstructions(*Vm, "morok.antihook.vm.rwx") >= 1u);
    CHECK(countNamedInstructions(*Vm, "morok.antihook.vm.rwx.large") >= 1u);
    CHECK(countNamedInstructions(*Vm, "morok.antihook.vm.private.exec") >= 1u);
    CHECK(countNamedInstructions(*M->getFunction("morok.antihook"),
                                 "morok.antihook.prologue.x86.hit") >= 1u);
    CHECK(M->getFunction("_NSGetExecutablePath") != nullptr);
    CHECK(M->getFunction("_dyld_image_count") != nullptr);
    CHECK(M->getFunction("_dyld_get_image_header") != nullptr);
    CHECK(M->getFunction("_dyld_get_image_vmaddr_slide") != nullptr);
    CHECK(M->getFunction("mach_vm_region") != nullptr);
    CHECK(M->getFunction("mach_port_deallocate") != nullptr);
    CHECK(M->getFunction("getpagesize") != nullptr);
    CHECK(M->getGlobalVariable("mach_task_self_") != nullptr);
    CHECK_FALSE(hasReadableByteString(*M, "MSHookFunction"));
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("antiHookingModule emits Windows VirtualQuery address-space census") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
target triple = "x86_64-pc-windows-msvc"
define i32 @work(i32 %x) {
entry:
  %y = add i32 %x, 7
  ret i32 %y
}
define i32 @main() {
entry:
  %v = call i32 @work(i32 35)
  ret i32 %v
}
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(8804);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::antiHookingModule(*M, rng));

    Function *Vm = M->getFunction("morok.antihook.vm.windows");
    REQUIRE(Vm != nullptr);
    Function *Wx = M->getFunction("morok.antihook.wxorx.windows");
    REQUIRE(Wx != nullptr);
    Function *Stack = M->getFunction("morok.antihook.stack.windows");
    REQUIRE(Stack != nullptr);
    Function *Sandbox = M->getFunction("morok.antihook.sandbox");
    REQUIRE(Sandbox != nullptr);
    Function *Smc = M->getFunction("morok.antihook.dbi.smc");
    REQUIRE(Smc != nullptr);
    Function *NegativeTiming = M->getFunction("morok.negative.timing");
    REQUIRE(NegativeTiming != nullptr);
    Function *Work = M->getFunction("work");
    REQUIRE(Work != nullptr);
    CHECK(M->getFunction("VirtualQuery") != nullptr);
    CHECK(M->getFunction("VirtualProtect") != nullptr);
    CHECK(M->getFunction("QueryPerformanceCounter") != nullptr);
    CHECK(M->getFunction("clock_gettime") == nullptr);
    CHECK(M->getFunction("dlsym") == nullptr);
    CHECK(M->getFunction("exit") == nullptr);
    CHECK(hasInlineAsmCall(*Sandbox));
    CHECK(countNamedInstructions(
              *Sandbox, "morok.antihook.sandbox.cpuid.hypervisor") >= 1u);
    CHECK(countNamedInstructions(*Sandbox,
                                 "morok.antihook.sandbox.vmware.backdoor") >=
          1u);
    CHECK(countNamedInstructions(*Sandbox,
                                 "morok.antihook.sandbox.sidt.base") >= 1u);
    CHECK(countNamedInstructions(*Smc,
                                 "morok.antihook.dbi.smc.virtualprotect.rwx") >=
          1u);
    CHECK(countNamedInstructions(*Smc, "morok.antihook.dbi.smc.trip") >= 1u);
    CHECK(countNamedInstructions(*NegativeTiming,
                                 "morok.negative.timing.slow") >= 1u);
    CHECK(countNamedInstructions(*M->getFunction("morok.antihook"),
                                 "morok.negative.modules.extra") >= 1u);
    CHECK(countNamedInstructions(*Wx, "morok.antihook.wxorx.virtualprotect") >=
          1u);
    CHECK(countNamedInstructions(*Stack, "morok.antihook.stack.query") >= 1u);
    CHECK(countNamedInstructions(*Work, "morok.antihook.stack.ra") >= 1u);
    CHECK(countNamedInstructions(*Work, "morok.antihook.stack.bad") >= 1u);
    CHECK(countNamedInstructions(*Vm, "morok.antihook.win.rwx") >= 1u);
    CHECK(countNamedInstructions(*Vm, "morok.antihook.win.rwx.large") >= 1u);
    CHECK(countNamedInstructions(*Vm, "morok.antihook.win.private") >= 1u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("antiHookingModule emits arm64 prologue branch detector") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
target triple = "arm64-apple-macosx13.0.0"
define i32 @work(i32 %x) {
entry:
  %a = add i32 %x, 11
  ret i32 %a
}
define i32 @main() {
entry:
  %v = call i32 @work(i32 2)
  ret i32 %v
}
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(8803);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::antiHookingModule(*M, rng));

    Function *Ctor = M->getFunction("morok.antihook");
    REQUIRE(Ctor != nullptr);
    CHECK(countNamedInstructions(*Ctor,
                                 "morok.antihook.prologue.arm64.hit") >= 1u);
    CHECK(M->getFunction("morok.antihook.diverge.posix") == nullptr);
    CHECK(M->getFunction("dlsym") == nullptr);
    CHECK(M->getFunction("open") != nullptr);
    CHECK_FALSE(hasReadableByteString(*M, "MSHookFunction"));
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("antiDebuggingModule emits layered Linux checks without readable "
          "proc strings") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
target triple = "x86_64-unknown-linux-gnu"
define i32 @work(i32 %x) {
entry:
  %a = add i32 %x, 7
  %b = xor i32 %a, 19
  ret i32 %b
}
define i32 @main() {
entry:
  %v = call i32 @work(i32 41)
  ret i32 %v
}
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(881);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::antiDebuggingModule(*M, rng));

    CHECK(M->getGlobalVariable("morok.antidbg.state", true) != nullptr);
    CHECK(M->getFunction("morok.antidbg.linux.status") != nullptr);
    CHECK(M->getFunction("morok.antidbg.linux.stat4") != nullptr);
    CHECK(M->getFunction("morok.antidbg.linux.watch") != nullptr);
    CHECK(M->getFunction("morok.antidbg.linux.dr.sentinel") != nullptr);
    CHECK(M->getFunction("morok.antidbg.linux.dr.scrub") != nullptr);
    CHECK(M->getFunction("morok.antidbg.probe") != nullptr);
    CHECK(countUserCallsTo(*M, "morok.antidbg.probe") >= 1u);
    CHECK(M->getFunction("ptrace") == nullptr);
    CHECK(M->getFunction("prctl") == nullptr);
    CHECK(M->getFunction("syscall") == nullptr);
    CHECK(hasInlineAsmCall(*M->getFunction("morok.antidbg")));
    CHECK(hasInlineAsmCall(*M->getFunction("morok.antidbg.linux.status")));
    CHECK(hasInlineAsmCall(*M->getFunction("morok.antidbg.linux.stat4")));
    CHECK_FALSE(hasInlineAsmCall(*M->getFunction("morok.antidbg.linux.watch")));
    CHECK(hasInlineAsmCall(*M->getFunction("morok.antidbg.linux.dr.scrub")));
    CHECK(countNamedInstructions(*M->getFunction("morok.antidbg.linux.dr.scrub"),
                                 "morok.antidbg.dr.seize") >= 1u);
    CHECK(countNamedInstructions(*M->getFunction("morok.antidbg.linux.dr.scrub"),
                                 "morok.antidbg.dr.interrupt") >= 1u);
    CHECK(
        countNamedInstructions(*M->getFunction("morok.antidbg.linux.dr.scrub"),
                               "morok.antidbg.dr.poke") == 8u);
    CHECK(
        countNamedInstructions(*M->getFunction("morok.antidbg.linux.dr.scrub"),
                               "morok.negative.dr.notzero") >= 1u);
    CHECK(countNamedInstructions(*M->getFunction("morok.antidbg"),
                                 "morok.antidbg.dr.fork") >= 1u);
    CHECK(countNamedInstructions(*M->getFunction("morok.antidbg"),
                                 "morok.antidbg.ptrace.init") == 0u);
    CHECK(M->getFunction("pthread_create") != nullptr);
    CHECK(M->getFunction("pthread_detach") != nullptr);
    CHECK(M->getFunction("open") == nullptr);
    CHECK(M->getFunction("read") == nullptr);
    CHECK(M->getFunction("close") == nullptr);
    CHECK(M->getFunction("sleep") != nullptr);

    CHECK_FALSE(hasReadableByteString(*M, "/proc/self/status"));
    CHECK_FALSE(hasReadableByteString(*M, "/proc/self/stat"));
    CHECK_FALSE(hasReadableByteString(*M, "/proc/%ld/task"));
    CHECK_FALSE(hasReadableByteString(*M, "TracerPid"));
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("antiDebuggingModule can disable Linux self-trace for trap "
          "compatibility") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
target triple = "x86_64-unknown-linux-gnu"
define i32 @main() { ret i32 0 }
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(8820);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::antiDebuggingModule(*M, rng,
                                             /*allowSelfTrace=*/false));

    Function *Ctor = M->getFunction("morok.antidbg");
    Function *Watch = M->getFunction("morok.antidbg.linux.watch");
    REQUIRE(Ctor != nullptr);
    REQUIRE(Watch != nullptr);
    CHECK(M->getFunction("morok.antidbg.linux.status") != nullptr);
    CHECK(M->getFunction("morok.antidbg.linux.stat4") != nullptr);
    CHECK(M->getFunction("morok.antidbg.linux.dr.sentinel") != nullptr);
    CHECK(M->getFunction("morok.antidbg.linux.dr.scrub") != nullptr);
    CHECK(countNamedInstructions(*Ctor, "morok.antidbg.ptrace.init") == 0u);
    CHECK_FALSE(hasInlineAsmCall(*Watch));
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("antiDebuggingModule emits x86_64 Darwin source checks through "
          "direct syscalls") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
target triple = "x86_64-apple-macosx13.0.0"
define i32 @work(i32 %x) {
entry:
  %a = add i32 %x, 5
  ret i32 %a
}
define i32 @main() {
entry:
  %v = call i32 @work(i32 9)
  ret i32 %v
}
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(8821);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::antiDebuggingModule(*M, rng));

    Function *Ctor = M->getFunction("morok.antidbg");
    Function *Probe = M->getFunction("morok.antidbg.probe");
    REQUIRE(Ctor != nullptr);
    REQUIRE(Probe != nullptr);
    CHECK(M->getFunction("morok.antidbg.darwin.dr.watch") != nullptr);
    CHECK(M->getFunction("morok.antidbg.darwin.dr.scrub") != nullptr);
    CHECK(hasInlineAsmCall(*Ctor));
    CHECK(hasInlineAsmCall(*Probe));
    CHECK(M->getFunction("ptrace") == nullptr);
    CHECK(M->getFunction("sysctl") == nullptr);
    CHECK(M->getFunction("csops") == nullptr);
    CHECK(M->getFunction("getpid") == nullptr);
    CHECK(M->getFunction("syscall") == nullptr);
    CHECK(M->getFunction("getenv") != nullptr);
    CHECK(M->getFunction("task_threads") != nullptr);
    CHECK(M->getFunction("thread_get_state") != nullptr);
    CHECK(M->getFunction("thread_set_state") != nullptr);
    CHECK(M->getFunction("vm_deallocate") != nullptr);
    CHECK(M->getGlobalVariable("mach_task_self_") != nullptr);
    CHECK(
        countNamedInstructions(*M->getFunction("morok.antidbg.darwin.dr.scrub"),
                               "morok.antidbg.dr.thread.set") >= 1u);
    CHECK(M->getFunction("pthread_create") != nullptr);
    CHECK(M->getFunction("pthread_detach") != nullptr);
    CHECK(M->getFunction("sleep") != nullptr);
    CHECK_FALSE(hasReadableByteString(*M, "DYLD_INSERT_LIBRARIES"));
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("antiDebuggingModule emits Darwin source checks and cloaked DYLD "
          "census") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
target triple = "arm64-apple-macosx13.0.0"
define i32 @work(i32 %x) {
entry:
  %a = add i32 %x, 5
  %b = mul i32 %a, 3
  ret i32 %b
}
define i32 @main() {
entry:
  %v = call i32 @work(i32 9)
  ret i32 %v
}
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(882);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::antiDebuggingModule(*M, rng));

    CHECK(M->getGlobalVariable("morok.antidbg.state", true) != nullptr);
    CHECK(M->getFunction("ptrace") != nullptr);
    CHECK(M->getFunction("sysctl") != nullptr);
    CHECK(M->getFunction("csops") != nullptr);
    CHECK(M->getFunction("getenv") != nullptr);
    CHECK(M->getFunction("morok.antidbg.probe") != nullptr);
    CHECK(M->getFunction("morok.antidbg.probe.watch") != nullptr);
    CHECK(M->getFunction("morok.antidbg.darwin.dr.watch") != nullptr);
    CHECK(M->getFunction("morok.antidbg.darwin.dr.scrub") != nullptr);
    CHECK(M->getFunction("task_threads") != nullptr);
    CHECK(M->getFunction("thread_get_state") != nullptr);
    CHECK(M->getFunction("thread_set_state") != nullptr);
    CHECK(M->getFunction("vm_deallocate") != nullptr);
    CHECK(M->getGlobalVariable("mach_task_self_") != nullptr);
    CHECK(
        countNamedInstructions(*M->getFunction("morok.antidbg.darwin.dr.scrub"),
                               "morok.antidbg.dr.thread.set") >= 1u);
    CHECK(M->getFunction("pthread_create") != nullptr);
    CHECK(M->getFunction("pthread_detach") != nullptr);
    CHECK(M->getFunction("sleep") != nullptr);
    CHECK(countUserCallsTo(*M, "morok.antidbg.probe") >= 1u);
    CHECK(countGlobals(*M, "morok.cloak.c") >= 8u);
    CHECK_FALSE(hasReadableByteString(*M, "DYLD_INSERT_LIBRARIES"));
    CHECK_FALSE(hasReadableByteString(*M, "DYLD_PRINT"));
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("timingOracleModule emits x86 rdtscp and raw clock probes") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
target triple = "x86_64-unknown-linux-gnu"
define i32 @main() { ret i32 0 }
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(883);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::timingOracleModule(*M, rng));

    Function *Oracle = M->getFunction("morok.timing.oracle");
    REQUIRE(Oracle != nullptr);
    CHECK(M->getGlobalVariable("morok.timing.state", true) != nullptr);
    CHECK(M->getFunction("morok.timing") != nullptr);
    CHECK(M->getFunction("clock_gettime") != nullptr);
    CHECK(hasInlineAsmCall(*Oracle));
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("timingOracleModule emits Darwin mach and raw clock probes") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
target triple = "arm64-apple-macosx13.0.0"
define i32 @main() { ret i32 0 }
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(884);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::timingOracleModule(*M, rng));

    Function *Oracle = M->getFunction("morok.timing.oracle");
    REQUIRE(Oracle != nullptr);
    CHECK(M->getGlobalVariable("morok.timing.state", true) != nullptr);
    CHECK(M->getFunction("mach_absolute_time") != nullptr);
    CHECK(M->getFunction("clock_gettime") != nullptr);
    CHECK_FALSE(hasInlineAsmCall(*Oracle));
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("trapOracleModule emits x86 trap stimuli and SIGTRAP handler") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
target triple = "x86_64-unknown-linux-gnu"
define i32 @main() { ret i32 0 }
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(885);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::trapOracleModule(*M, rng));

    Function *Ctor = M->getFunction("morok.trap");
    Function *Handler = M->getFunction("morok.trap.handler");
    REQUIRE(Ctor != nullptr);
    REQUIRE(Handler != nullptr);
    CHECK(Handler->arg_size() == 3);
    CHECK(M->getGlobalVariable("morok.trap.state", true) != nullptr);
    CHECK(M->getGlobalVariable("morok.trap.hits", true) != nullptr);
    CHECK(M->getFunction("sigaction") != nullptr);
    CHECK(M->getFunction("signal") == nullptr);
    CHECK(hasInlineAsmCall(*Ctor));
    CHECK(countNamedInstructions(*Handler, "morok.trap.icebp") >= 1u);
    CHECK_FALSE(verifyModule(*M, &errs()));
}

TEST_CASE("trapOracleModule emits portable raise fallback on Darwin arm64") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
target triple = "arm64-apple-macosx13.0.0"
define i32 @main() { ret i32 0 }
)ir");
    auto engine = morok::core::Xoshiro256pp::fromSeed(886);
    morok::ir::IRRandom rng(engine);

    CHECK(morok::passes::trapOracleModule(*M, rng));

    Function *Ctor = M->getFunction("morok.trap");
    REQUIRE(Ctor != nullptr);
    CHECK(M->getFunction("morok.trap.handler") != nullptr);
    CHECK(M->getFunction("signal") != nullptr);
    CHECK(M->getFunction("raise") != nullptr);
    CHECK_FALSE(hasInlineAsmCall(*Ctor));
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
