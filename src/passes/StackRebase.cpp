// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/StackRebase.cpp
//
// StackRebase ("AnchorScramble") emits legal stack constructs that tend to
// produce over-aligned, variable-sized frames while keeping selected frame
// addresses observable.  The transform is deliberately conservative about
// functions whose ABI, unwind, sanitizer, or verifier constraints are fragile.

#include "morok/passes/StackRebase.hpp"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/TargetParser/Triple.h"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>

using namespace llvm;

namespace morok::passes {

namespace {

using Builder = IRBuilder<NoFolder>;

constexpr std::uint32_t kMinRealign = 32;
constexpr std::uint32_t kMaxRealign = 4096;
constexpr std::uint32_t kMinDynamicExtra = 2;
constexpr std::uint32_t kMaxDynamicExtra = 4096;
constexpr std::uint32_t kPersistentMinBytes = 17;
constexpr std::uint32_t kNonEntryMaxBlocks = 2;

bool isPowerOfTwo(std::uint32_t V) {
    return V != 0 && (V & (V - 1u)) == 0;
}

std::uint32_t nextPowerOfTwo(std::uint32_t V) {
    if (V <= 1)
        return 1;
    --V;
    V |= V >> 1;
    V |= V >> 2;
    V |= V >> 4;
    V |= V >> 8;
    V |= V >> 16;
    return V + 1;
}

std::uint32_t normalizedAlign(std::uint32_t Requested) {
    if (Requested == 0)
        return 0;
    Requested = std::clamp(Requested, kMinRealign, kMaxRealign);
    return isPowerOfTwo(Requested) ? Requested : nextPowerOfTwo(Requested);
}

std::uint32_t normalizedDynamicExtra(std::uint32_t Requested) {
    if (Requested == 0)
        return 0;
    return std::clamp(Requested, kMinDynamicExtra, kMaxDynamicExtra);
}

bool isGeneratedFunction(const Function &F) {
    return F.getName().starts_with("morok.");
}

bool supportedTarget(const Module &M) {
    const Triple TT(M.getTargetTriple());
    if (TT.isOSWindows())
        return false;
    return TT.isOSBinFormatELF() || TT.isOSBinFormatMachO();
}

bool hasAnyFnAttr(const Function &F, ArrayRef<Attribute::AttrKind> Attrs) {
    for (Attribute::AttrKind A : Attrs)
        if (F.hasFnAttribute(A))
            return true;
    return false;
}

bool isRiskyIntrinsic(Intrinsic::ID ID) {
    switch (ID) {
    case Intrinsic::coro_align:
    case Intrinsic::coro_alloc:
    case Intrinsic::coro_alloca_alloc:
    case Intrinsic::coro_alloca_free:
    case Intrinsic::coro_alloca_get:
    case Intrinsic::coro_async_context_alloc:
    case Intrinsic::coro_async_context_dealloc:
    case Intrinsic::coro_async_resume:
    case Intrinsic::coro_async_size_replace:
    case Intrinsic::coro_await_suspend_bool:
    case Intrinsic::coro_await_suspend_handle:
    case Intrinsic::coro_await_suspend_void:
    case Intrinsic::coro_begin:
    case Intrinsic::coro_begin_custom_abi:
    case Intrinsic::coro_dead:
    case Intrinsic::coro_destroy:
    case Intrinsic::coro_done:
    case Intrinsic::coro_end:
    case Intrinsic::coro_end_async:
    case Intrinsic::coro_end_results:
    case Intrinsic::coro_frame:
    case Intrinsic::coro_free:
    case Intrinsic::coro_id:
    case Intrinsic::coro_id_async:
    case Intrinsic::coro_id_retcon:
    case Intrinsic::coro_id_retcon_once:
    case Intrinsic::coro_is_in_ramp:
    case Intrinsic::coro_noop:
    case Intrinsic::coro_prepare_async:
    case Intrinsic::coro_prepare_retcon:
    case Intrinsic::coro_promise:
    case Intrinsic::coro_resume:
    case Intrinsic::coro_save:
    case Intrinsic::coro_size:
    case Intrinsic::coro_subfn_addr:
    case Intrinsic::coro_suspend:
    case Intrinsic::coro_suspend_async:
    case Intrinsic::coro_suspend_retcon:
    case Intrinsic::eh_sjlj_callsite:
    case Intrinsic::eh_sjlj_functioncontext:
    case Intrinsic::eh_sjlj_longjmp:
    case Intrinsic::eh_sjlj_lsda:
    case Intrinsic::eh_sjlj_setjmp:
    case Intrinsic::eh_sjlj_setup_dispatch:
    case Intrinsic::experimental_gc_statepoint:
    case Intrinsic::localescape:
    case Intrinsic::localrecover:
        return true;
    default:
        return false;
    }
}

bool isSetjmpLikeName(StringRef Name) {
    return Name.contains_insensitive("setjmp") ||
           Name.contains_insensitive("sigsetjmp") ||
           Name.contains_insensitive("longjmp");
}

bool hasFragileInstructions(const Function &F) {
    for (const Instruction &I : instructions(F)) {
        if (I.isEHPad() || isa<InvokeInst>(&I) || isa<CallBrInst>(&I))
            return true;
        const auto *CB = dyn_cast<CallBase>(&I);
        if (!CB)
            continue;
        if (CB->isMustTailCall() || CB->isInlineAsm() || CB->hasOperandBundles())
            return true;
        if (const auto *II = dyn_cast<IntrinsicInst>(CB))
            if (isRiskyIntrinsic(II->getIntrinsicID()))
                return true;
        if (const Function *Callee = CB->getCalledFunction()) {
            if (Callee->hasFnAttribute(Attribute::ReturnsTwice))
                return true;
            if (isSetjmpLikeName(Callee->getName()))
                return true;
        }
    }
    return false;
}

bool shouldSkipFunction(const Function &F, const StackRebaseParams &Params) {
    if (F.isDeclaration() || isGeneratedFunction(F) || F.isVarArg())
        return true;
    if (Params.realign_align == 0 && Params.dynamic_size == 0 &&
        Params.relocate_probability == 0 && Params.alias_amplify == 0 &&
        !Params.nonentry_shuffle)
        return true;
    const Module *M = F.getParent();
    if (!M || !supportedTarget(*M))
        return true;
    if (F.hasGC() || F.hasPersonalityFn())
        return true;
    if (hasAnyFnAttr(F,
                     {Attribute::AlwaysInline, Attribute::Naked,
                      Attribute::OptimizeNone, Attribute::MinSize,
                      Attribute::OptimizeForSize, Attribute::SafeStack,
                      Attribute::ShadowCallStack, Attribute::StackProtect,
                      Attribute::StackProtectReq, Attribute::StackProtectStrong,
                      Attribute::SanitizeAddress, Attribute::SanitizeHWAddress,
                      Attribute::SanitizeMemTag, Attribute::SanitizeMemory,
                      Attribute::SanitizeThread,
                      Attribute::SpeculativeLoadHardening}))
        return true;
    return hasFragileInstructions(F);
}

std::string randomName(ir::IRRandom &rng) {
    return std::string("__") + utohexstr(rng.next());
}

GlobalVariable *makeSink(Module &M, Type *Ty, Constant *Init,
                         ir::IRRandom &rng) {
    auto *GV =
        new GlobalVariable(M, Ty, /*isConstant=*/false,
                           GlobalValue::PrivateLinkage, Init, randomName(rng));
    GV->setDSOLocal(true);
    GV->setVisibility(GlobalValue::HiddenVisibility);
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    if (Ty->isIntegerTy() || Ty->isPointerTy())
        GV->setAlignment(Align(8));
    return GV;
}

GlobalVariable *makeIntSink(Module &M, IntegerType *Ty, ir::IRRandom &rng) {
    return makeSink(M, Ty, ConstantInt::get(Ty, rng.next()), rng);
}

GlobalVariable *makePtrSink(Module &M, ir::IRRandom &rng) {
    auto *PtrTy = PointerType::get(M.getContext(), 0);
    return makeSink(M, PtrTy, ConstantPointerNull::get(PtrTy), rng);
}

IntegerType *intPtrTy(Module &M) {
    return M.getDataLayout().getIntPtrType(M.getContext(), 0);
}

Value *asI64(Builder &B, Value *V, Module &M) {
    auto *I64 = B.getInt64Ty();
    if (V->getType() == I64)
        return V;
    if (V->getType()->isPointerTy())
        V = B.CreatePtrToInt(V, intPtrTy(M));
    if (V->getType()->isHalfTy() || V->getType()->isBFloatTy())
        V = B.CreateBitCast(V, B.getInt16Ty());
    else if (V->getType()->isFloatTy())
        V = B.CreateBitCast(V, B.getInt32Ty());
    else if (V->getType()->isDoubleTy())
        V = B.CreateBitCast(V, I64);

    auto *IT = dyn_cast<IntegerType>(V->getType());
    if (!IT)
        return nullptr;
    if (IT->getBitWidth() < 64)
        return B.CreateZExt(V, I64);
    if (IT->getBitWidth() > 64)
        return B.CreateTrunc(V, I64);
    return V;
}

Value *ptrAsInt(Builder &B, Value *Ptr, Module &M) {
    return B.CreatePtrToInt(Ptr, intPtrTy(M));
}

void volatileStore(Builder &B, Value *V, Value *Ptr, Align A = Align(1)) {
    StoreInst *SI = B.CreateStore(V, Ptr);
    SI->setVolatile(true);
    SI->setAlignment(A);
}

Value *loadVolatile(Builder &B, Type *Ty, Value *Ptr, Align A = Align(1)) {
    LoadInst *LI = B.CreateLoad(Ty, Ptr);
    LI->setVolatile(true);
    LI->setAlignment(A);
    return LI;
}

Value *buildMix(Builder &B, Module &M, Function &F, Value *Anchor,
                ir::IRRandom &rng) {
    auto *I64 = B.getInt64Ty();
    GlobalVariable *Seed = makeIntSink(M, I64, rng);
    Value *Mix = loadVolatile(B, I64, Seed, Align(8));
    Mix = B.CreateXor(Mix, ConstantInt::get(I64, rng.next()));
    if (Anchor) {
        if (Value *A = asI64(B, Anchor, M)) {
            Mix = B.CreateXor(Mix, A);
            Mix = B.CreateMul(Mix, ConstantInt::get(I64, rng.next() | 1ull));
        }
    }

    for (Argument &Arg : F.args()) {
        if (Value *T = asI64(B, &Arg, M)) {
            Mix = B.CreateXor(Mix, T);
            Mix = B.CreateMul(Mix, ConstantInt::get(I64, rng.next() | 1ull));
        }
    }
    return Mix;
}

Value *buildDynamicSize(Builder &B, Value *Mix, std::uint32_t ExtraCap) {
    auto *I64 = B.getInt64Ty();
    Value *Extra =
        B.CreateAnd(Mix, ConstantInt::get(I64, ExtraCap - 1u));
    return B.CreateAdd(Extra, ConstantInt::get(I64, kPersistentMinBytes));
}

Value *scramble(Builder &B, Value *V, Value *Mix, ir::IRRandom &rng) {
    auto *I64 = B.getInt64Ty();
    const std::uint64_t K0 = rng.next();
    const std::uint64_t K1 = rng.next() | 1ull;
    switch (rng.range(4)) {
    case 0:
        return B.CreateMul(B.CreateXor(V, ConstantInt::get(I64, K0)),
                           ConstantInt::get(I64, K1));
    case 1: {
        Value *X = B.CreateAdd(V, ConstantInt::get(I64, K0));
        const unsigned S = 7u + rng.range(49);
        Value *L = B.CreateShl(X, ConstantInt::get(I64, S));
        Value *R = B.CreateLShr(X, ConstantInt::get(I64, 64u - S));
        return B.CreateXor(B.CreateOr(L, R), Mix);
    }
    case 2:
        return B.CreateAdd(B.CreateMul(V, ConstantInt::get(I64, K1)),
                           B.CreateXor(Mix, ConstantInt::get(I64, K0)));
    default:
        return B.CreateXor(
            B.CreateMul(B.CreateAdd(V, Mix), ConstantInt::get(I64, K1)),
            ConstantInt::get(I64, K0));
    }
}

bool isEligibleAlloca(const AllocaInst &AI, const DataLayout &DL) {
    if (AI.getAddressSpace() != 0)
        return false;
    if (!AI.isStaticAlloca() || AI.isUsedWithInAlloca() || AI.isSwiftError())
        return false;
    const std::optional<TypeSize> Size = AI.getAllocationSize(DL);
    return Size.has_value() && !Size->isScalable() && Size->getFixedValue() != 0;
}

SmallVector<AllocaInst *, 16> collectStaticAllocas(Function &F,
                                                   const DataLayout &DL) {
    SmallVector<AllocaInst *, 16> Out;
    BasicBlock &Entry = F.getEntryBlock();
    for (Instruction &I : Entry)
        if (auto *AI = dyn_cast<AllocaInst>(&I))
            if (isEligibleAlloca(*AI, DL))
                Out.push_back(AI);
    return Out;
}

Instruction *entryInsertionPoint(Function &F) {
    BasicBlock &Entry = F.getEntryBlock();
    return &*Entry.getFirstInsertionPt();
}

Instruction *afterEntryAllocas(Function &F) {
    BasicBlock &Entry = F.getEntryBlock();
    for (Instruction &I : Entry) {
        if (isa<AllocaInst>(&I))
            continue;
        return &I;
    }
    return Entry.getTerminator();
}

AllocaInst *emitRealignAnchor(Builder &B, std::uint32_t AlignBytes) {
    if (AlignBytes == 0)
        return nullptr;

    auto *I8 = B.getInt8Ty();
    auto *AnchorTy = ArrayType::get(I8, 16);
    AllocaInst *Anchor = B.CreateAlloca(AnchorTy);
    Anchor->setAlignment(Align(AlignBytes));
    return Anchor;
}

void emitPointerIntEscape(Builder &B, Module &M, Value *Ptr,
                          ir::IRRandom &rng) {
    auto *IPTy = intPtrTy(M);
    GlobalVariable *Sink = makeIntSink(M, IPTy, rng);
    volatileStore(B, ptrAsInt(B, Ptr, M), Sink, Align(8));
}

AllocaInst *emitPersistentDynamicAlloca(Function &F, Builder &B, Module &M,
                                        Value *Anchor, std::uint32_t ExtraCap,
                                        ir::IRRandom &rng) {
    if (ExtraCap == 0)
        return nullptr;
    Value *Mix = buildMix(B, M, F, Anchor, rng);
    Value *Size = buildDynamicSize(B, Mix, ExtraCap);
    AllocaInst *Frame = B.CreateAlloca(B.getInt8Ty(), Size);
    Frame->setAlignment(Align(16));

    auto *IPTy = intPtrTy(M);
    GlobalVariable *Sink = makeIntSink(M, IPTy, rng);
    volatileStore(B, ptrAsInt(B, Frame, M), Sink, Align(8));

    Value *TouchPtr =
        B.CreateInBoundsGEP(B.getInt8Ty(), Frame, ConstantInt::get(B.getInt64Ty(), 0));
    Value *Byte = B.CreateTrunc(Mix, B.getInt8Ty());
    volatileStore(B, Byte, TouchPtr);
    return Frame;
}

void emitRelocationEscapes(Builder &B, Module &M, ArrayRef<AllocaInst *> Allocas,
                           std::uint32_t Probability, Value *Mix,
                           ir::IRRandom &rng) {
    if (Probability == 0)
        return;
    auto *I64 = B.getInt64Ty();
    for (AllocaInst *AI : Allocas) {
        if (!rng.chance(Probability))
            continue;
        GlobalVariable *Sink = makeIntSink(M, I64, rng);
        Value *Addr = asI64(B, AI, M);
        if (!Addr)
            continue;
        volatileStore(B, scramble(B, Addr, Mix, rng), Sink, Align(8));
    }
}

void emitAliasAmplifier(Builder &B, Module &M, ArrayRef<AllocaInst *> Allocas,
                        std::uint32_t Probability, Value *Mix,
                        ir::IRRandom &rng) {
    if (Probability == 0 || Allocas.empty() || !rng.chance(Probability))
        return;
    AllocaInst *Victim = Allocas[rng.range(static_cast<std::uint32_t>(Allocas.size()))];
    GlobalVariable *PtrSink = makePtrSink(M, rng);
    volatileStore(B, Victim, PtrSink, Align(8));

    auto *I64 = B.getInt64Ty();
    GlobalVariable *IntSink = makeIntSink(M, I64, rng);
    if (Value *Addr = asI64(B, Victim, M))
        volatileStore(B, scramble(B, Addr, Mix, rng), IntSink, Align(8));
}

SmallVector<BasicBlock *, 8> shuffledNonEntryBlocks(Function &F,
                                                    ir::IRRandom &rng) {
    SmallVector<BasicBlock *, 8> Blocks;
    for (BasicBlock &BB : F) {
        if (&BB == &F.getEntryBlock() || BB.isEHPad() || BB.isLandingPad())
            continue;
        if (!BB.getTerminator())
            continue;
        Blocks.push_back(&BB);
    }
    for (std::size_t I = Blocks.size(); I > 1; --I) {
        std::size_t J = rng.range(static_cast<std::uint32_t>(I));
        std::swap(Blocks[I - 1], Blocks[J]);
    }
    return Blocks;
}

bool emitNonEntryShuffle(Function &F, Module &M, std::uint32_t ExtraCap,
                         ir::IRRandom &rng) {
    if (ExtraCap == 0)
        return false;

    LLVMContext &Ctx = M.getContext();
    auto *PtrTy = PointerType::get(Ctx, 0);
    Function *StackSave =
        Intrinsic::getOrInsertDeclaration(&M, Intrinsic::stacksave, {PtrTy});
    Function *StackRestore =
        Intrinsic::getOrInsertDeclaration(&M, Intrinsic::stackrestore, {PtrTy});

    std::uint32_t Emitted = 0;
    for (BasicBlock *BB : shuffledNonEntryBlocks(F, rng)) {
        if (Emitted >= kNonEntryMaxBlocks)
            break;
        Builder B(BB->getTerminator());
        Value *Save = B.CreateCall(StackSave->getFunctionType(), StackSave, {});
        Value *Mix = buildMix(B, M, F, nullptr, rng);
        AllocaInst *Frame =
            B.CreateAlloca(B.getInt8Ty(), buildDynamicSize(B, Mix, ExtraCap));
        Frame->setAlignment(Align(16));
        Value *Ptr = B.CreateInBoundsGEP(B.getInt8Ty(), Frame,
                                         ConstantInt::get(B.getInt64Ty(), 1));
        volatileStore(B, B.CreateTrunc(Mix, B.getInt8Ty()), Ptr);
        B.CreateCall(StackRestore->getFunctionType(), StackRestore, {Save});
        ++Emitted;
    }
    return Emitted != 0;
}

} // namespace

bool stackRebaseFunction(Function &F, const StackRebaseParams &Params,
                         ir::IRRandom &rng) {
    if (shouldSkipFunction(F, Params))
        return false;

    Module &M = *F.getParent();
    const DataLayout &DL = M.getDataLayout();
    const std::uint32_t AlignBytes = normalizedAlign(Params.realign_align);
    const std::uint32_t ExtraCap = normalizedDynamicExtra(Params.dynamic_size);
    const bool HasPersistentWork = AlignBytes != 0 || ExtraCap != 0 ||
                                   Params.relocate_probability != 0 ||
                                   Params.alias_amplify != 0;
    if (!HasPersistentWork && !Params.nonentry_shuffle)
        return false;

    SmallVector<AllocaInst *, 16> OriginalAllocas = collectStaticAllocas(F, DL);

    F.addFnAttr(Attribute::NoInline);
    F.addFnAttr("frame-pointer", "all");

    bool Changed = false;
    Value *Mix = nullptr;
    if (HasPersistentWork) {
        Builder AllocaB(entryInsertionPoint(F));
        AllocaInst *Anchor = emitRealignAnchor(AllocaB, AlignBytes);

        Builder BodyB(afterEntryAllocas(F));
        if (Anchor)
            emitPointerIntEscape(BodyB, M, Anchor, rng);
        AllocaInst *Dyn =
            emitPersistentDynamicAlloca(F, BodyB, M, Anchor, ExtraCap, rng);
        Mix = buildMix(BodyB, M, F, Dyn ? static_cast<Value *>(Dyn)
                                        : static_cast<Value *>(Anchor),
                       rng);

        emitRelocationEscapes(BodyB, M, OriginalAllocas,
                              Params.relocate_probability, Mix, rng);
        emitAliasAmplifier(BodyB, M, OriginalAllocas, Params.alias_amplify, Mix,
                           rng);
        Changed = Anchor || Dyn || Params.relocate_probability != 0 ||
                  Params.alias_amplify != 0;
    }

    if (Params.nonentry_shuffle) {
        Changed |= emitNonEntryShuffle(
            F, M, ExtraCap == 0 ? kMinDynamicExtra : ExtraCap, rng);
    }

    return Changed;
}

PreservedAnalyses StackRebasePass::run(Function &F, FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return stackRebaseFunction(F, params_, rng) ? PreservedAnalyses::none()
                                                : PreservedAnalyses::all();
}

} // namespace morok::passes
