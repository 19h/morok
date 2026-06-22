// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/CoherentDecoys.cpp
//
// Coherent decoy dead paths.  Each selected scalar return is split into a guard
// block, the real return block, and a dead alternate return block.  The guard
// uses two volatile loads from a private global, so the predicate is true at
// runtime but not foldable.  The decoy return computes a type-correct value
// from real inputs and live values rather than emitting arbitrary junk.  If the
// false arm is patched into execution, it records a nonzero hidden state that
// later integrity-entangled data flow can consume.

#include "morok/passes/CoherentDecoys.hpp"

#include "morok/ir/InstUtil.hpp"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include <algorithm>
#include <cstdint>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr char kOpaqueGlobal[] = "morok.decoy.opaque";
constexpr char kStateGlobal[] = "morok.decoy.state";
constexpr char kAltBlock[] = "morok.decoy.alt";

GlobalVariable *opaqueGlobal(Module &M, ir::IRRandom &rng) {
    if (auto *GV = M.getGlobalVariable(kOpaqueGlobal, /*AllowInternal=*/true))
        return GV;
    auto *I32 = Type::getInt32Ty(M.getContext());
    auto *GV = new GlobalVariable(
        M, I32, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I32, static_cast<std::uint32_t>(rng.next())),
        kOpaqueGlobal);
    GV->setAlignment(Align(4));
    return GV;
}

GlobalVariable *stateGlobal(Module &M) {
    if (auto *GV = M.getGlobalVariable(kStateGlobal, /*AllowInternal=*/true))
        return GV;
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *GV = new GlobalVariable(
        M, I64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I64, 0), kStateGlobal);
    GV->setAlignment(Align(8));
    return GV;
}

bool isGeneratedBlock(const BasicBlock &BB) {
    return BB.getName().starts_with("morok.decoy");
}

bool isLinuxX86_64Target(const Function &F) {
    const Module *M = F.getParent();
    if (!M)
        return false;
    const Triple TT(M->getTargetTriple());
    return TT.getArch() == Triple::x86_64 && TT.isOSLinux();
}

bool eligibleReturn(ReturnInst &RI) {
    if (ir::isMustTailReturn(RI))
        return false;
    Value *Ret = RI.getReturnValue();
    if (!Ret)
        return false;
    Type *Ty = Ret->getType();
    if (auto *IT = dyn_cast<IntegerType>(Ty))
        return IT->getBitWidth() > 0;
    return Ty->isHalfTy() || Ty->isBFloatTy() || Ty->isFloatTy() ||
           Ty->isDoubleTy();
}

bool smallIntegerReturn(ReturnInst &RI) {
    Value *Ret = RI.getReturnValue();
    if (!Ret)
        return false;
    auto *IT = dyn_cast<IntegerType>(Ret->getType());
    return IT && IT->getBitWidth() <= 32;
}

bool isSupportedFp(Type *Ty) {
    return Ty->isHalfTy() || Ty->isBFloatTy() || Ty->isFloatTy() ||
           Ty->isDoubleTy();
}

IntegerType *integerCarrierForFp(Type *Ty) {
    if (Ty->isHalfTy() || Ty->isBFloatTy())
        return IntegerType::get(Ty->getContext(), 16);
    if (Ty->isFloatTy())
        return IntegerType::get(Ty->getContext(), 32);
    if (Ty->isDoubleTy())
        return IntegerType::get(Ty->getContext(), 64);
    return nullptr;
}

std::vector<ReturnInst *> collectReturns(Function &F,
                                         bool SkipSmallIntegerReturns) {
    std::vector<ReturnInst *> Returns;
    for (Instruction &I : instructions(F)) {
        auto *RI = dyn_cast<ReturnInst>(&I);
        if (!RI || isGeneratedBlock(*RI->getParent()) || !eligibleReturn(*RI))
            continue;
        // LLVM 23's Linux x86_64 backend can abort while printing optimized
        // dead-arm i32 decoy mixes (IMUL32rri with an invalid killed source).
        // Keep coherent decoys for wider integer/floating returns on the target.
        if (SkipSmallIntegerReturns && smallIntegerReturn(*RI))
            continue;
        Returns.push_back(RI);
    }
    return Returns;
}

void shuffleReturns(std::vector<ReturnInst *> &Returns, ir::IRRandom &rng) {
    for (std::size_t I = Returns.size(); I > 1; --I) {
        const std::size_t J = rng.range(static_cast<std::uint32_t>(I));
        std::swap(Returns[I - 1], Returns[J]);
    }
}

bool isCompatibleTerm(Type *RetTy, Type *TermTy) {
    if (RetTy->isIntegerTy())
        return TermTy->isIntegerTy() || isSupportedFp(TermTy);
    return TermTy->isIntegerTy() || isSupportedFp(TermTy);
}

Value *asIntegerReturnType(IRBuilder<NoFolder> &B, Value *V,
                           IntegerType *RetTy) {
    if (!V)
        return nullptr;
    if (isSupportedFp(V->getType())) {
        auto *CarrierTy = integerCarrierForFp(V->getType());
        if (!CarrierTy)
            return nullptr;
        V = B.CreateBitCast(V, CarrierTy, "morok.decoy.alt.fpbits");
    }
    if (!V->getType()->isIntegerTy())
        return nullptr;
    if (V->getType() == RetTy)
        return V;
    auto *IT = cast<IntegerType>(V->getType());
    const unsigned SrcBits = IT->getBitWidth();
    const unsigned DstBits = RetTy->getBitWidth();
    if (SrcBits < DstBits)
        return B.CreateZExt(V, RetTy, "morok.decoy.alt.zext");
    if (SrcBits > DstBits)
        return B.CreateTrunc(V, RetTy, "morok.decoy.alt.trunc");
    return B.CreateIntCast(V, RetTy, false, "morok.decoy.alt.cast");
}

Value *asFloatingReturnType(IRBuilder<NoFolder> &B, Value *V, Type *RetTy) {
    if (!V)
        return nullptr;
    Type *Ty = V->getType();
    if (Ty == RetTy)
        return V;
    if (Ty->isIntegerTy())
        return B.CreateSIToFP(V, RetTy, "morok.decoy.alt.sitofp");
    if (Ty->isHalfTy() || Ty->isBFloatTy() || Ty->isFloatTy() ||
        Ty->isDoubleTy())
        return B.CreateFPCast(V, RetTy, "morok.decoy.alt.fpcast");
    return nullptr;
}

Value *asReturnType(IRBuilder<NoFolder> &B, Value *V, Type *RetTy) {
    if (auto *IT = dyn_cast<IntegerType>(RetTy))
        return asIntegerReturnType(B, V, IT);
    return asFloatingReturnType(B, V, RetTy);
}

Value *asI64Bits(IRBuilder<NoFolder> &B, Value *V) {
    auto *I64 = B.getInt64Ty();
    Type *Ty = V->getType();
    Value *Frozen = B.CreateFreeze(V, "morok.decoy.state.freeze");
    if (auto *IT = dyn_cast<IntegerType>(Ty)) {
        if (IT->getBitWidth() > 64)
            return nullptr;
        return B.CreateZExtOrTrunc(Frozen, I64, "morok.decoy.state.bits");
    }
    if (isSupportedFp(Ty)) {
        auto *Carrier = integerCarrierForFp(Ty);
        if (!Carrier || Carrier->getBitWidth() > 64)
            return nullptr;
        Value *Bits = B.CreateBitCast(Frozen, Carrier,
                                      "morok.decoy.state.rawbits");
        return B.CreateZExtOrTrunc(Bits, I64, "morok.decoy.state.bits");
    }
    return nullptr;
}

void recordDecoyExecution(IRBuilder<NoFolder> &B, GlobalVariable *State,
                          Value *Alt, ir::IRRandom &rng) {
    Value *Bits = asI64Bits(B, Alt);
    if (!Bits)
        return;
    auto *I64 = B.getInt64Ty();
    auto *Cur = B.CreateLoad(I64, State, "morok.decoy.state.load");
    Cur->setVolatile(true);
    Cur->setAlignment(Align(8));
    Value *Mix =
        B.CreateXor(Cur, ConstantInt::get(I64, rng.next()),
                    "morok.decoy.state.mix");
    Mix = B.CreateAdd(Mix, Bits, "morok.decoy.state.mix");
    Mix = B.CreateXor(Mix,
                      B.CreateShl(Bits, ConstantInt::get(I64, 7),
                                  "morok.decoy.state.shift"),
                      "morok.decoy.state.mix");
    Mix = B.CreateMul(Mix, ConstantInt::get(I64, rng.next() | 1ull),
                      "morok.decoy.state.mix");
    Mix = B.CreateOr(Mix, ConstantInt::get(I64, 1),
                     "morok.decoy.state.mark");
    auto *Store = B.CreateStore(Mix, State);
    Store->setVolatile(true);
    Store->setAlignment(Align(8));
}

void addTerm(Value *V, Type *RetTy, SmallPtrSetImpl<Value *> &Seen,
             std::vector<Value *> &Terms) {
    if (!V || !isCompatibleTerm(RetTy, V->getType()))
        return;
    if (Seen.insert(V).second)
        Terms.push_back(V);
}

std::vector<Value *> collectTerms(ReturnInst &RI, BasicBlock &VisibleBlock) {
    std::vector<Value *> Terms;
    SmallPtrSet<Value *, 32> Seen;
    Type *RetTy = RI.getReturnValue()->getType();
    Function *F = RI.getFunction();
    for (Argument &Arg : F->args())
        addTerm(&Arg, RetTy, Seen, Terms);

    for (Instruction &I : VisibleBlock) {
        if (I.isTerminator())
            break;
        if (isa<AllocaInst>(&I))
            continue;
        addTerm(&I, RetTy, Seen, Terms);
    }
    return Terms;
}

void shuffleTerms(std::vector<Value *> &Terms, ir::IRRandom &rng) {
    for (std::size_t I = Terms.size(); I > 1; --I) {
        const std::size_t J = rng.range(static_cast<std::uint32_t>(I));
        std::swap(Terms[I - 1], Terms[J]);
    }
}

double fpSalt(ir::IRRandom &rng) {
    const auto Raw = static_cast<std::uint32_t>(rng.next());
    const double Mag = static_cast<double>((Raw & 0xffu) + 1u) / 13.0;
    return (Raw & 0x100u) ? -Mag : Mag;
}

Value *buildIntegerAlternateValue(IRBuilder<NoFolder> &B, ReturnInst &RI,
                                  ArrayRef<Value *> Terms,
                                  const CoherentDecoyParams &Params,
                                  ir::IRRandom &rng) {
    auto *RetTy = cast<IntegerType>(RI.getReturnValue()->getType());
    Value *Alt = RI.getReturnValue();
    Alt = B.CreateXor(Alt,
                      ConstantInt::get(RetTy,
                                       static_cast<std::uint64_t>(rng.next())),
                      "morok.decoy.alt.seed");
    const std::uint32_t Limit = std::min<std::uint32_t>(
        Params.depth, static_cast<std::uint32_t>(Terms.size()));

    for (std::uint32_t I = 0; I < Limit; ++I) {
        Value *Term = asReturnType(B, Terms[I], RetTy);
        if (!Term)
            continue;
        Value *Salt =
            ConstantInt::get(RetTy, static_cast<std::uint64_t>(rng.next()));
        Value *Odd = ConstantInt::get(
            RetTy, static_cast<std::uint64_t>(rng.next()) | 1ull);
        Alt = B.CreateAdd(Alt, B.CreateXor(Term, Salt, "morok.decoy.alt.term"),
                          "morok.decoy.alt.add");
        Alt = B.CreateMul(Alt, Odd, "morok.decoy.alt.mul");
        Alt = B.CreateXor(Alt, Term, "morok.decoy.alt.mix");
    }

    return Alt;
}

Value *buildFloatingAlternateValue(IRBuilder<NoFolder> &B, ReturnInst &RI,
                                   ArrayRef<Value *> Terms,
                                   const CoherentDecoyParams &Params,
                                   ir::IRRandom &rng) {
    Type *RetTy = RI.getReturnValue()->getType();
    Value *Alt = B.CreateFAdd(RI.getReturnValue(),
                              ConstantFP::get(RetTy, fpSalt(rng)),
                              "morok.decoy.alt.seed");
    const std::uint32_t Limit = std::min<std::uint32_t>(
        Params.depth, static_cast<std::uint32_t>(Terms.size()));

    for (std::uint32_t I = 0; I < Limit; ++I) {
        Value *Term = asReturnType(B, Terms[I], RetTy);
        if (!Term)
            continue;
        Value *Salt = ConstantFP::get(RetTy, fpSalt(rng));
        Value *Scale = ConstantFP::get(RetTy, fpSalt(rng));
        Value *Shift = B.CreateFSub(Term, Salt, "morok.decoy.alt.term");
        Alt = B.CreateFAdd(Alt, Shift, "morok.decoy.alt.add");
        Alt = B.CreateFMul(Alt, Scale, "morok.decoy.alt.mul");
        Alt = B.CreateFSub(Alt, Term, "morok.decoy.alt.mix");
    }

    return Alt;
}

Value *buildAlternateValue(IRBuilder<NoFolder> &B, ReturnInst &RI,
                           BasicBlock &VisibleBlock,
                           const CoherentDecoyParams &Params,
                           ir::IRRandom &rng) {
    std::vector<Value *> Terms = collectTerms(RI, VisibleBlock);
    shuffleTerms(Terms, rng);
    if (RI.getReturnValue()->getType()->isIntegerTy())
        return buildIntegerAlternateValue(B, RI, Terms, Params, rng);
    return buildFloatingAlternateValue(B, RI, Terms, Params, rng);
}

Value *opaqueTrue(IRBuilder<NoFolder> &B, GlobalVariable *GV) {
    auto *I32 = B.getInt32Ty();
    auto *A = B.CreateLoad(I32, GV, "morok.decoy.a");
    A->setVolatile(true);
    A->setAlignment(Align(4));
    auto *Bv = B.CreateLoad(I32, GV, "morok.decoy.b");
    Bv->setVolatile(true);
    Bv->setAlignment(Align(4));
    return B.CreateICmpEQ(A, Bv, "morok.decoy.pred");
}

bool rewriteReturn(ReturnInst *RI, GlobalVariable *GV, GlobalVariable *State,
                   const CoherentDecoyParams &Params, ir::IRRandom &rng) {
    BasicBlock *Head = RI->getParent();
    Function *F = Head->getParent();
    BasicBlock *Real = SplitBlock(Head, RI);
    Instruction *HeadTerm = Head->getTerminator();

    auto *AltBB = BasicBlock::Create(F->getContext(), kAltBlock, F, Real);
    IRBuilder<NoFolder> AltB(AltBB);
    Value *Alt = buildAlternateValue(AltB, *RI, *Head, Params, rng);
    recordDecoyExecution(AltB, State, Alt, rng);
    AltB.CreateRet(Alt);

    IRBuilder<NoFolder> GuardB(HeadTerm);
    Value *Pred = opaqueTrue(GuardB, GV);
    GuardB.CreateCondBr(Pred, Real, AltBB);
    HeadTerm->eraseFromParent();
    return true;
}

} // namespace

bool coherentDecoysFunction(Function &F, const CoherentDecoyParams &params,
                            ir::IRRandom &rng) {
    if (F.isDeclaration() || F.getName().starts_with("morok.") ||
        params.probability == 0 || params.max_blocks == 0)
        return false;

    std::vector<ReturnInst *> Returns =
        collectReturns(F, isLinuxX86_64Target(F));
    shuffleReturns(Returns, rng);
    if (Returns.empty())
        return false;

    GlobalVariable *GV = nullptr;
    GlobalVariable *State = nullptr;
    bool Changed = false;
    std::uint32_t Count = 0;
    for (ReturnInst *RI : Returns) {
        if (Count >= params.max_blocks)
            break;
        if (!rng.chance(params.probability))
            continue;
        if (!GV)
            GV = opaqueGlobal(*F.getParent(), rng);
        if (!State)
            State = stateGlobal(*F.getParent());
        Changed |= rewriteReturn(RI, GV, State, params, rng);
        ++Count;
    }
    return Changed;
}

PreservedAnalyses CoherentDecoysPass::run(Function &F,
                                          FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return coherentDecoysFunction(F, params_, rng) ? PreservedAnalyses::none()
                                                   : PreservedAnalyses::all();
}

} // namespace morok::passes
