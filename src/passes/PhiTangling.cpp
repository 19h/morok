// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/PhiTangling.cpp
//
// SSA/PHI tangling: surround an existing scalar integer/FP PHI with redundant
// edge copies and PHIs that all carry the same value.  Cross-PHI XORs over
// integer carriers produce zero and are folded into downstream uses, preserving
// semantics while making expression propagation walk a denser cross-block web.

#include "morok/passes/PhiTangling.hpp"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/NoFolder.h"

#include <algorithm>
#include <cstdint>
#include <utility>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

bool isPassGenerated(const Value *V) {
    if (const auto *I = dyn_cast<Instruction>(V))
        return I->getName().starts_with("morok.phi");
    return false;
}

IntegerType *integerCarrierFor(Type *Ty) {
    if (auto *IT = dyn_cast<IntegerType>(Ty))
        return IT;
    if (Ty->isHalfTy() || Ty->isBFloatTy())
        return IntegerType::get(Ty->getContext(), 16);
    if (Ty->isFloatTy())
        return IntegerType::get(Ty->getContext(), 32);
    if (Ty->isDoubleTy())
        return IntegerType::get(Ty->getContext(), 64);
    return nullptr;
}

bool eligiblePhi(const PHINode &PN) {
    IntegerType *CarrierTy = integerCarrierFor(PN.getType());
    if (!CarrierTy || CarrierTy->getBitWidth() == 0 || isPassGenerated(&PN))
        return false;
    if (PN.getNumIncomingValues() < 2)
        return false;

    for (unsigned i = 0; i < PN.getNumIncomingValues(); ++i) {
        BasicBlock *Pred = PN.getIncomingBlock(i);
        if (!Pred || Pred->isEHPad() || Pred->isLandingPad() ||
            isa<InvokeInst>(Pred->getTerminator()))
            return false;
    }
    return true;
}

void trackGenerated(Value *V, std::vector<Instruction *> &Generated) {
    if (auto *I = dyn_cast<Instruction>(V))
        Generated.push_back(I);
}

void shufflePhis(std::vector<PHINode *> &phis, ir::IRRandom &rng) {
    for (std::size_t i = phis.size(); i > 1; --i) {
        const std::size_t j = rng.range(static_cast<std::uint32_t>(i));
        std::swap(phis[i - 1], phis[j]);
    }
}

Value *toCarrier(IRBuilder<NoFolder> &B, Value *V, IntegerType *CarrierTy) {
    if (V->getType()->isIntegerTy())
        return V;
    return B.CreateBitCast(V, CarrierTy, "morok.phi.bits");
}

Value *fromCarrier(IRBuilder<NoFolder> &B, Value *V, Type *ResultTy,
                   StringRef Name) {
    if (ResultTy->isIntegerTy())
        return V;
    return B.CreateBitCast(V, ResultTy, Name);
}

Value *edgeCopy(PHINode &PN, unsigned incoming, IntegerType *CarrierTy,
                ir::IRRandom &rng, std::vector<Instruction *> &generated) {
    BasicBlock *Pred = PN.getIncomingBlock(incoming);
    Instruction *Term = Pred->getTerminator();
    IRBuilder<NoFolder> B(Term);
    Value *V = PN.getIncomingValue(incoming);
    // For a self-loop edge the incoming value IS the PHI, so the carrier
    // instructions below use the original PHI.  Record every instruction we
    // create here in `generated` so replaceUses() never rewrites that PHI
    // operand to the later tangled replacement — which, when this edge copy is
    // emitted ahead of the replacement (a latch whose first non-PHI is the
    // terminator), would be an invalid use-before-def.  toCarrier/fromCarrier
    // can return their input unchanged, so only track newly created values.
    Value *Bits = toCarrier(B, V, CarrierTy);
    if (Bits != V)
        trackGenerated(Bits, generated);
    Value *K = rng.constInt(CarrierTy);
    Value *Mixed = B.CreateXor(Bits, K, "morok.phi.edge.mix");
    Value *Copy = B.CreateXor(Mixed, K, "morok.phi.edge.copy.bits");
    trackGenerated(Mixed, generated);
    trackGenerated(Copy, generated);
    Value *Result = fromCarrier(B, Copy, PN.getType(), "morok.phi.edge.copy");
    if (Result != Copy)
        trackGenerated(Result, generated);
    return Result;
}

PHINode *cloneDirectPhi(PHINode &PN) {
    auto *Copy = PHINode::Create(PN.getType(), PN.getNumIncomingValues(),
                                 "morok.phi.direct", PN.getIterator());
    for (unsigned i = 0; i < PN.getNumIncomingValues(); ++i)
        Copy->addIncoming(PN.getIncomingValue(i), PN.getIncomingBlock(i));
    return Copy;
}

PHINode *cloneEdgePhi(PHINode &PN, IntegerType *CarrierTy, ir::IRRandom &rng,
                      std::vector<Instruction *> &generated) {
    auto *Copy = PHINode::Create(PN.getType(), PN.getNumIncomingValues(),
                                 "morok.phi.edge", PN.getIterator());
    // A predecessor can appear at more than one incoming index (callbr/asm-goto
    // with duplicate targets, or `br` with both arms to one block).  Every
    // entry for the same block must carry an identical value, so compute the
    // edge copy once per distinct predecessor and reuse it.
    DenseMap<BasicBlock *, Value *> PerBlock;
    for (unsigned i = 0; i < PN.getNumIncomingValues(); ++i) {
        BasicBlock *Pred = PN.getIncomingBlock(i);
        auto It = PerBlock.find(Pred);
        if (It == PerBlock.end())
            It = PerBlock
                     .try_emplace(Pred,
                                  edgeCopy(PN, i, CarrierTy, rng, generated))
                     .first;
        Copy->addIncoming(It->second, Pred);
    }
    return Copy;
}

Instruction *firstInsertionAfterPhis(BasicBlock &BB) {
    for (Instruction &I : BB)
        if (!isa<PHINode>(&I))
            return &I;
    return BB.getTerminator();
}

Value *buildTangledValue(PHINode &PN, const PhiTangleParams &params,
                         ir::IRRandom &rng,
                         std::vector<Instruction *> &generated) {
    auto *CarrierTy = integerCarrierFor(PN.getType());
    BasicBlock &BB = *PN.getParent();
    Instruction *InsertPt = firstInsertionAfterPhis(BB);
    IRBuilder<NoFolder> B(InsertPt);

    Value *Acc = &PN;
    const std::uint32_t layers = std::max<std::uint32_t>(params.layers, 1);
    for (std::uint32_t i = 0; i < layers; ++i) {
        PHINode *Edge = cloneEdgePhi(PN, CarrierTy, rng, generated);
        PHINode *Direct = cloneDirectPhi(PN);
        generated.push_back(Edge);
        generated.push_back(Direct);

        Value *EdgeBits = toCarrier(B, Edge, CarrierTy);
        Value *DirectBits = toCarrier(B, Direct, CarrierTy);
        Value *Zero = B.CreateXor(EdgeBits, DirectBits, "morok.phi.zero");
        Value *AccBits = toCarrier(B, Acc, CarrierTy);
        Value *NextBits = B.CreateXor(AccBits, Zero, PN.getType()->isIntegerTy()
                                                         ? "morok.phi.value"
                                                         : "morok.phi.value.bits");
        Value *Next =
            fromCarrier(B, NextBits, PN.getType(), "morok.phi.value");
        trackGenerated(EdgeBits, generated);
        trackGenerated(DirectBits, generated);
        trackGenerated(Zero, generated);
        trackGenerated(AccBits, generated);
        trackGenerated(NextBits, generated);
        trackGenerated(Next, generated);
        Acc = Next;
    }
    return Acc;
}

void replaceUses(PHINode &PN, Value *Replacement,
                 const std::vector<Instruction *> &generated) {
    SmallPtrSet<const User *, 16> generatedUsers;
    for (Instruction *I : generated)
        generatedUsers.insert(I);

    PN.replaceUsesWithIf(Replacement, [&](Use &U) {
        if (generatedUsers.contains(U.getUser()))
            return false;
        if (auto *UserI = dyn_cast<Instruction>(U.getUser()))
            if (isa<PHINode>(UserI) && UserI->getParent() == PN.getParent())
                return false;
        return true;
    });
}

} // namespace

bool phiTangleFunction(Function &F, const PhiTangleParams &params,
                       ir::IRRandom &rng) {
    if (F.isDeclaration() || params.probability == 0 || params.max_phis == 0)
        return false;

    std::vector<PHINode *> candidates;
    for (BasicBlock &BB : F)
        for (Instruction &I : BB) {
            auto *PN = dyn_cast<PHINode>(&I);
            if (!PN)
                break;
            if (eligiblePhi(*PN))
                candidates.push_back(PN);
        }

    shufflePhis(candidates, rng);

    bool changed = false;
    std::uint32_t selected = 0;
    for (PHINode *PN : candidates) {
        if (selected >= params.max_phis)
            break;
        if (!rng.chance(params.probability))
            continue;

        std::vector<Instruction *> generated;
        Value *Replacement = buildTangledValue(*PN, params, rng, generated);
        replaceUses(*PN, Replacement, generated);
        changed = true;
        ++selected;
    }

    return changed;
}

PreservedAnalyses PhiTanglingPass::run(Function &F, FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return phiTangleFunction(F, params_, rng) ? PreservedAnalyses::none()
                                              : PreservedAnalyses::all();
}

} // namespace morok::passes
