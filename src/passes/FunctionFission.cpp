// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/FunctionFission.cpp
//
// Splits a function into several smaller functions by outlining single-entry/
// single-exit regions (from RegionInfo) through LLVM's CodeExtractor.  Each
// extracted region becomes a fresh internal `morok.fission.*` callee and the
// region is replaced by a call, so the original function shrinks and its logic
// is scattered across smaller callees.  The pass runs before the per-function
// obfuscation wave, so the shrunken original and (via shell hardening) the parts
// are obfuscated afterwards; the parts are marked noinline so the later -O
// inliner cannot fuse them back together.

#include "morok/passes/FunctionFission.hpp"

#include "llvm/Analysis/DominanceFrontier.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/Analysis/RegionInfo.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/CodeExtractor.h"

#include <algorithm>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr char kPartAttr[] = "morok-fission-part";
constexpr std::uint32_t kHardMaxSplits = 64;

bool callReturnsTwice(CallBase &CB) {
    if (CB.hasFnAttr(Attribute::ReturnsTwice))
        return true;
    if (Function *Callee = CB.getCalledFunction())
        return Callee->hasFnAttribute(Attribute::ReturnsTwice);
    return false;
}

bool functionEligible(Function &F) {
    if (F.isDeclaration() || F.getName().starts_with("morok.") ||
        F.hasFnAttribute(Attribute::Naked) || F.hasFnAttribute(kPartAttr) ||
        F.hasPersonalityFn() || F.isVarArg())
        return false;
    if (F.callsFunctionThatReturnsTwice())
        return false;
    // Computed-goto / blockaddress functions are fragile to outline (moving a
    // referenced block invalidates its address); skip the whole function.
    for (BasicBlock &BB : F) {
        if (BB.hasAddressTaken())
            return false;
        if (isa<IndirectBrInst>(BB.getTerminator()))
            return false;
        for (Instruction &I : BB)
            if (auto *CB = dyn_cast<CallBase>(&I))
                if (callReturnsTwice(*CB))
                    return false;
    }
    return true;
}

bool regionBlockSafe(BasicBlock &BB) {
    if (BB.isEHPad() || BB.isLandingPad() || BB.hasAddressTaken())
        return false;
    for (Instruction &I : BB) {
        if (isa<AllocaInst>(&I))
            return false; // CodeExtractor runs with AllowAlloca = false
        if (I.getType()->isTokenTy())
            return false; // CodeExtractor cannot thread token values safely.
        if (auto *CB = dyn_cast<CallBase>(&I)) {
            if (callReturnsTwice(*CB))
                return false;
            if (auto *CI = dyn_cast<CallInst>(&I))
                if (CI->isMustTailCall())
                    return false;
        }
        if (auto *II = dyn_cast<IntrinsicInst>(&I)) {
            switch (II->getIntrinsicID()) {
            case Intrinsic::vastart:
            case Intrinsic::vaend:
            case Intrinsic::vacopy:
            case Intrinsic::eh_typeid_for:
            case Intrinsic::eh_sjlj_setjmp:
            case Intrinsic::eh_sjlj_longjmp:
                return false;
            default:
                break;
            }
        }
    }
    return true;
}

std::vector<BasicBlock *> regionBlocks(Region &R) {
    return std::vector<BasicBlock *>(R.block_begin(), R.block_end());
}

bool regionEligible(Region &R, Function &F, const FunctionFissionParams &params,
                    const SmallPtrSetImpl<BasicBlock *> &tried) {
    if (R.isTopLevelRegion())
        return false;
    BasicBlock *Entry = R.getEntry();
    if (!Entry || Entry == &F.getEntryBlock() || tried.count(Entry))
        return false;
    std::vector<BasicBlock *> Blocks = regionBlocks(R);
    const std::size_t N = Blocks.size();
    if (N < params.min_region_blocks || N > params.max_region_blocks ||
        N + 1 >= F.size())
        return false; // leave at least the entry and a remainder in F
    for (BasicBlock *BB : Blocks)
        if (!regionBlockSafe(*BB))
            return false;
    return true;
}

void collectRegions(Region *R, std::vector<Region *> &Out) {
    if (!R)
        return;
    Out.push_back(R);
    for (const auto &Sub : *R)
        collectRegions(Sub.get(), Out);
}

} // namespace

bool functionFissionFunction(Function &F, const FunctionFissionParams &params,
                             ir::IRRandom &rng) {
    if (params.max_splits == 0 || params.probability == 0 ||
        !functionEligible(F))
        return false;

    const std::uint32_t Limit = std::min(params.max_splits, kHardMaxSplits);
    SmallPtrSet<BasicBlock *, 16> Tried;
    bool Changed = false;

    for (std::uint32_t Done = 0; Done < Limit;) {
        DominatorTree DT(F);
        PostDominatorTree PDT(F);
        DominanceFrontier DF;
        DF.analyze(DT);
        RegionInfo RI;
        RI.recalculate(F, &DT, &PDT, &DF);

        std::vector<Region *> All;
        collectRegions(RI.getTopLevelRegion(), All);
        std::vector<Region *> Cands;
        Cands.reserve(All.size());
        for (Region *R : All)
            if (regionEligible(*R, F, params, Tried))
                Cands.push_back(R);
        if (Cands.empty())
            break;

        Region *R = Cands[rng.range(static_cast<std::uint32_t>(Cands.size()))];
        Tried.insert(R->getEntry());
        if (!rng.chance(params.probability))
            continue;

        std::vector<BasicBlock *> Blocks = regionBlocks(*R);
        CodeExtractorAnalysisCache CEAC(F);
        CodeExtractor CE(Blocks, &DT, /*AggregateArgs=*/false,
                         /*BFI=*/nullptr, /*BPI=*/nullptr, /*AC=*/nullptr,
                         /*AllowVarArgs=*/false, /*AllowAlloca=*/false);
        if (!CE.isEligible())
            continue;
        Function *G = CE.extractCodeRegion(CEAC);
        if (!G)
            continue;

        G->setLinkage(GlobalValue::InternalLinkage);
        G->setName("morok.fission");
        G->addFnAttr(kPartAttr);
        // Keep the split: stop the later inliner from fusing the part back into
        // the (now smaller) caller, which would undo the boundary obfuscation.
        G->addFnAttr(Attribute::NoInline);
        ++Done;
        Changed = true;
    }
    return Changed;
}

bool functionFissionModule(Module &M, const FunctionFissionParams &params,
                           ir::IRRandom &rng) {
    if (params.max_splits == 0 || params.probability == 0)
        return false;

    // Snapshot the eligible functions first: parts created during the walk are
    // appended to M but must not themselves be re-split.
    std::vector<Function *> Targets;
    for (Function &F : M)
        if (functionEligible(F))
            Targets.push_back(&F);

    bool Changed = false;
    for (Function *F : Targets)
        Changed |= functionFissionFunction(*F, params, rng);
    return Changed;
}

PreservedAnalyses FunctionFissionPass::run(Function &F,
                                           FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return functionFissionFunction(F, params_, rng) ? PreservedAnalyses::none()
                                                    : PreservedAnalyses::all();
}

} // namespace morok::passes
