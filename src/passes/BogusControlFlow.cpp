// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/passes/BogusControlFlow.cpp
//
// For each chosen block we split off the body, then branch to it under an
// opaque predicate that is always true at run time but cannot be folded by the
// optimizer: two volatile loads of a never-written private global compared for
// equality.  LLVM may not assume two volatile loads are equal, so the bogus
// edge survives; at run time the values are identical, so the junk arm is never
// taken. The body is split after its PHIs and gains no new PHI obligations, so
// the transform is correct by construction.

#include "morok/passes/BogusControlFlow.hpp"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr char kOpaqueGlobal[] = "morok.bcf.opaque";

// A never-written private i32 global used to source opaque predicates.
GlobalVariable *opaqueGlobal(Module &M, ir::IRRandom &rng) {
    if (auto *gv = M.getGlobalVariable(kOpaqueGlobal, /*AllowInternal=*/true))
        return gv;
    auto *i32 = Type::getInt32Ty(M.getContext());
    return new GlobalVariable(
        M, i32, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(i32, rng.next() & 0xFFFFFFFFu), kOpaqueGlobal);
}

} // namespace

bool bogusControlFlowFunction(Function &F, const BcfParams &params,
                              ir::IRRandom &rng) {
    const std::uint32_t iterations = params.iterations ? params.iterations : 1;
    Module &M = *F.getParent();
    auto *i32 = Type::getInt32Ty(F.getContext());
    bool changed = false;

    for (std::uint32_t it = 0; it < iterations; ++it) {
        std::vector<BasicBlock *> blocks;
        for (BasicBlock &bb : F)
            blocks.push_back(&bb);

        for (BasicBlock *head : blocks) {
            if (head->isEHPad() || head->isLandingPad())
                continue;
            if (!rng.chance(params.probability))
                continue;

            BasicBlock::iterator splitPt = head->getFirstNonPHIIt();
            if (splitPt == head->end() || splitPt->isTerminator())
                continue; // nothing meaningful to guard

            // head = [PHIs] + (unconditional br to body); body = the rest.
            BasicBlock *body = SplitBlock(head, splitPt);
            GlobalVariable *gv = opaqueGlobal(M, rng);

            // Build the opaque-true predicate at the end of head, replacing the
            // unconditional branch SplitBlock inserted.
            Instruction *headTerm = head->getTerminator();
            IRBuilder<> B(headTerm);
            Value *a = B.CreateLoad(i32, gv, /*isVolatile=*/true);
            Value *b = B.CreateLoad(i32, gv, /*isVolatile=*/true);
            Value *pred = B.CreateICmpEQ(a, b); // always true at run time

            // Junk block: a dead computation that re-joins the body.
            BasicBlock *junk =
                BasicBlock::Create(F.getContext(), "morok.bcf.junk", &F, body);
            IRBuilder<> JB(junk);
            Value *j = JB.CreateLoad(i32, gv, /*isVolatile=*/true);
            j = JB.CreateAdd(j, ConstantInt::get(i32, rng.next() & 0xFFFF));
            j = JB.CreateXor(j, ConstantInt::get(i32, rng.next() & 0xFFFF));
            (void)j;
            JB.CreateBr(body);

            // Replace head's unconditional branch with the guarded one.
            B.CreateCondBr(pred, body, junk);
            headTerm->eraseFromParent();

            changed = true;
        }
    }
    return changed;
}

PreservedAnalyses BogusControlFlowPass::run(Function &F,
                                            FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return bogusControlFlowFunction(F, params_, rng) ? PreservedAnalyses::none()
                                                     : PreservedAnalyses::all();
}

} // namespace morok::passes
