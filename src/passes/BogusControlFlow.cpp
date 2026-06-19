// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
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
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include <algorithm>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr char kOpaqueGlobal[] = "morok.bcf.opaque";
constexpr char kEntropyGlobal[] = "morok.bcf.entropy";

// Upper bound on opaque-predicate depth so a malformed/huge `complexity` cannot
// explode the guard size.
constexpr std::uint32_t kMaxComplexity = 16;

// Each iteration clones/branches more of the function's blocks, so the CFG
// grows with the iteration count.  The "max" preset asks for 3; clamp to a
// generous ceiling so a malformed config — or a stale/partial build that hands
// this pass an uninitialized BogusControlFlowParams — can never explode compile
// time on the amplified function.
constexpr std::uint32_t kMaxBcfIterations = 8;

// A never-written private i32 global used to source opaque predicates.
GlobalVariable *opaqueGlobal(Module &M, ir::IRRandom &rng) {
    if (auto *gv = M.getGlobalVariable(kOpaqueGlobal, /*AllowInternal=*/true))
        return gv;
    auto *i32 = Type::getInt32Ty(M.getContext());
    return new GlobalVariable(
        M, i32, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(i32, rng.next() & 0xFFFFFFFFu), kOpaqueGlobal);
}

// A shared private i32 the entropy_chain knob threads through every junk arm.
GlobalVariable *entropyGlobal(Module &M, ir::IRRandom &rng) {
    if (auto *gv = M.getGlobalVariable(kEntropyGlobal, /*AllowInternal=*/true))
        return gv;
    auto *i32 = Type::getInt32Ty(M.getContext());
    return new GlobalVariable(
        M, i32, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(i32, rng.next() & 0xFFFFFFFFu), kEntropyGlobal);
}

} // namespace

bool bogusControlFlowFunction(Function &F, const BcfParams &params,
                              ir::IRRandom &rng) {
    const std::uint32_t iterations = std::clamp<std::uint32_t>(
        params.iterations ? params.iterations : 1, 1, kMaxBcfIterations);
    Module &M = *F.getParent();
    auto *i32 = Type::getInt32Ty(F.getContext());
    bool changed = false;
    // Resolve the shared opaque global once; the first use lazily creates it
    // (consuming one rng draw, exactly as before), and later guarded blocks
    // reuse the pointer instead of re-running a module-wide symbol lookup.
    GlobalVariable *gv = nullptr;
    GlobalVariable *entropyGv = nullptr;

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
            if (!gv)
                gv = opaqueGlobal(M, rng);

            // Build the opaque-true predicate at the end of head, replacing the
            // unconditional branch SplitBlock inserted.  `complexity` chains a
            // conjunction of independent always-true comparisons; each `a == b`
            // over two volatile loads is true at run time but unfoldable, so the
            // whole AND is always true and the body is always taken.
            Instruction *headTerm = head->getTerminator();
            IRBuilder<> B(headTerm);
            const std::uint32_t depth = std::clamp<std::uint32_t>(
                params.complexity ? params.complexity : 1, 1, kMaxComplexity);
            Value *pred = nullptr;
            for (std::uint32_t d = 0; d < depth; ++d) {
                Value *a = B.CreateLoad(i32, gv, /*isVolatile=*/true);
                Value *b = B.CreateLoad(i32, gv, /*isVolatile=*/true);
                Value *eq = B.CreateICmpEQ(a, b);
                pred = pred ? B.CreateAnd(pred, eq) : eq;
            }

            // Junk block: a dead computation that re-joins the body.
            BasicBlock *junk =
                BasicBlock::Create(F.getContext(), "morok.bcf.junk", &F, body);
            IRBuilder<> JB(junk);
            Value *j = JB.CreateLoad(i32, gv, /*isVolatile=*/true);
            j = JB.CreateAdd(j, ConstantInt::get(i32, rng.next() & 0xFFFF));
            j = JB.CreateXor(j, ConstantInt::get(i32, rng.next() & 0xFFFF));
            // entropy_chain: thread a shared global through every junk arm so the
            // dead computations form a chain.  This arm never executes (the
            // predicate is always true), so it is semantics-preserving.
            if (params.entropy_chain) {
                if (!entropyGv)
                    entropyGv = entropyGlobal(M, rng);
                Value *e = JB.CreateLoad(i32, entropyGv, /*isVolatile=*/true);
                e = JB.CreateXor(JB.CreateAdd(e, j),
                                 ConstantInt::get(i32, rng.next() & 0xFFFF));
                JB.CreateStore(e, entropyGv)->setVolatile(true);
            }
            // junk_asm: emit dead inline-asm barriers in the junk arm.
            if (params.junk_asm) {
                const std::uint32_t lo =
                    std::min(params.junk_asm_min, kBcfMaxJunkAsm);
                const std::uint32_t hi =
                    std::min(std::max(lo, params.junk_asm_max),
                             kBcfMaxJunkAsm);
                const std::uint32_t n =
                    lo + (hi > lo ? rng.range(hi - lo + 1) : 0);
                auto *asmTy =
                    FunctionType::get(Type::getVoidTy(F.getContext()), false);
                InlineAsm *ia =
                    InlineAsm::get(asmTy, "", "", /*hasSideEffects=*/true);
                for (std::uint32_t k = 0; k < n; ++k)
                    JB.CreateCall(ia);
            }
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
