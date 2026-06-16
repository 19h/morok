// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/ConstantEncryption.cpp
//
// Only operands of integer arithmetic, comparison, select, cast, return, and
// ordinary call-argument instructions are rewritten — never switch cases, GEP
// indices, intrinsic immediate arguments, callees, or operand bundles, which
// must remain literal — so the output is always valid IR. The XOR-share split
// is the verified one from morok/core/XorShare.hpp; the shares live in private
// mutable globals and are read with volatile loads so the reconstruction
// survives optimisation.

#include "morok/passes/ConstantEncryption.hpp"

#include "morok/core/XorShare.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"

#include <algorithm>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr std::size_t kMaxConstEncTargetsPerIteration = 128;

bool eligibleWidth(unsigned bits) {
    return bits >= 1 && bits <= 64;
}

// Only the operands of these instructions are safe to turn into runtime values.
bool isRewritableUser(const Instruction &I) {
    return isa<BinaryOperator>(I) || isa<ICmpInst>(I) ||
           isa<SelectInst>(I) || isa<CastInst>(I) || isa<ReturnInst>(I);
}

bool safeCallArgs(const CallBase &CB) {
    if (CB.isInlineAsm() || CB.hasOperandBundles() || CB.isMustTailCall())
        return false;
    if (Function *Callee = CB.getCalledFunction())
        if (Callee->isIntrinsic())
            return false;
    return true;
}

Value *reconstruct(Module &M, Instruction &user, ConstantInt *c,
                   unsigned shareCount, ir::IRRandom &rng) {
    auto *ty = cast<IntegerType>(c->getType());
    const unsigned bits = ty->getBitWidth();
    const auto shares =
        core::splitXorShares(c->getZExtValue(), shareCount, bits, rng.engine());

    IRBuilder<NoFolder> B(&user);
    Value *acc = nullptr;
    for (std::uint64_t share : shares) {
        auto *gv = new GlobalVariable(
            M, ty, /*isConstant=*/false, GlobalValue::PrivateLinkage,
            ConstantInt::get(ty, share), "morok.share");
        Value *loaded = B.CreateLoad(ty, gv, /*isVolatile=*/true);
        acc = acc ? B.CreateXor(acc, loaded) : loaded;
    }
    return acc;
}

} // namespace

bool constantEncryptFunction(Function &F, const ConstEncParams &params,
                             ir::IRRandom &rng) {
    Module &M = *F.getParent();
    const unsigned shareCount = std::clamp<unsigned>(
        params.share_count, core::kMinShares, core::kMaxShares);
    const std::uint32_t iterations = params.iterations ? params.iterations : 1;
    bool changed = false;

    for (std::uint32_t it = 0; it < iterations; ++it) {
        // Collect (instruction, operand index, constant) first; mutating
        // operands while walking would invalidate the iteration.
        struct Target {
            Instruction *user;
            unsigned index;
            ConstantInt *value;
        };
        std::vector<Target> targets;
        for (BasicBlock &bb : F) {
            for (Instruction &inst : bb) {
                if (targets.size() >= kMaxConstEncTargetsPerIteration)
                    break;
                if (auto *CB = dyn_cast<CallBase>(&inst)) {
                    if (!safeCallArgs(*CB))
                        continue;
                    for (unsigned I = 0; I < CB->arg_size(); ++I) {
                        if (auto *C =
                                dyn_cast<ConstantInt>(CB->getArgOperand(I)))
                            if (eligibleWidth(
                                    C->getType()->getIntegerBitWidth()))
                                targets.push_back({&inst, I, C});
                    }
                } else {
                    if (!isRewritableUser(inst))
                        continue;
                    for (unsigned i = 0; i < inst.getNumOperands(); ++i)
                        if (auto *c = dyn_cast<ConstantInt>(inst.getOperand(i)))
                            if (eligibleWidth(
                                    c->getType()->getIntegerBitWidth()))
                                targets.push_back({&inst, i, c});
                }
            }
            if (targets.size() >= kMaxConstEncTargetsPerIteration)
                break;
        }

        for (const Target &t : targets) {
            if (!rng.chance(params.probability))
                continue;
            Value *repl = reconstruct(M, *t.user, t.value, shareCount, rng);
            t.user->setOperand(t.index, repl);
            changed = true;
        }
    }
    return changed;
}

PreservedAnalyses ConstantEncryptionPass::run(Function &F,
                                              FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return constantEncryptFunction(F, params_, rng) ? PreservedAnalyses::none()
                                                    : PreservedAnalyses::all();
}

} // namespace morok::passes
