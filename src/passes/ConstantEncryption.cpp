// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/ConstantEncryption.cpp
//
// Only operands of scalar integer/FP arithmetic, comparison, select, cast, PHI
// incoming values, conditional branch/switch conditions, return, store values,
// and ordinary call-argument instructions are rewritten — never branch
// destinations, switch cases, GEP indices, store pointers, intrinsic immediate
// arguments, callees, or operand bundles, which must remain literal — so the
// output is always valid IR. The XOR-share split is the verified one from
// morok/core/XorShare.hpp; the shares live in private mutable globals and are
// read with volatile loads so the reconstruction survives optimisation.

#include "morok/passes/ConstantEncryption.hpp"

#include "morok/core/XorShare.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include <algorithm>
#include <map>
#include <optional>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr std::size_t kMaxConstEncTargetsPerIteration = 128;

bool eligibleWidth(unsigned bits) {
    return bits >= 1 && bits <= 64;
}

bool supportedFloatType(Type *Ty) {
    return Ty->isHalfTy() || Ty->isBFloatTy() || Ty->isFloatTy() ||
           Ty->isDoubleTy();
}

// Only the operands of these instructions are safe to turn into runtime values.
bool isRewritableUser(const Instruction &I) {
    return isa<BinaryOperator>(I) || isa<ICmpInst>(I) || isa<FCmpInst>(I) ||
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

bool eligibleConstant(Constant *C) {
    if (auto *CI = dyn_cast<ConstantInt>(C))
        return eligibleWidth(CI->getType()->getIntegerBitWidth());
    auto *CFP = dyn_cast<ConstantFP>(C);
    if (!CFP || !supportedFloatType(CFP->getType()))
        return false;
    return eligibleWidth(CFP->getValueAPF().bitcastToAPInt().getBitWidth());
}

Constant *eligibleStoreValue(StoreInst &SI) {
    auto *C = dyn_cast<Constant>(SI.getValueOperand());
    if (!C || !eligibleConstant(C))
        return nullptr;
    return C;
}

ConstantInt *eligibleBranchCondition(BranchInst &BI) {
    if (!BI.isConditional())
        return nullptr;
    auto *C = dyn_cast<ConstantInt>(BI.getCondition());
    if (!C || !eligibleWidth(C->getType()->getIntegerBitWidth()))
        return nullptr;
    return C;
}

ConstantInt *eligibleSwitchCondition(SwitchInst &SI) {
    auto *C = dyn_cast<ConstantInt>(SI.getCondition());
    if (!C || !eligibleWidth(C->getType()->getIntegerBitWidth()))
        return nullptr;
    return C;
}

bool eligiblePhiIncoming(PHINode &PN, unsigned Incoming) {
    auto *C = dyn_cast<Constant>(PN.getIncomingValue(Incoming));
    if (!C || !eligibleConstant(C))
        return false;
    BasicBlock *Pred = PN.getIncomingBlock(Incoming);
    Instruction *Term = Pred ? Pred->getTerminator() : nullptr;
    if (!Term || Term->getNumSuccessors() == 0)
        return false;
    return Term->getNumSuccessors() == 1 || isa<BranchInst>(Term) ||
           isa<SwitchInst>(Term);
}

struct EncodedConstant {
    IntegerType *carrier_ty = nullptr;
    Type *result_ty = nullptr;
    std::uint64_t raw = 0;
};

std::optional<EncodedConstant> encodeConstant(Constant *C) {
    if (auto *CI = dyn_cast<ConstantInt>(C)) {
        auto *Ty = cast<IntegerType>(CI->getType());
        if (!eligibleWidth(Ty->getIntegerBitWidth()))
            return std::nullopt;
        return EncodedConstant{Ty, Ty, CI->getZExtValue()};
    }

    auto *CFP = dyn_cast<ConstantFP>(C);
    if (!CFP || !supportedFloatType(CFP->getType()))
        return std::nullopt;
    APInt Bits = CFP->getValueAPF().bitcastToAPInt();
    if (!eligibleWidth(Bits.getBitWidth()))
        return std::nullopt;
    auto *CarrierTy = IntegerType::get(C->getContext(), Bits.getBitWidth());
    return EncodedConstant{CarrierTy, C->getType(), Bits.getZExtValue()};
}

Value *reconstruct(Module &M, Instruction &user, Constant *c,
                   unsigned shareCount, ir::IRRandom &rng) {
    std::optional<EncodedConstant> Enc = encodeConstant(c);
    if (!Enc)
        return c;
    auto *ty = Enc->carrier_ty;
    const unsigned bits = ty->getBitWidth();
    const auto shares =
        core::splitXorShares(Enc->raw, shareCount, bits, rng.engine());

    IRBuilder<NoFolder> B(&user);
    Value *acc = nullptr;
    for (std::uint64_t share : shares) {
        auto *gv = new GlobalVariable(
            M, ty, /*isConstant=*/false, GlobalValue::PrivateLinkage,
            ConstantInt::get(ty, share), "morok.share");
        Value *loaded = B.CreateLoad(ty, gv, /*isVolatile=*/true);
        acc = acc ? B.CreateXor(acc, loaded) : loaded;
    }
    if (Enc->result_ty != Enc->carrier_ty)
        return B.CreateBitCast(acc, Enc->result_ty, "morok.share.fp");
    return acc;
}

} // namespace

bool constantEncryptFunction(Function &F, const ConstEncParams &params,
                             ir::IRRandom &rng) {
    Module &M = *F.getParent();
    const unsigned shareCount = std::clamp<unsigned>(
        params.share_count, core::kMinShares, core::kMaxShares);
    // Each iteration re-encrypts constants (including those introduced by the
    // previous round's key material), so IR size grows with the iteration
    // count.  The "max" preset asks for 3; clamp to a generous ceiling so a
    // malformed config — or a stale/partial build handing this pass an
    // uninitialized ConstEncParams — cannot detonate compile time.
    constexpr std::uint32_t kMaxConstEncIterations = 8;
    const std::uint32_t iterations = std::clamp<std::uint32_t>(
        params.iterations ? params.iterations : 1, 1, kMaxConstEncIterations);
    bool changed = false;

    for (std::uint32_t it = 0; it < iterations; ++it) {
        // Collect (instruction, operand index, constant) first; mutating
        // operands while walking would invalidate the iteration.
        struct Target {
            Instruction *user;
            unsigned index;
            Constant *value;
            bool phi_incoming = false;
            BasicBlock *incoming_block = nullptr;
        };
        std::vector<Target> targets;
        for (BasicBlock &bb : F) {
            for (Instruction &inst : bb) {
                if (targets.size() >= kMaxConstEncTargetsPerIteration)
                    break;
                if (auto *PN = dyn_cast<PHINode>(&inst)) {
                    for (unsigned I = 0; I < PN->getNumIncomingValues(); ++I) {
                        if (!eligiblePhiIncoming(*PN, I))
                            continue;
                        targets.push_back(
                            {&inst, I, cast<Constant>(PN->getIncomingValue(I)),
                             true, PN->getIncomingBlock(I)});
                    }
                } else if (auto *CB = dyn_cast<CallBase>(&inst)) {
                    if (!safeCallArgs(*CB))
                        continue;
                    for (unsigned I = 0; I < CB->arg_size(); ++I) {
                        if (auto *C = dyn_cast<Constant>(CB->getArgOperand(I)))
                            if (eligibleConstant(C))
                                targets.push_back({&inst, I, C});
                    }
                } else if (auto *SI = dyn_cast<StoreInst>(&inst)) {
                    if (auto *C = eligibleStoreValue(*SI))
                        targets.push_back({&inst, 0, C});
                } else if (auto *BI = dyn_cast<BranchInst>(&inst)) {
                    if (auto *C = eligibleBranchCondition(*BI))
                        targets.push_back({&inst, 0, C});
                } else if (auto *SW = dyn_cast<SwitchInst>(&inst)) {
                    if (auto *C = eligibleSwitchCondition(*SW))
                        targets.push_back({&inst, 0, C});
                } else {
                    if (!isRewritableUser(inst))
                        continue;
                    for (unsigned i = 0; i < inst.getNumOperands(); ++i)
                        if (auto *c = dyn_cast<Constant>(inst.getOperand(i)))
                            if (eligibleConstant(c))
                                targets.push_back({&inst, i, c});
                }
            }
            if (targets.size() >= kMaxConstEncTargetsPerIteration)
                break;
        }

        std::map<std::pair<BasicBlock *, BasicBlock *>, BasicBlock *>
            splitEdges;
        auto insertionPoint = [&](const Target &T) -> Instruction * {
            if (!T.phi_incoming)
                return T.user;
            auto *PN = cast<PHINode>(T.user);
            BasicBlock *Succ = PN->getParent();
            BasicBlock *Pred = T.incoming_block;
            auto Key = std::make_pair(Pred, Succ);
            auto It = splitEdges.find(Key);
            if (It != splitEdges.end())
                return It->second->getTerminator();

            Instruction *Term = Pred ? Pred->getTerminator() : nullptr;
            if (!Term)
                return nullptr;
            if (Term->getNumSuccessors() == 1)
                return Term;
            BasicBlock *Edge =
                SplitEdge(Pred, Succ, nullptr, nullptr, nullptr,
                          "morok.const.phi.edge");
            if (!Edge)
                return nullptr;
            splitEdges[Key] = Edge;
            return Edge->getTerminator();
        };

        for (const Target &t : targets) {
            if (!rng.chance(params.probability))
                continue;
            Instruction *InsertBefore = insertionPoint(t);
            if (!InsertBefore)
                continue;
            Value *repl =
                reconstruct(M, *InsertBefore, t.value, shareCount, rng);
            if (t.phi_incoming) {
                auto *PN = cast<PHINode>(t.user);
                BasicBlock *Incoming = t.incoming_block;
                auto It = splitEdges.find(std::make_pair(Incoming,
                                                         PN->getParent()));
                if (It != splitEdges.end())
                    Incoming = It->second;
                const int IncomingIndex = PN->getBasicBlockIndex(Incoming);
                if (IncomingIndex < 0)
                    continue;
                PN->setIncomingValue(static_cast<unsigned>(IncomingIndex), repl);
            } else {
                t.user->setOperand(t.index, repl);
            }
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
