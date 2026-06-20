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

#include "morok/core/Feistel.hpp"
#include "morok/core/XorShare.hpp"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Support/Regex.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include <algorithm>
#include <map>
#include <optional>
#include <string>
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

// A "wide magic" is an integer constant that needs more than a single 16-bit
// move to materialize — i.e. a hash/sentinel a license gate compares against,
// not a small loop bound or array index.  The conditions-only sweep targets
// only these: they are the patchable cleartext `cmp reg, #imm` an attacker
// reads, and restricting to them keeps the early sweep from encrypting hundreds
// of tiny loop comparisons (which would inflate the host past the budget the
// integrity passes need).
bool isWideMagic(Constant *C) {
    auto *CI = dyn_cast<ConstantInt>(C);
    return CI && CI->getValue().getActiveBits() > 16;
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

// Emit the inverse of core::feistelEncrypt as IR (4 reverse rounds), recovering
// the plaintext from the reconstructed ciphertext.  The round multiply is the
// non-linear component that defeats purely affine/XOR-fold static recovery of
// the XOR-share layer.
Value *emitFeistelDecrypt(IRBuilder<NoFolder> &B, Value *V, unsigned bits,
                          const core::FeistelKeys &keys) {
    auto *ty = cast<IntegerType>(V->getType());
    const unsigned half = bits / 2;
    const std::uint64_t mask =
        half >= 64 ? ~std::uint64_t{0} : ((std::uint64_t{1} << half) - 1u);
    Value *maskV = ConstantInt::get(ty, mask);
    Value *halfV = ConstantInt::get(ty, half);
    Value *l = B.CreateAnd(B.CreateLShr(V, halfV), maskV);
    Value *r = B.CreateAnd(V, maskV);
    for (int i = core::FeistelKeys::kRounds - 1; i >= 0; --i) {
        const auto &rk = keys.rounds[static_cast<std::size_t>(i)];
        Value *f = B.CreateAnd(
            B.CreateXor(B.CreateMul(l, ConstantInt::get(ty, rk.mult)),
                        ConstantInt::get(ty, rk.xork)),
            maskV);
        Value *newL = B.CreateAnd(B.CreateXor(r, f), maskV);
        r = l;
        l = newL;
    }
    return B.CreateOr(B.CreateShl(l, halfV), r);
}

Value *reconstruct(Module &M, Instruction &user, Constant *c,
                   unsigned shareCount, ir::IRRandom &rng, bool feistel = false,
                   bool subXor = false, std::uint32_t subProb = 100,
                   bool globalize = false,
                   std::uint32_t globalizeProb = 100) {
    std::optional<EncodedConstant> Enc = encodeConstant(c);
    if (!Enc)
        return c;
    auto *ty = Enc->carrier_ty;
    const unsigned bits = ty->getBitWidth();
    std::uint64_t value = Enc->raw;

    // Feistel layer (balanced network needs an even width >= 16).  Encrypt at
    // compile time, emit the inverse at runtime.
    const bool useFeistel = feistel && bits >= 16 && (bits % 2 == 0);
    core::FeistelKeys fkeys;
    if (useFeistel) {
        fkeys = core::makeFeistelKeys(rng.engine(), bits);
        value = core::feistelEncrypt(value, bits, fkeys);
    }
    // Substitute-XOR layer: blind the shared value with a runtime-loaded key so
    // the shares no longer XOR-fold to the (post-Feistel) value statically.
    const std::uint64_t widthMask =
        bits >= 64 ? ~std::uint64_t{0} : ((std::uint64_t{1} << bits) - 1u);
    const bool useSub = subXor && rng.chance(subProb);
    std::uint64_t subKey = 0;
    if (useSub) {
        subKey = rng.next() & widthMask;
        value ^= subKey;
    }

    const auto shares =
        core::splitXorShares(value, shareCount, bits, rng.engine());
    IRBuilder<NoFolder> B(&user);
    Value *acc = nullptr;
    for (std::uint64_t share : shares) {
        auto *gv = new GlobalVariable(
            M, ty, /*isConstant=*/false, GlobalValue::PrivateLinkage,
            ConstantInt::get(ty, share), "morok.share");
        Value *loaded = B.CreateLoad(ty, gv, /*isVolatile=*/true);
        acc = acc ? B.CreateXor(acc, loaded) : loaded;
    }
    // Undo the layers in reverse: substitute-XOR (runtime key), then Feistel.
    if (useSub) {
        auto *kv = new GlobalVariable(
            M, ty, /*isConstant=*/false, GlobalValue::PrivateLinkage,
            ConstantInt::get(ty, subKey), "morok.subkey");
        acc = B.CreateXor(acc, B.CreateLoad(ty, kv, /*isVolatile=*/true),
                          "morok.sub.undo");
    }
    if (useFeistel)
        acc = emitFeistelDecrypt(B, acc, bits, fkeys);
    if (globalize && rng.chance(globalizeProb)) {
        const Align align = M.getDataLayout().getABITypeAlign(ty);
        auto *gv = new GlobalVariable(
            M, ty, /*isConstant=*/false, GlobalValue::PrivateLinkage,
            ConstantInt::get(ty, 0), "morok.const.global");
        gv->setAlignment(align);
        auto *stored = B.CreateStore(acc, gv, /*isVolatile=*/true);
        stored->setAlignment(align);
        auto *loaded = B.CreateLoad(ty, gv, /*isVolatile=*/true,
                                    "morok.const.global.load");
        loaded->setAlignment(align);
        acc = loaded;
    }
    if (Enc->result_ty != Enc->carrier_ty)
        return B.CreateBitCast(acc, Enc->result_ty, "morok.share.fp");
    return acc;
}

// A SwitchInst's case values are LITERAL by construction — constant encryption
// cannot touch them, so a license gate lowered to a `switch` (an
// `if (h==C1) ... if (h==C2) ...` chain SimplifyCFG folds into one) leaks every
// magic Ci as a cleartext `cmp reg, #imm` an attacker reads and patches.  This
// lowers such a switch into a linear chain of *encrypted* equality comparisons,
// so the magic case values become volatile share loads instead of immediates.
// Only switches carrying a wide-magic case are lowered — dense dispatch/jump-
// table switches (small case values) are left intact so hot dispatch is unharmed.
bool deSwitchWideMagics(Function &F, Module &M, unsigned shareCount,
                        ir::IRRandom &rng) {
    SmallVector<SwitchInst *, 8> Switches;
    for (BasicBlock &BB : F) {
        auto *SI = dyn_cast<SwitchInst>(BB.getTerminator());
        if (!SI || SI->getNumCases() == 0)
            continue;
        bool Magic = false;
        for (auto C : SI->cases())
            if (isWideMagic(C.getCaseValue())) {
                Magic = true;
                break;
            }
        if (Magic)
            Switches.push_back(SI);
    }
    if (Switches.empty())
        return false;

    LLVMContext &Ctx = F.getContext();
    for (SwitchInst *SI : Switches) {
        BasicBlock *OrigBB = SI->getParent();
        Value *Cond = SI->getCondition();
        BasicBlock *DefaultBB = SI->getDefaultDest();

        struct CaseRec {
            ConstantInt *val;
            BasicBlock *dest;
        };
        SmallVector<CaseRec, 16> Cases;
        for (auto C : SI->cases())
            Cases.push_back({C.getCaseValue(), C.getCaseSuccessor()});

        // The comparison for case i lives in ChainBB[i]; ChainBB[0] is OrigBB and
        // each subsequent comparison gets a fresh block.  A false result on the
        // last comparison falls through to the original default.
        SmallVector<BasicBlock *, 16> ChainBB;
        ChainBB.push_back(OrigBB);
        for (unsigned i = 1; i < Cases.size(); ++i)
            ChainBB.push_back(BasicBlock::Create(Ctx, "morok.deswitch", &F));

        // Snapshot each successor PHI's incoming value from OrigBB before the CFG
        // changes; the switch contributes exactly one OrigBB entry per PHI even
        // when several cases share a destination.
        DenseMap<PHINode *, Value *> PhiFromOrig;
        auto snapshot = [&](BasicBlock *Succ) {
            for (PHINode &Phi : Succ->phis()) {
                if (PhiFromOrig.count(&Phi))
                    continue;
                int Idx = Phi.getBasicBlockIndex(OrigBB);
                if (Idx >= 0)
                    PhiFromOrig[&Phi] =
                        Phi.getIncomingValue(static_cast<unsigned>(Idx));
            }
        };
        for (const CaseRec &C : Cases)
            snapshot(C.dest);
        snapshot(DefaultBB);

        // Drop the switch terminator; OrigBB keeps its other instructions.
        SI->eraseFromParent();

        for (unsigned i = 0; i < Cases.size(); ++i) {
            IRBuilder<NoFolder> B(ChainBB[i]);
            BasicBlock *FalseDest =
                (i + 1 < Cases.size()) ? ChainBB[i + 1] : DefaultBB;
            // When a case destination coincides with its fall-through (a case
            // whose target is also the switch default), an equality test would
            // emit `br %eq, S, S` — a degenerate two-edge branch that needs two
            // matching PHI entries and survives into later CFG passes.  Collapse
            // it to a plain branch; the compare carries no information here.
            if (Cases[i].dest == FalseDest) {
                B.CreateBr(Cases[i].dest);
                continue;
            }
            auto *Eq = cast<ICmpInst>(B.CreateICmpEQ(Cond, Cases[i].val,
                                                     "morok.deswitch.eq"));
            B.CreateCondBr(Eq, Cases[i].dest, FalseDest);
            // Replace the literal case value with its encrypted reconstruction.
            Value *Enc = reconstruct(M, *Eq, Cases[i].val, shareCount, rng);
            Eq->setOperand(1, Enc);
        }

        // Rebuild each successor PHI from the actual new edges.  A successor can
        // now be reached by several distinct chain blocks (cases sharing a
        // destination), by one chain block more than once (a not-collapsed
        // degenerate branch), and a multi-edge switch successor already carried
        // several OrigBB entries.  The old add-per-case / remove-one logic could
        // not reconcile any of these (ChainBB[0] is OrigBB itself), leaving
        // stale or duplicate entries.  Instead: drop every OrigBB entry, then
        // add exactly one entry per real edge from each chain block.
        SmallPtrSet<BasicBlock *, 16> Succs;
        for (const CaseRec &C : Cases)
            Succs.insert(C.dest);
        Succs.insert(DefaultBB);
        for (BasicBlock *S : Succs)
            for (PHINode &Phi : S->phis()) {
                auto It = PhiFromOrig.find(&Phi);
                if (It == PhiFromOrig.end())
                    continue;
                Value *V = It->second;
                for (int Idx = Phi.getBasicBlockIndex(OrigBB); Idx >= 0;
                     Idx = Phi.getBasicBlockIndex(OrigBB))
                    Phi.removeIncomingValue(static_cast<unsigned>(Idx),
                                            /*DeletePHIIfEmpty=*/false);
                for (BasicBlock *P : ChainBB) {
                    Instruction *Term = P->getTerminator();
                    for (unsigned s = 0; s < Term->getNumSuccessors(); ++s)
                        if (Term->getSuccessor(s) == S)
                            Phi.addIncoming(V, P);
                }
            }
    }
    return true;
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
    // A musttail call must be the last instruction before its `ret`.  The plain
    // XOR-share reconstruction is musttail-safe, but the Feistel/substitute
    // layers add a multi-instruction non-linear sequence; skip those layers for
    // such functions defensively (the program cf_musttail exercises this).
    bool hasMusttail = false;
    for (BasicBlock &bb : F) {
        for (Instruction &inst : bb)
            if (auto *CI = dyn_cast<CallInst>(&inst))
                if (CI->isMustTailCall()) {
                    hasMusttail = true;
                    break;
                }
        if (hasMusttail)
            break;
    }
    const bool useFeistel = params.feistel && !hasMusttail;
    const bool useSubstitute = params.substitute_xor && !hasMusttail;
    const bool useGlobalize = params.globalize && !hasMusttail;

    // Compile the value filters once.  Use llvm::Regex (not std::regex): this
    // codebase builds with exceptions disabled, so a malformed std::regex would
    // terminate the compiler — llvm::Regex reports invalidity without throwing,
    // and a malformed pattern is simply dropped.
    auto compile = [](const std::vector<std::string> &pats) {
        std::vector<llvm::Regex> out;
        for (const std::string &p : pats) {
            llvm::Regex re(p, llvm::Regex::IgnoreCase);
            if (re.isValid())
                out.push_back(std::move(re));
        }
        return out;
    };
    const std::vector<llvm::Regex> skipRe = compile(params.skip_value);
    const std::vector<llvm::Regex> forceRe = compile(params.force_value);
    const bool haveFilters = !skipRe.empty() || !forceRe.empty();
    // Classify a constant by value: Force (always encrypt), Skip (never), or
    // Normal (defer to `probability`).  With no filters every constant is Normal
    // so the rng draw sequence is byte-identical to the unfiltered pass.
    enum class Decision { Normal, Skip, Force };
    auto classify = [&](Constant *c) -> Decision {
        if (!haveFilters)
            return Decision::Normal;
        auto *CI = dyn_cast<ConstantInt>(c);
        if (!CI)
            return Decision::Normal; // value filters apply to integer literals
        const std::string hex =
            llvm::utohexstr(CI->getZExtValue(), /*LowerCase=*/true);
        for (const llvm::Regex &re : forceRe)
            if (re.match(hex))
                return Decision::Force;
        for (const llvm::Regex &re : skipRe)
            if (re.match(hex))
                return Decision::Skip;
        return Decision::Normal;
    };

    bool changed = false;
    const std::size_t maxTargets = kMaxConstEncTargetsPerIteration;

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
                if (targets.size() >= maxTargets)
                    break;
                // Decision-gate scope: only the constant operands of comparisons
                // and constant branch/switch conditions.  These are what an
                // attacker reads as a cleartext `cmp reg, #imm` and NOPs.
                if (params.conditions_only) {
                    if (auto *Cmp = dyn_cast<CmpInst>(&inst)) {
                        for (unsigned i = 0; i < Cmp->getNumOperands(); ++i)
                            if (auto *c = dyn_cast<Constant>(Cmp->getOperand(i)))
                                if (eligibleConstant(c) && isWideMagic(c))
                                    targets.push_back({&inst, i, c});
                    }
                    continue;
                }
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
            if (targets.size() >= maxTargets)
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
            const Decision d = classify(t.value);
            if (d == Decision::Skip)
                continue; // value filtered out; never encrypt
            if (d == Decision::Normal && !rng.chance(params.probability))
                continue; // Force bypasses the probability roll
            Instruction *InsertBefore = insertionPoint(t);
            if (!InsertBefore)
                continue;
            Value *repl =
                reconstruct(M, *InsertBefore, t.value, shareCount, rng,
                            useFeistel, useSubstitute,
                            params.substitute_xor_prob, useGlobalize,
                            params.globalize_prob);
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

bool deSwitchGateConstantsFunction(Function &F, const ConstEncParams &params,
                                   ir::IRRandom &rng) {
    if (F.isDeclaration())
        return false;
    const unsigned shareCount = std::clamp<unsigned>(
        params.share_count, core::kMinShares, core::kMaxShares);
    return deSwitchWideMagics(F, *F.getParent(), shareCount, rng);
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
