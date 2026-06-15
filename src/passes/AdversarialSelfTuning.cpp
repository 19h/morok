// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/AdversarialSelfTuning.cpp
//
// IR-level adversarial self-tuning harness.  The pass treats existing Morok
// transformations as candidate actions, scores each candidate on a cloned
// module, rejects invalid or weak candidates, and only replays the strongest
// verified plan on the original module.

#include "morok/passes/AdversarialSelfTuning.hpp"

#include "morok/passes/ArithmeticTables.hpp"
#include "morok/passes/DispatcherlessRouting.hpp"
#include "morok/passes/MicrocodeStress.hpp"
#include "morok/passes/PathExplosion.hpp"
#include "morok/passes/PhiTangling.hpp"
#include "morok/passes/PointerLaundering.hpp"
#include "morok/passes/StackCoalescing.hpp"
#include "morok/passes/StackDeltaGames.hpp"
#include "morok/passes/TraceKeying.hpp"
#include "morok/passes/TypePunning.hpp"
#include "morok/passes/UniformPrimitiveLowering.hpp"
#include "morok/passes/VectorObfuscation.hpp"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Cloning.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr std::uint64_t kTuneModuleInstLimit = 20000;
constexpr std::uint64_t kTuneModuleBlockLimit = 3000;
constexpr std::uint64_t kTuneModuleFunctionLimit = 500;
constexpr std::uint64_t kTuneFunctionInstLimit = 1500;
constexpr std::uint64_t kTuneFunctionBlockLimit = 160;

enum class CandidateKind : std::uint32_t {
    ValueRecovery = 1,
    TypeAlias = 2,
    SymbolicPaths = 3,
    MicrocodeCfg = 4,
    UniformSubstrate = 5,
};

struct Candidate {
    CandidateKind kind = CandidateKind::ValueRecovery;
    std::uint64_t seed = 0;
};

struct CandidateResult {
    Candidate candidate;
    AdversarialScore score;
    bool changed = false;
};

bool generatedFunction(const Function &F) {
    return F.getName().starts_with("morok.");
}

bool hasExistingTuneMarker(const Module &M) {
    for (const GlobalVariable &GV : M.globals())
        if (GV.getName().starts_with("morok.tune."))
            return true;
    return false;
}

std::uint64_t instructionCount(const Function &F) {
    std::uint64_t Count = 0;
    for (const BasicBlock &BB : F)
        Count += BB.size();
    return Count;
}

bool withinTuneFunctionBudget(const Function &F) {
    return instructionCount(F) <= kTuneFunctionInstLimit &&
           F.size() <= kTuneFunctionBlockLimit;
}

bool withinTuneModuleBudget(const Module &M) {
    std::uint64_t Instructions = 0;
    std::uint64_t Blocks = 0;
    std::uint64_t Functions = 0;
    for (const Function &F : M) {
        if (F.isDeclaration())
            continue;
        ++Functions;
        Blocks += F.size();
        Instructions += instructionCount(F);
        if (Instructions > kTuneModuleInstLimit ||
            Blocks > kTuneModuleBlockLimit ||
            Functions > kTuneModuleFunctionLimit)
            return false;
    }
    return true;
}

bool hasBlockAddress(const Constant *C,
                     SmallPtrSetImpl<const Constant *> &Seen) {
    if (!C || !Seen.insert(C).second)
        return false;
    if (isa<BlockAddress>(C))
        return true;
    for (const Use &U : C->operands())
        if (const auto *Child = dyn_cast<Constant>(U.get()))
            if (hasBlockAddress(Child, Seen))
                return true;
    return false;
}

bool hasBlockAddress(const Constant *C) {
    SmallPtrSet<const Constant *, 16> Seen;
    return hasBlockAddress(C, Seen);
}

std::uint64_t arrayElements(Type *Ty) {
    if (auto *AT = dyn_cast<ArrayType>(Ty))
        return AT->getNumElements();
    return 0;
}

void scoreAlloca(const AllocaInst &AI, AdversarialScore &S) {
    S.lvar_recovery += AI.isArrayAllocation() ? 48 : 14;
    Type *Allocated = AI.getAllocatedType();
    if (auto *AT = dyn_cast<ArrayType>(Allocated)) {
        if (AT->getElementType()->isIntegerTy(8))
            S.lvar_recovery +=
                90 + std::min<std::uint64_t>(AT->getNumElements(), 256);
    }
    if (!isa<ConstantInt>(AI.getArraySize()))
        S.lvar_recovery += 96;
}

void scoreGep(const GetElementPtrInst &GEP, AdversarialScore &S) {
    S.lvar_recovery += 8;
    S.type_recovery += 6;
    for (const Use &U : GEP.indices()) {
        if (!isa<ConstantInt>(U.get())) {
            S.lvar_recovery += 22;
            S.symbolic_pressure += 8;
        }
    }
}

void scoreInstruction(const Instruction &I, AdversarialScore &S) {
    S.diff_resistance += 1;

    if (const auto *AI = dyn_cast<AllocaInst>(&I)) {
        scoreAlloca(*AI, S);
        return;
    }
    if (const auto *GEP = dyn_cast<GetElementPtrInst>(&I)) {
        scoreGep(*GEP, S);
        return;
    }
    if (const auto *BI = dyn_cast<BranchInst>(&I)) {
        S.cfg_recovery += BI->isConditional() ? 18 : 4;
        return;
    }

    switch (I.getOpcode()) {
    case Instruction::IndirectBr:
        S.cfg_recovery += 180;
        S.symbolic_pressure += 90;
        break;
    case Instruction::Switch:
        S.cfg_recovery += 42;
        S.symbolic_pressure += 16;
        break;
    case Instruction::PHI:
        S.cfg_recovery += 22;
        S.lvar_recovery += 10;
        break;
    case Instruction::Select:
        S.symbolic_pressure += 14;
        break;
    case Instruction::PtrToInt:
    case Instruction::IntToPtr:
        S.lvar_recovery += 46;
        S.type_recovery += 46;
        S.symbolic_pressure += 18;
        break;
    case Instruction::BitCast:
    case Instruction::AddrSpaceCast:
        S.type_recovery += 18;
        break;
    case Instruction::ShuffleVector:
        S.type_recovery += 44;
        S.symbolic_pressure += 10;
        break;
    case Instruction::Call:
    case Instruction::Invoke:
        S.diff_resistance += 12;
        S.symbolic_pressure += 5;
        break;
    default:
        if (I.isBinaryOp())
            S.symbolic_pressure += 3;
        break;
    }

    if (auto *LI = dyn_cast<LoadInst>(&I)) {
        if (LI->isVolatile()) {
            S.lvar_recovery += 18;
            S.symbolic_pressure += 28;
        }
    } else if (auto *SI = dyn_cast<StoreInst>(&I)) {
        if (SI->isVolatile()) {
            S.lvar_recovery += 18;
            S.symbolic_pressure += 28;
        }
    }

    Type *Ty = I.getType();
    if (Ty && Ty->isVectorTy())
        S.type_recovery += 28;
}

void scoreFunction(const Function &F, AdversarialScore &S) {
    if (F.isDeclaration())
        return;
    S.cfg_recovery += static_cast<std::uint64_t>(F.size()) * 6;
    if (generatedFunction(F))
        S.diff_resistance += 90;
    for (const Instruction &I : instructions(F))
        scoreInstruction(I, S);
}

void scoreGlobal(const GlobalVariable &GV, AdversarialScore &S) {
    S.diff_resistance += GV.hasPrivateLinkage() ? 10 : 2;
    const std::uint64_t Elems = arrayElements(GV.getValueType());
    if (Elems != 0) {
        S.symbolic_pressure += std::min<std::uint64_t>(Elems / 4, 160);
        if (Elems >= 16)
            S.diff_resistance += 24;
    }
    if (GV.hasInitializer() && hasBlockAddress(GV.getInitializer())) {
        S.cfg_recovery += 220 + std::min<std::uint64_t>(Elems * 4, 256);
        S.symbolic_pressure += 80;
    }
    if (GV.getName().starts_with("morok."))
        S.diff_resistance += 36;
}

void finalizeScore(AdversarialScore &S) {
    S.total = (S.cfg_recovery * 3) + (S.lvar_recovery * 3) +
              (S.type_recovery * 2) + (S.symbolic_pressure * 2) +
              S.diff_resistance;
}

template <typename Fn> bool forEachEligibleFunction(Module &M, Fn &&Action) {
    std::vector<Function *> Functions;
    for (Function &F : M)
        if (!F.isDeclaration() && !generatedFunction(F))
            Functions.push_back(&F);

    bool Changed = false;
    for (Function *F : Functions)
        if (withinTuneFunctionBudget(*F))
            Changed |= Action(*F);
    return Changed;
}

using Action = bool (*)(Module &, ir::IRRandom &);

bool runStackCoalesce(Module &M, ir::IRRandom &Rng) {
    return forEachEligibleFunction(M, [&](Function &F) {
        return stackCoalesceFunction(F, {100, true}, Rng);
    });
}

bool runPointerLaunder(Module &M, ir::IRRandom &Rng) {
    return forEachEligibleFunction(M, [&](Function &F) {
        return pointerLaunderFunction(F, {100, 70}, Rng);
    });
}

bool runTypePun(Module &M, ir::IRRandom &Rng) {
    return forEachEligibleFunction(M, [&](Function &F) {
        return typePunFunction(F, {85, true, 32}, Rng);
    });
}

bool runPhiTangle(Module &M, ir::IRRandom &Rng) {
    return forEachEligibleFunction(M, [&](Function &F) {
        return phiTangleFunction(F, {100, 2, 24}, Rng);
    });
}

bool runPathExplosion(Module &M, ir::IRRandom &Rng) {
    return forEachEligibleFunction(M, [&](Function &F) {
        return pathExplosionFunction(F, {100, 2, 8}, Rng);
    });
}

bool runTraceKey(Module &M, ir::IRRandom &Rng) {
    return forEachEligibleFunction(
        M, [&](Function &F) { return traceKeyFunction(F, {100, 2}, Rng); });
}

bool runDispatcherless(Module &M, ir::IRRandom &Rng) {
    return forEachEligibleFunction(M, [&](Function &F) {
        return dispatcherlessRoutingFunction(F, {100, 8, 4}, Rng);
    });
}

bool runMicrocodeStress(Module &M, ir::IRRandom &Rng) {
    return forEachEligibleFunction(M, [&](Function &F) {
        return microcodeStressFunction(F, {100, 1, 16, 4, 2}, Rng);
    });
}

bool runStackDelta(Module &M, ir::IRRandom &Rng) {
    return forEachEligibleFunction(M, [&](Function &F) {
        return stackDeltaGamesFunction(F, {100, 1, 17, 32, 2}, Rng);
    });
}

bool runTableArithmetic(Module &M, ir::IRRandom &Rng) {
    return forEachEligibleFunction(M, [&](Function &F) {
        return tableArithmeticFunction(F, {80, 4}, Rng);
    });
}

bool runUniform(Module &M, ir::IRRandom &Rng) {
    return forEachEligibleFunction(M, [&](Function &F) {
        return uniformPrimitiveLowerFunction(F, {70, 70, 4, 4}, Rng);
    });
}

bool runVector(Module &M, ir::IRRandom &Rng) {
    return forEachEligibleFunction(M, [&](Function &F) {
        return vectorObfuscateFunction(F, {80, 256, true, true}, Rng);
    });
}

ArrayRef<Action> actionsFor(CandidateKind Kind) {
    static constexpr std::array<Action, 4> Value = {
        runStackCoalesce, runPointerLaunder, runPhiTangle, runTypePun};
    static constexpr std::array<Action, 3> Type = {
        runTypePun, runPointerLaunder, runStackCoalesce};
    static constexpr std::array<Action, 3> Symbolic = {
        runPathExplosion, runTraceKey, runPhiTangle};
    static constexpr std::array<Action, 3> Microcode = {
        runDispatcherless, runMicrocodeStress, runStackDelta};
    static constexpr std::array<Action, 3> Uniform = {runTableArithmetic,
                                                      runUniform, runVector};

    switch (Kind) {
    case CandidateKind::ValueRecovery:
        return ArrayRef<Action>(Value);
    case CandidateKind::TypeAlias:
        return ArrayRef<Action>(Type);
    case CandidateKind::SymbolicPaths:
        return ArrayRef<Action>(Symbolic);
    case CandidateKind::MicrocodeCfg:
        return ArrayRef<Action>(Microcode);
    case CandidateKind::UniformSubstrate:
        return ArrayRef<Action>(Uniform);
    }
    return {};
}

bool applyCandidate(Module &M, Candidate Candidate,
                    std::uint32_t MaxCandidatePasses) {
    if (MaxCandidatePasses == 0)
        return false;

    auto Engine = core::Xoshiro256pp::fromSeed(Candidate.seed);
    ir::IRRandom Rng(Engine);
    bool Changed = false;
    std::uint32_t Attempted = 0;
    for (Action A : actionsFor(Candidate.kind)) {
        if (Attempted >= MaxCandidatePasses)
            break;
        Changed |= A(M, Rng);
        ++Attempted;
    }
    return Changed;
}

std::vector<Candidate> makeCandidates(std::uint32_t MaxCandidates,
                                      ir::IRRandom &Rng) {
    static constexpr std::array<CandidateKind, 5> Pool = {
        CandidateKind::ValueRecovery, CandidateKind::TypeAlias,
        CandidateKind::SymbolicPaths, CandidateKind::MicrocodeCfg,
        CandidateKind::UniformSubstrate};

    std::vector<Candidate> Out;
    const std::uint32_t Count = std::min<std::uint32_t>(
        MaxCandidates, static_cast<std::uint32_t>(Pool.size()));
    const std::uint64_t Base = Rng.next();
    for (std::uint32_t I = 0; I < Count; ++I) {
        const std::uint64_t Salt =
            0x9E3779B97F4A7C15ULL * static_cast<std::uint64_t>(I + 1);
        Out.push_back(
            {Pool[I],
             Base ^ Salt ^ (static_cast<std::uint64_t>(Pool[I]) << 32)});
    }
    return Out;
}

bool verified(const Module &M) { return !verifyModule(M, &errs()); }

CandidateResult evaluateCandidate(const Module &Original, Candidate Candidate,
                                  std::uint32_t MaxCandidatePasses) {
    auto Trial = CloneModule(Original);
    CandidateResult Result;
    Result.candidate = Candidate;
    Result.changed = applyCandidate(*Trial, Candidate, MaxCandidatePasses);
    if (!Result.changed || !verified(*Trial)) {
        Result.changed = false;
        return Result;
    }
    Result.score = adversarialScoreModule(*Trial);
    return Result;
}

bool betterThan(const CandidateResult &A, const CandidateResult &B) {
    if (!A.changed)
        return false;
    if (!B.changed)
        return true;
    if (A.score.total != B.score.total)
        return A.score.total > B.score.total;
    if (A.score.cfg_recovery != B.score.cfg_recovery)
        return A.score.cfg_recovery > B.score.cfg_recovery;
    if (A.score.lvar_recovery != B.score.lvar_recovery)
        return A.score.lvar_recovery > B.score.lvar_recovery;
    return static_cast<std::uint32_t>(A.candidate.kind) >
           static_cast<std::uint32_t>(B.candidate.kind);
}

void createI64Global(Module &M, const char *Name,
                     ArrayRef<std::uint64_t> Data) {
    auto *I64 = Type::getInt64Ty(M.getContext());
    if (Data.size() == 1) {
        auto *GV = new GlobalVariable(
            M, I64, /*isConstant=*/true, GlobalValue::PrivateLinkage,
            ConstantInt::get(I64, Data.front()), Name);
        GV->setDSOLocal(true);
        GV->setAlignment(Align(8));
        return;
    }

    auto *AT = ArrayType::get(I64, Data.size());
    std::vector<Constant *> Elems;
    Elems.reserve(Data.size());
    for (std::uint64_t V : Data)
        Elems.push_back(ConstantInt::get(I64, V));
    auto *GV = new GlobalVariable(M, AT, /*isConstant=*/true,
                                  GlobalValue::PrivateLinkage,
                                  ConstantArray::get(AT, Elems), Name);
    GV->setDSOLocal(true);
    GV->setAlignment(Align(8));
}

void emitChoiceMarker(Module &M, Candidate Candidate,
                      const AdversarialScore &Before,
                      const AdversarialScore &After) {
    createI64Global(M, "morok.tune.choice",
                    {static_cast<std::uint64_t>(Candidate.kind)});
    createI64Global(M, "morok.tune.score",
                    {Before.total, After.total, After.cfg_recovery,
                     After.lvar_recovery, After.type_recovery,
                     After.symbolic_pressure, After.diff_resistance,
                     Candidate.seed});
}

} // namespace

AdversarialScore adversarialScoreModule(const Module &M) {
    AdversarialScore S;
    for (const Function &F : M)
        scoreFunction(F, S);
    for (const GlobalVariable &GV : M.globals())
        scoreGlobal(GV, S);
    finalizeScore(S);
    return S;
}

bool adversarialSelfTuneModule(Module &M, const AdversarialTuningParams &Params,
                               ir::IRRandom &Rng) {
    if (Params.max_candidates == 0 || Params.max_candidate_passes == 0 ||
        hasExistingTuneMarker(M) || !withinTuneModuleBudget(M))
        return false;

    const AdversarialScore Before = adversarialScoreModule(M);
    CandidateResult Best;
    for (Candidate C : makeCandidates(Params.max_candidates, Rng)) {
        CandidateResult Result =
            evaluateCandidate(M, C, Params.max_candidate_passes);
        if (betterThan(Result, Best))
            Best = Result;
    }
    if (!Best.changed || Best.score.total <= Before.total)
        return false;
    if (Best.score.total - Before.total < Params.score_floor)
        return false;

    if (!applyCandidate(M, Best.candidate, Params.max_candidate_passes))
        return false;

    const AdversarialScore After = adversarialScoreModule(M);
    if (Params.emit_marker)
        emitChoiceMarker(M, Best.candidate, Before, After);
    return true;
}

PreservedAnalyses AdversarialSelfTuningPass::run(Module &M,
                                                 ModuleAnalysisManager &) {
    ir::IRRandom Rng(engine_);
    return adversarialSelfTuneModule(M, params_, Rng)
               ? PreservedAnalyses::none()
               : PreservedAnalyses::all();
}

} // namespace morok::passes
