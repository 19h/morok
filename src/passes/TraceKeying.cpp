// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/TraceKeying.cpp
//
// Execution-trace keying.  This pass threads a private rolling hash through
// selected CFG edges and bounded live scalar values, then guards selected blocks
// by comparing a volatile accumulator load with the edge-carried expected
// value.  The valid path is semantics-neutral; if instrumentation or replay
// perturbs the order or value trace, the mismatch is recorded into module-wide
// latent state and unrelated branch/return/switch sites later sample that state
// with a probabilistic gate.

#include "morok/passes/TraceKeying.hpp"

#include "morok/ir/InstUtil.hpp"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Support/ModRef.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include <algorithm>
#include <cstdint>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr char kSeedName[] = "morok.trace.seed";
constexpr char kLatentName[] = "morok.trace.latent";
constexpr std::uint32_t kMaxValueTerms = 4;
constexpr std::uint32_t kMaxDelayedProbes = 4;
constexpr std::uint64_t kDelayedProbeMask = 0xf;

struct GuardedBlock {
    BasicBlock *guard = nullptr;
    BasicBlock *body = nullptr;
    BasicBlock *record = nullptr;
    PHINode *expected = nullptr;
    Value *diff = nullptr;
};

struct DelayedSample {
    Value *fire = nullptr;
    Value *sample = nullptr;
};

bool generatedFunction(const Function &F) {
    return F.getName().starts_with("morok.");
}

bool generatedBlock(const BasicBlock &BB) {
    return BB.getName().starts_with("morok.");
}

Instruction *traceSplitPoint(BasicBlock &BB) {
    for (Instruction &I : BB) {
        if (isa<PHINode>(&I))
            continue;
        return &I;
    }
    return nullptr;
}

bool directTerminator(const Instruction *Term) {
    return isa_and_nonnull<BranchInst>(Term) || isa_and_nonnull<SwitchInst>(Term);
}

bool eligibleBlock(BasicBlock &BB, BasicBlock &Entry) {
    if (&BB == &Entry || BB.isEHPad() || BB.isLandingPad() ||
        generatedBlock(BB))
        return false;
    if (!traceSplitPoint(BB))
        return false;

    bool HasPred = false;
    for (BasicBlock *Pred : predecessors(&BB)) {
        HasPred = true;
        if (!Pred || Pred->isEHPad() || Pred->isLandingPad() ||
            !directTerminator(Pred->getTerminator()))
            return false;
    }
    return HasPred;
}

void shuffleBlocks(std::vector<BasicBlock *> &Blocks, ir::IRRandom &Rng) {
    for (std::size_t I = Blocks.size(); I > 1; --I) {
        const std::size_t J = Rng.range(static_cast<std::uint32_t>(I));
        std::swap(Blocks[I - 1], Blocks[J]);
    }
}

GlobalVariable *traceSeed(Module &M, ir::IRRandom &Rng) {
    if (auto *GV = M.getGlobalVariable(kSeedName, true))
        return GV;
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *GV = new GlobalVariable(
        M, I64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I64, Rng.next()), kSeedName);
    GV->setAlignment(Align(8));
    return GV;
}

GlobalVariable *traceLatent(Module &M) {
    if (auto *GV = M.getGlobalVariable(kLatentName, true))
        return GV;
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *GV = new GlobalVariable(
        M, I64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I64, 0), kLatentName);
    GV->setAlignment(Align(8));
    return GV;
}

AllocaInst *createAccumulator(Function &F, ir::IRRandom &Rng) {
    Module &M = *F.getParent();
    IRBuilder<> B(&*F.getEntryBlock().getFirstInsertionPt());
    auto *I64 = B.getInt64Ty();
    auto *State = B.CreateAlloca(I64, nullptr, "morok.trace.state");
    State->setAlignment(Align(8));

    auto *Seed = B.CreateLoad(I64, traceSeed(M, Rng), "morok.trace.seed.load");
    Seed->setVolatile(true);
    Seed->setAlignment(Align(8));
    Value *Init =
        B.CreateXor(Seed, ConstantInt::get(I64, Rng.next()),
                    "morok.trace.init");
    auto *Store = B.CreateStore(Init, State);
    Store->setVolatile(true);
    Store->setAlignment(Align(8));
    return State;
}

std::uint64_t mix64Const(std::uint64_t State, std::uint64_t Tag,
                         std::uint64_t Salt) {
    std::uint64_t X = State ^ Tag;
    X += Salt;
    X ^= X >> 33;
    X *= 0xff51afd7ed558ccdULL;
    X ^= X >> 29;
    X *= 0xc4ceb9fe1a85ec53ULL;
    return X;
}

Value *mix64(IRBuilder<NoFolder> &B, Value *State, Value *Tag,
             std::uint64_t Salt, const char *Name = "morok.trace.edge.mix") {
    auto *I64 = B.getInt64Ty();
    Value *X = B.CreateXor(State, Tag, Name);
    X = B.CreateAdd(X, ConstantInt::get(I64, Salt), Name);
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 33)),
                    Name);
    X = B.CreateMul(X, ConstantInt::get(I64, 0xff51afd7ed558ccdULL),
                    Name);
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 29)),
                    Name);
    return B.CreateMul(X, ConstantInt::get(I64, 0xc4ceb9fe1a85ec53ULL),
                       Name);
}

// A swifterror pointer (a swifterror alloca or a swifterror argument) may only
// be loaded/stored or passed directly as a swifterror argument; freeze and
// ptrtoint on it are invalid IR the verifier rejects.  Mirrors the guards in
// PointerLaundering / PathExplosion / StackCoalescing.  False on non-Swift IR.
bool isSwiftErrorValue(const Value *V) {
    if (const auto *Arg = dyn_cast<Argument>(V))
        return Arg->hasSwiftErrorAttr();
    if (const auto *AI = dyn_cast<AllocaInst>(V))
        return AI->isSwiftError();
    return false;
}

Value *traceValueBits(IRBuilder<NoFolder> &B, Value *V) {
    auto *I64 = B.getInt64Ty();
    Type *Ty = V->getType();
    if (Ty->isVoidTy() || Ty->isTokenTy() || Ty->isMetadataTy())
        return nullptr;

    if (auto *IT = dyn_cast<IntegerType>(Ty)) {
        if (IT->getBitWidth() > 64)
            return nullptr;
        Value *Frozen = B.CreateFreeze(V, "morok.trace.value.freeze");
        return B.CreateZExtOrTrunc(Frozen, I64, "morok.trace.value.bits");
    }
    if (Ty->isPointerTy()) {
        if (isSwiftErrorValue(V))
            return nullptr;
        Value *Frozen = B.CreateFreeze(V, "morok.trace.value.freeze");
        return B.CreatePtrToInt(Frozen, I64, "morok.trace.value.bits");
    }
    if (Ty->isHalfTy() || Ty->isBFloatTy() || Ty->isFloatTy() ||
        Ty->isDoubleTy()) {
        unsigned Bits = static_cast<unsigned>(Ty->getPrimitiveSizeInBits());
        if (Bits == 0 || Bits > 64)
            return nullptr;
        Value *Frozen = B.CreateFreeze(V, "morok.trace.value.freeze");
        auto *Carrier = IntegerType::get(Ty->getContext(), Bits);
        Value *Raw = B.CreateBitCast(Frozen, Carrier,
                                     "morok.trace.value.rawbits");
        return B.CreateZExtOrTrunc(Raw, I64, "morok.trace.value.bits");
    }
    return nullptr;
}

Value *mixRuntimeValue(IRBuilder<NoFolder> &B, Value *Acc, Value *V,
                       ir::IRRandom &Rng) {
    Value *Bits = traceValueBits(B, V);
    if (!Bits)
        return Acc;
    return mix64(B, Acc, Bits, Rng.next());
}

Value *valueTraceTag(IRBuilder<NoFolder> &B, Instruction &Term, Value *EdgeTag,
                     ir::IRRandom &Rng) {
    Value *Tag = EdgeTag;

    if (auto *BI = dyn_cast<BranchInst>(&Term)) {
        if (BI->isConditional())
            Tag = mixRuntimeValue(B, Tag, BI->getCondition(), Rng);
    } else if (auto *SI = dyn_cast<SwitchInst>(&Term)) {
        Tag = mixRuntimeValue(B, Tag, SI->getCondition(), Rng);
    }

    std::uint32_t Terms = 0;
    auto It = Term.getIterator();
    while (It != Term.getParent()->begin() && Terms < kMaxValueTerms) {
        --It;
        Instruction &Candidate = *It;
        if (Candidate.getName().starts_with("morok.trace.") ||
            isa<DbgInfoIntrinsic>(&Candidate))
            continue;
        if (Candidate.getType()->isVoidTy())
            continue;
        Value *Mixed = mixRuntimeValue(B, Tag, &Candidate, Rng);
        if (Mixed != Tag) {
            Tag = Mixed;
            ++Terms;
        }
    }
    return Tag;
}

void relaxMemoryAttrs(Function &F) {
    F.setMemoryEffects(MemoryEffects::unknown());
    F.removeFnAttr(Attribute::NoSync);
    F.removeFnAttr(Attribute::WillReturn);
}

void invalidateCallerEffects(Function &F) {
    SmallVector<Function *, 8> Worklist;
    SmallPtrSet<Function *, 16> Seen;
    Worklist.push_back(&F);
    Seen.insert(&F);

    while (!Worklist.empty()) {
        Function *Current = Worklist.pop_back_val();
        for (User *U : Current->users()) {
            auto *CB = dyn_cast<CallBase>(U);
            if (!CB)
                continue;
            CB->setMemoryEffects(MemoryEffects::unknown());
            CB->removeFnAttr(Attribute::NoSync);
            CB->removeFnAttr(Attribute::WillReturn);

            Function *Caller = CB->getFunction();
            if (!Caller || !Seen.insert(Caller).second)
                continue;
            relaxMemoryAttrs(*Caller);
            Worklist.push_back(Caller);
        }
    }
}

void recordTraceMismatch(BasicBlock *Record, BasicBlock *Body,
                         GlobalVariable *Latent, Value *Diff,
                         ir::IRRandom &Rng) {
    IRBuilder<NoFolder> B(Record);
    auto *I64 = B.getInt64Ty();
    auto *Cur = B.CreateLoad(I64, Latent, "morok.trace.latent.load");
    Cur->setVolatile(true);
    Cur->setAlignment(Align(8));
    Value *Mixed = mix64(B, Cur, Diff, Rng.next(), "morok.trace.record.mix");
    auto *Store = B.CreateStore(Mixed, Latent);
    Store->setVolatile(true);
    Store->setAlignment(Align(8));
    B.CreateBr(Body);
}

GuardedBlock splitWithGuard(BasicBlock *BB, AllocaInst *State,
                            GlobalVariable *Latent, ir::IRRandom &Rng) {
    Function *F = BB->getParent();
    LLVMContext &Ctx = F->getContext();
    auto *I64 = Type::getInt64Ty(Ctx);
    Instruction *SplitPt = traceSplitPoint(*BB);
    auto *Expected =
        PHINode::Create(I64, 0, "morok.trace.expected", SplitPt);
    BasicBlock *Body = SplitBlock(BB, SplitPt);
    Body->setName("morok.trace.body");

    BasicBlock *Record =
        BasicBlock::Create(Ctx, "morok.trace.record", F, Body);

    Instruction *OldTerm = BB->getTerminator();
    IRBuilder<NoFolder> GB(OldTerm);
    auto *Loaded =
        GB.CreateLoad(I64, State, "morok.trace.state.load");
    Loaded->setVolatile(true);
    Loaded->setAlignment(Align(8));
    Value *Diff = GB.CreateXor(Loaded, Expected, "morok.trace.diff");
    Value *Guard =
        GB.CreateICmpEQ(Diff, ConstantInt::get(I64, 0), "morok.trace.guard");
    GB.CreateCondBr(Guard, Body, Record);
    OldTerm->eraseFromParent();

    recordTraceMismatch(Record, Body, Latent, Diff, Rng);
    return {BB, Body, Record, Expected, Diff};
}

Value *tagForSuccessor(IRBuilder<NoFolder> &B, BasicBlock *Succ,
                       const DenseMap<BasicBlock *, std::uint64_t> &KeyOf,
                       ir::IRRandom &Rng) {
    auto *I64 = B.getInt64Ty();
    if (auto It = KeyOf.find(Succ); It != KeyOf.end())
        return ConstantInt::get(I64, It->second);
    return ConstantInt::get(I64, Rng.next());
}

Value *selectedEdgeTag(IRBuilder<NoFolder> &B, Instruction &Term,
                       const DenseMap<BasicBlock *, std::uint64_t> &KeyOf,
                       ir::IRRandom &Rng) {
    if (auto *BI = dyn_cast<BranchInst>(&Term)) {
        if (BI->isUnconditional())
            return tagForSuccessor(B, BI->getSuccessor(0), KeyOf, Rng);
        return B.CreateSelect(
            BI->getCondition(),
            tagForSuccessor(B, BI->getSuccessor(0), KeyOf, Rng),
            tagForSuccessor(B, BI->getSuccessor(1), KeyOf, Rng),
            "morok.trace.edge.tag");
    }

    auto *SI = cast<SwitchInst>(&Term);
    Value *Tag = tagForSuccessor(B, SI->getDefaultDest(), KeyOf, Rng);
    Value *Cond = SI->getCondition();
    for (auto It = SI->case_begin(), End = SI->case_end(); It != End; ++It) {
        Value *Match =
            B.CreateICmpEQ(Cond, It->getCaseValue(), "morok.trace.edge.case");
        Tag = B.CreateSelect(Match,
                             tagForSuccessor(B, It->getCaseSuccessor(), KeyOf,
                                             Rng),
                             Tag, "morok.trace.edge.tag");
    }
    return Tag;
}

bool hasSelectedSuccessor(Instruction &Term,
                          const DenseMap<BasicBlock *, GuardedBlock> &Guards) {
    for (BasicBlock *Succ : llvm::successors(&Term))
        if (Guards.contains(Succ))
            return true;
    return false;
}

Value *insertEdgeUpdate(Instruction &Term, AllocaInst *State,
                        const DenseMap<BasicBlock *, std::uint64_t> &KeyOf,
                        const DenseMap<BasicBlock *, GuardedBlock> &Guards,
                        ir::IRRandom &Rng) {
    if (!hasSelectedSuccessor(Term, Guards))
        return nullptr;

    IRBuilder<NoFolder> B(&Term);
    auto *I64 = B.getInt64Ty();
    auto *Cur = B.CreateLoad(I64, State, "morok.trace.edge.cur");
    Cur->setVolatile(true);
    Cur->setAlignment(Align(8));
    Value *Tag = selectedEdgeTag(B, Term, KeyOf, Rng);
    Value *RuntimeTag = valueTraceTag(B, Term, Tag, Rng);
    Value *Next = mix64(B, Cur, RuntimeTag, Rng.next());
    auto *Store = B.CreateStore(Next, State);
    Store->setVolatile(true);
    Store->setAlignment(Align(8));
    return Next;
}

void addExpectedIncoming(AllocaInst *State,
                         DenseMap<BasicBlock *, GuardedBlock> &Guards,
                         const DenseMap<BasicBlock *, std::uint64_t> &KeyOf,
                         ir::IRRandom &Rng) {
    DenseMap<Instruction *, Value *> EdgeValue;

    for (auto &Pair : Guards) {
        BasicBlock *Target = Pair.first;
        PHINode *Expected = Pair.second.expected;
        SmallVector<BasicBlock *, 8> Preds(predecessors(Target));
        for (BasicBlock *Pred : Preds) {
            Instruction *Term = Pred->getTerminator();
            if (!directTerminator(Term))
                continue;
            Value *Next = EdgeValue.lookup(Term);
            if (!Next) {
                Next = insertEdgeUpdate(*Term, State, KeyOf, Guards, Rng);
                EdgeValue[Term] = Next;
            }
            if (Next)
                Expected->addIncoming(Next, Pred);
        }
    }
}

bool supportsDelayedProbe(Instruction &Term) {
    if (auto *RI = dyn_cast<ReturnInst>(&Term)) {
        if (ir::isMustTailReturn(*RI))
            return false;
        auto *Ret = RI->getReturnValue();
        auto *IT = Ret ? dyn_cast<IntegerType>(Ret->getType()) : nullptr;
        return IT && IT->getBitWidth() <= 64;
    }

    if (auto *BI = dyn_cast<BranchInst>(&Term))
        return BI->isConditional();

    if (auto *SI = dyn_cast<SwitchInst>(&Term)) {
        auto *IT = dyn_cast<IntegerType>(SI->getCondition()->getType());
        return IT && IT->getBitWidth() <= 64;
    }

    return false;
}

DelayedSample delayedSample(IRBuilder<NoFolder> &B, GlobalVariable *Latent,
                            ir::IRRandom &Rng) {
    auto *I64 = B.getInt64Ty();
    auto *Loaded = B.CreateLoad(I64, Latent, "morok.trace.delay.load");
    Loaded->setVolatile(true);
    Loaded->setAlignment(Align(8));
    Value *LoadedKey = Loaded;
    if (Module *M = B.GetInsertBlock()->getModule()) {
        if (auto *Crypto = M->getGlobalVariable("morok.watchdog.crypto",
                                                /*AllowInternal=*/true)) {
            auto *CryptoLoad =
                B.CreateLoad(I64, Crypto, "morok.trace.watchdog.crypto");
            CryptoLoad->setVolatile(true);
            CryptoLoad->setAlignment(Align(8));
            LoadedKey = B.CreateXor(LoadedKey, CryptoLoad,
                                    "morok.trace.crypto.latent");
        }
    }

    const std::uint64_t Tag = Rng.next();
    const std::uint64_t Salt = Rng.next();
    Value *TagValue = ConstantInt::get(I64, Tag);
    Value *Sample =
        mix64(B, LoadedKey, TagValue, Salt, "morok.trace.delay.mix");

    const std::uint64_t ValidLow =
        mix64Const(0, Tag, Salt) & kDelayedProbeMask;
    const std::uint64_t Needle =
        (ValidLow + 1u + Rng.range(static_cast<std::uint32_t>(
                            kDelayedProbeMask))) &
        kDelayedProbeMask;
    Value *Low =
        B.CreateAnd(Sample, ConstantInt::get(I64, kDelayedProbeMask),
                    "morok.trace.delay.low");
    Value *Fire = B.CreateICmpEQ(Low, ConstantInt::get(I64, Needle),
                                 "morok.trace.delay.fire");
    return {Fire, Sample};
}

Value *delayedKey64(IRBuilder<NoFolder> &B, const DelayedSample &Probe) {
    return B.CreateSelect(Probe.fire, Probe.sample,
                          ConstantInt::get(B.getInt64Ty(), 0),
                          "morok.trace.delay.key");
}

bool insertDelayedProbe(Instruction &Term, GlobalVariable *Latent,
                        ir::IRRandom &Rng) {
    IRBuilder<NoFolder> B(&Term);
    DelayedSample Probe = delayedSample(B, Latent, Rng);

    if (auto *RI = dyn_cast<ReturnInst>(&Term)) {
        Value *Ret = RI->getReturnValue();
        auto *IT = dyn_cast_or_null<IntegerType>(Ret ? Ret->getType()
                                                     : nullptr);
        if (!IT || IT->getBitWidth() > 64 || ir::isMustTailReturn(*RI))
            return false;
        Value *Key = delayedKey64(B, Probe);
        if (IT->getBitWidth() < 64)
            Key = B.CreateTrunc(Key, IT, "morok.trace.delay.ret.key");
        Value *Poisoned = B.CreateXor(Ret, Key, "morok.trace.delay.ret");
        RI->setOperand(0, Poisoned);
        return true;
    }

    if (auto *BI = dyn_cast<BranchInst>(&Term)) {
        if (!BI->isConditional())
            return false;
        Value *Cond = B.CreateXor(BI->getCondition(), Probe.fire,
                                  "morok.trace.delay.branch.cond");
        BI->setCondition(Cond);
        return true;
    }

    if (auto *SI = dyn_cast<SwitchInst>(&Term)) {
        auto *IT = dyn_cast<IntegerType>(SI->getCondition()->getType());
        if (!IT || IT->getBitWidth() > 64)
            return false;
        Value *Key = delayedKey64(B, Probe);
        if (IT->getBitWidth() < 64)
            Key = B.CreateTrunc(Key, IT, "morok.trace.delay.switch.key");
        Value *Cond =
            B.CreateXor(SI->getCondition(), Key,
                        "morok.trace.delay.switch.cond");
        SI->setCondition(Cond);
        return true;
    }

    return false;
}

void shuffleInstructions(std::vector<Instruction *> &Insts,
                         ir::IRRandom &Rng) {
    for (std::size_t I = Insts.size(); I > 1; --I) {
        const std::size_t J = Rng.range(static_cast<std::uint32_t>(I));
        std::swap(Insts[I - 1], Insts[J]);
    }
}

bool insertDelayedProbes(Function &F, GlobalVariable *Latent,
                         const DenseMap<BasicBlock *, GuardedBlock> &Guards,
                         ir::IRRandom &Rng) {
    SmallPtrSet<BasicBlock *, 16> GuardBlocks;
    for (const auto &Pair : Guards) {
        const GuardedBlock &GB = Pair.second;
        GuardBlocks.insert(GB.guard);
        GuardBlocks.insert(GB.body);
        GuardBlocks.insert(GB.record);
    }

    std::vector<Instruction *> Candidates;
    for (BasicBlock &BB : F) {
        if (generatedBlock(BB) || GuardBlocks.contains(&BB))
            continue;
        Instruction *Term = BB.getTerminator();
        if (Term && supportsDelayedProbe(*Term))
            Candidates.push_back(Term);
    }
    if (Candidates.empty())
        return false;

    shuffleInstructions(Candidates, Rng);
    std::uint32_t Inserted = 0;
    bool Changed = false;
    for (Instruction *Term : Candidates) {
        if (Inserted >= kMaxDelayedProbes)
            break;
        if (Inserted != 0 && !Rng.chance(50))
            continue;
        if (!insertDelayedProbe(*Term, Latent, Rng))
            continue;
        ++Inserted;
        Changed = true;
    }
    return Changed;
}

} // namespace

bool traceKeyFunction(Function &F, const TraceKeyParams &Params,
                      ir::IRRandom &Rng) {
    if (F.isDeclaration() || generatedFunction(F) || Params.probability == 0 ||
        Params.max_blocks == 0)
        return false;

    std::vector<BasicBlock *> Candidates;
    BasicBlock &Entry = F.getEntryBlock();
    for (BasicBlock &BB : F)
        if (eligibleBlock(BB, Entry))
            Candidates.push_back(&BB);
    if (Candidates.empty())
        return false;

    shuffleBlocks(Candidates, Rng);
    std::vector<BasicBlock *> Selected;
    for (BasicBlock *BB : Candidates) {
        if (Selected.size() >= Params.max_blocks)
            break;
        if (Rng.chance(Params.probability))
            Selected.push_back(BB);
    }
    if (Selected.empty())
        return false;

    AllocaInst *State = createAccumulator(F, Rng);
    GlobalVariable *Latent = traceLatent(*F.getParent());

    DenseMap<BasicBlock *, GuardedBlock> Guards;
    DenseMap<BasicBlock *, std::uint64_t> KeyOf;
    for (BasicBlock *BB : Selected)
        KeyOf[BB] = Rng.next();
    for (BasicBlock *BB : Selected)
        Guards[BB] = splitWithGuard(BB, State, Latent, Rng);

    addExpectedIncoming(State, Guards, KeyOf, Rng);
    insertDelayedProbes(F, Latent, Guards, Rng);
    relaxMemoryAttrs(F);
    invalidateCallerEffects(F);
    return true;
}

PreservedAnalyses TraceKeyingPass::run(Function &F,
                                       FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom Rng(engine_);
    return traceKeyFunction(F, params_, Rng) ? PreservedAnalyses::none()
                                             : PreservedAnalyses::all();
}

} // namespace morok::passes
