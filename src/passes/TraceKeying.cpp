// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/TraceKeying.cpp
//
// Execution-trace keying.  This pass threads a private rolling hash through
// selected CFG edges, then guards selected blocks by comparing a volatile
// accumulator load with the edge-carried expected value.  The valid path is
// semantics-neutral; if instrumentation or replay perturbs the order, branch
// conditions and integer returns are keyed by the accumulator mismatch and the
// block guard traps.

#include "morok/passes/TraceKeying.hpp"

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

struct GuardedBlock {
    BasicBlock *guard = nullptr;
    BasicBlock *body = nullptr;
    PHINode *expected = nullptr;
    Value *diff = nullptr;
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

Value *mix64(IRBuilder<NoFolder> &B, Value *State, Value *Tag,
             std::uint64_t Salt) {
    auto *I64 = B.getInt64Ty();
    Value *X = B.CreateXor(State, Tag, "morok.trace.edge.mix");
    X = B.CreateAdd(X, ConstantInt::get(I64, Salt), "morok.trace.edge.mix");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 33)),
                    "morok.trace.edge.mix");
    X = B.CreateMul(X, ConstantInt::get(I64, 0xff51afd7ed558ccdULL),
                    "morok.trace.edge.mix");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 29)),
                    "morok.trace.edge.mix");
    return B.CreateMul(X, ConstantInt::get(I64, 0xc4ceb9fe1a85ec53ULL),
                       "morok.trace.edge.mix");
}

Value *asReturnWidth(IRBuilder<NoFolder> &B, Value *Diff, Type *Ty) {
    auto *IT = dyn_cast<IntegerType>(Ty);
    if (!IT)
        return nullptr;
    const unsigned Bits = IT->getBitWidth();
    if (Bits > 64)
        return nullptr;
    if (Bits == 64)
        return Diff;
    if (Bits < 64)
        return B.CreateTrunc(Diff, IT, "morok.trace.ret.key");
    return nullptr;
}

Value *asConditionKey(IRBuilder<NoFolder> &B, Value *Diff) {
    return B.CreateICmpNE(Diff, ConstantInt::get(B.getInt64Ty(), 0),
                          "morok.trace.bad");
}

void poisonTerminator(BasicBlock *Body, Value *Diff) {
    Instruction *Term = Body->getTerminator();
    IRBuilder<NoFolder> B(Term);

    if (auto *RI = dyn_cast<ReturnInst>(Term)) {
        Value *Ret = RI->getReturnValue();
        if (!Ret)
            return;
        Value *Key = asReturnWidth(B, Diff, Ret->getType());
        if (!Key)
            return;
        Value *Poisoned = B.CreateXor(Ret, Key, "morok.trace.ret");
        RI->setOperand(0, Poisoned);
        return;
    }

    if (auto *BI = dyn_cast<BranchInst>(Term)) {
        if (!BI->isConditional())
            return;
        Value *Bad = asConditionKey(B, Diff);
        Value *Cond =
            B.CreateXor(BI->getCondition(), Bad, "morok.trace.branch.cond");
        BI->setCondition(Cond);
        return;
    }

    if (auto *SI = dyn_cast<SwitchInst>(Term)) {
        auto *IT = dyn_cast<IntegerType>(SI->getCondition()->getType());
        if (!IT || IT->getBitWidth() > 64)
            return;
        Value *Key = nullptr;
        if (IT->getBitWidth() == 64)
            Key = Diff;
        else
            Key = B.CreateTrunc(Diff, IT, "morok.trace.switch.key");
        Value *Cond =
            B.CreateXor(SI->getCondition(), Key, "morok.trace.switch.cond");
        SI->setCondition(Cond);
    }
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

GuardedBlock splitWithGuard(BasicBlock *BB, AllocaInst *State) {
    Function *F = BB->getParent();
    LLVMContext &Ctx = F->getContext();
    auto *I64 = Type::getInt64Ty(Ctx);
    Instruction *SplitPt = traceSplitPoint(*BB);
    auto *Expected =
        PHINode::Create(I64, 0, "morok.trace.expected", SplitPt);
    BasicBlock *Body = SplitBlock(BB, SplitPt);
    Body->setName("morok.trace.body");

    BasicBlock *Fail =
        BasicBlock::Create(Ctx, "morok.trace.fail", F, Body);
    IRBuilder<NoFolder> FB(Fail);
    Function *Trap =
        Intrinsic::getOrInsertDeclaration(F->getParent(), Intrinsic::trap);
    FB.CreateCall(Trap);
    FB.CreateUnreachable();

    Instruction *OldTerm = BB->getTerminator();
    IRBuilder<NoFolder> GB(OldTerm);
    auto *Loaded =
        GB.CreateLoad(I64, State, "morok.trace.state.load");
    Loaded->setVolatile(true);
    Loaded->setAlignment(Align(8));
    Value *Diff = GB.CreateXor(Loaded, Expected, "morok.trace.diff");
    Value *Guard =
        GB.CreateICmpEQ(Diff, ConstantInt::get(I64, 0), "morok.trace.guard");
    GB.CreateCondBr(Guard, Body, Fail);
    OldTerm->eraseFromParent();

    poisonTerminator(Body, Diff);
    return {BB, Body, Expected, Diff};
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
    for (BasicBlock *Succ : Term.successors())
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
    Value *Next = mix64(B, Cur, Tag, Rng.next());
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

    DenseMap<BasicBlock *, GuardedBlock> Guards;
    DenseMap<BasicBlock *, std::uint64_t> KeyOf;
    for (BasicBlock *BB : Selected)
        KeyOf[BB] = Rng.next();
    for (BasicBlock *BB : Selected)
        Guards[BB] = splitWithGuard(BB, State);

    addExpectedIncoming(State, Guards, KeyOf, Rng);
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
