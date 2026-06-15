// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/DispatcherlessRouting.cpp
//
// Dispatcherless computed CFG routing.  Instead of building one central switch,
// this pass rewrites each selected direct branch/switch terminator into a local
// indirectbr through a shared block-address table.  The selected table index is
// fused with a previous route-state value and live integer data, then
// neutralized via volatile shadow slots so the runtime target remains exact
// while the slice no longer consists of a plaintext branch condition alone.

#include "morok/passes/DispatcherlessRouting.hpp"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"

#include <algorithm>
#include <cstdint>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

struct RouteSite {
    Instruction *term = nullptr;
    std::vector<BasicBlock *> successors;
};

struct RoutingState {
    GlobalVariable *table = nullptr;
    AllocaInst *state = nullptr;
    AllocaInst *shadow = nullptr;
    std::unordered_map<BasicBlock *, std::uint32_t> idOf;
};

constexpr std::uint32_t kMaxRoutesPerInvocation = 32;
constexpr std::uint32_t kMaxTermsPerSite = 8;
constexpr std::uint32_t kMaxSuccessorsPerSite = 32;

bool isGeneratedBlock(const BasicBlock &BB) {
    return BB.getName().starts_with("morok.");
}

void addUnique(std::vector<BasicBlock *> &Blocks, BasicBlock *BB) {
    if (!BB)
        return;
    if (std::find(Blocks.begin(), Blocks.end(), BB) == Blocks.end())
        Blocks.push_back(BB);
}

bool validSuccessor(const BasicBlock *Succ, const BasicBlock *Entry) {
    return Succ && Succ != Entry && !Succ->isEHPad() && !Succ->isLandingPad();
}

std::vector<BasicBlock *> terminatorSuccessors(Instruction &Term) {
    std::vector<BasicBlock *> Succs;
    if (auto *Br = dyn_cast<BranchInst>(&Term)) {
        for (BasicBlock *Succ : Br->successors())
            addUnique(Succs, Succ);
    } else if (auto *Sw = dyn_cast<SwitchInst>(&Term)) {
        addUnique(Succs, Sw->getDefaultDest());
        for (const auto &Case : Sw->cases())
            addUnique(Succs, Case.getCaseSuccessor());
    }
    return Succs;
}

bool eligibleTerminator(Instruction &Term, BasicBlock *Entry) {
    if (auto *Br = dyn_cast<BranchInst>(&Term)) {
        if (Br->getNumSuccessors() == 0)
            return false;
    } else if (auto *Sw = dyn_cast<SwitchInst>(&Term)) {
        if (Sw->getNumSuccessors() == 0)
            return false;
    } else {
        return false;
    }

    BasicBlock *Parent = Term.getParent();
    if (!Parent || Parent->isEHPad() || Parent->isLandingPad() ||
        isGeneratedBlock(*Parent))
        return false;
    std::vector<BasicBlock *> Succs = terminatorSuccessors(Term);
    if (Succs.empty() || Succs.size() > kMaxSuccessorsPerSite)
        return false;
    for (BasicBlock *Succ : Succs)
        if (!validSuccessor(Succ, Entry))
            return false;
    return true;
}

AllocaInst *createState(Function &F) {
    IRBuilder<> B(&*F.getEntryBlock().getFirstInsertionPt());
    auto *I32 = Type::getInt32Ty(F.getContext());
    auto *State = B.CreateAlloca(I32, nullptr, "morok.dlf.state");
    B.CreateStore(ConstantInt::get(I32, 0), State);
    return State;
}

AllocaInst *createShadow(Function &F) {
    IRBuilder<> B(&*F.getEntryBlock().getFirstInsertionPt());
    auto *I32 = Type::getInt32Ty(F.getContext());
    auto *ShadowTy = ArrayType::get(I32, 2);
    auto *Shadow = B.CreateAlloca(ShadowTy, nullptr, "morok.dlf.shadow");
    Shadow->setAlignment(Align(4));
    return Shadow;
}

GlobalVariable *createTable(Module &M, Function &F,
                            ArrayRef<BasicBlock *> Targets) {
    LLVMContext &Ctx = M.getContext();
    auto *PtrTy = PointerType::getUnqual(Ctx);
    auto *ArrTy = ArrayType::get(PtrTy, Targets.size());
    std::vector<Constant *> Entries;
    Entries.reserve(Targets.size());
    for (BasicBlock *BB : Targets)
        Entries.push_back(BlockAddress::get(&F, BB));
    return new GlobalVariable(
        M, ArrTy, /*isConstant=*/true, GlobalValue::PrivateLinkage,
        ConstantArray::get(ArrTy, Entries), "morok.dlf.table");
}

Value *asI32(IRBuilder<NoFolder> &B, Value *V) {
    auto *I32 = B.getInt32Ty();
    if (V->getType() == I32)
        return V;
    if (auto *IT = dyn_cast<IntegerType>(V->getType())) {
        const unsigned Bits = IT->getBitWidth();
        if (Bits < 32)
            return B.CreateZExt(V, I32, "morok.dlf.term.zext");
        if (Bits > 32)
            return B.CreateTrunc(V, I32, "morok.dlf.term.trunc");
    }
    return nullptr;
}

void addTerm(Value *V, SmallPtrSetImpl<Value *> &Seen,
             std::vector<Value *> &Terms, std::uint32_t Limit) {
    if (Terms.size() >= Limit)
        return;
    if (!V || !V->getType()->isIntegerTy())
        return;
    if (Seen.insert(V).second)
        Terms.push_back(V);
}

std::vector<Value *> collectTerms(Instruction &Term, std::uint32_t MaxTerms) {
    std::vector<Value *> Terms;
    const std::uint32_t Limit = std::min(MaxTerms, kMaxTermsPerSite);
    if (Limit == 0)
        return Terms;
    SmallPtrSet<Value *, 32> Seen;

    if (auto *Br = dyn_cast<BranchInst>(&Term)) {
        if (Br->isConditional())
            addTerm(Br->getCondition(), Seen, Terms, Limit);
    } else if (auto *Sw = dyn_cast<SwitchInst>(&Term)) {
        addTerm(Sw->getCondition(), Seen, Terms, Limit);
    }

    for (Instruction &I : *Term.getParent()) {
        if (Terms.size() >= Limit)
            break;
        if (&I == &Term)
            break;
        if (isa<AllocaInst>(&I))
            continue;
        addTerm(&I, Seen, Terms, Limit);
    }
    return Terms;
}

void shuffleTerms(std::vector<Value *> &Terms, ir::IRRandom &rng) {
    for (std::size_t I = Terms.size(); I > 1; --I) {
        const std::size_t J = rng.range(static_cast<std::uint32_t>(I));
        std::swap(Terms[I - 1], Terms[J]);
    }
}

Value *
selectedIndex(IRBuilder<NoFolder> &B, Instruction &Term,
              const std::unordered_map<BasicBlock *, std::uint32_t> &ID) {
    auto *I32 = B.getInt32Ty();

    if (auto *Br = dyn_cast<BranchInst>(&Term)) {
        if (Br->isUnconditional())
            return ConstantInt::get(I32, ID.at(Br->getSuccessor(0)));
        return B.CreateSelect(Br->getCondition(),
                              ConstantInt::get(I32, ID.at(Br->getSuccessor(0))),
                              ConstantInt::get(I32, ID.at(Br->getSuccessor(1))),
                              "morok.dlf.target");
    }

    auto *Sw = cast<SwitchInst>(&Term);
    Value *Target = ConstantInt::get(I32, ID.at(Sw->getDefaultDest()));
    Value *Cond = Sw->getCondition();
    for (auto It = Sw->case_begin(), End = Sw->case_end(); It != End; ++It) {
        Value *Match =
            B.CreateICmpEQ(Cond, It->getCaseValue(), "morok.dlf.case");
        Target = B.CreateSelect(
            Match, ConstantInt::get(I32, ID.at(It->getCaseSuccessor())), Target,
            "morok.dlf.target");
    }
    return Target;
}

Value *shadowSlot(IRBuilder<NoFolder> &B, AllocaInst *Shadow, unsigned Slot) {
    auto *I32 = B.getInt32Ty();
    return B.CreateInBoundsGEP(
        Shadow->getAllocatedType(), Shadow,
        {ConstantInt::get(I32, 0), ConstantInt::get(I32, Slot)},
        "morok.dlf.shadow.slot");
}

Value *tokenFor(IRBuilder<NoFolder> &B, RoutingState &State, Instruction &Term,
                const DispatcherlessRoutingParams &Params, ir::IRRandom &rng) {
    auto *I32 = B.getInt32Ty();
    Value *Cur = B.CreateLoad(I32, State.state, "morok.dlf.cur");
    Value *Token = B.CreateXor(
        Cur, ConstantInt::get(I32, static_cast<std::uint32_t>(rng.next())),
        "morok.dlf.token.seed");

    std::vector<Value *> Terms = collectTerms(Term, Params.max_terms);
    shuffleTerms(Terms, rng);
    const std::uint32_t Limit = std::min<std::uint32_t>(
        Params.max_terms, static_cast<std::uint32_t>(Terms.size()));
    for (std::uint32_t I = 0; I < Limit; ++I) {
        Value *Term32 = asI32(B, Terms[I]);
        if (!Term32)
            continue;
        Value *Salt =
            ConstantInt::get(I32, static_cast<std::uint32_t>(rng.next()));
        Token = B.CreateXor(Token, B.CreateXor(Term32, Salt),
                            "morok.dlf.token.fold");
        Token = B.CreateMul(
            Token,
            ConstantInt::get(I32, static_cast<std::uint32_t>(rng.next()) | 1u),
            "morok.dlf.token.mix");
    }
    return Token;
}

Value *volatileCancel(IRBuilder<NoFolder> &B, RoutingState &State,
                      Value *Token) {
    auto *I32 = B.getInt32Ty();
    Value *S0 = shadowSlot(B, State.shadow, 0);
    Value *S1 = shadowSlot(B, State.shadow, 1);
    auto *Store0 = B.CreateStore(Token, S0);
    Store0->setVolatile(true);
    Store0->setAlignment(Align(4));
    auto *Store1 = B.CreateStore(Token, S1);
    Store1->setVolatile(true);
    Store1->setAlignment(Align(4));

    auto *A = B.CreateLoad(I32, S0, "morok.dlf.shadow.a");
    A->setVolatile(true);
    A->setAlignment(Align(4));
    auto *Bv = B.CreateLoad(I32, S1, "morok.dlf.shadow.b");
    Bv->setVolatile(true);
    Bv->setAlignment(Align(4));
    return B.CreateXor(A, Bv, "morok.dlf.cancel");
}

std::vector<BasicBlock *> uniqueSuccessors(ArrayRef<BasicBlock *> Succs) {
    std::vector<BasicBlock *> Unique;
    for (BasicBlock *Succ : Succs)
        addUnique(Unique, Succ);
    return Unique;
}

void rewriteSite(RouteSite &Site, RoutingState &State,
                 const DispatcherlessRoutingParams &Params, ir::IRRandom &rng) {
    Instruction *Term = Site.term;
    IRBuilder<NoFolder> B(Term);
    auto *I64 = B.getInt64Ty();
    auto *PtrTy = PointerType::getUnqual(B.getContext());
    auto *TableTy = cast<ArrayType>(State.table->getValueType());

    Value *Target = selectedIndex(B, *Term, State.idOf);
    Value *Token = tokenFor(B, State, *Term, Params, rng);
    Value *Next =
        B.CreateXor(Target, volatileCancel(B, State, Token), "morok.dlf.next");
    B.CreateStore(Next, State.state);

    Value *Idx = B.CreateZExt(Next, I64, "morok.dlf.idx");
    Value *Slot =
        B.CreateInBoundsGEP(TableTy, State.table,
                            {ConstantInt::get(I64, 0), Idx}, "morok.dlf.slot");
    Value *Dest = B.CreateLoad(PtrTy, Slot, "morok.dlf.dest");
    std::vector<BasicBlock *> Dests = uniqueSuccessors(Site.successors);
    auto *IB = B.CreateIndirectBr(Dest, static_cast<unsigned>(Dests.size()));
    for (BasicBlock *Succ : Dests)
        IB->addDestination(Succ);
    Term->eraseFromParent();
}

} // namespace

bool dispatcherlessRoutingFunction(Function &F,
                                   const DispatcherlessRoutingParams &params,
                                   ir::IRRandom &rng) {
    if (F.isDeclaration() || F.getName().starts_with("morok.") ||
        params.probability == 0 || params.max_routes == 0)
        return false;

    const std::uint32_t RouteLimit =
        std::min(params.max_routes, kMaxRoutesPerInvocation);
    BasicBlock *Entry = &F.getEntryBlock();
    std::vector<RouteSite> Selected;
    Selected.reserve(RouteLimit);
    for (BasicBlock &BB : F) {
        if (Selected.size() >= RouteLimit)
            break;
        Instruction *Term = BB.getTerminator();
        if (!Term || !eligibleTerminator(*Term, Entry))
            continue;
        if (rng.chance(params.probability))
            Selected.push_back({Term, terminatorSuccessors(*Term)});
    }
    if (Selected.empty())
        return false;

    std::vector<BasicBlock *> Targets;
    for (const RouteSite &Site : Selected)
        for (BasicBlock *Succ : Site.successors)
            addUnique(Targets, Succ);
    if (Targets.empty())
        return false;

    RoutingState State;
    Module &M = *F.getParent();
    State.table = createTable(M, F, Targets);
    State.state = createState(F);
    State.shadow = createShadow(F);
    for (std::uint32_t I = 0; I < Targets.size(); ++I)
        State.idOf[Targets[I]] = I;

    for (RouteSite &Site : Selected)
        rewriteSite(Site, State, params, rng);
    return true;
}

PreservedAnalyses DispatcherlessRoutingPass::run(Function &F,
                                                 FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return dispatcherlessRoutingFunction(F, params_, rng)
               ? PreservedAnalyses::none()
               : PreservedAnalyses::all();
}

} // namespace morok::passes
