// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/MqGate.cpp
//
// Planted MQ gates for anti-symbolic pressure.  The emitted gate is built from
// argument-derived bits but rebased through volatile scratch cancellation to
// the planted assignment, so the guard is true at runtime and remains
// semantics-preserving for arbitrary programs.

#include "morok/passes/MqGate.hpp"

#include "morok/core/MqGf2.hpp"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Support/ModRef.h"

#include <algorithm>
#include <cstdint>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr char kScratchName[] = "morok.mq.scratch";
constexpr std::uint64_t kMqInstLimit = 700;
constexpr std::uint64_t kMqBlockLimit = 96;

bool generatedFunction(const Function &F) {
    return F.getName().starts_with("morok.");
}

bool generatedBlock(const BasicBlock &BB) {
    return BB.getName().starts_with("morok.");
}

std::uint64_t instructionCount(const Function &F) {
    std::uint64_t Count = 0;
    for (const BasicBlock &BB : F)
        Count += BB.size();
    return Count;
}

bool withinMqBudget(const Function &F) {
    return instructionCount(F) <= kMqInstLimit && F.size() <= kMqBlockLimit;
}

bool inputDerived(Value *V, unsigned Depth, SmallPtrSetImpl<Value *> &Seen) {
    if (!V || Depth == 0 || !Seen.insert(V).second)
        return false;
    if (isa<Argument>(V) || isa<LoadInst>(V))
        return true;
    if (isa<Constant>(V))
        return false;
    if (auto *I = dyn_cast<Instruction>(V)) {
        if (isa<BinaryOperator>(I) || isa<ICmpInst>(I) || isa<CastInst>(I) ||
            isa<SelectInst>(I) || isa<GetElementPtrInst>(I)) {
            for (Value *Op : I->operands())
                if (inputDerived(Op, Depth - 1, Seen))
                    return true;
        }
    }
    return false;
}

bool eligibleBranch(BranchInst &BI) {
    if (!BI.isConditional())
        return false;
    BasicBlock *BB = BI.getParent();
    if (!BB || BB->isEHPad() || BB->isLandingPad() || generatedBlock(*BB))
        return false;
    SmallPtrSet<Value *, 32> Seen;
    return inputDerived(BI.getCondition(), 8, Seen);
}

void shuffleBranches(std::vector<BranchInst *> &Branches, ir::IRRandom &Rng) {
    for (std::size_t I = Branches.size(); I > 1; --I) {
        const std::size_t J = Rng.range(static_cast<std::uint32_t>(I));
        std::swap(Branches[I - 1], Branches[J]);
    }
}

Value *asInteger(IRBuilder<NoFolder> &B, Value *V) {
    if (V->getType()->isIntegerTy())
        return V;
    if (V->getType()->isPointerTy())
        return B.CreatePtrToInt(V, B.getInt64Ty(), "morok.mq.arg.ptr");
    return nullptr;
}

void collectInputSources(Value *V, unsigned Depth,
                         SmallPtrSetImpl<Value *> &Seen,
                         SmallVectorImpl<Value *> &Sources) {
    if (!V || Depth == 0 || !Seen.insert(V).second)
        return;
    if ((isa<Argument>(V) || isa<LoadInst>(V)) &&
        (V->getType()->isIntegerTy() || V->getType()->isPointerTy())) {
        Sources.push_back(V);
        return;
    }
    if (auto *I = dyn_cast<Instruction>(V))
        for (Value *Op : I->operands())
            collectInputSources(Op, Depth - 1, Seen, Sources);
}

void collectSources(Function &F, Value *Root,
                    SmallVectorImpl<Value *> &Sources) {
    SmallPtrSet<Value *, 32> Seen;
    collectInputSources(Root, 8, Seen, Sources);
    if (!Sources.empty())
        return;
    for (Argument &Arg : F.args())
        if (Arg.getType()->isIntegerTy() || Arg.getType()->isPointerTy())
            Sources.push_back(&Arg);
}

AllocaInst *ensureScratch(Function &F, std::uint32_t Vars) {
    for (Instruction &I : F.getEntryBlock())
        if (auto *AI = dyn_cast<AllocaInst>(&I))
            if (AI->getName().starts_with(kScratchName))
                return AI;

    IRBuilder<> B(&*F.getEntryBlock().getFirstInsertionPt());
    auto *I8 = B.getInt8Ty();
    auto *ArrTy = ArrayType::get(I8, std::max<std::uint32_t>(Vars, 1));
    auto *Scratch = B.CreateAlloca(ArrTy, nullptr, kScratchName);
    Scratch->setAlignment(Align(1));
    return Scratch;
}

Value *scratchPtr(IRBuilder<NoFolder> &B, AllocaInst *Scratch, unsigned Index) {
    return B.CreateInBoundsGEP(Scratch->getAllocatedType(), Scratch,
                               {B.getInt32(0), B.getInt32(Index)},
                               "morok.mq.scratch.ptr");
}

Value *extractSourceBit(IRBuilder<NoFolder> &B, Value *Source, unsigned Bit) {
    Value *Int = asInteger(B, Source);
    if (!Int)
        return B.getFalse();
    auto *IT = cast<IntegerType>(Int->getType());
    const unsigned Width = IT->getBitWidth();
    Value *Shifted = Int;
    if (Width > 1)
        Shifted = B.CreateLShr(Int, ConstantInt::get(IT, Bit % Width),
                               "morok.mq.input.shift");
    return B.CreateTrunc(Shifted, B.getInt1Ty(), "morok.mq.input.bit");
}

std::vector<std::uint8_t> plantedBits(std::uint32_t Vars, ir::IRRandom &Rng) {
    std::vector<std::uint8_t> Bits(Vars);
    for (std::uint8_t &Bit : Bits)
        Bit = static_cast<std::uint8_t>(Rng.next() & 1u);
    return Bits;
}

void emitSystemGlobal(Module &M, const core::mq::Gate &Gate) {
    LLVMContext &Ctx = M.getContext();
    std::vector<std::uint8_t> Packed;
    for (const core::mq::QuadForm &Form : Gate.forms) {
        Packed.push_back(static_cast<std::uint8_t>(Form.m & 0xFFu));
        Packed.push_back(Form.cst & 1u);
        Packed.insert(Packed.end(), Form.lin.begin(), Form.lin.end());
        Packed.insert(Packed.end(), Form.quad.begin(), Form.quad.end());
    }
    if (Packed.empty())
        Packed.push_back(0);
    auto *ArrTy = ArrayType::get(Type::getInt8Ty(Ctx), Packed.size());
    std::vector<Constant *> Elems;
    Elems.reserve(Packed.size());
    for (std::uint8_t Byte : Packed)
        Elems.push_back(ConstantInt::get(Type::getInt8Ty(Ctx), Byte));
    auto *Init = ConstantArray::get(ArrTy, Elems);
    auto *GV =
        new GlobalVariable(M, ArrTy, /*isConstant=*/true,
                           GlobalValue::PrivateLinkage, Init, "morok.mq.sys");
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    GV->setAlignment(Align(1));
}

SmallVector<Value *, 64> buildGateInputs(IRBuilder<NoFolder> &B,
                                         AllocaInst *Scratch,
                                         ArrayRef<std::uint8_t> Planted,
                                         ArrayRef<Value *> Sources) {
    SmallVector<Value *, 64> Bits;
    Bits.reserve(Planted.size());
    for (unsigned I = 0; I < Planted.size(); ++I) {
        Value *Source = Sources[I % Sources.size()];
        Value *InputBit = extractSourceBit(B, Source, I);
        Value *Byte = B.CreateZExt(InputBit, B.getInt8Ty(), "morok.mq.input");
        Value *Ptr = scratchPtr(B, Scratch, I);
        auto *Store = B.CreateStore(Byte, Ptr);
        Store->setVolatile(true);
        Store->setAlignment(Align(1));
        auto *A = B.CreateLoad(B.getInt8Ty(), Ptr, "morok.mq.scratch.load");
        A->setVolatile(true);
        A->setAlignment(Align(1));
        auto *C = B.CreateLoad(B.getInt8Ty(), Ptr, "morok.mq.scratch.load");
        C->setVolatile(true);
        C->setAlignment(Align(1));
        Value *Zero = B.CreateXor(A, C, "morok.mq.input.zero");
        Value *PlantedBit =
            B.CreateXor(Zero, ConstantInt::get(B.getInt8Ty(), Planted[I] & 1u),
                        "morok.mq.input.planted");
        Bits.push_back(
            B.CreateTrunc(PlantedBit, B.getInt1Ty(), "morok.mq.bit"));
    }
    return Bits;
}

Value *emitForm(IRBuilder<NoFolder> &B, const core::mq::QuadForm &Form,
                ArrayRef<Value *> Bits) {
    Value *Acc = ConstantInt::get(B.getInt1Ty(), Form.cst & 1u);
    for (unsigned I = 0; I < Form.m; ++I)
        if ((Form.lin[I] & 1u) != 0)
            Acc = B.CreateXor(Acc, Bits[I], "morok.mq.form");
    for (unsigned I = 0; I < Form.m; ++I)
        for (unsigned J = I; J < Form.m; ++J)
            if ((Form.quad[core::mq::triIndex(I, J, Form.m)] & 1u) != 0) {
                Value *Term = B.CreateAnd(Bits[I], Bits[J], "morok.mq.term");
                Acc = B.CreateXor(Acc, Term, "morok.mq.form");
            }
    return Acc;
}

Value *emitGate(IRBuilder<NoFolder> &B, const core::mq::Gate &Gate,
                ArrayRef<Value *> Bits) {
    Value *Open = B.getTrue();
    for (const core::mq::QuadForm &Form : Gate.forms) {
        Value *FormValue = emitForm(B, Form, Bits);
        Value *Eq = B.CreateICmpEQ(FormValue, B.getFalse(), "morok.mq.eq");
        Open = B.CreateAnd(Open, Eq, "morok.mq.gate");
    }
    return Open;
}

void buildFailBlock(BasicBlock *Fail, BasicBlock *Cont, AllocaInst *Scratch,
                    Value *Condition) {
    IRBuilder<NoFolder> B(Fail);
    Value *Byte = B.CreateZExt(Condition, B.getInt8Ty(), "morok.mq.fail.byte");
    Value *Ptr = scratchPtr(B, Scratch, 0);
    auto *Store = B.CreateStore(Byte, Ptr);
    Store->setVolatile(true);
    Store->setAlignment(Align(1));
    B.CreateBr(Cont);
}

void relaxMemoryAttrs(Function &F) {
    F.setMemoryEffects(MemoryEffects::unknown());
    F.removeFnAttr(Attribute::NoSync);
    F.removeFnAttr(Attribute::WillReturn);
}

bool transformBranch(BranchInst &BI, const MqGateParams &Params,
                     ir::IRRandom &Rng) {
    Function &F = *BI.getFunction();
    Module &M = *F.getParent();
    const std::uint32_t Vars = std::clamp<std::uint32_t>(Params.vars, 1, 128);
    const std::uint32_t Eqs = std::clamp<std::uint32_t>(Params.eqs, 1, 128);
    const std::uint32_t Density = std::min<std::uint32_t>(Params.density, 100);

    SmallVector<Value *, 16> Sources;
    collectSources(F, BI.getCondition(), Sources);
    if (Sources.empty())
        return false;

    AllocaInst *Scratch = ensureScratch(F, Vars);
    std::vector<std::uint8_t> Planted = plantedBits(Vars, Rng);
    core::mq::Gate Gate =
        core::mq::makePlantedGate(Vars, Eqs, Planted, Density, Rng.engine());

    BasicBlock *Head = BI.getParent();
    BasicBlock *Then = BI.getSuccessor(0);
    BasicBlock *Else = BI.getSuccessor(1);
    Value *OrigCond = BI.getCondition();
    LLVMContext &Ctx = F.getContext();

    BasicBlock *Fail =
        BasicBlock::Create(Ctx, "morok.mq.fail", &F, Head->getNextNode());
    BasicBlock *Cont =
        BasicBlock::Create(Ctx, "morok.mq.cont", &F, Fail->getNextNode());

    Then->replacePhiUsesWith(Head, Cont);
    Else->replacePhiUsesWith(Head, Cont);

    IRBuilder<NoFolder> HB(&BI);
    SmallVector<Value *, 64> Bits =
        buildGateInputs(HB, Scratch, Planted, Sources);
    if (Bits.size() != Vars) {
        Fail->eraseFromParent();
        Cont->eraseFromParent();
        return false;
    }
    emitSystemGlobal(M, Gate);
    Value *Open = emitGate(HB, Gate, Bits);
    HB.CreateCondBr(Open, Cont, Fail);
    BI.eraseFromParent();

    buildFailBlock(Fail, Cont, Scratch, Open);
    IRBuilder<NoFolder> CB(Cont);
    CB.CreateCondBr(OrigCond, Then, Else);

    if (Params.fold_diff)
        relaxMemoryAttrs(F);
    return true;
}

} // namespace

bool mqGateFunction(Function &F, const MqGateParams &Params,
                    ir::IRRandom &Rng) {
    if (F.isDeclaration() || generatedFunction(F) || Params.probability == 0 ||
        Params.max_gates == 0 || !withinMqBudget(F))
        return false;

    std::vector<BranchInst *> Candidates;
    for (BasicBlock &BB : F)
        if (auto *BI = dyn_cast<BranchInst>(BB.getTerminator()))
            if (eligibleBranch(*BI))
                Candidates.push_back(BI);
    if (Candidates.empty())
        return false;

    shuffleBranches(Candidates, Rng);
    bool Changed = false;
    std::uint32_t Count = 0;
    for (BranchInst *BI : Candidates) {
        if (Count >= Params.max_gates)
            break;
        if (!Rng.chance(Params.probability))
            continue;
        if (transformBranch(*BI, Params, Rng)) {
            Changed = true;
            ++Count;
        }
    }
    return Changed;
}

PreservedAnalyses MqGatePass::run(Function &F, FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom Rng(engine_);
    return mqGateFunction(F, params_, Rng) ? PreservedAnalyses::none()
                                           : PreservedAnalyses::all();
}

} // namespace morok::passes
