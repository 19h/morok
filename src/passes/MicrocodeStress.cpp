// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/MicrocodeStress.cpp
//
// Sparse computed jump-table stress for decompiler microcode recovery.  Each
// selected block is split and reached through a memory-loaded blockaddress table
// whose entries target either the original body or decoy blocks.  Decoys perform
// volatile scratch writes through ptr/int aliases before rejoining the body, so
// all table entries preserve program-visible semantics while expanding the CFG
// and alias surface handed to downstream recovery.

#include "morok/passes/MicrocodeStress.hpp"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Support/ModRef.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

using Builder = IRBuilder<NoFolder>;

constexpr char kSeedName[] = "morok.micro.seed";
constexpr char kScratchName[] = "morok.micro.scratch";
constexpr char kTableName[] = "morok.micro.table";
constexpr char kDecoyPrefix[] = "morok.micro.decoy";
constexpr char kAnalysisBaitName[] = "morok.micro.analysis.bait";

bool isGeneratedFunction(const Function &F) {
    return F.getName().starts_with("morok.");
}

bool isGeneratedBlock(const BasicBlock &BB) {
    return BB.getName().starts_with("morok.micro");
}

Instruction *guardSplitPoint(BasicBlock &BB) {
    for (Instruction &I : BB) {
        if (isa<PHINode>(&I) || isa<AllocaInst>(&I))
            continue;
        if (I.isTerminator())
            return nullptr;
        return &I;
    }
    return nullptr;
}

void relaxFunctionEffects(Function &F) {
    F.setMemoryEffects(MemoryEffects::unknown());
    F.removeFnAttr(Attribute::NoSync);
    F.removeFnAttr(Attribute::ReadNone);
    F.removeFnAttr(Attribute::ReadOnly);
}

void invalidateDirectCallers(Function &F) {
    for (User *U : F.users()) {
        auto *CB = dyn_cast<CallBase>(U);
        if (!CB)
            continue;
        CB->setMemoryEffects(MemoryEffects::unknown());
        CB->removeFnAttr(Attribute::NoSync);
        if (Function *Caller = CB->getFunction())
            relaxFunctionEffects(*Caller);
    }
}

GlobalVariable *ensureSeed(Module &M, ir::IRRandom &rng) {
    if (auto *GV = M.getGlobalVariable(kSeedName, /*AllowInternal=*/true))
        return GV;
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *GV = new GlobalVariable(
        M, I64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I64, rng.next()), kSeedName);
    GV->setAlignment(Align(8));
    GV->setDSOLocal(true);
    return GV;
}

AllocaInst *findScratch(Function &F) {
    for (Instruction &I : F.getEntryBlock())
        if (auto *AI = dyn_cast<AllocaInst>(&I))
            if (AI->getName().starts_with(kScratchName))
                return AI;
    return nullptr;
}

AllocaInst *ensureScratch(Function &F) {
    if (AllocaInst *Existing = findScratch(F))
        return Existing;
    IRBuilder<> B(&*F.getEntryBlock().getFirstInsertionPt());
    auto *I64 = Type::getInt64Ty(F.getContext());
    auto *Ty = ArrayType::get(I64, 8);
    auto *Scratch = B.CreateAlloca(Ty, nullptr, kScratchName);
    Scratch->setAlignment(Align(8));
    return Scratch;
}

std::uint32_t nextPow2(std::uint32_t V) {
    std::uint32_t P = 1;
    while (P < V && P < 256)
        P <<= 1;
    return P;
}

std::uint32_t normalizedDecoys(const MicrocodeStressParams &Params) {
    return std::clamp<std::uint32_t>(Params.decoy_blocks, 1, 32);
}

std::uint32_t normalizedEntries(const MicrocodeStressParams &Params,
                                std::uint32_t Decoys) {
    const std::uint32_t Min = std::max<std::uint32_t>(8, Decoys + 1);
    const std::uint32_t Requested = std::clamp<std::uint32_t>(
        Params.table_entries, Min, 256);
    return nextPow2(Requested);
}

bool isSupportedScalarFp(Type *Ty) {
    return Ty->isHalfTy() || Ty->isBFloatTy() || Ty->isFloatTy() ||
           Ty->isDoubleTy();
}

IntegerType *integerCarrierForFp(Type *Ty) {
    if (Ty->isHalfTy() || Ty->isBFloatTy())
        return IntegerType::get(Ty->getContext(), 16);
    if (Ty->isFloatTy())
        return IntegerType::get(Ty->getContext(), 32);
    if (Ty->isDoubleTy())
        return IntegerType::get(Ty->getContext(), 64);
    return nullptr;
}

void addTerm(Value *V, SmallPtrSetImpl<Value *> &Seen,
             std::vector<Value *> &Terms) {
    if (!V || (!V->getType()->isIntegerTy() &&
               !V->getType()->isPointerTy() &&
               !isSupportedScalarFp(V->getType())))
        return;
    if (Seen.insert(V).second)
        Terms.push_back(V);
}

std::vector<Value *> collectTerms(Function &F, BasicBlock &Head,
                                  Instruction &Term) {
    std::vector<Value *> Terms;
    SmallPtrSet<Value *, 32> Seen;
    for (Argument &Arg : F.args())
        addTerm(&Arg, Seen, Terms);
    for (Instruction &I : Head) {
        if (&I == &Term)
            break;
        if (isa<AllocaInst>(&I) || isa<PHINode>(&I))
            continue;
        addTerm(&I, Seen, Terms);
    }
    return Terms;
}

Value *asI64(Builder &B, Value *V) {
    auto *I64 = B.getInt64Ty();
    if (V->getType() == I64)
        return V;
    if (V->getType()->isPointerTy())
        return B.CreatePtrToInt(V, I64, "morok.micro.term.ptr");
    if (isSupportedScalarFp(V->getType())) {
        auto *CarrierTy = integerCarrierForFp(V->getType());
        if (!CarrierTy)
            return nullptr;
        Value *Bits = B.CreateBitCast(V, CarrierTy, "morok.micro.term.fp");
        if (CarrierTy->getBitWidth() < 64)
            return B.CreateZExt(Bits, I64, "morok.micro.term.zext");
        return Bits;
    }
    auto *IT = dyn_cast<IntegerType>(V->getType());
    if (!IT)
        return nullptr;
    if (IT->getBitWidth() < 64)
        return B.CreateZExt(V, I64, "morok.micro.term.zext");
    return B.CreateTrunc(V, I64, "morok.micro.term.trunc");
}

Value *buildIndex(Builder &B, GlobalVariable *Seed,
                  ArrayRef<Value *> Terms, std::uint32_t Entries,
                  ir::IRRandom &rng) {
    auto *I64 = B.getInt64Ty();
    auto *Loaded = B.CreateLoad(I64, Seed, "morok.micro.seed.load");
    Loaded->setVolatile(true);
    Loaded->setAlignment(Align(8));
    Value *Mix = B.CreateXor(Loaded, ConstantInt::get(I64, rng.next()),
                             "morok.micro.mix");
    for (Value *Term : Terms) {
        Value *T = asI64(B, Term);
        if (!T)
            continue;
        Mix = B.CreateXor(Mix, T, "morok.micro.mix.term");
        Mix = B.CreateMul(Mix, ConstantInt::get(I64, rng.next() | 1ull),
                          "morok.micro.mix.mul");
    }
    return B.CreateAnd(Mix, ConstantInt::get(I64, Entries - 1u),
                       "morok.micro.index");
}

Value *scratchSlot(Builder &B, AllocaInst *Scratch, std::uint32_t Slot) {
    auto *I32 = B.getInt32Ty();
    return B.CreateInBoundsGEP(
        Scratch->getAllocatedType(), Scratch,
        {ConstantInt::get(I32, 0), ConstantInt::get(I32, Slot & 7u)},
        "morok.micro.scratch.slot");
}

Value *aliasPtr(Builder &B, Value *Ptr, ir::IRRandom &rng,
                const Twine &Name) {
    auto *I64 = B.getInt64Ty();
    Value *Bits = B.CreatePtrToInt(Ptr, I64, Name + ".bits");
    Value *Key = ConstantInt::get(I64, rng.next() | 1ull);
    Value *Masked = B.CreateXor(Bits, Key, Name + ".mask");
    Value *Raw = B.CreateXor(Masked, Key, Name + ".raw");
    return B.CreateIntToPtr(Raw, Ptr->getType(), Name + ".alias");
}

void volatileAliasStore(Builder &B, AllocaInst *Scratch, Value *Seed,
                        std::uint32_t Slot, ir::IRRandom &rng) {
    auto *I64 = B.getInt64Ty();
    Value *Ptr = aliasPtr(B, scratchSlot(B, Scratch, Slot), rng,
                          "morok.micro.alias");
    auto *Prev = B.CreateLoad(I64, Ptr, "morok.micro.prev");
    Prev->setVolatile(true);
    Prev->setAlignment(Align(8));
    Value *Mix = B.CreateXor(Prev, Seed, "morok.micro.store.mix");
    Mix = B.CreateAdd(Mix, ConstantInt::get(I64, rng.next()),
                      "morok.micro.store.value");
    auto *Store = B.CreateStore(Mix, Ptr);
    Store->setVolatile(true);
    Store->setAlignment(Align(8));
}

void buildDecoy(BasicBlock *BB, BasicBlock *Body, AllocaInst *Scratch,
                Value *Seed, const MicrocodeStressParams &Params,
                std::uint32_t DecoyIndex, ir::IRRandom &rng) {
    Builder B(BB);
    const std::uint32_t Stores =
        std::max<std::uint32_t>(Params.alias_stores, 1);
    for (std::uint32_t I = 0; I != Stores; ++I)
        volatileAliasStore(B, Scratch, Seed, DecoyIndex + I, rng);
    B.CreateBr(Body);
}

GlobalVariable *createTable(Module &M, Function &F,
                            ArrayRef<BasicBlock *> Dests,
                            std::uint32_t Entries, ir::IRRandom &rng) {
    auto *PtrTy = PointerType::get(M.getContext(), 0);
    auto *ArrTy = ArrayType::get(PtrTy, Entries);
    std::vector<Constant *> Values;
    Values.reserve(Entries);
    Values.push_back(BlockAddress::get(&F, Dests.front()));
    for (std::uint32_t I = 1; I != Entries; ++I) {
        const std::size_t Pick = rng.range(static_cast<std::uint32_t>(
            Dests.size()));
        Values.push_back(BlockAddress::get(&F, Dests[Pick]));
    }
    auto *GV = new GlobalVariable(
        M, ArrTy, /*isConstant=*/true, GlobalValue::PrivateLinkage,
        ConstantArray::get(ArrTy, Values), kTableName);
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return GV;
}

void rewriteSite(Function &F, BasicBlock *Body, Instruction &HeadTerm,
                 ArrayRef<Value *> Terms,
                 AllocaInst *Scratch, GlobalVariable *Seed,
                 const MicrocodeStressParams &Params, ir::IRRandom &rng) {
    const std::uint32_t DecoyCount = normalizedDecoys(Params);
    const std::uint32_t Entries = normalizedEntries(Params, DecoyCount);

    std::vector<BasicBlock *> Dests;
    Dests.reserve(DecoyCount + 1u);
    Dests.push_back(Body);

    Builder HeadBuilder(&HeadTerm);
    Value *SiteSeed = buildIndex(HeadBuilder, Seed, Terms, Entries, rng);
    for (std::uint32_t I = 0; I != DecoyCount; ++I) {
        auto *Decoy = BasicBlock::Create(F.getContext(), kDecoyPrefix, &F,
                                         Body);
        Dests.push_back(Decoy);
    }

    for (std::uint32_t I = 0; I != DecoyCount; ++I)
        buildDecoy(Dests[I + 1u], Body, Scratch, SiteSeed, Params, I, rng);

    GlobalVariable *Table = createTable(*F.getParent(), F, Dests, Entries, rng);
    auto *I32 = HeadBuilder.getInt32Ty();
    Value *Index32 = HeadBuilder.CreateTrunc(SiteSeed, I32,
                                             "morok.micro.index32");
    Value *Slot = HeadBuilder.CreateInBoundsGEP(
        Table->getValueType(), Table,
        {ConstantInt::get(I32, 0), Index32}, "morok.micro.table.slot");
    Value *Target =
        HeadBuilder.CreateLoad(PointerType::get(F.getContext(), 0), Slot,
                               "morok.micro.target");
    auto *IB =
        HeadBuilder.CreateIndirectBr(Target, static_cast<unsigned>(Dests.size()));
    for (BasicBlock *Dest : Dests)
        IB->addDestination(Dest);
}

std::optional<std::pair<StringRef, StringRef>>
analysisBaitAsm(const Triple &TT) {
    switch (TT.getArch()) {
    case Triple::x86_64:
        return std::pair<StringRef, StringRef>{
            "jmp 0f\n\t"
            ".byte 0xf3,0x0f,0x1e,0xfa\n\t"
            ".byte 0x55,0x48,0x89,0xe5\n\t"
            ".byte 0x5d,0xc3\n\t"
            ".byte 0x0f,0x1f,0x44,0x00,0x00\n"
            "0:",
            "~{dirflag},~{fpsr},~{flags},~{memory}"};
    case Triple::x86:
        return std::pair<StringRef, StringRef>{
            "jmp 0f\n\t"
            ".byte 0xf3,0x0f,0x1e,0xfb\n\t"
            ".byte 0x55,0x89,0xe5\n\t"
            ".byte 0x5d,0xc3\n"
            "0:",
            "~{dirflag},~{fpsr},~{flags},~{memory}"};
    case Triple::aarch64:
    case Triple::aarch64_be:
        return std::pair<StringRef, StringRef>{
            "b 0f\n\t"
            ".inst 0xd503245f\n\t"
            ".inst 0xa9bf7bfd\n\t"
            ".inst 0x910003fd\n\t"
            ".inst 0xa8c17bfd\n\t"
            ".inst 0xd65f03c0\n"
            "0:",
            "~{memory}"};
    default:
        return std::nullopt;
    }
}

void ensureAnalysisBait(Module &M) {
    if (M.getFunction(kAnalysisBaitName))
        return;

    auto Asm = analysisBaitAsm(Triple(M.getTargetTriple()));
    if (!Asm)
        return;

    LLVMContext &Ctx = M.getContext();
    auto *FTy = FunctionType::get(Type::getVoidTy(Ctx), false);
    auto *Fn = Function::Create(FTy, GlobalValue::InternalLinkage,
                                kAnalysisBaitName, M);
    Fn->setDSOLocal(true);
    Fn->addFnAttr(Attribute::NoInline);
    Fn->addFnAttr(Attribute::Cold);
    Fn->setAlignment(Align(16));

    IRBuilder<> B(BasicBlock::Create(Ctx, "entry", Fn));
    InlineAsm *IA = InlineAsm::get(FTy, Asm->first, Asm->second,
                                   /*hasSideEffects=*/true);
    B.CreateCall(FTy, IA);
    B.CreateRetVoid();

    appendToUsed(M, {Fn});
    appendToCompilerUsed(M, {Fn});
}

void shuffleBlocks(std::vector<BasicBlock *> &Blocks, ir::IRRandom &rng) {
    for (std::size_t I = Blocks.size(); I > 1; --I) {
        const std::size_t J = rng.range(static_cast<std::uint32_t>(I));
        std::swap(Blocks[I - 1], Blocks[J]);
    }
}

} // namespace

bool microcodeStressFunction(Function &F, const MicrocodeStressParams &params,
                             ir::IRRandom &rng) {
    if (F.isDeclaration() || isGeneratedFunction(F) || params.probability == 0 ||
        params.max_sites == 0 || params.table_entries == 0 ||
        params.decoy_blocks == 0)
        return false;

    std::vector<BasicBlock *> Blocks;
    for (BasicBlock &BB : F)
        Blocks.push_back(&BB);
    shuffleBlocks(Blocks, rng);

    GlobalVariable *Seed = nullptr;
    AllocaInst *Scratch = nullptr;
    bool Changed = false;
    std::uint32_t Count = 0;
    for (BasicBlock *Head : Blocks) {
        if (Count >= params.max_sites)
            break;
        if (Head->isEHPad() || Head->isLandingPad() || isGeneratedBlock(*Head))
            continue;
        if (!rng.chance(params.probability))
            continue;
        Instruction *SplitPt = guardSplitPoint(*Head);
        if (!SplitPt)
            continue;

        if (!Seed)
            Seed = ensureSeed(*F.getParent(), rng);
        if (!Scratch)
            Scratch = ensureScratch(F);

        BasicBlock *Body = SplitBlock(Head, SplitPt);
        Instruction *HeadTerm = Head->getTerminator();
        std::vector<Value *> Terms = collectTerms(F, *Head, *HeadTerm);
        rewriteSite(F, Body, *HeadTerm, Terms, Scratch, Seed, params, rng);
        HeadTerm->eraseFromParent();

        Changed = true;
        ++Count;
    }

    if (Changed) {
        ensureAnalysisBait(*F.getParent());
        relaxFunctionEffects(F);
        invalidateDirectCallers(F);
    }
    return Changed;
}

PreservedAnalyses MicrocodeStressPass::run(Function &F,
                                           FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return microcodeStressFunction(F, params_, rng) ? PreservedAnalyses::none()
                                                    : PreservedAnalyses::all();
}

} // namespace morok::passes
