// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/Nanomites.cpp
//
// Nanomites remove direct conditional branch opcodes from selected sites.  Each
// site materializes the branch predicate into volatile state, raises a
// synchronous trap, and leaves only an indirectbr fallback for IR legality.  A
// SIGTRAP handler decodes an encrypted PC→target table and rewrites the saved
// PC in ucontext_t before execution reaches that fallback.

#include "morok/passes/Nanomites.hpp"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Support/Alignment.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <algorithm>
#include <cstdint>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr std::uint32_t kMaxSitesPerFunction = 2;

struct NanomiteLayout {
    std::uint64_t sigactionSize = 0;
    std::uint64_t flagsOffset = 0;
    std::uint64_t linuxPcSlotOffset = 0;
    std::uint64_t darwinMcontextOffset = 0;
    std::uint64_t darwinPcOffset = 0;
    std::uint32_t saSiginfo = 0;
    std::uint32_t trapAdvance = 0;
    bool darwinMcontext = false;
    const char *trapAsm = "int3";
    const char *trapConstraints = "~{dirflag},~{fpsr},~{flags}";
};

struct Site {
    Function *function = nullptr;
    BasicBlock *trap = nullptr;
    BasicBlock *resume = nullptr;
    BasicBlock *trueTarget = nullptr;
    BasicBlock *falseTarget = nullptr;
    std::uint64_t siteMask = 0;
    std::uint64_t resumeMask = 0;
    std::uint64_t trueMask = 0;
    std::uint64_t falseMask = 0;
    std::uint64_t condKey = 0;
    std::uint64_t condSalt = 0;
    std::uint64_t condKeyMask = 0;
    std::uint64_t condSaltMask = 0;
};

IntegerType *intPtrTy(Module &M) {
    unsigned bits = M.getDataLayout().getPointerSizeInBits(0);
    if (bits == 0)
        bits = 64;
    return IntegerType::get(M.getContext(), bits);
}

ConstantInt *constIp(Module &M, std::uint64_t V) {
    return ConstantInt::get(intPtrTy(M), V);
}

Value *gepI8(IRBuilderBase &B, Module &M, Value *Base, Value *Offset,
             const Twine &Name = "") {
    return B.CreateGEP(Type::getInt8Ty(M.getContext()), Base, {Offset}, Name);
}

LoadInst *loadUnaligned(IRBuilderBase &B, Type *Ty, Value *Ptr,
                        const Twine &Name = "") {
    auto *LI = B.CreateLoad(Ty, Ptr, Name);
    LI->setAlignment(Align(1));
    return LI;
}

Value *loadAt(IRBuilderBase &B, Module &M, Type *Ty, Value *Base,
              std::uint64_t Offset, const Twine &Name = "") {
    return loadUnaligned(B, Ty, gepI8(B, M, Base, constIp(M, Offset),
                                      Name + ".ptr"),
                         Name);
}

FunctionCallee sigactionDecl(Module &M) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);
    return M.getOrInsertFunction(
        "sigaction", FunctionType::get(i32, {i32, ptr, ptr}, false));
}

void zeroActionBytes(IRBuilderBase &B, Module &M, AllocaInst *Action,
                     std::uint64_t Bytes) {
    auto *i8 = Type::getInt8Ty(M.getContext());
    for (std::uint64_t i = 0; i < Bytes; ++i)
        B.CreateStore(ConstantInt::get(i8, 0),
                      gepI8(B, M, Action, constIp(M, i)));
}

void storeSiginfoAction(IRBuilderBase &B, Module &M, AllocaInst *Action,
                        Function *Handler, const NanomiteLayout &Layout) {
    auto *i32 = Type::getInt32Ty(M.getContext());
    zeroActionBytes(B, M, Action, Layout.sigactionSize);
    B.CreateStore(Handler,
                  gepI8(B, M, Action, constIp(M, 0),
                        "morok.nanomite.sa.handler"));
    B.CreateStore(ConstantInt::get(i32, Layout.saSiginfo),
                  gepI8(B, M, Action, constIp(M, Layout.flagsOffset),
                        "morok.nanomite.sa.flags"));
}

bool nanomiteLayout(const Triple &TT, NanomiteLayout &L) {
    if (TT.isOSLinux() && TT.getArch() == Triple::x86_64) {
        L.sigactionSize = 152;
        L.flagsOffset = 136;
        L.linuxPcSlotOffset = 168;
        L.saSiginfo = 4;
        L.trapAdvance = 1;
        L.trapAsm = "int3";
        L.trapConstraints = "~{dirflag},~{fpsr},~{flags}";
        return true;
    }

    if (TT.isOSDarwin() && TT.getArch() == Triple::x86_64) {
        L.sigactionSize = 16;
        L.flagsOffset = 12;
        L.darwinMcontextOffset = 48;
        L.darwinPcOffset = 160;
        L.saSiginfo = 0x40;
        L.trapAdvance = 1;
        L.darwinMcontext = true;
        L.trapAsm = "int3";
        L.trapConstraints = "~{dirflag},~{fpsr},~{flags}";
        return true;
    }

    if (TT.isOSDarwin() &&
        (TT.getArch() == Triple::aarch64 ||
         TT.getArch() == Triple::aarch64_32)) {
        L.sigactionSize = 16;
        L.flagsOffset = 12;
        L.darwinMcontextOffset = 48;
        L.darwinPcOffset = 272;
        L.saSiginfo = 0x40;
        L.trapAdvance = 0;
        L.darwinMcontext = true;
        L.trapAsm = "brk #0x4d4b";
        L.trapConstraints = "~{memory}";
        return true;
    }

    return false;
}

GlobalVariable *decisionGlobal(Module &M) {
    if (auto *existing =
            M.getGlobalVariable("morok.nanomite.decision",
                                /*AllowInternal=*/true))
        return existing;
    auto *ip = intPtrTy(M);
    auto *gv = new GlobalVariable(
        M, ip, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(ip, 0), "morok.nanomite.decision");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    gv->setAlignment(Align(8));
    return gv;
}

GlobalVariable *tokenGlobal(Module &M) {
    if (auto *existing =
            M.getGlobalVariable("morok.nanomite.token",
                                /*AllowInternal=*/true))
        return existing;
    auto *ip = intPtrTy(M);
    auto *gv = new GlobalVariable(
        M, ip, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(ip, 0), "morok.nanomite.token");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    gv->setAlignment(Align(8));
    return gv;
}

GlobalVariable *targetGlobal(Module &M) {
    if (auto *existing =
            M.getGlobalVariable("morok.nanomite.target",
                                /*AllowInternal=*/true))
        return existing;
    auto *ip = intPtrTy(M);
    auto *gv = new GlobalVariable(
        M, ip, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(ip, 0), "morok.nanomite.target");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    gv->setAlignment(Align(8));
    return gv;
}

std::uint64_t ptrWidthMask(Module &M, std::uint64_t V) {
    if (intPtrTy(M)->getBitWidth() >= 64)
        return V;
    return static_cast<std::uint32_t>(V);
}

bool generatedFunction(const Function &F) {
    return F.getName().starts_with("morok.") ||
           F.getName().starts_with("llvm.");
}

SmallPtrSet<BasicBlock *, 32> naturalLoopBlocks(Function &F) {
    DominatorTree DT(F);
    SmallPtrSet<BasicBlock *, 32> blocks;
    for (BasicBlock &BB : F) {
        for (BasicBlock *Succ : successors(&BB)) {
            if (!DT.dominates(Succ, &BB))
                continue;

            blocks.insert(Succ);
            SmallVector<BasicBlock *, 16> worklist;
            if (&BB != Succ) {
                worklist.push_back(&BB);
                blocks.insert(&BB);
            }
            while (!worklist.empty()) {
                BasicBlock *Cur = worklist.pop_back_val();
                for (BasicBlock *Pred : predecessors(Cur)) {
                    if (blocks.insert(Pred).second && Pred != Succ)
                        worklist.push_back(Pred);
                }
            }
        }
    }
    return blocks;
}

bool functionAddressEscapes(const Function &F) {
    SmallVector<const Value *, 8> worklist;
    SmallPtrSet<const Value *, 16> seen;
    worklist.push_back(&F);

    while (!worklist.empty()) {
        const Value *V = worklist.pop_back_val();
        if (!seen.insert(V).second)
            continue;

        for (const User *U : V->users()) {
            if (auto *CB = dyn_cast<CallBase>(U)) {
                if (CB->getCalledOperand()->stripPointerCasts() == &F)
                    continue;
                return true;
            }

            if (auto *SI = dyn_cast<StoreInst>(U)) {
                if (SI->getValueOperand()->stripPointerCasts() == &F)
                    return true;
            }

            if (isa<ConstantExpr>(U) || isa<CastInst>(U) ||
                isa<GetElementPtrInst>(U) || isa<PHINode>(U) ||
                isa<SelectInst>(U)) {
                worklist.push_back(U);
                continue;
            }

            return true;
        }
    }

    return false;
}

bool calledFromNaturalLoop(Function &Target) {
    SmallVector<const Value *, 8> worklist;
    SmallPtrSet<const Value *, 16> seen;
    worklist.push_back(&Target);

    while (!worklist.empty()) {
        const Value *V = worklist.pop_back_val();
        if (!seen.insert(V).second)
            continue;

        for (const User *U : V->users()) {
            if (auto *CB = dyn_cast<CallBase>(U)) {
                if (CB->getCalledOperand()->stripPointerCasts() != &Target)
                    continue;
                const BasicBlock *ConstBB = CB->getParent();
                BasicBlock *BB = const_cast<BasicBlock *>(ConstBB);
                Function *Caller = BB ? BB->getParent() : nullptr;
                if (!Caller || Caller == &Target)
                    continue;
                SmallPtrSet<BasicBlock *, 32> loopBlocks =
                    naturalLoopBlocks(*Caller);
                if (loopBlocks.contains(BB))
                    return true;
                continue;
            }

            if (isa<ConstantExpr>(U) || isa<CastInst>(U)) {
                worklist.push_back(U);
                continue;
            }
        }
    }

    return false;
}

bool eligibleFunction(Function &F) {
    return !F.isDeclaration() && !generatedFunction(F) && !F.hasPersonalityFn() &&
           !F.hasFnAttribute(Attribute::Naked) &&
           !F.hasFnAttribute(Attribute::OptimizeNone) &&
           !functionAddressEscapes(F) && !calledFromNaturalLoop(F);
}

bool eligibleBranchShape(BranchInst &BI) {
    if (!BI.isConditional())
        return false;
    BasicBlock *head = BI.getParent();
    BasicBlock *trueTarget = BI.getSuccessor(0);
    BasicBlock *falseTarget = BI.getSuccessor(1);
    return head && !head->isEHPad() && !head->isLandingPad() && trueTarget &&
           falseTarget && trueTarget != falseTarget && !trueTarget->isEHPad() &&
           !trueTarget->isLandingPad() && !falseTarget->isEHPad() &&
           !falseTarget->isLandingPad();
}

DenseMap<const BasicBlock *, unsigned> blockOrder(const Function &F) {
    DenseMap<const BasicBlock *, unsigned> order;
    unsigned index = 0;
    for (const BasicBlock &BB : F)
        order[&BB] = index++;
    return order;
}

bool forwardBranch(BranchInst &BI,
                   const DenseMap<const BasicBlock *, unsigned> &Order) {
    if (!eligibleBranchShape(BI))
        return false;
    const unsigned head = Order.lookup(BI.getParent());
    return Order.lookup(BI.getSuccessor(0)) > head &&
           Order.lookup(BI.getSuccessor(1)) > head;
}

void shuffleBranches(std::vector<BranchInst *> &Branches, ir::IRRandom &Rng) {
    for (std::size_t i = Branches.size(); i > 1; --i) {
        const std::size_t j = Rng.range(static_cast<std::uint32_t>(i));
        std::swap(Branches[i - 1], Branches[j]);
    }
}

void emitTrap(IRBuilderBase &B, const NanomiteLayout &Layout) {
    auto *asmTy = FunctionType::get(Type::getVoidTy(B.getContext()), false);
    InlineAsm *IA = InlineAsm::get(asmTy, Layout.trapAsm,
                                   Layout.trapConstraints,
                                   /*hasSideEffects=*/true);
    B.CreateCall(asmTy, IA);
}

Value *materializeBlockAddressInt(IRBuilderBase &B, Module &M, Function *F,
                                  BasicBlock *BB, std::uint64_t Addend,
                                  const Twine &Name) {
    Value *addr =
        B.CreatePtrToInt(BlockAddress::get(F, BB), intPtrTy(M), Name);
    if (Addend != 0)
        addr = B.CreateAdd(addr, constIp(M, Addend), Name + ".after.trap");
    return addr;
}

void relaxFunctionAttrs(Function &F) {
    F.removeFnAttr(Attribute::NoSync);
    F.removeFnAttr(Attribute::WillReturn);
    F.removeFnAttr(Attribute::Speculatable);
}

bool lowerBranch(BranchInst &BI, Site &S, GlobalVariable *Decision,
                 GlobalVariable *Token, GlobalVariable *Target,
                 const NanomiteLayout &Layout, Module &M) {
    Function &F = *BI.getFunction();
    LLVMContext &ctx = F.getContext();
    auto *ip = intPtrTy(M);
    BasicBlock *head = BI.getParent();
    BasicBlock *thenBB = BI.getSuccessor(0);
    BasicBlock *elseBB = BI.getSuccessor(1);
    Value *cond = BI.getCondition();

    auto *trapBB =
        BasicBlock::Create(ctx, "morok.nanomite.trap", &F, head->getNextNode());
    auto *resumeBB = BasicBlock::Create(ctx, "morok.nanomite.dispatch", &F,
                                        trapBB->getNextNode());

    thenBB->replacePhiUsesWith(head, resumeBB);
    elseBB->replacePhiUsesWith(head, resumeBB);

    IRBuilder<NoFolder> HB(&BI);
    Value *siteAddr = materializeBlockAddressInt(
        HB, M, &F, trapBB, Layout.trapAdvance, "morok.nanomite.site.addr");
    Value *fallbackAddr = materializeBlockAddressInt(
        HB, M, &F, elseBB, 0, "morok.nanomite.fallback");
    Value *wideCond = HB.CreateZExt(cond, ip, "morok.nanomite.cond");
    Value *odd =
        ConstantInt::get(ip, ptrWidthMask(M, (S.condKey << 1) | 1ULL));
    Value *mixed = HB.CreateMul(wideCond, odd, "morok.nanomite.cond.mul");
    mixed = HB.CreateXor(mixed, ConstantInt::get(ip, S.condKey),
                         "morok.nanomite.cond.xor");
    mixed = HB.CreateAdd(mixed, ConstantInt::get(ip, S.condSalt),
                         "morok.nanomite.cond.enc");
    HB.CreateStore(mixed, Decision)->setVolatile(true);

    Value *token = HB.CreateAdd(
        HB.CreateXor(siteAddr, ConstantInt::get(ip, S.condKey),
                     "morok.nanomite.site.xor"),
        ConstantInt::get(ip, S.condSalt), "morok.nanomite.site.token");
    HB.CreateStore(token, Token)->setVolatile(true);
    HB.CreateStore(fallbackAddr, Target)->setVolatile(true);
    HB.CreateBr(trapBB);
    BI.eraseFromParent();

    IRBuilder<NoFolder> TB(trapBB);
    emitTrap(TB, Layout);
    TB.CreateBr(resumeBB);

    IRBuilder<> RB(resumeBB);
    auto *target = RB.CreateLoad(ip, Target, "morok.nanomite.target.v");
    target->setVolatile(true);
    auto *fallback = RB.CreateIndirectBr(RB.CreateIntToPtr(target,
                                                           PointerType::getUnqual(
                                                               ctx)),
                                         2);
    fallback->addDestination(thenBB);
    fallback->addDestination(elseBB);

    S.function = &F;
    S.trap = trapBB;
    S.resume = resumeBB;
    S.trueTarget = thenBB;
    S.falseTarget = elseBB;
    relaxFunctionAttrs(F);
    return true;
}

StructType *entryType(Module &M) {
    auto *ip = intPtrTy(M);
    return StructType::get(M.getContext(), {ip, ip, ip, ip, ip, ip});
}

GlobalVariable *makeTable(Module &M, std::size_t Sites) {
    StructType *entryTy = entryType(M);
    auto *arrTy = ArrayType::get(entryTy, Sites);
    auto *gv = new GlobalVariable(M, arrTy, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage,
                                  ConstantAggregateZero::get(arrTy),
                                  "morok.nanomite.table");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    gv->setAlignment(Align(8));
    return gv;
}

Value *entryField(IRBuilder<> &B, Module &M, GlobalVariable *Table,
                  unsigned Index, unsigned Field, const Twine &Name) {
    auto *arrTy = cast<ArrayType>(Table->getValueType());
    Value *ptr = B.CreateInBoundsGEP(
        arrTy, Table,
        {ConstantInt::get(Type::getInt32Ty(M.getContext()), 0),
         ConstantInt::get(Type::getInt32Ty(M.getContext()), Index),
         ConstantInt::get(Type::getInt32Ty(M.getContext()), Field)},
        Name + ".ptr");
    auto *LI = B.CreateLoad(intPtrTy(M), ptr, Name);
    LI->setVolatile(true);
    return LI;
}

void storeEntryField(IRBuilderBase &B, Module &M, GlobalVariable *Table,
                     unsigned Index, unsigned Field, Value *Stored,
                     const Twine &Name) {
    auto *arrTy = cast<ArrayType>(Table->getValueType());
    Value *ptr = B.CreateInBoundsGEP(
        arrTy, Table,
        {ConstantInt::get(Type::getInt32Ty(M.getContext()), 0),
         ConstantInt::get(Type::getInt32Ty(M.getContext()), Index),
         ConstantInt::get(Type::getInt32Ty(M.getContext()), Field)},
        Name + ".ptr");
    auto *st = B.CreateStore(Stored, ptr);
    st->setVolatile(true);
}

void initializeTable(IRBuilderBase &B, Module &M, GlobalVariable *Table,
                     ArrayRef<Site> Sites, const NanomiteLayout &Layout) {
    auto *ip = intPtrTy(M);
    for (unsigned i = 0; i < Sites.size(); ++i) {
        const Site &S = Sites[i];
        Value *site = materializeBlockAddressInt(
            B, M, S.function, S.trap, Layout.trapAdvance,
            "morok.nanomite.init.site");
        Value *resume = materializeBlockAddressInt(
            B, M, S.function, S.resume, 0, "morok.nanomite.init.resume");
        Value *trueTarget = materializeBlockAddressInt(
            B, M, S.function, S.trueTarget, 0, "morok.nanomite.init.true");
        Value *falseTarget = materializeBlockAddressInt(
            B, M, S.function, S.falseTarget, 0, "morok.nanomite.init.false");
        storeEntryField(B, M, Table, i, 0,
                        B.CreateXor(site, ConstantInt::get(ip, S.siteMask),
                                    "morok.nanomite.init.site.enc"),
                        "morok.nanomite.init.site.store");
        storeEntryField(B, M, Table, i, 1,
                        B.CreateXor(resume,
                                    ConstantInt::get(ip, S.resumeMask),
                                    "morok.nanomite.init.resume.enc"),
                        "morok.nanomite.init.resume.store");
        storeEntryField(B, M, Table, i, 2,
                        B.CreateXor(trueTarget,
                                    ConstantInt::get(ip, S.trueMask),
                                    "morok.nanomite.init.true.enc"),
                        "morok.nanomite.init.true.store");
        storeEntryField(B, M, Table, i, 3,
                        B.CreateXor(falseTarget,
                                    ConstantInt::get(ip, S.falseMask),
                                    "morok.nanomite.init.false.enc"),
                        "morok.nanomite.init.false.store");
        storeEntryField(B, M, Table, i, 4,
                        ConstantInt::get(
                            ip, ptrWidthMask(M, S.condKey ^ S.condKeyMask)),
                        "morok.nanomite.init.key.store");
        storeEntryField(B, M, Table, i, 5,
                        ConstantInt::get(
                            ip, ptrWidthMask(M,
                                             S.condSalt ^ S.condSaltMask)),
                        "morok.nanomite.init.salt.store");
    }
}

void storeDecodedPc(IRBuilder<> &B, Value *PcSlot, Value *Target) {
    auto *st = B.CreateStore(Target, PcSlot);
    st->setVolatile(true);
    st->setAlignment(Align(1));
}

Function *makeHandler(Module &M, GlobalVariable *Table,
                      GlobalVariable *Decision, GlobalVariable *Token,
                      GlobalVariable *Target, ArrayRef<Site> Sites,
                      const NanomiteLayout &Layout) {
    if (Function *existing = M.getFunction("morok.nanomite.handler"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(
        FunctionType::get(Type::getVoidTy(ctx), {i32, ptr, ptr}, false),
        GlobalValue::PrivateLinkage, "morok.nanomite.handler", &M);
    fn->setDSOLocal(true);
    fn->addFnAttr(Attribute::NoInline);
    fn->getArg(0)->setName("sig");
    fn->getArg(1)->setName("info");
    fn->getArg(2)->setName("uctx");

    auto *entryBB = BasicBlock::Create(ctx, "entry", fn);
    auto *loadPcBB = BasicBlock::Create(ctx, "pc.load", fn);
    auto *loadDarwinPcBB = BasicBlock::Create(ctx, "pc.darwin", fn);
    auto *scanStartBB = BasicBlock::Create(ctx, "scan", fn);
    auto *doneBB = BasicBlock::Create(ctx, "done", fn);

    IRBuilder<> B(entryBB);
    auto *pcSlot = B.CreateAlloca(ip, nullptr, "morok.nanomite.pc");
    auto *pcSlotPtr =
        B.CreateAlloca(ptr, nullptr, "morok.nanomite.pc.slot");
    B.CreateStore(ConstantInt::get(ip, 0), pcSlot)->setVolatile(true);
    B.CreateStore(ConstantPointerNull::get(ptr), pcSlotPtr)->setVolatile(true);
    B.CreateCondBr(B.CreateICmpNE(fn->getArg(2),
                                  ConstantPointerNull::get(ptr)),
                   loadPcBB, doneBB);

    IRBuilder<> PB(loadPcBB);
    if (Layout.darwinMcontext) {
        Value *mctx = loadAt(PB, M, ptr, fn->getArg(2),
                             Layout.darwinMcontextOffset,
                             "morok.nanomite.mcontext");
        PB.CreateCondBr(PB.CreateICmpNE(mctx, ConstantPointerNull::get(ptr)),
                        loadDarwinPcBB, doneBB);

        IRBuilder<> DB(loadDarwinPcBB);
        Value *slot =
            gepI8(DB, M, mctx, constIp(M, Layout.darwinPcOffset),
                  "morok.nanomite.pc.slot.darwin");
        Value *pc = loadUnaligned(DB, ip, slot, "morok.nanomite.pc.darwin");
        DB.CreateStore(pc, pcSlot)->setVolatile(true);
        DB.CreateStore(slot, pcSlotPtr)->setVolatile(true);
        DB.CreateBr(scanStartBB);
    } else {
        Value *slot =
            gepI8(PB, M, fn->getArg(2), constIp(M, Layout.linuxPcSlotOffset),
                  "morok.nanomite.pc.slot.linux");
        Value *pc = loadUnaligned(PB, ip, slot, "morok.nanomite.pc.linux");
        PB.CreateStore(pc, pcSlot)->setVolatile(true);
        PB.CreateStore(slot, pcSlotPtr)->setVolatile(true);
        PB.CreateBr(scanStartBB);

        IRBuilder<> DB(loadDarwinPcBB);
        DB.CreateUnreachable();
    }

    BasicBlock *nextBB = scanStartBB;
    for (unsigned i = 0; i < Sites.size(); ++i) {
        const Site &S = Sites[i];
        BasicBlock *checkBB = nextBB;
        BasicBlock *hitBB =
            BasicBlock::Create(ctx, "morok.nanomite.hit", fn, doneBB);
        nextBB = BasicBlock::Create(ctx, "morok.nanomite.next", fn, doneBB);

        IRBuilder<> CB(checkBB);
        Value *pc = CB.CreateLoad(ip, pcSlot, "morok.nanomite.pc.v");
        cast<LoadInst>(pc)->setVolatile(true);
        Value *siteEnc =
            entryField(CB, M, Table, i, 0, "morok.nanomite.site.enc");
        Value *site = CB.CreateXor(siteEnc, ConstantInt::get(ip, S.siteMask),
                                   "morok.nanomite.site");
        CB.CreateCondBr(CB.CreateICmpEQ(pc, site, "morok.nanomite.match"),
                        hitBB, nextBB);

        IRBuilder<> HB(hitBB);
        Value *resumeEnc =
            entryField(HB, M, Table, i, 1, "morok.nanomite.resume.enc");
        Value *trueEnc =
            entryField(HB, M, Table, i, 2, "morok.nanomite.true.enc");
        Value *falseEnc =
            entryField(HB, M, Table, i, 3, "morok.nanomite.false.enc");
        Value *keyEnc =
            entryField(HB, M, Table, i, 4, "morok.nanomite.key.enc");
        Value *saltEnc =
            entryField(HB, M, Table, i, 5, "morok.nanomite.salt.enc");
        Value *condKey =
            HB.CreateXor(keyEnc, ConstantInt::get(ip, S.condKeyMask),
                         "morok.nanomite.key");
        Value *condSalt =
            HB.CreateXor(saltEnc, ConstantInt::get(ip, S.condSaltMask),
                         "morok.nanomite.salt");
        Value *decision =
            HB.CreateLoad(ip, Decision, "morok.nanomite.decision.v");
        cast<LoadInst>(decision)->setVolatile(true);
        Value *token = HB.CreateLoad(ip, Token, "morok.nanomite.token.v");
        cast<LoadInst>(token)->setVolatile(true);
        Value *expectToken = HB.CreateAdd(HB.CreateXor(pc, condKey),
                                          condSalt,
                                          "morok.nanomite.token.expected");
        Value *tokenOk =
            HB.CreateICmpEQ(token, expectToken, "morok.nanomite.token.ok");
        Value *bit = HB.CreateAnd(HB.CreateXor(HB.CreateSub(decision, condSalt),
                                               condKey),
                                  ConstantInt::get(ip, 1),
                                  "morok.nanomite.bit");
        Value *takeTrue = HB.CreateAnd(
            HB.CreateICmpEQ(bit, ConstantInt::get(ip, 1),
                            "morok.nanomite.true.bit"),
            tokenOk, "morok.nanomite.take.true");
        Value *trueTarget =
            HB.CreateXor(trueEnc, ConstantInt::get(ip, S.trueMask),
                         "morok.nanomite.true");
        Value *falseTarget =
            HB.CreateXor(falseEnc, ConstantInt::get(ip, S.falseMask),
                         "morok.nanomite.false");
        Value *target = HB.CreateSelect(takeTrue, trueTarget, falseTarget,
                                        "morok.nanomite.target");
        HB.CreateStore(target, Target)->setVolatile(true);
        Value *resume =
            HB.CreateXor(resumeEnc, ConstantInt::get(ip, S.resumeMask),
                         "morok.nanomite.resume");
        Value *slotPtr = HB.CreateLoad(ptr, pcSlotPtr,
                                       "morok.nanomite.pc.slot.v");
        cast<LoadInst>(slotPtr)->setVolatile(true);
        storeDecodedPc(HB, slotPtr, resume);
        HB.CreateBr(doneBB);
    }

    IRBuilder<> NB(nextBB);
    NB.CreateBr(doneBB);

    IRBuilder<> DB(doneBB);
    DB.CreateRetVoid();
    return fn;
}

Function *makeCtor(Module &M, Function *Handler, GlobalVariable *Table,
                   ArrayRef<Site> Sites,
                   const NanomiteLayout &Layout) {
    if (Function *existing = M.getFunction("morok.nanomite.install"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(Type::getVoidTy(ctx), false),
                                GlobalValue::InternalLinkage,
                                "morok.nanomite.install", &M);
    fn->setDSOLocal(true);
    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    IRBuilder<NoFolder> B(entry);
    initializeTable(B, M, Table, Sites, Layout);
    auto *actionTy = ArrayType::get(i8, Layout.sigactionSize);
    AllocaInst *action =
        B.CreateAlloca(actionTy, nullptr, "morok.nanomite.sa");
    storeSiginfoAction(B, M, action, Handler, Layout);
    B.CreateCall(sigactionDecl(M),
                 {ConstantInt::get(i32, 5), action,
                  ConstantPointerNull::get(ptr)},
                 "morok.nanomite.sigaction");
    B.CreateRetVoid();
    appendToGlobalCtors(M, fn, 0);
    return fn;
}

} // namespace

bool nanomitesModule(Module &M, const NanomiteParams &Params,
                     ir::IRRandom &Rng) {
    if (Params.probability == 0 || Params.max_sites == 0)
        return false;

    NanomiteLayout layout;
    const Triple tt(M.getTargetTriple());
    if (intPtrTy(M)->getBitWidth() != 64 || !nanomiteLayout(tt, layout))
        return false;

    std::vector<BranchInst *> candidates;
    for (Function &F : M) {
        if (!eligibleFunction(F))
            continue;
        SmallPtrSet<BasicBlock *, 32> loopBlocks = naturalLoopBlocks(F);
        DenseMap<const BasicBlock *, unsigned> order = blockOrder(F);
        for (BasicBlock &BB : F) {
            if (loopBlocks.contains(&BB))
                continue;
            if (auto *BI = dyn_cast<BranchInst>(BB.getTerminator()))
                if (forwardBranch(*BI, order))
                    candidates.push_back(BI);
        }
    }
    if (candidates.empty())
        return false;

    shuffleBranches(candidates, Rng);
    GlobalVariable *decision = decisionGlobal(M);
    GlobalVariable *token = tokenGlobal(M);
    GlobalVariable *target = targetGlobal(M);
    std::vector<Site> sites;
    sites.reserve(std::min<std::size_t>(Params.max_sites, candidates.size()));
    DenseMap<Function *, std::uint32_t> sitesPerFunction;

    for (BranchInst *BI : candidates) {
        if (sites.size() >= Params.max_sites)
            break;
        Function *F = BI->getFunction();
        if (!F || sitesPerFunction.lookup(F) >= kMaxSitesPerFunction)
            continue;
        if (!BI->getParent() || !eligibleBranchShape(*BI) ||
            !Rng.chance(Params.probability))
            continue;

        Site site;
        site.siteMask = ptrWidthMask(M, Rng.next());
        site.resumeMask = ptrWidthMask(M, Rng.next());
        site.trueMask = ptrWidthMask(M, Rng.next());
        site.falseMask = ptrWidthMask(M, Rng.next());
        site.condKey = ptrWidthMask(M, Rng.next());
        site.condSalt = ptrWidthMask(M, Rng.next());
        site.condKeyMask = ptrWidthMask(M, Rng.next());
        site.condSaltMask = ptrWidthMask(M, Rng.next());
        if (lowerBranch(*BI, site, decision, token, target, layout, M)) {
            sites.push_back(site);
            ++sitesPerFunction[F];
        }
    }

    if (sites.empty())
        return false;

    GlobalVariable *table = makeTable(M, sites.size());
    Function *handler =
        makeHandler(M, table, decision, token, target, sites, layout);
    makeCtor(M, handler, table, sites, layout);
    return true;
}

PreservedAnalyses NanomitesPass::run(Module &M, ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    NanomiteParams params;
    return nanomitesModule(M, params, rng) ? PreservedAnalyses::none()
                                           : PreservedAnalyses::all();
}

} // namespace morok::passes
