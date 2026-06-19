// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/VTableIntegrity.cpp
//
// Itanium C++ ABI vptr/vtable-slot guard.  The pass harvests vtable address
// points stored into objects, records the expected virtual function pointer for
// each dispatched slot, and inserts a small verifier before recognized virtual
// calls.  A vptr swap to an unknown table trips only after the object's vptr
// storage has been observed receiving a harvested vtable address point; a
// patched known table slot always trips before the indirect call executes.

#include "morok/passes/VTableIntegrity.hpp"

#include "llvm/ADT/APInt.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/Support/AtomicOrdering.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <tuple>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr std::uint64_t kMaxAddressPoints = 256;
constexpr std::uint64_t kMaxGuardEntries = 1024;
constexpr std::uint64_t kTrackedVPtrSlots = 1024;
constexpr std::uint64_t kHashMul1 = 0xFF51AFD7ED558CCDULL;
constexpr std::uint64_t kHashMul2 = 0xC4CEB9FE1A85EC53ULL;
constexpr std::uint64_t kSlotMix = 0x9E3779B97F4A7C15ULL;

struct VTableInfo {
    GlobalVariable *global = nullptr;
    std::uint64_t address_offset = 0;
    Constant *address_point = nullptr;
    std::map<std::uint64_t, Constant *> pointer_entries;
};

struct DispatchSite {
    CallBase *call = nullptr;
    LoadInst *target_load = nullptr;
    Value *vptr_slot = nullptr;
    Value *vptr = nullptr;
    std::uint64_t slot_offset = 0;
};

struct GuardEntry {
    Constant *address_point = nullptr;
    std::uint64_t slot_offset = 0;
    Constant *expected_target = nullptr;
    std::uint64_t cookie = 0;
};

bool isVTableGlobal(const GlobalVariable &GV) {
    return GV.hasInitializer() && GV.getName().starts_with("_ZTV");
}

bool isFunctionPointerConstant(Constant *C) {
    if (!C || !C->getType()->isPointerTy())
        return false;
    Value *Stripped = C->stripPointerCasts();
    return isa<Function>(Stripped) || isa<GlobalAlias>(Stripped);
}

std::uint64_t fixedAllocSize(const DataLayout &DL, Type *Ty) {
    return DL.getTypeAllocSize(Ty).getFixedValue();
}

void collectPointerEntries(Constant *C, const DataLayout &DL,
                           std::uint64_t Base,
                           std::map<std::uint64_t, Constant *> &Out) {
    if (!C)
        return;
    Type *Ty = C->getType();
    if (Ty->isPointerTy()) {
        Out.emplace(Base, C);
        return;
    }
    if (auto *CA = dyn_cast<ConstantArray>(C)) {
        Type *ElemTy = CA->getType()->getElementType();
        const std::uint64_t Step = fixedAllocSize(DL, ElemTy);
        for (unsigned I = 0; I < CA->getNumOperands(); ++I)
            if (auto *Elem = dyn_cast<Constant>(CA->getOperand(I)))
                collectPointerEntries(Elem, DL, Base + I * Step, Out);
        return;
    }
    if (auto *CS = dyn_cast<ConstantStruct>(C)) {
        auto *STy = CS->getType();
        const StructLayout *Layout = DL.getStructLayout(STy);
        for (unsigned I = 0; I < CS->getNumOperands(); ++I)
            if (auto *Elem = dyn_cast<Constant>(CS->getOperand(I)))
                collectPointerEntries(Elem, DL,
                                      Base + Layout->getElementOffset(I), Out);
    }
}

GlobalVariable *baseGlobal(Value *V) {
    if (!V)
        return nullptr;
    return dyn_cast<GlobalVariable>(V->stripPointerCasts());
}

bool getVTableAddressPoint(Constant *C, const DataLayout &DL,
                           GlobalVariable *&GV, std::uint64_t &Offset) {
    GV = nullptr;
    Offset = 0;
    if (!C)
        return false;

    if (auto *GEP = dyn_cast<GEPOperator>(C)) {
        Value *Base = GEP->getPointerOperand();
        GV = baseGlobal(Base);
        if (!GV || !isVTableGlobal(*GV))
            return false;
        const unsigned AS = Base->getType()->getPointerAddressSpace();
        APInt RawOffset(DL.getIndexSizeInBits(AS), 0, true);
        if (!GEP->accumulateConstantOffset(DL, RawOffset))
            return false;
        if (RawOffset.isNegative())
            return false;
        Offset = RawOffset.getZExtValue();
        return true;
    }

    GV = baseGlobal(C);
    if (!GV || !isVTableGlobal(*GV))
        return false;
    Offset = 0;
    return true;
}

void collectStoredAddressPoints(
    Module &M, const DataLayout &DL,
    std::map<GlobalVariable *, std::set<std::uint64_t>> &AddressPoints,
    std::vector<StoreInst *> *VPtrStores = nullptr) {
    for (Function &F : M) {
        if (F.isDeclaration() || F.getName().starts_with("morok."))
            continue;
        for (BasicBlock &BB : F)
            for (Instruction &I : BB) {
                auto *SI = dyn_cast<StoreInst>(&I);
                if (!SI)
                    continue;
                auto *C = dyn_cast<Constant>(SI->getValueOperand());
                if (!C)
                    continue;
                GlobalVariable *GV = nullptr;
                std::uint64_t Offset = 0;
                if (getVTableAddressPoint(C, DL, GV, Offset)) {
                    AddressPoints[GV].insert(Offset);
                    if (VPtrStores)
                        VPtrStores->push_back(SI);
                }
            }
    }
}

void collectConventionalAddressPoints(
    const std::map<std::uint64_t, Constant *> &Entries, std::uint64_t PtrSize,
    std::set<std::uint64_t> &AddressPoints) {
    for (const auto &[Offset, C] : Entries) {
        if (AddressPoints.size() >= kMaxAddressPoints)
            return;
        if (Offset < 2 * PtrSize)
            continue;
        if (!isFunctionPointerConstant(C))
            continue;
        auto Prev = Entries.find(Offset - PtrSize);
        if (Prev == Entries.end() || !Entries.contains(Offset - 2 * PtrSize))
            continue;
        if (isFunctionPointerConstant(Prev->second))
            continue;
        AddressPoints.insert(Offset);
    }
}

std::vector<VTableInfo> collectVTables(Module &M, const DataLayout &DL,
                                       std::uint64_t PtrSize,
                                       std::vector<StoreInst *> *VPtrStores) {
    std::map<GlobalVariable *, std::set<std::uint64_t>> AddressPoints;
    collectStoredAddressPoints(M, DL, AddressPoints, VPtrStores);

    std::vector<VTableInfo> Out;
    for (GlobalVariable &GV : M.globals()) {
        if (!isVTableGlobal(GV))
            continue;

        std::map<std::uint64_t, Constant *> Entries;
        collectPointerEntries(GV.getInitializer(), DL, 0, Entries);
        if (Entries.empty())
            continue;

        auto &Offsets = AddressPoints[&GV];
        collectConventionalAddressPoints(Entries, PtrSize, Offsets);
        for (std::uint64_t Offset : Offsets) {
            if (Out.size() >= kMaxAddressPoints)
                return Out;
            auto It = Entries.find(Offset);
            if (It == Entries.end() || !isFunctionPointerConstant(It->second))
                continue;
            Out.push_back({&GV, Offset,
                           ConstantExpr::getInBoundsGetElementPtr(
                               Type::getInt8Ty(M.getContext()), &GV,
                               ConstantInt::get(
                                   Type::getInt64Ty(M.getContext()), Offset)),
                           Entries});
        }
    }
    return Out;
}

bool getConstantGepOffset(const DataLayout &DL, Value *Ptr, Value *&Base,
                          std::uint64_t &Offset) {
    Ptr = Ptr->stripPointerCasts();
    if (auto *GEP = dyn_cast<GEPOperator>(Ptr)) {
        Base = GEP->getPointerOperand()->stripPointerCasts();
        const unsigned AS = Base->getType()->getPointerAddressSpace();
        APInt RawOffset(DL.getIndexSizeInBits(AS), 0, true);
        if (!GEP->accumulateConstantOffset(DL, RawOffset) ||
            RawOffset.isNegative())
            return false;
        Offset = RawOffset.getZExtValue();
        return true;
    }
    Base = Ptr;
    Offset = 0;
    return true;
}

bool isLoadedVptr(Value *V) {
    V = V->stripPointerCasts();
    auto *LI = dyn_cast<LoadInst>(V);
    if (!LI || !LI->getType()->isPointerTy())
        return false;
    if (auto *GV =
            dyn_cast<GlobalValue>(LI->getPointerOperand()->stripPointerCasts()))
        if (GV->getName().starts_with("morok."))
            return false;
    return true;
}

bool extractDispatchSite(CallBase &CB, const DataLayout &DL,
                         DispatchSite &Out) {
    if (CB.getCalledFunction() || CB.isInlineAsm())
        return false;
    if (auto *CI = dyn_cast<CallInst>(&CB))
        if (CI->isMustTailCall())
            return false;

    auto *TargetLoad =
        dyn_cast<LoadInst>(CB.getCalledOperand()->stripPointerCasts());
    if (!TargetLoad || !TargetLoad->getType()->isPointerTy())
        return false;

    Value *Base = nullptr;
    std::uint64_t SlotOffset = 0;
    if (!getConstantGepOffset(DL, TargetLoad->getPointerOperand(), Base,
                              SlotOffset))
        return false;
    if (!isLoadedVptr(Base))
        return false;
    auto *VPtrLoad = dyn_cast<LoadInst>(Base->stripPointerCasts());
    if (!VPtrLoad)
        return false;

    Out = {&CB, TargetLoad, VPtrLoad->getPointerOperand(),
           Base->stripPointerCasts(), SlotOffset};
    return true;
}

Constant *targetAtSlot(const VTableInfo &Info, std::uint64_t SlotOffset) {
    const std::uint64_t Absolute = Info.address_offset + SlotOffset;
    auto It = Info.pointer_entries.find(Absolute);
    if (It == Info.pointer_entries.end() ||
        !isFunctionPointerConstant(It->second))
        return nullptr;
    return It->second;
}

Function *functionFromConstant(Constant *C) {
    if (!C)
        return nullptr;
    Value *Stripped = C->stripPointerCasts();
    if (auto *Alias = dyn_cast<GlobalAlias>(Stripped))
        Stripped = Alias->getAliaseeObject();
    return dyn_cast<Function>(Stripped);
}

bool functionTypesMatch(FunctionType *A, FunctionType *B) {
    if (!A || !B)
        return false;
    if (A->isVarArg() != B->isVarArg() ||
        A->getReturnType() != B->getReturnType() ||
        A->getNumParams() != B->getNumParams())
        return false;
    for (unsigned I = 0; I < A->getNumParams(); ++I)
        if (A->getParamType(I) != B->getParamType(I))
            return false;
    return true;
}

bool targetMatchesCall(Constant *Target, CallBase &CB) {
    Function *Expected = functionFromConstant(Target);
    return Expected &&
           functionTypesMatch(Expected->getFunctionType(), CB.getFunctionType());
}

Value *mixHash(IRBuilder<> &B, Value *VPtr, Value *Slot, Value *Target,
               Value *Cookie) {
    auto *I64 = B.getInt64Ty();
    Value *VP = B.CreatePtrToInt(VPtr, I64, "morok.vti.vptr.i");
    Value *TP = B.CreatePtrToInt(Target, I64, "morok.vti.target.i");
    Value *Rot = B.CreateOr(B.CreateShl(TP, ConstantInt::get(I64, 17)),
                            B.CreateLShr(TP, ConstantInt::get(I64, 47)),
                            "morok.vti.target.rot");
    Value *X = B.CreateXor(VP, Rot, "morok.vti.h0");
    X = B.CreateXor(X, B.CreateMul(Slot, ConstantInt::get(I64, kSlotMix)),
                    "morok.vti.h1");
    X = B.CreateXor(X, Cookie, "morok.vti.h2");
    X = B.CreateMul(B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 33))),
                    ConstantInt::get(I64, kHashMul1), "morok.vti.h3");
    X = B.CreateMul(B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 33))),
                    ConstantInt::get(I64, kHashMul2), "morok.vti.h4");
    return B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 33)),
                       "morok.vti.hash");
}

GlobalVariable *constantArray(Module &M, ArrayType *Ty,
                              ArrayRef<Constant *> Values, StringRef Name) {
    auto *GV = new GlobalVariable(M, Ty, /*isConstant=*/true,
                                  GlobalValue::PrivateLinkage,
                                  ConstantArray::get(Ty, Values), Name);
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return GV;
}

Align pointerAlign(Module &M) {
    const std::uint64_t PtrSize = M.getDataLayout().getPointerSize(0);
    return Align(PtrSize == 0 ? 8 : PtrSize);
}

GlobalVariable *trackedSlotTable(Module &M) {
    if (auto *Existing =
            M.getGlobalVariable("morok.vti.tracked.slots",
                                /*AllowInternal=*/true))
        return Existing;
    auto *PtrTy = PointerType::getUnqual(M.getContext());
    auto *TableTy = ArrayType::get(PtrTy, kTrackedVPtrSlots);
    auto *GV = new GlobalVariable(M, TableTy, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage,
                                  ConstantAggregateZero::get(TableTy),
                                  "morok.vti.tracked.slots");
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    GV->setAlignment(pointerAlign(M));
    return GV;
}

Value *trackedSlotIndex(IRBuilder<> &B, Value *SlotPtr, StringRef Prefix) {
    auto *I64 = B.getInt64Ty();
    Value *X = B.CreatePtrToInt(SlotPtr, I64, Prefix + ".ptr");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 33)),
                    Prefix + ".h0");
    X = B.CreateMul(X, ConstantInt::get(I64, kHashMul1), Prefix + ".h1");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 29)),
                    Prefix + ".h2");
    X = B.CreateMul(X, ConstantInt::get(I64, kHashMul2), Prefix + ".h3");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 32)),
                    Prefix + ".h4");
    return B.CreateAnd(X, ConstantInt::get(I64, kTrackedVPtrSlots - 1),
                       Prefix + ".idx");
}

Function *createSlotRemember(Module &M, GlobalVariable *SlotTable) {
    if (Function *Existing = M.getFunction("morok.vti.remember"))
        return Existing;

    LLVMContext &Ctx = M.getContext();
    auto *VoidTy = Type::getVoidTy(Ctx);
    auto *PtrTy = PointerType::getUnqual(Ctx);
    auto *FnTy = FunctionType::get(VoidTy, {PtrTy}, false);
    auto *Fn = Function::Create(FnTy, GlobalValue::InternalLinkage,
                                "morok.vti.remember", M);
    Fn->setDSOLocal(true);
    Fn->addFnAttr(Attribute::NoInline);
    Fn->addFnAttr(Attribute::NoUnwind);

    Value *SlotPtr = &*Fn->arg_begin();
    SlotPtr->setName("slot.addr");

    BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", Fn);
    IRBuilder<> B(EntryBB);
    auto *TableTy = cast<ArrayType>(SlotTable->getValueType());
    Value *Index = trackedSlotIndex(B, SlotPtr, "morok.vti.track");
    Value *Slot = B.CreateInBoundsGEP(
        TableTy, SlotTable, {ConstantInt::get(B.getInt64Ty(), 0), Index},
        "morok.vti.track.slot");
    auto *Store = B.CreateStore(SlotPtr, Slot);
    Store->setAtomic(AtomicOrdering::Release);
    Store->setAlignment(pointerAlign(M));
    B.CreateRetVoid();
    return Fn;
}

bool instrumentVPtrStores(ArrayRef<StoreInst *> Stores, Function *Remember) {
    bool Changed = false;
    for (StoreInst *SI : Stores) {
        if (!SI || !SI->getParent())
            continue;
        IRBuilder<> B(SI->getNextNode());
        B.CreateCall(Remember->getFunctionType(), Remember,
                     {SI->getPointerOperand()});
        Changed = true;
    }
    return Changed;
}

Function *createVerifier(Module &M, ArrayRef<GuardEntry> Entries,
                         GlobalVariable *TrackedSlots) {
    LLVMContext &Ctx = M.getContext();
    auto *VoidTy = Type::getVoidTy(Ctx);
    auto *PtrTy = PointerType::getUnqual(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *IdxTy = I64;
    auto *EntryCount = ConstantInt::get(IdxTy, Entries.size());

    SmallVector<Constant *, 16> VPtrs;
    SmallVector<Constant *, 16> Slots;
    SmallVector<Constant *, 16> Targets;
    SmallVector<Constant *, 16> Cookies;
    VPtrs.reserve(Entries.size());
    Slots.reserve(Entries.size());
    Targets.reserve(Entries.size());
    Cookies.reserve(Entries.size());
    for (const GuardEntry &Entry : Entries) {
        VPtrs.push_back(Entry.address_point);
        Slots.push_back(ConstantInt::get(I64, Entry.slot_offset));
        Targets.push_back(Entry.expected_target);
        Cookies.push_back(ConstantInt::get(I64, Entry.cookie));
    }

    auto *PtrArrTy = ArrayType::get(PtrTy, Entries.size());
    auto *I64ArrTy = ArrayType::get(I64, Entries.size());
    GlobalVariable *VPtrTable =
        constantArray(M, PtrArrTy, VPtrs, "morok.vti.vptrs");
    GlobalVariable *SlotTable =
        constantArray(M, I64ArrTy, Slots, "morok.vti.slots");
    GlobalVariable *TargetTable =
        constantArray(M, PtrArrTy, Targets, "morok.vti.targets");
    GlobalVariable *CookieTable =
        constantArray(M, I64ArrTy, Cookies, "morok.vti.cookies");

    auto *FnTy = FunctionType::get(VoidTy, {PtrTy, PtrTy, I64, PtrTy}, false);
    auto *Fn = Function::Create(FnTy, GlobalValue::InternalLinkage,
                                "morok.vti.verify", M);
    Fn->setDSOLocal(true);
    Fn->addFnAttr(Attribute::NoInline);
    Fn->addFnAttr(Attribute::NoUnwind);

    auto ArgIt = Fn->arg_begin();
    Value *LiveVPtrSlot = &*ArgIt++;
    LiveVPtrSlot->setName("vptr.slot");
    Value *LiveVPtr = &*ArgIt++;
    LiveVPtr->setName("vptr");
    Value *LiveSlot = &*ArgIt++;
    LiveSlot->setName("slot");
    Value *LiveTarget = &*ArgIt;
    LiveTarget->setName("target");

    BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", Fn);
    BasicBlock *LoopBB = BasicBlock::Create(Ctx, "loop", Fn);
    BasicBlock *CheckBB = BasicBlock::Create(Ctx, "check", Fn);
    BasicBlock *NextBB = BasicBlock::Create(Ctx, "next", Fn);
    BasicBlock *UnknownBB = BasicBlock::Create(Ctx, "unknown", Fn);
    BasicBlock *PassBB = BasicBlock::Create(Ctx, "pass", Fn);
    BasicBlock *FailBB = BasicBlock::Create(Ctx, "fail", Fn);

    IRBuilder<> B(EntryBB);
    B.CreateBr(LoopBB);

    B.SetInsertPoint(LoopBB);
    PHINode *Index = B.CreatePHI(IdxTy, 2, "morok.vti.i");
    Index->addIncoming(ConstantInt::get(IdxTy, 0), EntryBB);
    Value *VPtrSlot = B.CreateInBoundsGEP(PtrArrTy, VPtrTable,
                                          {ConstantInt::get(IdxTy, 0), Index},
                                          "morok.vti.vptr.slot");
    Value *SlotSlot = B.CreateInBoundsGEP(I64ArrTy, SlotTable,
                                          {ConstantInt::get(IdxTy, 0), Index},
                                          "morok.vti.slot.slot");
    LoadInst *ExpectedVPtr =
        B.CreateLoad(PtrTy, VPtrSlot, "morok.vti.expected.vptr");
    LoadInst *ExpectedSlot =
        B.CreateLoad(I64, SlotSlot, "morok.vti.expected.slot");
    Value *VPtrOk = B.CreateICmpEQ(LiveVPtr, ExpectedVPtr, "morok.vti.vptr.ok");
    Value *SlotOk = B.CreateICmpEQ(LiveSlot, ExpectedSlot, "morok.vti.slot.ok");
    B.CreateCondBr(B.CreateAnd(VPtrOk, SlotOk), CheckBB, NextBB);

    B.SetInsertPoint(CheckBB);
    Value *TargetSlot = B.CreateInBoundsGEP(PtrArrTy, TargetTable,
                                            {ConstantInt::get(IdxTy, 0), Index},
                                            "morok.vti.target.slot");
    Value *CookieSlot = B.CreateInBoundsGEP(I64ArrTy, CookieTable,
                                            {ConstantInt::get(IdxTy, 0), Index},
                                            "morok.vti.cookie.slot");
    LoadInst *ExpectedTarget =
        B.CreateLoad(PtrTy, TargetSlot, "morok.vti.expected.target");
    LoadInst *Cookie = B.CreateLoad(I64, CookieSlot, "morok.vti.cookie");
    Value *LiveHash = mixHash(B, LiveVPtr, LiveSlot, LiveTarget, Cookie);
    Value *ExpectedHash =
        mixHash(B, ExpectedVPtr, ExpectedSlot, ExpectedTarget, Cookie);
    B.CreateCondBr(B.CreateICmpEQ(LiveHash, ExpectedHash, "morok.vti.hash.ok"),
                   PassBB, FailBB);

    B.SetInsertPoint(NextBB);
    Value *Next =
        B.CreateAdd(Index, ConstantInt::get(IdxTy, 1), "morok.vti.next");
    Index->addIncoming(Next, NextBB);
    B.CreateCondBr(B.CreateICmpULT(Next, EntryCount), LoopBB, UnknownBB);

    B.SetInsertPoint(UnknownBB);
    auto *TrackedTy = cast<ArrayType>(TrackedSlots->getValueType());
    Value *TrackedIndex =
        trackedSlotIndex(B, LiveVPtrSlot, "morok.vti.unknown");
    Value *TrackedSlotPtr = B.CreateInBoundsGEP(
        TrackedTy, TrackedSlots,
        {ConstantInt::get(IdxTy, 0), TrackedIndex},
        "morok.vti.unknown.slot");
    auto *TrackedSlot =
        B.CreateLoad(PtrTy, TrackedSlotPtr, "morok.vti.unknown.tracked");
    TrackedSlot->setAtomic(AtomicOrdering::Acquire);
    TrackedSlot->setAlignment(pointerAlign(M));
    // Loop exhaustion is only fatal for storage locations that were actually
    // armed by a runtime store of a harvested _ZTV address point.  Unarmed
    // callback/ops tables still fall through, preserving the #48 DoS fix.
    Value *KnownVPtrSlot =
        B.CreateICmpEQ(TrackedSlot, LiveVPtrSlot, "morok.vti.unknown.armed");
    B.CreateCondBr(KnownVPtrSlot, FailBB, PassBB);

    B.SetInsertPoint(PassBB);
    B.CreateRetVoid();

    B.SetInsertPoint(FailBB);
    Function *Trap = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::trap);
    B.CreateCall(Trap);
    B.CreateUnreachable();

    return Fn;
}

void hashBytes(std::uint64_t &X, StringRef S) {
    for (char Ch : S) {
        X ^= static_cast<std::uint64_t>(static_cast<unsigned char>(Ch));
        X *= 0x100000001B3ULL;
    }
}

void hashConstantId(std::uint64_t &X, Constant *C) {
    if (!C) {
        X ^= 0x421E0D7BAA78F90BULL;
        X *= 0x100000001B3ULL;
        return;
    }
    if (auto *GV = dyn_cast<GlobalValue>(C->stripPointerCasts())) {
        hashBytes(X, GV->getName());
        return;
    }
    if (auto *CE = dyn_cast<ConstantExpr>(C)) {
        hashBytes(X, CE->getOpcodeName());
        for (const Use &Op : CE->operands())
            if (auto *Child = dyn_cast<Constant>(Op.get()))
                hashConstantId(X, Child);
        return;
    }
    X ^= static_cast<std::uint64_t>(C->getValueID());
    X *= 0x100000001B3ULL;
}

std::uint64_t entryCookie(Constant *AddressPoint, std::uint64_t SlotOffset,
                          Constant *Target) {
    std::uint64_t X = 0xCBF29CE484222325ULL;
    hashConstantId(X, AddressPoint);
    X ^= SlotOffset + kSlotMix + (X << 6) + (X >> 2);
    hashConstantId(X, Target);
    X ^= 0xA73B5D1CE4E5B9ULL;
    X ^= X >> 33;
    X *= kHashMul1;
    X ^= X >> 33;
    X *= kHashMul2;
    X ^= X >> 33;
    return X;
}

} // namespace

bool vtableIntegrityModule(Module &M) {
    const DataLayout &DL = M.getDataLayout();
    const std::uint64_t PtrSize = DL.getPointerSize(0);
    if (PtrSize == 0)
        return false;

    std::vector<StoreInst *> VPtrStores;
    std::vector<VTableInfo> VTables =
        collectVTables(M, DL, PtrSize, &VPtrStores);
    if (VTables.empty())
        return false;

    std::vector<DispatchSite> Sites;
    for (Function &F : M) {
        if (F.isDeclaration() || F.getName().starts_with("morok."))
            continue;
        for (BasicBlock &BB : F)
            for (Instruction &I : BB)
                if (auto *CB = dyn_cast<CallBase>(&I)) {
                    DispatchSite Site;
                    if (extractDispatchSite(*CB, DL, Site))
                        Sites.push_back(Site);
                }
    }
    if (Sites.empty())
        return false;

    std::vector<GuardEntry> Entries;
    std::set<std::tuple<Constant *, std::uint64_t, Constant *>> Seen;
    std::set<CallBase *> Instrumented;
    for (const DispatchSite &Site : Sites) {
        bool HasExpectedTarget = false;
        for (const VTableInfo &Info : VTables) {
            Constant *Target = targetAtSlot(Info, Site.slot_offset);
            if (!Target || !targetMatchesCall(Target, *Site.call))
                continue;
            HasExpectedTarget = true;
            auto Key =
                std::make_tuple(Info.address_point, Site.slot_offset, Target);
            if (!Seen.insert(Key).second)
                continue;
            if (Entries.size() >= kMaxGuardEntries)
                break;
            Entries.push_back(
                {Info.address_point, Site.slot_offset, Target,
                 entryCookie(Info.address_point, Site.slot_offset, Target)});
        }
        if (HasExpectedTarget)
            Instrumented.insert(Site.call);
        if (Entries.size() >= kMaxGuardEntries)
            break;
    }
    if (Entries.empty() || Instrumented.empty())
        return false;

    GlobalVariable *TrackedSlots = trackedSlotTable(M);
    Function *Verifier = createVerifier(M, Entries, TrackedSlots);
    auto *I64 = Type::getInt64Ty(M.getContext());
    bool Changed = false;
    if (!VPtrStores.empty()) {
        Function *Remember = createSlotRemember(M, TrackedSlots);
        Changed = instrumentVPtrStores(VPtrStores, Remember);
    }
    for (const DispatchSite &Site : Sites) {
        if (!Instrumented.contains(Site.call))
            continue;
        IRBuilder<> B(Site.call);
        B.CreateCall(Verifier->getFunctionType(), Verifier,
                     {Site.vptr_slot, Site.vptr,
                      ConstantInt::get(I64, Site.slot_offset),
                      Site.target_load});
        Changed = true;
    }
    return Changed;
}

PreservedAnalyses VTableIntegrityPass::run(Module &M, ModuleAnalysisManager &) {
    return vtableIntegrityModule(M) ? PreservedAnalyses::none()
                                    : PreservedAnalyses::all();
}

} // namespace morok::passes
