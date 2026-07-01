// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/Mirage.cpp — counterfeit-computation substrate.
//
// See morok/passes/Mirage.hpp for the design.  Summary: for each eligible
// verdict-like function `F`, clone `F` into N equivalent real implementations,
// synthesize M plausible-but-wrong counterfeit algorithms with the same
// signature, publish them in a private candidate table, and replace `F`'s body
// with a thin branchless hub that dispatches per invocation:
//
//   * clean runtime seal state  -> a real clone chosen from a per-hub epoch
//   * dirty runtime seal state  -> a counterfeit chosen from the seal KDF key
//
// The real clones are equivalence-by-construction (CloneFunction + the normal
// semantics-preserving Morok transforms downstream); the counterfeits are
// deliberately wrong.  All candidates carry non-`morok.*` names while they flow
// through the scheduler (so they receive transforms / VM lifting) and are
// PrivateLinkage so their `__mirage` names never reach the object symbol table.

#include "morok/passes/Mirage.hpp"

#include "morok/ir/Annotations.hpp"
#include "morok/passes/RuntimeSeal.hpp"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/IR/ValueMap.h"
#include "llvm/Support/ModRef.h"
#include "llvm/Transforms/Utils/Cloning.h"

#include <algorithm>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

using Builder = IRBuilder<NoFolder>;

// KDF domain for the Mirage seal key (arbitrary per-pass constant).
constexpr std::uint64_t kMirageDomain = 0x4d1'7a9e'c0de'71a5ULL;
// Bounded DFS budget for the recursion / call-cycle check.
constexpr std::uint64_t kCycleVisitLimit = 4096;

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

bool instructionCountAtMost(const Function &F, std::uint64_t Max) {
    std::uint64_t Count = 0;
    for (const BasicBlock &BB : F) {
        Count += BB.size();
        if (Count > Max)
            return false;
    }
    return true;
}

// Relax function-effect attributes that a rewritten/synthesized body may no
// longer satisfy.  Mirrors AdversarialFunctionMerging::relaxFunctionEffects and
// only touches promises (memory effects / speculatability), never the ABI-
// carrying return/parameter attributes, so the call boundary is preserved.
void relaxEffects(Function &F) {
    F.setMemoryEffects(MemoryEffects::unknown());
    F.removeFnAttr(Attribute::NoSync);
    F.removeFnAttr(Attribute::NoRecurse);
    F.removeFnAttr(Attribute::NoFree);
    F.removeFnAttr(Attribute::ReadNone);
    F.removeFnAttr(Attribute::ReadOnly);
    F.removeFnAttr(Attribute::WillReturn);
    F.removeFnAttr(Attribute::Speculatable);
}

void addNoInlineBarrier(Function &F) {
    F.removeFnAttr(Attribute::AlwaysInline);
    F.addFnAttr(Attribute::NoInline);
}

void stamp(Function &F, std::initializer_list<StringRef> Anns) {
    for (StringRef A : Anns)
        ir::addAnnotation(F, A);
}

GlobalVariable *newPrivateGlobal(Module &M, Type *Ty, Constant *Init,
                                 const Twine &Name, Align Alignment,
                                 bool Constant) {
    auto *GV = new GlobalVariable(M, Ty, Constant, GlobalValue::PrivateLinkage,
                                  Init, Name);
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    GV->setAlignment(Alignment);
    GV->setDSOLocal(true);
    return GV;
}

// ---------------------------------------------------------------------------
// Eligibility
// ---------------------------------------------------------------------------

bool scalarArgType(Type *T) {
    if (T->isIntegerTy())
        return true;
    if (auto *P = dyn_cast<PointerType>(T))
        return P->getAddressSpace() == 0;
    return false;
}

bool returnTypeOk(Type *T) {
    auto *I = dyn_cast<IntegerType>(T);
    return I && I->getBitWidth() >= 1 && I->getBitWidth() <= 64;
}

bool argHasAbiHazard(const Argument &A) {
    return A.hasByValAttr() || A.hasStructRetAttr() || A.hasInAllocaAttr() ||
           A.hasAttribute(Attribute::Preallocated) ||
           A.hasAttribute(Attribute::SwiftError) ||
           A.hasAttribute(Attribute::SwiftSelf) ||
           A.hasAttribute(Attribute::SwiftAsync) ||
           A.hasAttribute(Attribute::Nest);
}

// Direct, defined callees of F (declarations cannot recurse back into F).
void directDefinedCallees(const Function &F,
                          SmallVectorImpl<Function *> &Out) {
    for (const BasicBlock &BB : F)
        for (const Instruction &I : BB)
            if (const auto *CB = dyn_cast<CallBase>(&I))
                if (Function *Callee = CB->getCalledFunction())
                    if (!Callee->isDeclaration())
                        Out.push_back(Callee);
}

// True if F participates in a direct-call cycle (self- or mutual recursion).
// Bounded; a graph larger than the budget is treated conservatively as cyclic
// so Mirage simply declines to touch it.
bool inRecursiveCycle(Function &F) {
    SmallPtrSet<Function *, 32> Visited;
    SmallVector<Function *, 64> Stack;
    directDefinedCallees(F, Stack);
    while (!Stack.empty()) {
        Function *G = Stack.pop_back_val();
        if (G == &F)
            return true;
        if (!Visited.insert(G).second)
            continue;
        if (Visited.size() > kCycleVisitLimit)
            return true;
        directDefinedCallees(*G, Stack);
    }
    return false;
}

// A store is "local" only if it clearly targets an alloca in this function.
bool storesOnlyToLocalStack(const StoreInst &SI) {
    const Value *Base = SI.getPointerOperand();
    for (;;) {
        if (const auto *G = dyn_cast<GetElementPtrInst>(Base)) {
            Base = G->getPointerOperand();
            continue;
        }
        if (const auto *C = dyn_cast<CastInst>(Base)) {
            Base = C->getOperand(0);
            continue;
        }
        break;
    }
    return isa<AllocaInst>(Base);
}

// Conservative: any write to non-stack memory, volatile/atomic op, or call that
// is not a provably read-only, non-throwing helper is treated as an observable
// side effect.  Such functions are only Mirage-eligible when explicitly marked
// `mirage`, because counterfeits do not preserve side effects.
bool hasObservableSideEffects(const Function &F) {
    for (const BasicBlock &BB : F)
        for (const Instruction &I : BB) {
            if (const auto *SI = dyn_cast<StoreInst>(&I)) {
                if (SI->isVolatile() || !storesOnlyToLocalStack(*SI))
                    return true;
                continue;
            }
            if (const auto *LI = dyn_cast<LoadInst>(&I)) {
                if (LI->isVolatile())
                    return true;
                continue;
            }
            if (isa<AtomicRMWInst>(I) || isa<AtomicCmpXchgInst>(I) ||
                isa<FenceInst>(I))
                return true;
            if (const auto *CB = dyn_cast<CallBase>(&I)) {
                const Function *Callee = CB->getCalledFunction();
                if (Callee && Callee->isIntrinsic()) {
                    if (CB->mayHaveSideEffects() || CB->mayWriteToMemory())
                        return true;
                    continue;
                }
                if (!Callee || !CB->onlyReadsMemory() || !CB->doesNotThrow())
                    return true;
            }
        }
    return false;
}

bool hasUnsupportedControl(const Function &F) {
    if (F.hasPersonalityFn() || F.hasFnAttribute(Attribute::Naked) ||
        F.isPresplitCoroutine())
        return true;
    for (const BasicBlock &BB : F) {
        // An address-taken block means a `blockaddress(@F, %bb)` constant may be
        // referenced from anywhere — other functions, module-level globals (a
        // computed-goto jump table), etc.  CloneFunctionInto only remaps
        // blockaddress uses that live inside the cloned body; references sitting
        // in outside constants still point at the original F.  When the driver
        // then deletes F's body to install the hub, those dangling blockaddress
        // uses are rewritten to `inttoptr(1)` placeholders, corrupting the
        // clone's `indirectbr`.  Decline such functions (also covers indirectbr,
        // whose targets are always address-taken).
        if (BB.hasAddressTaken())
            return true;
        for (const Instruction &I : BB)
            if (isa<InvokeInst>(I) || isa<CallBrInst>(I) ||
                isa<IndirectBrInst>(I) || isa<LandingPadInst>(I) ||
                isa<CatchSwitchInst>(I) || isa<CatchPadInst>(I) ||
                isa<CleanupPadInst>(I) || isa<CatchReturnInst>(I) ||
                isa<CleanupReturnInst>(I) || isa<ResumeInst>(I))
                return true;
    }
    return false;
}

bool eligible(Function &F, const MirageParams &P) {
    if (F.isDeclaration() || F.isIntrinsic())
        return false;
    StringRef Name = F.getName();
    if (Name.starts_with("morok.") || Name.starts_with("llvm.") ||
        Name.contains("__mirage"))
        return false;
    if (F.hasAvailableExternallyLinkage())
        return false;
    if (ir::hasAnnotation(F, "nomirage"))
        return false;

    const bool Marked = ir::hasAnnotation(F, "mirage");
    const bool Sensitive = ir::hasAnnotation(F, "sensitive");
    if (P.sensitive_only && !Marked && !Sensitive)
        return false;

    if (F.isVarArg() || F.hasStructRetAttr())
        return false;
    if (!returnTypeOk(F.getReturnType()))
        return false;
    for (const Argument &A : F.args())
        if (!scalarArgType(A.getType()) || argHasAbiHazard(A))
            return false;

    if (hasUnsupportedControl(F))
        return false;
    if (inRecursiveCycle(F))
        return false;
    if (!instructionCountAtMost(F, P.max_instructions))
        return false;

    // Side-effecting functions are only safe with explicit opt-in: real clones
    // keep the side effects but counterfeits may not reproduce them.
    if (!Marked && hasObservableSideEffects(F))
        return false;

    return true;
}

// ---------------------------------------------------------------------------
// Real clone generation (equivalence by construction)
// ---------------------------------------------------------------------------

Function *cloneReal(Function &F, Module &M, unsigned Index) {
    auto *Clone = Function::Create(
        F.getFunctionType(), GlobalValue::PrivateLinkage,
        F.getName() + ".__mirage.real" + Twine(Index), &M);
    Clone->copyAttributesFrom(&F);
    Clone->setLinkage(GlobalValue::PrivateLinkage);
    Clone->setVisibility(GlobalValue::DefaultVisibility);
    Clone->setComdat(nullptr);
    Clone->setCallingConv(F.getCallingConv());
    Clone->setDSOLocal(true);

    ValueToValueMapTy VMap;
    auto Dest = Clone->arg_begin();
    for (Argument &A : F.args()) {
        Dest->setName(A.getName());
        VMap[&A] = &*Dest++;
    }
    SmallVector<ReturnInst *, 8> Returns;
    CloneFunctionInto(Clone, &F, VMap, CloneFunctionChangeType::LocalChangesOnly,
                      Returns);
    // CloneFunctionInto may copy linkage/visibility back from the source.
    Clone->setLinkage(GlobalValue::PrivateLinkage);
    Clone->setVisibility(GlobalValue::DefaultVisibility);
    Clone->setComdat(nullptr);
    addNoInlineBarrier(*Clone);
    return Clone;
}

// ---------------------------------------------------------------------------
// Counterfeit algorithm synthesis (plausible, wrong-by-design)
// ---------------------------------------------------------------------------

unsigned domainNameToIndex(StringRef Name) {
    if (Name == "license_check")
        return 0;
    if (Name == "signature_verify")
        return 1;
    if (Name == "token_validate")
        return 2;
    if (Name == "feature_flag")
        return 3;
    // Unknown domain: fold the name into one of the four templates.
    std::uint32_t H = 2166136261u;
    for (char C : Name)
        H = (H ^ static_cast<unsigned char>(C)) * 16777619u;
    return H & 3u;
}

unsigned pickDomain(const std::vector<std::string> &Domains, unsigned Index,
                    unsigned Base) {
    if (Domains.empty())
        return (Base + Index) & 3u;
    return domainNameToIndex(Domains[Index % Domains.size()]);
}

// One counterfeit "round": a per-domain non-invertible-looking fold.  All ops
// are UB-free (shifts are masked below 64, no division, overflow wraps).
Value *roundMix(Builder &B, unsigned Domain, Value *Acc, Value *T, Value *Iv,
                std::uint64_t K) {
    auto *I64 = B.getInt64Ty();
    switch (Domain & 3u) {
    case 0: { // license_check: multi-round hash/MAC fold
        Value *X = B.CreateXor(Acc, T);
        X = B.CreateMul(X, ConstantInt::get(I64, K | 1ULL));
        return B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 29)));
    }
    case 1: { // signature_verify: square-and-multiply-shaped fold
        Value *Sq = B.CreateMul(Acc, Acc);
        Value *Mul = B.CreateMul(T, B.CreateOr(Iv, ConstantInt::get(I64, 1)));
        Value *X = B.CreateXor(Sq, Mul);
        return B.CreateOr(B.CreateShl(X, ConstantInt::get(I64, 7)),
                          B.CreateLShr(X, ConstantInt::get(I64, 57)));
    }
    case 2: { // token_validate: field extraction + expiry-like recombination
        Value *Hi = B.CreateLShr(Acc, ConstantInt::get(I64, 32));
        Value *Lo = B.CreateAnd(Acc, ConstantInt::get(I64, 0xffffffffULL));
        Value *NHi = B.CreateXor(Hi, T);
        Value *NLo = B.CreateAnd(B.CreateAdd(Lo, T),
                                 ConstantInt::get(I64, 0xffffffffULL));
        return B.CreateOr(B.CreateShl(NHi, ConstantInt::get(I64, 32)), NLo);
    }
    default: { // feature_flag: permission-table / bitmask accumulation
        Value *Bit = B.CreateAnd(T, ConstantInt::get(I64, 63));
        Value *Mask = B.CreateShl(ConstantInt::get(I64, 1), Bit);
        Value *X = B.CreateXor(Acc, Mask);
        return B.CreateAdd(X, B.CreateMul(T, ConstantInt::get(I64, K | 1ULL)));
    }
    }
}

Function *emitCounterfeit(Function &F, Module &M, unsigned Index,
                          unsigned Domain, ir::IRRandom &Rng) {
    LLVMContext &Ctx = M.getContext();
    auto *I64 = Type::getInt64Ty(Ctx);
    Type *RetTy = F.getReturnType();

    auto *Fake = Function::Create(
        F.getFunctionType(), GlobalValue::PrivateLinkage,
        F.getName() + ".__mirage.fake" + Twine(Index), &M);
    Fake->copyAttributesFrom(&F);
    Fake->setLinkage(GlobalValue::PrivateLinkage);
    Fake->setVisibility(GlobalValue::DefaultVisibility);
    Fake->setComdat(nullptr);
    Fake->setCallingConv(F.getCallingConv());
    Fake->setDSOLocal(true);
    relaxEffects(*Fake);
    addNoInlineBarrier(*Fake);
    // A counterfeit deliberately returns a wrong value that may fall outside any
    // return-value range `F` declared; drop that constraint so the wrong value
    // stays a concrete plausible result rather than becoming poison.
    Fake->removeRetAttr(Attribute::Range);

    // Per-build private mixing table (no cleartext strings / imports).
    constexpr unsigned Len = 8; // power of two -> mask-index is always in range
    std::vector<Constant *> TVals;
    TVals.reserve(Len);
    for (unsigned I = 0; I < Len; ++I)
        TVals.push_back(ConstantInt::get(I64, Rng.next() | 1ULL));
    auto *ArrTy = ArrayType::get(I64, Len);
    auto *Tbl = newPrivateGlobal(
        M, ArrTy, ConstantArray::get(ArrTy, TVals),
        F.getName() + ".__mirage.fake" + Twine(Index) + ".tbl", Align(8),
        /*Constant=*/true);

    const std::uint64_t Seed = Rng.next();
    const std::uint64_t RoundK = Rng.next() | 1ULL;
    const std::uint64_t Magic = Rng.next() & 0xffffULL;
    const std::uint64_t Rounds = 8 + Rng.range(9);       // 8..16
    const std::uint64_t RetSalt = Rng.next();
    const std::uint64_t CodeRange = 7 + Rng.range(25);   // 7..31 (nonzero rem)

    auto *Entry = BasicBlock::Create(Ctx, "entry", Fake);
    auto *Header = BasicBlock::Create(Ctx, "round.header", Fake);
    auto *Body = BasicBlock::Create(Ctx, "round.body", Fake);
    auto *Latch = BasicBlock::Create(Ctx, "round.latch", Fake);
    auto *Exit = BasicBlock::Create(Ctx, "verdict", Fake);

    Builder B(Entry);
    unsigned AI = 0;
    Value *Acc = ConstantInt::get(I64, Seed);
    for (Argument &A : Fake->args()) {
        A.setName("m" + Twine(AI++));
        Value *AV = A.getType()->isPointerTy() ? B.CreatePtrToInt(&A, I64)
                                                : B.CreateZExtOrTrunc(&A, I64);
        Acc = B.CreateXor(Acc, AV);
        Acc = B.CreateAdd(Acc, ConstantInt::get(I64, RoundK));
    }
    Value *AccEntry = Acc;
    B.CreateBr(Header);

    B.SetInsertPoint(Header);
    auto *Iv = B.CreatePHI(I64, 2, "iv");
    auto *AccPhi = B.CreatePHI(I64, 2, "acc");
    Iv->addIncoming(ConstantInt::get(I64, 0), Entry);
    AccPhi->addIncoming(AccEntry, Entry);
    Value *Cont = B.CreateICmpULT(Iv, ConstantInt::get(I64, Rounds));
    B.CreateCondBr(Cont, Body, Exit);

    B.SetInsertPoint(Body);
    Value *TIdx = B.CreateAnd(Iv, ConstantInt::get(I64, Len - 1));
    Value *Slot =
        B.CreateInBoundsGEP(ArrTy, Tbl, {ConstantInt::get(I64, 0), TIdx});
    auto *T = B.CreateLoad(I64, Slot, "t");
    T->setAlignment(Align(8));
    Value *Mixed = roundMix(B, Domain, AccPhi, T, Iv, RoundK);
    B.CreateBr(Latch);

    B.SetInsertPoint(Latch);
    Value *IvNext = B.CreateAdd(Iv, ConstantInt::get(I64, 1));
    Iv->addIncoming(IvNext, Latch);
    AccPhi->addIncoming(Mixed, Latch);
    B.CreateBr(Header);

    B.SetInsertPoint(Exit);
    Value *Folded =
        B.CreateXor(AccPhi, B.CreateLShr(AccPhi, ConstantInt::get(I64, 32)));
    Folded = B.CreateXor(Folded, ConstantInt::get(I64, RetSalt));
    Value *RV;
    if (RetTy->isIntegerTy(1)) {
        // Arg-dependent verdict, biased toward denial (equal to a specific
        // per-build magic only for rare inputs) but not a trivial constant.
        Value *Lo = B.CreateAnd(Folded, ConstantInt::get(I64, 0xffffULL));
        RV = B.CreateICmpEQ(Lo, ConstantInt::get(I64, Magic));
    } else {
        // Plausible small nonzero status/error/tier code, arg-dependent.
        Value *Code = B.CreateAdd(
            ConstantInt::get(I64, 1),
            B.CreateURem(Folded, ConstantInt::get(I64, CodeRange)));
        RV = B.CreateZExtOrTrunc(Code, RetTy);
    }
    B.CreateRet(RV);
    return Fake;
}

// ---------------------------------------------------------------------------
// Candidate annotations
// ---------------------------------------------------------------------------

// Divergent per-clone profiles so a single trace of one clone does not
// generalize to the population:
//
//   * even clones (incl. real0): native-heavy scalar pressure + indirect
//     branching + one flattening-family member.
//   * odd clone 1 with VM available: VM-priority.  If the virtualizer can claim
//     it, it is lifted; if it cannot — e.g. the hub's own indirect call keeps
//     every address-taken candidate native, exactly the fallback §7.2 of the
//     plan anticipates — the SAME clone still carries a divergent native-heavy
//     profile (dispatcherless routing + phi-tangling + data-entangled
//     flattening), so it is strongly and *differently* obfuscated regardless.
//   * odd clones without VM: the divergent native-heavy profile directly.
void stampRealClone(Function &Clone, unsigned Index, bool VmAvailable,
                    ir::IRRandom &) {
    const bool Odd = (Index & 1u) != 0u;
    if (!Odd) {
        stamp(Clone, {"sensitive", "sub", "mba", "indibran", "fla", "nomirage",
                      "novm"});
        return;
    }
    if (VmAvailable) {
        // VM-priority + native fallback (no `novm`, so the VM wave may claim it;
        // if it does, the fallback annotations are moot).
        stamp(Clone, {"sensitive", "vm", "virtualization", "nomirage", "sub",
                      "mba", "dispatchless", "phitangle", "entfla"});
        return;
    }
    stamp(Clone, {"sensitive", "sub", "mba", "dispatchless", "phitangle",
                  "entfla", "nomirage", "novm"});
}

void stampCounterfeit(Function &Fake) {
    stamp(Fake, {"sensitive", "sub", "mba", "split", "bcf", "nomirage", "novm"});
}

// ---------------------------------------------------------------------------
// Hub
// ---------------------------------------------------------------------------

Value *rotl64(Builder &B, Value *V, unsigned R) {
    auto *I64 = B.getInt64Ty();
    R &= 63u;
    if (R == 0)
        return V;
    return B.CreateOr(B.CreateShl(V, ConstantInt::get(I64, R)),
                      B.CreateLShr(V, ConstantInt::get(I64, 64 - R)));
}

Value *mixLite(Builder &B, Value *V) {
    auto *I64 = B.getInt64Ty();
    Value *X = B.CreateXor(V, B.CreateLShr(V, ConstantInt::get(I64, 31)));
    return B.CreateMul(X, ConstantInt::get(I64, 0x2545F4914F6CDD1DULL));
}

// Emit the per-invocation real-clone index in [0, CloneCount).
Value *emitBaseIndex(Builder &B, Module &M, Function &F, unsigned CloneCount,
                     const MirageParams &P, ir::IRRandom &Rng) {
    auto *I64 = B.getInt64Ty();
    if (!P.per_invocation_epoch || CloneCount <= 1)
        return ConstantInt::get(I64, 0);

    auto *Epoch = newPrivateGlobal(M, I64, ConstantInt::get(I64, Rng.next()),
                                   F.getName() + ".__mirage.epoch", Align(8),
                                   /*Constant=*/false);
    auto *Cur = B.CreateLoad(I64, Epoch, "mirage.epoch");
    Cur->setVolatile(true);
    Cur->setAlignment(Align(8));
    Value *Next = B.CreateAdd(Cur, ConstantInt::get(I64, Rng.next() | 1ULL),
                              "mirage.epoch.next");
    auto *St = B.CreateStore(Next, Epoch);
    St->setVolatile(true);
    St->setAlignment(Align(8));
    Value *Salted =
        B.CreateXor(Cur, ConstantInt::get(I64, Rng.next()), "mirage.epoch.mix");
    return B.CreateURem(Salted, ConstantInt::get(I64, CloneCount),
                        "mirage.base");
}

// Zero on a clean seal state, nonzero when any consumed channel is dirty.
Value *emitDirtyKey(Builder &B, Module &M, ir::IRRandom &Rng) {
    using namespace runtime_seal;
    auto *I64 = B.getInt64Ty();

    auto delta = [&](StringLiteral Ch, const Twine &N) -> Value * {
        GlobalVariable *GV = getChannel(M, Ch, Rng);
        return emitDelta(B, GV, initialValue(GV), N);
    };
    Value *DAnti = delta(kAntiDebugChannel, "mirage.d.anti");
    Value *DEnv = delta(kEnvBindingChannel, "mirage.d.env");
    Value *DTracer = delta(kTracerChannel, "mirage.d.tracer");

    Value *AnyDirty = B.CreateICmpNE(DAnti, ConstantInt::get(I64, 0));
    AnyDirty = B.CreateOr(
        AnyDirty, B.CreateICmpNE(DEnv, ConstantInt::get(I64, 0)));
    AnyDirty = B.CreateOr(
        AnyDirty, B.CreateICmpNE(DTracer, ConstantInt::get(I64, 0)));

    Value *Mixed = B.CreateXor(DAnti, rotl64(B, DEnv, 17));
    Mixed = B.CreateXor(Mixed, mixLite(B, DTracer));
    // Guarantee the seed is nonzero whenever any channel is dirty, so a rare
    // XOR cancellation can never launder a dirty state back to "clean".
    Value *Seed = B.CreateSelect(
        AnyDirty, B.CreateOr(Mixed, ConstantInt::get(I64, 1)),
        ConstantInt::get(I64, 0), "mirage.seed");
    return emitKdf64(B, Seed, kMirageDomain, "mirage.key");
}

// Emit the branchless selection (epoch + seal delta + KDF + table load) into
// `B` and return the loaded candidate function pointer.
Value *emitSelection(Builder &B, Function &F, GlobalVariable *Table,
                     unsigned CloneCount, unsigned FakeCount,
                     const MirageParams &P, ir::IRRandom &Rng, Module &M) {
    LLVMContext &Ctx = M.getContext();
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *PtrTy = PointerType::get(Ctx, 0);
    auto *TableTy = ArrayType::get(PtrTy, CloneCount + FakeCount);

    Value *BaseIdx = emitBaseIndex(B, M, F, CloneCount, P, Rng);

    Value *Idx;
    const bool CounterfeitPath =
        FakeCount > 0 && P.force_route != MirageForceRoute::Real &&
        (P.seal_gated_reality || P.force_route == MirageForceRoute::Fake);
    if (!CounterfeitPath) {
        Idx = BaseIdx;
    } else if (P.force_route == MirageForceRoute::Fake) {
        // Diagnostic build: pin the counterfeit path, still varying which fake.
        Value *Pick = P.per_invocation_epoch
                          ? BaseIdx
                          : ConstantInt::get(I64, Rng.next());
        Idx = B.CreateAdd(ConstantInt::get(I64, CloneCount),
                          B.CreateURem(Pick, ConstantInt::get(I64, FakeCount)),
                          "mirage.idx");
    } else {
        Value *Key = emitDirtyKey(B, M, Rng);
        Value *Dirty = B.CreateICmpNE(Key, ConstantInt::get(I64, 0),
                                      "mirage.dirty");
        Value *FakeSel =
            B.CreateAdd(ConstantInt::get(I64, CloneCount),
                        B.CreateURem(Key, ConstantInt::get(I64, FakeCount)),
                        "mirage.fake");
        Idx = B.CreateSelect(Dirty, FakeSel, BaseIdx, "mirage.idx");
    }

    Value *Slot = B.CreateInBoundsGEP(TableTy, Table,
                                      {ConstantInt::get(I64, 0), Idx},
                                      "mirage.slot");
    return B.CreateLoad(PtrTy, Slot, "mirage.target");
}

void buildHub(Function &F, GlobalVariable *Table, unsigned CloneCount,
              unsigned FakeCount, const MirageParams &P, ir::IRRandom &Rng,
              Module &M) {
    LLVMContext &Ctx = M.getContext();
    auto *PtrTy = PointerType::get(Ctx, 0);

    // The seal-gated selection lives in a private `morok.*` helper.  The main
    // per-function obfuscation loop (and the guaranteed integrity waves) skip
    // every `morok.*` name, so the helper's zero-on-clean seal-delta / KDF
    // arithmetic is never rewritten by an integrity-fusion or constant-mutating
    // pass — which on an unsealed build would otherwise flip the delta nonzero
    // and misroute a clean run to a counterfeit.  The helper returns the chosen
    // candidate pointer; F stays the public ABI entry and only forwards.
    auto *SelTy = FunctionType::get(PtrTy, /*isVarArg=*/false);
    auto *Sel = Function::Create(SelTy, GlobalValue::PrivateLinkage,
                                 "morok.mirage.sel." + F.getName(), &M);
    Sel->setDSOLocal(true);
    Sel->setUnnamedAddr(GlobalValue::UnnamedAddr::None);
    addNoInlineBarrier(*Sel);
    Sel->setMemoryEffects(MemoryEffects::unknown());
    {
        auto *SelEntry = BasicBlock::Create(Ctx, "entry", Sel);
        Builder SB(SelEntry);
        Value *Target =
            emitSelection(SB, F, Table, CloneCount, FakeCount, P, Rng, M);
        SB.CreateRet(Target);
    }

    auto *Entry = BasicBlock::Create(Ctx, "entry", &F);
    Builder B(Entry);
    Value *Target = B.CreateCall(SelTy, Sel, {}, "mirage.target");

    SmallVector<Value *, 8> Args;
    for (Argument &A : F.args())
        Args.push_back(&A);
    auto *Call = B.CreateCall(F.getFunctionType(), Target, Args,
                              F.getReturnType()->isVoidTy() ? "" : "mirage.r");
    Call->setCallingConv(F.getCallingConv());
    if (F.doesNotThrow())
        Call->setDoesNotThrow();
    if (F.getReturnType()->isVoidTy())
        B.CreateRetVoid();
    else
        B.CreateRet(Call);
}

} // namespace

// ---------------------------------------------------------------------------
// Module driver
// ---------------------------------------------------------------------------

bool mirageModule(Module &M, const MirageParams &Params, ir::IRRandom &Rng) {
    const unsigned CloneCount = std::max(1u, Params.clone_count);
    const unsigned FakeCount = Params.counterfeit_count;
    const unsigned MaxFunctions = Params.max_functions;

    // Snapshot eligible targets before mutating the module (clone/fake/hub
    // creation adds functions we must not re-process).
    std::vector<Function *> Targets;
    for (Function &F : M) {
        if (Targets.size() >= MaxFunctions)
            break;
        if (eligible(F, Params))
            Targets.push_back(&F);
    }

    const unsigned DomainBase = static_cast<unsigned>(Rng.next());
    bool Changed = false;

    for (Function *FP : Targets) {
        Function &F = *FP;

        // Build the real clones from the original body first.
        std::vector<Function *> Reals;
        Reals.reserve(CloneCount);
        for (unsigned I = 0; I < CloneCount; ++I)
            Reals.push_back(cloneReal(F, M, I));

        std::vector<Function *> Fakes;
        Fakes.reserve(FakeCount);
        for (unsigned I = 0; I < FakeCount; ++I)
            Fakes.push_back(emitCounterfeit(
                F, M, I, pickDomain(Params.counterfeit_domains, I, DomainBase),
                Rng));

        // Divergent per-candidate profiles.
        for (unsigned I = 0; I < Reals.size(); ++I)
            stampRealClone(*Reals[I], I, Params.vm_profile_available, Rng);
        for (Function *Fake : Fakes)
            stampCounterfeit(*Fake);

        // Candidate table: [real0..realN-1, fake0..fakeM-1].
        auto *PtrTy = PointerType::get(M.getContext(), 0);
        std::vector<Constant *> Entries;
        Entries.reserve(Reals.size() + Fakes.size());
        for (Function *R : Reals)
            Entries.push_back(R);
        for (Function *Fake : Fakes)
            Entries.push_back(Fake);
        auto *TableTy = ArrayType::get(PtrTy, Entries.size());
        auto *Table = newPrivateGlobal(M, TableTy,
                                       ConstantArray::get(TableTy, Entries),
                                       F.getName() + ".__mirage.table",
                                       Align(8), /*Constant=*/true);

        // Replace F's body with the dispatch hub.
        F.deleteBody();
        relaxEffects(F);
        // The hub forwards a counterfeit's out-of-range value on the dirty path;
        // drop any return-value range so that stays a concrete value, not poison.
        F.removeRetAttr(Attribute::Range);
        addNoInlineBarrier(F);
        // Keep the hub native (novm) and never re-mirage it (nomirage).  The
        // seal-gated selection now lives in the skipped `morok.mirage.sel.*`
        // helper, so the thin wrapper carries no seal arithmetic to corrupt;
        // still exempt it from the integrity-fusion passes as defense-in-depth
        // (a thin two-call forwarder gains nothing from them).  Ordinary
        // semantics-preserving obfuscation (bcf/mba/sub/…) still applies.
        stamp(F, {"nomirage", "novm", "nodfi", "noselfcheck", "nomutualguard"});
        buildHub(F, Table, CloneCount, FakeCount, Params, Rng, M);

        Changed = true;
    }

    return Changed;
}

PreservedAnalyses MiragePass::run(Module &M, ModuleAnalysisManager &) {
    ir::materializeAnnotations(M);
    ir::IRRandom rng(engine_);
    return mirageModule(M, params_, rng) ? PreservedAnalyses::none()
                                         : PreservedAnalyses::all();
}

} // namespace morok::passes
