// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// Buddy-process tracer material for RuntimeSeal.

#include "morok/passes/TracerAttestation.hpp"

#include "morok/passes/RuntimeSeal.hpp"
#include "morok/runtime/PlatformRuntime.hpp"

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <initializer_list>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr StringLiteral kCtorName = "morok.tracer.attest";
constexpr StringLiteral kShareName = "morok.tracer.share";
constexpr std::uint32_t kMaxShares = 4;
constexpr std::uint32_t kRepairSites = 3;
constexpr std::uint32_t kAttachRetries = 16;

enum LinuxX64Syscall : std::uint32_t {
    SysRead = 0,
    SysWrite = 1,
    SysClose = 3,
    SysGetpid = 39,
    SysFork = 57,
    SysExit = 60,
    SysWait4 = 61,
    SysPtrace = 101,
    SysGetppid = 110,
    SysPrctl = 157,
    SysSchedYield = 24,
};

enum PtraceRequest : std::uint32_t {
    PtracePeekData = 2,
    PtracePokeData = 5,
    PtraceAttach = 16,
    PtraceDetach = 17,
};

bool isForkOrSignalApiName(StringRef Name) {
    return Name == "fork" || Name == "vfork" || Name == "clone" ||
           Name == "sigaction" || Name == "signal" || Name == "sigprocmask" ||
           Name == "pthread_sigmask" || Name == "sigsuspend" ||
           Name == "sigwait" || Name == "sigwaitinfo" ||
           Name == "sigtimedwait" || Name == "sigpending" ||
           Name == "sigfillset" || Name == "sigemptyset" ||
           Name == "sigaddset" || Name == "sigdelset" || Name == "raise" ||
           Name == "kill" || Name == "alarm" || Name == "pause";
}

bool moduleUsesForkOrSignalApis(Module &M) {
    for (Function &F : M)
        if (!F.use_empty() && isForkOrSignalApiName(F.getName()))
            return true;
    return false;
}

bool supportsDirectTracer(const Triple &TT) {
    return TT.isOSLinux() && TT.getArch() == Triple::x86_64;
}

IntegerType *intPtrTy(Module &M) {
    return runtime::platformWordTy(M);
}

Value *emitLinuxSyscall(IRBuilder<> &B, Module &M, std::uint32_t Number,
                        std::initializer_list<Value *> Args,
                        const Twine &Name) {
    return runtime::emitLinuxSyscall(B, M, Triple(M.getTargetTriple()), Number,
                                     Args, Name);
}

Value *emitPtrace(IRBuilder<> &B, Module &M, std::uint32_t Request, Value *Pid,
                  Value *Addr, Value *Data, const Twine &Name) {
    auto *IP = intPtrTy(M);
    return emitLinuxSyscall(B, M, SysPtrace,
                            {ConstantInt::get(IP, Request), Pid, Addr, Data},
                            Name);
}

Value *mix64(IRBuilderBase &B, Value *X, std::uint64_t Salt,
             const Twine &Name) {
    auto *I64 = B.getInt64Ty();
    X = B.CreateAdd(X, ConstantInt::get(I64, Salt), Name + ".add");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 23)),
                    Name + ".fold23");
    X = B.CreateMul(X, ConstantInt::get(I64, 0xD6E8FEB86659FD93ULL),
                    Name + ".mul0");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 41)),
                    Name + ".fold41");
    X = B.CreateMul(X, ConstantInt::get(I64, 0xA24BAED4963EE407ULL),
                    Name + ".mul1");
    return B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 31)),
                       Name + ".fold31");
}

void addHelperAttrs(Function &F, bool VirtualizeHelpers) {
    F.addFnAttr(Attribute::NoUnwind);
    F.addFnAttr(Attribute::NoInline);
    if (!VirtualizeHelpers)
        F.addFnAttr("morok.tracer.no_vm");
}

Function *makeCtorShell(Module &M) {
    auto *Fn = Function::Create(
        FunctionType::get(Type::getVoidTy(M.getContext()), false),
        GlobalValue::InternalLinkage, kCtorName, &M);
    Fn->setDSOLocal(true);
    Fn->addFnAttr(Attribute::NoUnwind);
    BasicBlock::Create(M.getContext(), "entry", Fn);
    return Fn;
}

Function *getShareHelper(Module &M, ir::IRRandom &Rng, bool VirtualizeHelpers) {
    if (Function *Existing = M.getFunction(kShareName))
        return Existing;

    LLVMContext &Ctx = M.getContext();
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *Ty = FunctionType::get(I64, {I64, I64, I64, I64}, false);
    Function *Fn =
        Function::Create(Ty, GlobalValue::PrivateLinkage, kShareName, &M);
    Fn->setDSOLocal(true);
    addHelperAttrs(*Fn, VirtualizeHelpers);

    auto It = Fn->arg_begin();
    Value *Parent = &*It++;
    Parent->setName("parent");
    Value *Self = &*It++;
    Self->setName("self");
    Value *Slot = &*It++;
    Slot->setName("slot");
    Value *Index = &*It++;
    Index->setName("index");

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    IRBuilder<> B(Entry);
    Value *X = B.CreateXor(Parent, B.CreateShl(Self, ConstantInt::get(I64, 9)),
                           "morok.tracer.share.pid");
    X = B.CreateXor(X,
                    B.CreateOr(B.CreateShl(Slot, ConstantInt::get(I64, 17)),
                               B.CreateLShr(Slot, ConstantInt::get(I64, 47)),
                               "morok.tracer.share.slot.rot"),
                    "morok.tracer.share.slot");
    X = B.CreateXor(X,
                    B.CreateMul(Index, ConstantInt::get(I64, Rng.next() | 1)),
                    "morok.tracer.share.idx");
    X = mix64(B, X, Rng.next(), "morok.tracer.share.mix0");
    X = B.CreateAdd(X, ConstantInt::get(I64, Rng.next() | 1),
                    "morok.tracer.share.bias");
    X = mix64(B, X, Rng.next(), "morok.tracer.share.mix1");
    B.CreateRet(
        B.CreateOr(X, ConstantInt::get(I64, 1), "morok.tracer.share.nonzero"));
    return Fn;
}

void restorePtracer(IRBuilder<> &B, Module &M, GlobalVariable *AntiBuddyPid) {
    auto *IP = intPtrTy(M);
    Value *Restore = ConstantInt::get(IP, 0);
    if (AntiBuddyPid) {
        auto *Loaded = B.CreateLoad(AntiBuddyPid->getValueType(), AntiBuddyPid,
                                    "morok.tracer.restore.buddy");
        Loaded->setVolatile(true);
        Value *Wide = B.CreateSExtOrTrunc(Loaded, IP);
        Value *Valid = B.CreateICmpSGT(Wide, ConstantInt::get(IP, 1),
                                       "morok.tracer.restore.valid");
        Restore = B.CreateSelect(Valid, Wide, ConstantInt::get(IP, 0),
                                 "morok.tracer.restore.pid");
    }
    emitLinuxSyscall(B, M, SysPrctl,
                     {ConstantInt::get(IP, 0x59616D61), Restore,
                      ConstantInt::get(IP, 0), ConstantInt::get(IP, 0),
                      ConstantInt::get(IP, 0)},
                     "morok.tracer.restore.ptracer");
}

void emitChildExit(IRBuilder<> &B, Module &M) {
    auto *IP = intPtrTy(M);
    emitLinuxSyscall(B, M, SysExit, {ConstantInt::get(IP, 0)},
                     "morok.tracer.child.exit");
    B.CreateUnreachable();
}

void emitShareRound(Module &M, Function &Ctor, IRBuilder<> &B,
                    Function *ShareHelper, GlobalVariable *AntiBuddyPid,
                    bool BindToRuntimeSeal, bool EnableRepair,
                    std::uint32_t Index, std::uint64_t FoldSalt) {
    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *IP = intPtrTy(M);
    auto *Ptr = PointerType::getUnqual(Ctx);

    AllocaInst *Slot = B.CreateAlloca(I64, nullptr, "morok.tracer.slot");
    AllocaInst *ParentStatus =
        B.CreateAlloca(I32, nullptr, "morok.tracer.parent.status");
    Value *FallbackSeed =
        B.CreatePtrToInt(Slot, I64, "morok.tracer.fail.slot");
    FallbackSeed =
        B.CreateXor(FallbackSeed,
                    ConstantInt::get(I64, FoldSalt ^ (Index + 1)),
                    "morok.tracer.fail.seed");
    Value *Fallback = mix64(B, FallbackSeed, 0xF1357AEA2E62A9C5ULL,
                            "morok.tracer.fail.mix");
    Fallback = B.CreateOr(Fallback, ConstantInt::get(I64, 1),
                          "morok.tracer.fail.nonzero");
    auto *FallbackStore = B.CreateStore(Fallback, Slot);
    FallbackStore->setVolatile(true);
    FallbackStore->setAlignment(Align(8));
    std::array<AllocaInst *, kRepairSites> RepairSlots{};
    if (EnableRepair) {
        for (std::uint32_t I = 0; I < kRepairSites; ++I) {
            AllocaInst *Repair =
                B.CreateAlloca(I64, nullptr, "morok.tracer.repair.slot");
            RepairSlots[I] = Repair;
            Value *RepairSeed =
                B.CreatePtrToInt(Repair, I64, "morok.tracer.repair.fail.slot");
            RepairSeed = B.CreateXor(
                RepairSeed,
                ConstantInt::get(I64, FoldSalt ^ (0xA7u + I * 0x31u)),
                "morok.tracer.repair.fail.seed");
            Value *RepairFallback =
                mix64(B, RepairSeed,
                      0xC6BC279692B5CC83ULL ^ (I * 0x9E3779B97F4A7C15ULL),
                      "morok.tracer.repair.fail.mix");
            RepairFallback = B.CreateOr(
                RepairFallback, ConstantInt::get(I64, 1),
                "morok.tracer.repair.fail.nonzero");
            auto *RepairStore = B.CreateStore(RepairFallback, Repair);
            RepairStore->setVolatile(true);
            RepairStore->setAlignment(Align(8));
        }
    }

    Value *Pid = emitLinuxSyscall(B, M, SysFork, {}, "morok.tracer.fork");
    BasicBlock *ChildBB = BasicBlock::Create(Ctx, "morok.tracer.child", &Ctor);
    BasicBlock *ParentBB =
        BasicBlock::Create(Ctx, "morok.tracer.parent", &Ctor);
    BasicBlock *PtracerBB =
        BasicBlock::Create(Ctx, "morok.tracer.ptracer", &Ctor);
    BasicBlock *FoldBB = BasicBlock::Create(Ctx, "morok.tracer.fold", &Ctor);
    BasicBlock *ContBB = BasicBlock::Create(Ctx, "morok.tracer.cont", &Ctor);
    B.CreateCondBr(
        B.CreateICmpEQ(Pid, ConstantInt::get(IP, 0), "morok.tracer.is_child"),
        ChildBB, ParentBB);

    IRBuilder<> ChildB(ChildBB);
    Value *Parent =
        emitLinuxSyscall(ChildB, M, SysGetppid, {}, "morok.tracer.child.ppid");
    Value *Self =
        emitLinuxSyscall(ChildB, M, SysGetpid, {}, "morok.tracer.child.pid");
    Value *SlotAddr =
        ChildB.CreatePtrToInt(Slot, I64, "morok.tracer.child.slot");
    Value *Share =
        ChildB.CreateCall(ShareHelper->getFunctionType(), ShareHelper,
                          {ChildB.CreateZExtOrTrunc(Parent, I64),
                           ChildB.CreateZExtOrTrunc(Self, I64), SlotAddr,
                           ConstantInt::get(I64, Index)},
                          "morok.tracer.child.share");
    std::array<Value *, kRepairSites> ChildRepairAddrs{};
    std::array<Value *, kRepairSites> ChildRepairWords{};
    if (EnableRepair) {
        for (std::uint32_t I = 0; I < kRepairSites; ++I) {
            ChildRepairAddrs[I] =
                ChildB.CreatePtrToInt(RepairSlots[I], I64,
                                      "morok.tracer.repair.child.slot");
            ChildRepairWords[I] = ChildB.CreateCall(
                ShareHelper->getFunctionType(), ShareHelper,
                {ChildB.CreateZExtOrTrunc(Parent, I64),
                 ChildB.CreateZExtOrTrunc(Self, I64), ChildRepairAddrs[I],
                 ConstantInt::get(I64, Index * 17u + I + 0x51u)},
                "morok.tracer.repair.child.word");
        }
    }
    BasicBlock *AttachBB =
        BasicBlock::Create(Ctx, "morok.tracer.attach", &Ctor);
    BasicBlock *AttachedBB =
        BasicBlock::Create(Ctx, "morok.tracer.attached", &Ctor);
    BasicBlock *RetryBB = BasicBlock::Create(Ctx, "morok.tracer.retry", &Ctor);
    BasicBlock *ChildExitBB =
        BasicBlock::Create(Ctx, "morok.tracer.child.done", &Ctor);
    ChildB.CreateBr(AttachBB);

    IRBuilder<> AttachB(AttachBB);
    PHINode *Attempt = AttachB.CreatePHI(IP, 2, "morok.tracer.retry.count");
    Attempt->addIncoming(ConstantInt::get(IP, 0), ChildBB);
    Value *AttachRc =
        emitPtrace(AttachB, M, PtraceAttach, Parent, ConstantInt::get(IP, 0),
                   ConstantInt::get(IP, 0), "morok.tracer.attach.rc");
    AttachB.CreateCondBr(AttachB.CreateICmpEQ(AttachRc, ConstantInt::get(IP, 0),
                                              "morok.tracer.attach.ok"),
                         AttachedBB, RetryBB);

    IRBuilder<> RetryB(RetryBB);
    emitLinuxSyscall(RetryB, M, SysSchedYield, {}, "morok.tracer.retry.yield");
    Value *NextAttempt = RetryB.CreateAdd(Attempt, ConstantInt::get(IP, 1),
                                          "morok.tracer.retry.next");
    RetryB.CreateCondBr(
        RetryB.CreateICmpULT(NextAttempt, ConstantInt::get(IP, kAttachRetries),
                             "morok.tracer.retry.keep"),
        AttachBB, ChildExitBB);
    Attempt->addIncoming(NextAttempt, RetryBB);

    IRBuilder<> AttachedB(AttachedBB);
    AllocaInst *ChildStatus =
        AttachedB.CreateAlloca(I32, nullptr, "morok.tracer.child.status");
    Value *WaitParent =
        emitLinuxSyscall(AttachedB, M, SysWait4,
                         {Parent, ChildStatus, ConstantInt::get(IP, 0),
                          ConstantPointerNull::get(Ptr)},
                         "morok.tracer.child.wait");
    Value *WaitOk = AttachedB.CreateICmpEQ(WaitParent, Parent,
                                           "morok.tracer.child.wait.ok");
    Value *BadShare = mix64(AttachedB, Share,
                            FoldSalt ^ 0xB6A6F89D4D3C7E21ULL,
                            "morok.tracer.child.fail");
    BadShare = AttachedB.CreateOr(BadShare, ConstantInt::get(I64, 1),
                                  "morok.tracer.child.fail.nonzero");
    Value *Word =
        AttachedB.CreateSelect(WaitOk, Share, BadShare,
                               "morok.tracer.child.word");
    Value *WordIP = AttachedB.CreateZExtOrTrunc(Word, IP);
    emitPtrace(AttachedB, M, PtracePokeData, Parent, SlotAddr, WordIP,
               "morok.tracer.poke");
    if (EnableRepair) {
        for (std::uint32_t I = 0; I < kRepairSites; ++I) {
            Value *RepairIP =
                AttachedB.CreateZExtOrTrunc(ChildRepairWords[I], IP);
            emitPtrace(AttachedB, M, PtracePokeData, Parent,
                       ChildRepairAddrs[I], RepairIP,
                       "morok.tracer.repair.poke");
        }
    }
    emitPtrace(AttachedB, M, PtraceDetach, Parent, ConstantInt::get(IP, 0),
               ConstantInt::get(IP, 0), "morok.tracer.detach");
    AttachedB.CreateBr(ChildExitBB);

    IRBuilder<> ChildExitB(ChildExitBB);
    emitChildExit(ChildExitB, M);

    IRBuilder<> ParentB(ParentBB);
    ParentB.CreateCondBr(ParentB.CreateICmpSGT(Pid, ConstantInt::get(IP, 0),
                                               "morok.tracer.pid.valid"),
                         PtracerBB, FoldBB);

    IRBuilder<> PtracerB(PtracerBB);
    emitLinuxSyscall(PtracerB, M, SysPrctl,
                     {ConstantInt::get(IP, 0x59616D61), Pid,
                      ConstantInt::get(IP, 0), ConstantInt::get(IP, 0),
                      ConstantInt::get(IP, 0)},
                     "morok.tracer.ptracer.rc");
    emitLinuxSyscall(PtracerB, M, SysWait4,
                     {Pid, ParentStatus, ConstantInt::get(IP, 0),
                      ConstantPointerNull::get(Ptr)},
                     "morok.tracer.parent.wait");
    restorePtracer(PtracerB, M, AntiBuddyPid);
    PtracerB.CreateBr(FoldBB);

    IRBuilder<> FoldB(FoldBB);
    auto *Loaded = FoldB.CreateLoad(I64, Slot, "morok.tracer.word");
    Loaded->setVolatile(true);
    Loaded->setAlignment(Align(8));
    Value *ParentSelf =
        emitLinuxSyscall(FoldB, M, SysGetpid, {}, "morok.tracer.parent.pid");
    Value *ParentSlotAddr =
        FoldB.CreatePtrToInt(Slot, I64, "morok.tracer.parent.slot");
    Value *Expected =
        FoldB.CreateCall(ShareHelper->getFunctionType(), ShareHelper,
                         {FoldB.CreateZExtOrTrunc(ParentSelf, I64),
                          FoldB.CreateZExtOrTrunc(Pid, I64), ParentSlotAddr,
                          ConstantInt::get(I64, Index)},
                         "morok.tracer.expected");
    Value *WordDiff =
        FoldB.CreateXor(Loaded, Expected, "morok.tracer.word.diff");
    Value *Mismatch = FoldB.CreateICmpNE(
        WordDiff, ConstantInt::get(I64, 0), "morok.tracer.word.bad");
    std::array<Value *, kRepairSites> RepairDiffs{};
    if (EnableRepair) {
        for (std::uint32_t I = 0; I < kRepairSites; ++I) {
            auto *RepairLoaded =
                FoldB.CreateLoad(I64, RepairSlots[I],
                                 "morok.tracer.repair.word");
            RepairLoaded->setVolatile(true);
            RepairLoaded->setAlignment(Align(8));
            Value *RepairAddr =
                FoldB.CreatePtrToInt(RepairSlots[I], I64,
                                     "morok.tracer.repair.parent.slot");
            Value *ExpectedRepair = FoldB.CreateCall(
                ShareHelper->getFunctionType(), ShareHelper,
                {FoldB.CreateZExtOrTrunc(ParentSelf, I64),
                 FoldB.CreateZExtOrTrunc(Pid, I64), RepairAddr,
                 ConstantInt::get(I64, Index * 17u + I + 0x51u)},
                "morok.tracer.repair.expected");
            Value *RepairDiff =
                FoldB.CreateXor(RepairLoaded, ExpectedRepair,
                                "morok.tracer.repair.word.diff");
            RepairDiffs[I] = RepairDiff;
            Value *RepairBad = FoldB.CreateICmpNE(
                RepairDiff, ConstantInt::get(I64, 0),
                "morok.tracer.repair.word.bad");
            Mismatch = FoldB.CreateOr(Mismatch, RepairBad,
                                      "morok.tracer.repair.bad.any");
        }
    }
    // Zero-on-clean (#97): fold the DIFF between delivered and expected words
    // into the tracer seal, NOT raw delivered words. On a clean attach the child
    // pokes exactly the expected non-zero words, so every diff is zero and
    // foldWord leaves the tracer channel at its S0 baseline. Tamper makes any
    // per-site diff non-zero, the seal diverges, and seal-dependent code fails
    // closed. Keep repair diffs independent: a chosen repair word must not be
    // able to cancel the primary share diff before the seal observes it.
    // The bind_to_runtime_seal opt-out must also leave any pre-existing seal
    // channels alone, because another pass may have created them already.
    if (BindToRuntimeSeal) {
        runtime_seal::foldWord(FoldB, runtime_seal::kTracerChannel,
                               WordDiff, FoldSalt, "morok.tracer.seal");
        if (EnableRepair) {
            for (std::uint32_t I = 0; I < kRepairSites; ++I)
                runtime_seal::foldWord(
                    FoldB, runtime_seal::kTracerChannel, RepairDiffs[I],
                    FoldSalt ^ (0xD1B54A32D192ED03ULL +
                                I * 0x9E3779B97F4A7C15ULL),
                    "morok.tracer.repair.seal");
        }
        runtime_seal::foldFlag(FoldB, runtime_seal::kAntiDebugChannel, Mismatch,
                               FoldSalt ^ 0x8A6F0E4D27D5C139ULL,
                               "morok.tracer.antidbg");
    }
    FoldB.CreateBr(ContBB);

    B.SetInsertPoint(ContBB);
}

} // namespace

bool tracerAttestationModule(Module &M, const TracerAttestationParams &Params,
                             ir::IRRandom &Rng) {
    if (!Params.enabled || Params.mode != "linux_ptrace" ||
        Params.renewal != "startup" || Params.shares == 0)
        return false;

    const Triple TT(M.getTargetTriple());
    if (!supportsDirectTracer(TT) || moduleUsesForkOrSignalApis(M) ||
        M.getFunction(kCtorName))
        return false;

    if (Params.bind_to_runtime_seal) {
        runtime_seal::getChannel(M, runtime_seal::kTracerChannel, Rng);
        runtime_seal::getChannel(M, runtime_seal::kAntiDebugChannel, Rng);
    }

    Function *ShareHelper = getShareHelper(M, Rng, Params.virtualize_helpers);
    Function *Ctor = makeCtorShell(M);
    GlobalVariable *AntiBuddyPid =
        M.getGlobalVariable("morok.antidbg.buddy.pid", true);

    IRBuilder<> B(&Ctor->getEntryBlock());
    const std::uint32_t ShareCount = std::min(Params.shares, kMaxShares);
    const bool EnableRepair = ShareCount >= kMaxShares;
    for (std::uint32_t I = 0; I < ShareCount; ++I)
        emitShareRound(M, *Ctor, B, ShareHelper, AntiBuddyPid,
                       Params.bind_to_runtime_seal, EnableRepair, I,
                       Rng.next());
    B.CreateRetVoid();
    appendToGlobalCtors(M, Ctor, 0);
    return true;
}

PreservedAnalyses TracerAttestationPass::run(Module &M,
                                             ModuleAnalysisManager &) {
    ir::IRRandom Rng(engine_);
    return tracerAttestationModule(M, params_, Rng) ? PreservedAnalyses::none()
                                                    : PreservedAnalyses::all();
}

} // namespace morok::passes
