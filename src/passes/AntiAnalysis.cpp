// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/AntiAnalysis.cpp
//
// Each pass injects a startup constructor (or inspects metadata).  The injected
// code is inert in an un-instrumented run, so program behaviour is unchanged.

#include "morok/passes/AntiAnalysis.hpp"

#include "morok/ir/SymbolCloak.hpp"
#include "morok/passes/RuntimeSeal.hpp"
#include "morok/runtime/PlatformRuntime.hpp"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/AtomicOrdering.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <array>
#include <cstdint>
#include <initializer_list>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr std::uint32_t kWatchdogMaxIterations = 4;
constexpr std::uint32_t kWatchdogCryptoStaleThreshold =
    kWatchdogMaxIterations;

SmallPtrSet<BasicBlock *, 32> naturalLoopBlocks(Function &F) {
    DominatorTree DT(F);
    SmallPtrSet<BasicBlock *, 32> Blocks;
    for (BasicBlock &BB : F) {
        for (BasicBlock *Succ : successors(&BB)) {
            if (!DT.dominates(Succ, &BB))
                continue;

            Blocks.insert(Succ);
            SmallVector<BasicBlock *, 16> Worklist;
            if (&BB != Succ) {
                Worklist.push_back(&BB);
                Blocks.insert(&BB);
            }
            while (!Worklist.empty()) {
                BasicBlock *Cur = Worklist.pop_back_val();
                for (BasicBlock *Pred : predecessors(Cur)) {
                    if (Blocks.insert(Pred).second && Pred != Succ)
                        Worklist.push_back(Pred);
                }
            }
        }
    }
    return Blocks;
}

bool directlyRecursive(Function &F) {
    for (Instruction &I : instructions(F)) {
        auto *CB = dyn_cast<CallBase>(&I);
        if (CB && CB->getCalledFunction() == &F)
            return true;
    }
    return false;
}

bool isForkOrSignalApiName(StringRef Name) {
    return Name == "fork" || Name == "vfork" || Name == "clone" ||
           Name == "sigaction" || Name == "signal" ||
           Name == "sigprocmask" || Name == "pthread_sigmask" ||
           Name == "sigsuspend" || Name == "sigwait" ||
           Name == "sigwaitinfo" || Name == "sigtimedwait" ||
           Name == "sigpending" || Name == "sigfillset" ||
           Name == "sigemptyset" || Name == "sigaddset" ||
           Name == "sigdelset" || Name == "raise" || Name == "kill" ||
           Name == "alarm" || Name == "pause";
}

bool moduleUsesForkOrSignalApis(Module &M) {
    for (Function &F : M)
        if (!F.use_empty() && isForkOrSignalApiName(F.getName()))
            return true;
    return false;
}

Function *makeCtorShell(Module &M, const char *name) {
    auto *fn = Function::Create(
        FunctionType::get(Type::getVoidTy(M.getContext()), false),
        GlobalValue::InternalLinkage, name, &M);
    BasicBlock::Create(M.getContext(), "entry", fn);
    return fn;
}

Function *makeLinuxArgCtorShell(Module &M, const char *name) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(
        FunctionType::get(Type::getVoidTy(ctx), {i32, ptr, ptr}, false),
        GlobalValue::InternalLinkage, name, &M);
    fn->setDSOLocal(true);
    BasicBlock::Create(ctx, "entry", fn);
    return fn;
}

GlobalVariable *environGlobal(Module &M) {
    auto *ptr = PointerType::getUnqual(M.getContext());
    return cast<GlobalVariable>(M.getOrInsertGlobal("environ", ptr));
}

IntegerType *intPtrTy(Module &M) {
    unsigned bits = M.getDataLayout().getPointerSizeInBits(0);
    if (bits == 0)
        bits = 64;
    return IntegerType::get(M.getContext(), bits);
}

GlobalVariable *antiDebugState(Module &M, ir::IRRandom &rng) {
    if (auto *existing =
            M.getGlobalVariable("morok.antidbg.state", /*AllowInternal=*/true))
        return existing;
    auto *i64 = Type::getInt64Ty(M.getContext());
    auto *gv = new GlobalVariable(
        M, i64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(i64, rng.next()), "morok.antidbg.state");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

GlobalVariable *antiDebugBuddyPid(Module &M) {
    if (auto *existing =
            M.getGlobalVariable("morok.antidbg.buddy.pid",
                                /*AllowInternal=*/true))
        return existing;
    auto *ip = intPtrTy(M);
    auto *gv = new GlobalVariable(
        M, ip, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(ip, 0), "morok.antidbg.buddy.pid");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

GlobalVariable *antiDebugDrActive(Module &M) {
    if (auto *existing =
            M.getGlobalVariable("morok.antidbg.dr.active",
                                /*AllowInternal=*/true))
        return existing;
    LLVMContext &ctx = M.getContext();
    auto *i1 = Type::getInt1Ty(ctx);
    auto *gv = new GlobalVariable(
        M, i1, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::getFalse(ctx), "morok.antidbg.dr.active");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    gv->setAlignment(Align(1));
    return gv;
}

GlobalVariable *antiDebugWatchdogHeartbeat(Module &M, ir::IRRandom &rng) {
    if (auto *existing =
            M.getGlobalVariable("morok.watchdog.heartbeat",
                                /*AllowInternal=*/true))
        return existing;
    auto *i64 = Type::getInt64Ty(M.getContext());
    auto *gv = new GlobalVariable(
        M, i64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(i64, rng.next() | 1ULL), "morok.watchdog.heartbeat");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    gv->setAlignment(Align(8));
    return gv;
}

GlobalVariable *watchdogCryptoState(Module &M) {
    if (auto *existing =
            M.getGlobalVariable("morok.watchdog.crypto",
                                /*AllowInternal=*/true))
        return existing;
    auto *i64 = Type::getInt64Ty(M.getContext());
    auto *gv = new GlobalVariable(
        M, i64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(i64, 0), "morok.watchdog.crypto");
    gv->setAlignment(Align(8));
    return gv;
}

GlobalVariable *antiAnalysisPoisonState(Module &M) {
    if (auto *existing = M.getGlobalVariable("morok.antianalysis.poison",
                                             /*AllowInternal=*/true))
        return existing;
    auto *i64 = Type::getInt64Ty(M.getContext());
    auto *gv = new GlobalVariable(M, i64, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage,
                                  ConstantInt::get(i64, 0),
                                  "morok.antianalysis.poison");
    gv->setAlignment(Align(8));
    return gv;
}

GlobalVariable *antiHookState(Module &M, ir::IRRandom &rng) {
    if (auto *existing =
            M.getGlobalVariable("morok.antihook.state", /*AllowInternal=*/true))
        return existing;
    auto *i64 = Type::getInt64Ty(M.getContext());
    auto *gv = new GlobalVariable(
        M, i64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(i64, rng.next()), "morok.antihook.state");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

Value *toI64(IRBuilderBase &B, Value *V) {
    auto *i64 = B.getInt64Ty();
    if (V->getType()->isIntegerTy(64))
        return V;
    if (V->getType()->isIntegerTy())
        return B.CreateZExtOrTrunc(V, i64);
    return B.CreatePtrToInt(V, i64);
}

void foldState(IRBuilderBase &B, GlobalVariable *State, Value *V,
               std::uint64_t Salt, const Twine &Name) {
    auto *i64 = B.getInt64Ty();
    auto *old = B.CreateLoad(i64, State, Name + ".old");
    old->setVolatile(true);

    Value *wide = toI64(B, V);
    Value *mixed = B.CreateXor(B.CreateShl(old, ConstantInt::get(i64, 13)),
                               B.CreateLShr(old, ConstantInt::get(i64, 7)));
    mixed =
        B.CreateAdd(mixed, ConstantInt::get(i64, Salt ^ 0x9E3779B97F4A7C15ULL));
    mixed = B.CreateXor(mixed,
                        B.CreateMul(wide, ConstantInt::get(i64, Salt | 1ull)));

    auto *st = B.CreateStore(mixed, State);
    st->setVolatile(true);
}

void foldFlag(IRBuilderBase &B, GlobalVariable *State, Value *Flag,
              std::uint64_t Salt, const Twine &Name) {
    foldState(B, State, B.CreateZExtOrTrunc(Flag, B.getInt64Ty()), Salt, Name);
}

void foldPoisonFlag(IRBuilderBase &B, Value *Flag, std::uint64_t Salt,
                    const Twine &Name) {
    Module *M = B.GetInsertBlock()->getModule();
    if (!M)
        return;
    auto *i64 = B.getInt64Ty();
    Value *tripped = B.CreateICmpNE(B.CreateZExtOrTrunc(Flag, i64),
                                    ConstantInt::get(i64, 0),
                                    Name + ".poison.trip");
    GlobalVariable *Poison = antiAnalysisPoisonState(*M);
    auto *old = B.CreateLoad(i64, Poison, Name + ".poison.old");
    old->setVolatile(true);
    old->setAlignment(Align(8));
    Value *rot = B.CreateOr(B.CreateShl(old, ConstantInt::get(i64, 19)),
                            B.CreateLShr(old, ConstantInt::get(i64, 45)),
                            Name + ".poison.rot");
    Value *mixed =
        B.CreateXor(rot, ConstantInt::get(i64, Salt ^ 0xA24BAED4963EE407ULL),
                    Name + ".poison.salt");
    mixed = B.CreateMul(
        mixed, ConstantInt::get(i64, (Salt ^ 0x9FB21C651E98DF25ULL) | 1ULL),
        Name + ".poison.mul");
    Value *next = B.CreateSelect(tripped, mixed, old, Name + ".poison.next");
    auto *st = B.CreateStore(next, Poison);
    st->setVolatile(true);
    st->setAlignment(Align(8));
}

GlobalVariable *antiDebugSeal(Module &M, ir::IRRandom &rng) {
    return runtime_seal::getChannel(M, runtime_seal::kAntiDebugChannel, rng);
}

// Fold a ZERO-ON-CLEAN detector flag into the seal.  Clean flags leave the seal
// byte-for-byte at S0; tripped flags run the current seal through a non-
// involutive mix, so repeated identical observations cannot cancel by parity.
// Must only be called with flags that are false on a legitimate run (e.g. traced
// / DYLD-inserted / debugger-parent) — otherwise it would corrupt clean runs.
void sealFold(IRBuilderBase &B, Value *Flag, std::uint64_t Salt) {
    runtime_seal::foldFlag(B, runtime_seal::kAntiDebugChannel, Flag, Salt,
                           "morok.seal.fold.anti_debug");
}

void foldEnforcedFlag(IRBuilderBase &B, GlobalVariable *State, Value *Flag,
                      std::uint64_t Salt, const Twine &Name) {
    foldFlag(B, State, Flag, Salt, Name);
    // Only use this for detector verdicts proven false on clean e2e runs.
    // Host/jitter-sensitive probes should remain foldFlag telemetry.
    sealFold(B, Flag, Salt ^ 0xA5B0E176D83429CFULL);
}

Value *constIp(Module &M, std::uint64_t V) {
    return ConstantInt::get(intPtrTy(M), V);
}

Value *constSignedIp(Module &M, std::int64_t V) {
    return ConstantInt::getSigned(intPtrTy(M), V);
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

Value *loadAt(IRBuilderBase &B, Module &M, Type *Ty, Value *Base, Value *Offset,
              const Twine &Name = "") {
    return loadUnaligned(B, Ty, gepI8(B, M, Base, Offset, Name + ".ptr"), Name);
}

// NB: the integer-offset parameter is `unsigned long long`, not std::uint64_t.
// A `0ULL` argument is both a null-pointer constant and an integer literal; with
// std::uint64_t (which is `unsigned long`, not `unsigned long long`, on LP64
// Linux) the call is ambiguous between this overload and the Value* one. Using
// `unsigned long long` makes `0ULL` an exact match on every platform.
Value *loadAt(IRBuilderBase &B, Module &M, Type *Ty, Value *Base,
              unsigned long long Offset, const Twine &Name = "") {
    return loadAt(B, M, Ty, Base, constIp(M, static_cast<std::uint64_t>(Offset)),
                  Name);
}

StoreInst *storeAt(IRBuilderBase &B, Module &M, Value *Base,
                   unsigned long long Offset, Value *V,
                   const Twine &Name = "") {
    auto *SI =
        B.CreateStore(V, gepI8(B, M, Base,
                               constIp(M, static_cast<std::uint64_t>(Offset)),
                               Name + ".ptr"));
    SI->setVolatile(true);
    SI->setAlignment(Align(1));
    return SI;
}

void incrementDiff(IRBuilderBase &B, AllocaInst *Diff, Value *Flag,
                   const Twine &Name) {
    auto *i64 = B.getInt64Ty();
    auto *old = B.CreateLoad(i64, Diff, Name + ".old");
    old->setVolatile(true);
    Value *next =
        B.CreateAdd(old, B.CreateZExtOrTrunc(Flag, i64), Name + ".next");
    auto *st = B.CreateStore(next, Diff);
    st->setVolatile(true);
}

Value *arrayBytePtr(IRBuilderBase &B, ArrayType *ArrTy, Value *Base,
                    Value *Index) {
    auto *idxTy = cast<IntegerType>(Index->getType());
    return B.CreateInBoundsGEP(ArrTy, Base,
                               {ConstantInt::get(idxTy, 0), Index});
}

Value *emitPtrace(IRBuilderBase &B, Module &M, int request) {
    return runtime::emitPtraceImport(B, M, request);
}

bool useDirectLinuxSyscalls(const Module &M, const Triple &TT) {
    return runtime::useDirectLinuxSyscalls(M, TT);
}

FunctionCallee getpidDecl(Module &M) {
    return runtime::getpidDecl(M);
}

FunctionCallee getppidDecl(Module &M) {
    return runtime::getppidDecl(M);
}

Value *emitLinuxSyscall(IRBuilder<> &B, Module &M, const Triple &TT,
                        std::uint32_t Number,
                        std::initializer_list<Value *> Args) {
    return runtime::emitLinuxSyscall(B, M, TT, Number, Args);
}

bool linuxCoreSyscalls(const Triple &TT, std::uint32_t &Ptrace,
                       std::uint32_t &Prctl, std::uint32_t &OpenAt,
                       std::uint32_t &Read, std::uint32_t &Close) {
    runtime::LinuxCoreSyscalls sys;
    if (!runtime::lookupLinuxCoreSyscalls(TT, sys))
        return false;
    Ptrace = sys.ptrace;
    Prctl = sys.prctl;
    OpenAt = sys.openat;
    Read = sys.read;
    Close = sys.close;
    return true;
}

Value *emitLinuxPtrace(IRBuilder<> &B, Module &M, const Triple &TT,
                       int request) {
    return runtime::emitLinuxPtrace(B, M, TT, request);
}

void emitLinuxSelfTraceFallback(IRBuilder<> &B, Module &M,
                                GlobalVariable *State,
                                GlobalVariable *SentinelActive,
                                const Triple &TT, const Twine &Name,
                                std::uint64_t Salt) {
    auto *i32 = Type::getInt32Ty(M.getContext());
    auto trace = [&]() {
        Value *traceRc = emitLinuxPtrace(B, M, TT, 0);
        foldFlag(B, State,
                 B.CreateICmpSLT(traceRc, ConstantInt::getSigned(i32, 0)),
                 Salt, Name);
    };
    if (!SentinelActive) {
        trace();
        return;
    }

    std::string base = Name.str();
    LLVMContext &ctx = M.getContext();
    auto *fn = B.GetInsertBlock()->getParent();
    auto *traceBB = BasicBlock::Create(ctx, base + ".trace", fn);
    auto *contBB = BasicBlock::Create(ctx, base + ".cont", fn);
    auto *active =
        B.CreateLoad(Type::getInt1Ty(ctx), SentinelActive,
                     base + ".active.load");
    active->setVolatile(true);
    active->setAlignment(Align(1));
    B.CreateCondBr(active, contBB, traceBB);

    B.SetInsertPoint(traceBB);
    trace();
    B.CreateBr(contBB);

    B.SetInsertPoint(contBB);
}

Value *emitLinuxPrctl(IRBuilder<> &B, Module &M, const Triple &TT,
                      std::int64_t Option, std::int64_t A2 = 0,
                      std::int64_t A3 = 0, std::int64_t A4 = 0,
                      std::int64_t A5 = 0) {
    return runtime::emitLinuxPrctl(B, M, TT, Option, A2, A3, A4, A5);
}

GlobalVariable *elfDynamicWeakSymbol(Module &M) {
    if (auto *existing = M.getGlobalVariable("_DYNAMIC"))
        return existing;
    auto *i8 = Type::getInt8Ty(M.getContext());
    return new GlobalVariable(M, i8, /*isConstant=*/false,
                              GlobalValue::ExternalWeakLinkage, nullptr,
                              "_DYNAMIC");
}

Value *emitElfDynamicPresent(IRBuilder<> &B, Module &M, const Triple &TT) {
    if (!TT.isOSLinux())
        return ConstantInt::getTrue(M.getContext());
    auto *ptr = PointerType::getUnqual(M.getContext());
    return B.CreateICmpNE(elfDynamicWeakSymbol(M),
                          ConstantPointerNull::get(ptr),
                          "morok.antihook.dynamic.present");
}

bool useDirectDarwinSyscalls(const Module &M, const Triple &TT) {
    return runtime::useDirectDarwinSyscalls(M, TT);
}

Value *emitDarwinSyscall(IRBuilder<> &B, Module &M, const Triple &TT,
                         std::uint32_t Number,
                         std::initializer_list<Value *> Args) {
    return runtime::emitDarwinSyscall(B, M, TT, Number, Args);
}

Value *emitDarwinGetpid(IRBuilder<> &B, Module &M, const Triple &TT) {
    return runtime::emitDarwinGetpid(B, M, TT);
}

Value *emitDarwinPtrace(IRBuilder<> &B, Module &M, const Triple &TT,
                        std::int32_t Request) {
    return runtime::emitDarwinPtrace(B, M, TT, Request);
}

Value *emitDarwinSysctl(IRBuilder<> &B, Module &M, const Triple &TT, Value *Mib,
                        Value *MibLen, Value *OldP, Value *OldLenP, Value *NewP,
                        Value *NewLen) {
    return runtime::emitDarwinSysctl(B, M, TT, Mib, MibLen, OldP, OldLenP, NewP,
                                     NewLen);
}

Value *emitClockGettimeNanos(IRBuilder<> &B, Module &M, std::int32_t ClockId,
                             const Twine &Name);

Value *emitDarwinCsops(IRBuilder<> &B, Module &M, const Triple &TT, Value *Pid,
                       Value *Ops, Value *UserAddr, Value *UserSize) {
    return runtime::emitDarwinCsops(B, M, TT, Pid, Ops, UserAddr, UserSize);
}

FunctionCallee openDecl(Module &M) {
    return runtime::openDecl(M);
}

FunctionCallee readDecl(Module &M) {
    return runtime::readDecl(M);
}

FunctionCallee closeDecl(Module &M) {
    return runtime::closeDecl(M);
}

Value *emitLinuxReadlink(IRBuilder<> &B, Module &M, const Triple &TT,
                         Value *Path, Value *Buf, Value *Size) {
    return runtime::emitLinuxReadlink(B, M, TT, Path, Buf, Size);
}

Value *emitLinuxLseek(IRBuilder<> &B, Module &M, const Triple &TT, Value *Fd,
                      std::int64_t Offset, std::int32_t Whence) {
    return runtime::emitLinuxLseek(B, M, TT, Fd, Offset, Whence);
}

Value *emitLinuxMmapAddr(IRBuilder<> &B, Module &M, const Triple &TT,
                         Value *Size, Value *Fd) {
    return runtime::emitLinuxMmapAddr(B, M, TT, Size, Fd);
}

void emitLinuxMunmap(IRBuilder<> &B, Module &M, const Triple &TT, Value *Addr,
                     Value *Size) {
    runtime::emitLinuxMunmap(B, M, TT, Addr, Size);
}

Value *emitLinuxMprotect(IRBuilder<> &B, Module &M, const Triple &TT,
                         Value *Addr, Value *Size, Value *Prot) {
    return runtime::emitLinuxMprotect(B, M, TT, Addr, Size, Prot);
}

Value *emitDarwinMprotect(IRBuilder<> &B, Module &M, const Triple &TT,
                          Value *Addr, Value *Size, Value *Prot) {
    return runtime::emitDarwinMprotect(B, M, TT, Addr, Size, Prot);
}

void emitLinuxClose(IRBuilder<> &B, Module &M, const Triple &TT, Value *Fd) {
    runtime::emitLinuxClose(B, M, TT, Fd);
}

Value *emitDarwinOpen(IRBuilder<> &B, Module &M, const Triple &TT, Value *Path,
                      std::int32_t Flags, std::int32_t Mode) {
    return runtime::emitDarwinOpen(B, M, TT, Path, Flags, Mode);
}

void emitDarwinClose(IRBuilder<> &B, Module &M, const Triple &TT, Value *Fd) {
    runtime::emitDarwinClose(B, M, TT, Fd);
}

Value *emitDarwinLseek(IRBuilder<> &B, Module &M, const Triple &TT, Value *Fd,
                       std::int64_t Offset, std::int32_t Whence) {
    return runtime::emitDarwinLseek(B, M, TT, Fd, Offset, Whence);
}

Value *emitDarwinMmap(IRBuilder<> &B, Module &M, const Triple &TT, Value *Size,
                      Value *Fd) {
    return runtime::emitDarwinMmap(B, M, TT, Size, Fd);
}

Value *emitPosixAnonMmapAddr(IRBuilder<> &B, Module &M, const Triple &TT,
                             Value *Size, Value *Prot, Value *Flags,
                             const Twine &Name) {
    return runtime::emitPosixAnonMmapAddr(B, M, TT, Size, Prot, Flags, Name);
}

Value *emitPosixMprotect(IRBuilder<> &B, Module &M, const Triple &TT,
                         Value *Addr, Value *Size, Value *Prot) {
    return runtime::emitPosixMprotect(B, M, TT, Addr, Size, Prot);
}

void emitDarwinMunmap(IRBuilder<> &B, Module &M, const Triple &TT,
                      Value *Mapped, Value *Size) {
    runtime::emitDarwinMunmap(B, M, TT, Mapped, Size);
}

struct ReadFileIR {
    AllocaInst *buf = nullptr;
    Value *n = nullptr;
    ArrayType *bufTy = nullptr;
    BasicBlock *afterRead = nullptr;
    BasicBlock *ret0 = nullptr;
};

ReadFileIR emitReadSmallFile(IRBuilder<> &B, Module &M, Function *Fn,
                             StringRef Path, std::uint64_t BufBytes,
                             ir::IRRandom &rng, const Triple &TT) {
    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    std::uint32_t ptraceNr = 0;
    std::uint32_t prctlNr = 0;
    std::uint32_t openatNr = 0;
    std::uint32_t readNr = 0;
    std::uint32_t closeNr = 0;

    ReadFileIR out;
    out.bufTy = ArrayType::get(i8, BufBytes);
    out.buf = B.CreateAlloca(out.bufTy, nullptr, "morok.antidbg.buf");

    Value *path = ir::emitCloakedSymbol(B, M, Path, rng);
    Value *fd = nullptr;
    const bool hasLinuxSyscalls =
        linuxCoreSyscalls(TT, ptraceNr, prctlNr, openatNr, readNr, closeNr);
    if (hasLinuxSyscalls) {
        Value *fdLong = emitLinuxSyscall(B, M, TT, openatNr,
                                         {ConstantInt::getSigned(ip, -100),
                                          path, ConstantInt::get(ip, 0),
                                          ConstantInt::get(ip, 0)});
        fd = B.CreateTruncOrBitCast(fdLong, i32);
    } else {
        fd = B.CreateCall(openDecl(M), {path, ConstantInt::get(i32, 0)});
    }

    auto *readBB = BasicBlock::Create(ctx, "read", Fn);
    out.ret0 = BasicBlock::Create(ctx, "ret0", Fn);
    Value *badFd = B.CreateICmpSLT(fd, ConstantInt::getSigned(i32, 0));
    B.CreateCondBr(badFd, out.ret0, readBB);

    IRBuilder<> RB(readBB);
    Value *bufPtr = RB.CreateInBoundsGEP(
        out.bufTy, out.buf, {ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)});
    if (hasLinuxSyscalls) {
        out.n =
            emitLinuxSyscall(RB, M, TT, readNr,
                             {fd, bufPtr, ConstantInt::get(ip, BufBytes - 1)});
        emitLinuxSyscall(RB, M, TT, closeNr, {fd});
    } else {
        out.n = RB.CreateCall(readDecl(M),
                              {fd, bufPtr, ConstantInt::get(ip, BufBytes - 1)});
        RB.CreateCall(closeDecl(M), {fd});
    }
    out.afterRead = readBB;
    return out;
}

void emitLinuxMemfdReexecCtor(Module &M, ir::IRRandom &rng, const Triple &TT) {
    if (!useDirectLinuxSyscalls(M, TT) ||
        M.getFunction("morok.antidbg.memfd"))
        return;

    constexpr std::uint32_t kRead = 0;
    constexpr std::uint32_t kWrite = 1;
    constexpr std::uint32_t kClose = 3;
    constexpr std::uint32_t kExecve = 59;
    constexpr std::uint32_t kReadlink = 89;
    constexpr std::uint32_t kOpenAt = 257;
    constexpr std::uint32_t kDup3 = 292;
    constexpr std::uint32_t kMemfdCreate = 319;
    constexpr std::uint32_t kExecveat = 322;
    constexpr std::int64_t kAtFdcwd = -100;
    constexpr std::uint64_t kAtEmptyPath = 0x1000;
    constexpr std::uint64_t kOCloexec = 0x80000;
    constexpr std::uint64_t kMfdCloexec = 0x1;
    constexpr std::uint64_t kBufBytes = 4096;
    constexpr std::uint64_t kFallbackFd = 200;

    LLVMContext &ctx = M.getContext();
    auto *i1 = Type::getInt1Ty(ctx);
    auto *i8 = Type::getInt8Ty(ctx);
    auto *ip = intPtrTy(M);

    Function *fn = makeLinuxArgCtorShell(M, "morok.antidbg.memfd");
    fn->getArg(0)->setName("argc");
    Argument *argv = fn->getArg(1);
    Argument *envp = fn->getArg(2);
    argv->setName("argv");
    envp->setName("envp");

    auto *entry = &fn->getEntryBlock();
    auto *prefixInitBB = BasicBlock::Create(ctx, "prefix.init", fn);
    auto *prefixBodyBB = BasicBlock::Create(ctx, "prefix.body", fn);
    auto *openBB = BasicBlock::Create(ctx, "open", fn);
    auto *memfdBB = BasicBlock::Create(ctx, "memfd", fn);
    auto *copyBB = BasicBlock::Create(ctx, "copy", fn);
    auto *readDoneBB = BasicBlock::Create(ctx, "read.done", fn);
    auto *writeBB = BasicBlock::Create(ctx, "write", fn);
    auto *writeContBB = BasicBlock::Create(ctx, "write.cont", fn);
    auto *execBB = BasicBlock::Create(ctx, "exec", fn);
    auto *execProcFdBB = BasicBlock::Create(ctx, "exec.procfd", fn);
    auto *closeSrcRetBB = BasicBlock::Create(ctx, "close.src.ret", fn);
    auto *closeBothRetBB = BasicBlock::Create(ctx, "close.both.ret", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    auto *pathTy = ArrayType::get(i8, kBufBytes);
    auto *bufTy = ArrayType::get(i8, kBufBytes);
    auto *emptyTy = ArrayType::get(i8, 1);
    auto *fallbackArgvTy = ArrayType::get(PointerType::getUnqual(ctx), 2);
    AllocaInst *path =
        B.CreateAlloca(pathTy, nullptr, "morok.antidbg.memfd.path");
    AllocaInst *buf = B.CreateAlloca(bufTy, nullptr,
                                     "morok.antidbg.memfd.copybuf");
    AllocaInst *empty =
        B.CreateAlloca(emptyTy, nullptr, "morok.antidbg.memfd.empty");
    AllocaInst *fallbackArgv = B.CreateAlloca(
        fallbackArgvTy, nullptr, "morok.antidbg.memfd.argv.fallback");
    Value *pathBuf = B.CreateInBoundsGEP(
        pathTy, path, {ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)},
        "morok.antidbg.memfd.path.buf");
    Value *copyBuf = B.CreateInBoundsGEP(
        bufTy, buf, {ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)},
        "morok.antidbg.memfd.copy.buf");
    Value *emptyPath = B.CreateInBoundsGEP(
        emptyTy, empty, {ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)},
        "morok.antidbg.memfd.empty.path");
    B.CreateStore(ConstantInt::get(i8, 0), emptyPath);
    Value *fallbackArgv0 = B.CreateInBoundsGEP(
        fallbackArgvTy, fallbackArgv,
        {ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)},
        "morok.antidbg.memfd.argv0.slot");
    Value *fallbackArgv1 = B.CreateInBoundsGEP(
        fallbackArgvTy, fallbackArgv,
        {ConstantInt::get(ip, 0), ConstantInt::get(ip, 1)},
        "morok.antidbg.memfd.argv1.slot");
    B.CreateStore(pathBuf, fallbackArgv0);
    B.CreateStore(ConstantPointerNull::get(PointerType::getUnqual(ctx)),
                  fallbackArgv1);

    Value *selfPath = ir::emitCloakedSymbol(B, M, "/proc/self/exe", rng);
    Value *pathLen = emitLinuxSyscall(
        B, M, TT, kReadlink,
        {selfPath, pathBuf, ConstantInt::get(ip, kBufBytes - 1)});
    pathLen->setName("morok.antidbg.memfd.readlink");
    Value *pathOk = B.CreateAnd(
        B.CreateICmpSGT(pathLen, ConstantInt::get(ip, 0)),
        B.CreateICmpULT(pathLen, ConstantInt::get(ip, kBufBytes - 1)),
        "morok.antidbg.memfd.path.ok");
    B.CreateCondBr(pathOk, prefixInitBB, retBB);

    IRBuilder<> PIB(prefixInitBB);
    constexpr std::array<unsigned char, 7> marker = {'/', 'm', 'e', 'm',
                                                     'f', 'd', ':'};
    Value *prefixEnough = PIB.CreateICmpUGE(
        pathLen, ConstantInt::get(ip, marker.size()),
        "morok.antidbg.memfd.prefix.enough");
    PIB.CreateCondBr(prefixEnough, prefixBodyBB, openBB);

    IRBuilder<> PBB(prefixBodyBB);
    Value *match = ConstantInt::get(i1, true);
    for (std::uint32_t i = 0; i < marker.size(); ++i) {
        Value *off = ConstantInt::get(ip, i);
        Value *ch = PBB.CreateLoad(i8, gepI8(PBB, M, pathBuf, off,
                                             "morok.antidbg.memfd.prefix.ch"));
        Value *eq = PBB.CreateICmpEQ(
            ch, ConstantInt::get(i8, marker[i]),
            "morok.antidbg.memfd.prefix.eq");
        match = PBB.CreateAnd(match, eq,
                              "morok.antidbg.memfd.prefix.match");
    }
    PBB.CreateCondBr(match, retBB, openBB);

    IRBuilder<> OB(openBB);
    OB.CreateStore(ConstantInt::get(i8, 0),
                   gepI8(OB, M, pathBuf, pathLen,
                         "morok.antidbg.memfd.path.nul"));
    Value *srcFd = emitLinuxSyscall(
        OB, M, TT, kOpenAt,
        {ConstantInt::getSigned(ip, kAtFdcwd), pathBuf,
         ConstantInt::get(ip, kOCloexec), ConstantInt::get(ip, 0)});
    srcFd->setName("morok.antidbg.memfd.open");
    Value *srcOk = OB.CreateICmpSGE(srcFd, ConstantInt::get(ip, 0),
                                    "morok.antidbg.memfd.open.ok");
    OB.CreateCondBr(srcOk, memfdBB, retBB);

    IRBuilder<> MB(memfdBB);
    Value *name = ir::emitCloakedSymbol(MB, M, ".nscd-cache", rng);
    Value *memFd = emitLinuxSyscall(
        MB, M, TT, kMemfdCreate, {name, ConstantInt::get(ip, kMfdCloexec)});
    memFd->setName("morok.antidbg.memfd.create");
    Value *memOk = MB.CreateICmpSGE(memFd, ConstantInt::get(ip, 0),
                                    "morok.antidbg.memfd.create.ok");
    MB.CreateCondBr(memOk, copyBB, closeSrcRetBB);

    IRBuilder<> CB(copyBB);
    Value *nread = emitLinuxSyscall(
        CB, M, TT, kRead, {srcFd, copyBuf, ConstantInt::get(ip, kBufBytes)});
    nread->setName("morok.antidbg.memfd.read");
    Value *readOk = CB.CreateICmpSGE(nread, ConstantInt::get(ip, 0),
                                     "morok.antidbg.memfd.read.ok");
    Value *readMore = CB.CreateICmpSGT(nread, ConstantInt::get(ip, 0),
                                       "morok.antidbg.memfd.read.more");
    CB.CreateCondBr(CB.CreateAnd(readOk, readMore), writeBB, readDoneBB);

    IRBuilder<> RDB(readDoneBB);
    RDB.CreateCondBr(readOk, execBB, closeBothRetBB);

    IRBuilder<> WB(writeBB);
    auto *written = WB.CreatePHI(ip, 2, "morok.antidbg.memfd.written");
    written->addIncoming(ConstantInt::get(ip, 0), copyBB);
    Value *remaining =
        WB.CreateSub(nread, written, "morok.antidbg.memfd.write.remaining");
    Value *writePtr = gepI8(WB, M, copyBuf, written,
                            "morok.antidbg.memfd.write.ptr");
    Value *nwrite =
        emitLinuxSyscall(WB, M, TT, kWrite, {memFd, writePtr, remaining});
    nwrite->setName("morok.antidbg.memfd.write");
    Value *writeOk = WB.CreateICmpSGT(nwrite, ConstantInt::get(ip, 0),
                                      "morok.antidbg.memfd.write.ok");
    WB.CreateCondBr(writeOk, writeContBB, closeBothRetBB);

    IRBuilder<> WCB(writeContBB);
    Value *writtenNext =
        WCB.CreateAdd(written, nwrite, "morok.antidbg.memfd.written.next");
    Value *chunkDone = WCB.CreateICmpUGE(
        writtenNext, nread, "morok.antidbg.memfd.chunk.done");
    WCB.CreateCondBr(chunkDone, copyBB, writeBB);
    written->addIncoming(writtenNext, writeContBB);

    IRBuilder<> EB(execBB);
    emitLinuxSyscall(EB, M, TT, kClose, {srcFd});
    Value *execRc =
        emitLinuxSyscall(EB, M, TT, kExecveat,
                         {memFd, emptyPath, argv, envp,
                          ConstantInt::get(ip, kAtEmptyPath)});
    execRc->setName("morok.antidbg.memfd.execveat");
    Value *fallbackArgvPtr = EB.CreateInBoundsGEP(
        fallbackArgvTy, fallbackArgv,
        {ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)},
        "morok.antidbg.memfd.argv.fallback.ptr");
    Value *fallbackEnvp =
        EB.CreateLoad(PointerType::getUnqual(ctx), environGlobal(M),
                      "morok.antidbg.memfd.environ");
    Value *retryRc =
        emitLinuxSyscall(EB, M, TT, kExecveat,
                         {memFd, emptyPath, fallbackArgvPtr, fallbackEnvp,
                          ConstantInt::get(ip, kAtEmptyPath)});
    retryRc->setName("morok.antidbg.memfd.execveat.retry");
    Value *dupFd =
        emitLinuxSyscall(EB, M, TT, kDup3,
                         {memFd, ConstantInt::get(ip, kFallbackFd),
                          ConstantInt::get(ip, kOCloexec)});
    dupFd->setName("morok.antidbg.memfd.dup3");
    EB.CreateCondBr(
        EB.CreateICmpEQ(dupFd, ConstantInt::get(ip, kFallbackFd),
                        "morok.antidbg.memfd.dup3.ok"),
        execProcFdBB, closeBothRetBB);

    IRBuilder<> EPB(execProcFdBB);
    Value *procFdPath =
        ir::emitCloakedSymbol(EPB, M, "/proc/self/fd/200", rng);
    Value *execProcRc = emitLinuxSyscall(
        EPB, M, TT, kExecve, {procFdPath, fallbackArgvPtr, fallbackEnvp});
    execProcRc->setName("morok.antidbg.memfd.execve.procfd");
    EPB.CreateBr(closeBothRetBB);

    IRBuilder<> CSRB(closeSrcRetBB);
    emitLinuxSyscall(CSRB, M, TT, kClose, {srcFd});
    CSRB.CreateBr(retBB);

    IRBuilder<> CBRB(closeBothRetBB);
    emitLinuxSyscall(CBRB, M, TT, kClose, {memFd});
    emitLinuxSyscall(CBRB, M, TT, kClose, {srcFd});
    CBRB.CreateBr(retBB);

    IRBuilder<> RB(retBB);
    RB.CreateRetVoid();

    appendToGlobalCtors(M, fn, 0);
}

void finishI32Ret(BasicBlock *BB, std::uint32_t Value) {
    IRBuilder<> B(BB);
    B.CreateRet(ConstantInt::get(Type::getInt32Ty(BB->getContext()), Value));
}

Function *linuxStatusTracerCheck(Module &M, ir::IRRandom &rng,
                                 const Triple &TT) {
    if (Function *existing = M.getFunction("morok.antidbg.linux.status"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i1 = Type::getInt1Ty(ctx);
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);

    auto *fn = Function::Create(FunctionType::get(i32, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antidbg.linux.status", &M);
    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    IRBuilder<> B(entry);
    ReadFileIR rf =
        emitReadSmallFile(B, M, fn, "/proc/self/status", 1024, rng, TT);

    constexpr std::array<unsigned char, 10> prefix = {'T', 'r', 'a', 'c', 'e',
                                                      'r', 'P', 'i', 'd', ':'};

    auto *loopBB = BasicBlock::Create(ctx, "scan", fn);
    auto *matchBB = BasicBlock::Create(ctx, "match", fn);
    auto *nextBB = BasicBlock::Create(ctx, "next", fn);
    auto *digitBB = BasicBlock::Create(ctx, "digit", fn);
    auto *digitCharBB = BasicBlock::Create(ctx, "digit.char", fn);
    auto *digitMaybeNlBB = BasicBlock::Create(ctx, "digit.nl", fn);
    auto *digitNextBB = BasicBlock::Create(ctx, "digit.next", fn);
    auto *ret1 = BasicBlock::Create(ctx, "ret1", fn);

    IRBuilder<> RB(rf.afterRead);
    Value *enough = RB.CreateICmpSGT(rf.n, ConstantInt::get(ip, prefix.size()));
    RB.CreateCondBr(enough, loopBB, rf.ret0);

    IRBuilder<> LB(loopBB);
    auto *idx = LB.CreatePHI(ip, 2, "morok.antidbg.idx");
    idx->addIncoming(ConstantInt::get(ip, 0), rf.afterRead);
    Value *last = LB.CreateSub(rf.n, ConstantInt::get(ip, prefix.size()));
    Value *inRange = LB.CreateICmpULE(idx, last);
    LB.CreateCondBr(inRange, matchBB, rf.ret0);

    IRBuilder<> MB(matchBB);
    Value *match = ConstantInt::get(i1, true);
    for (std::uint32_t j = 0; j < prefix.size(); ++j) {
        Value *off = MB.CreateAdd(idx, ConstantInt::get(ip, j));
        Value *ptr = arrayBytePtr(MB, rf.bufTy, rf.buf, off);
        Value *ch = MB.CreateLoad(i8, ptr);
        Value *eq = MB.CreateICmpEQ(ch, ConstantInt::get(i8, prefix[j]));
        match = MB.CreateAnd(match, eq);
    }
    Value *digitStart = MB.CreateAdd(idx, ConstantInt::get(ip, prefix.size()));
    MB.CreateCondBr(match, digitBB, nextBB);

    IRBuilder<> NB(nextBB);
    Value *idxNext = NB.CreateAdd(idx, ConstantInt::get(ip, 1));
    NB.CreateBr(loopBB);
    idx->addIncoming(idxNext, nextBB);

    IRBuilder<> DB(digitBB);
    auto *digitIdx = DB.CreatePHI(ip, 2, "morok.antidbg.digit");
    digitIdx->addIncoming(digitStart, matchBB);
    Value *digitInRange = DB.CreateICmpULT(digitIdx, rf.n);
    DB.CreateCondBr(digitInRange, digitCharBB, rf.ret0);

    IRBuilder<> DCB(digitCharBB);
    Value *dptr = arrayBytePtr(DCB, rf.bufTy, rf.buf, digitIdx);
    Value *ch = DCB.CreateLoad(i8, dptr);
    Value *geOne =
        DCB.CreateICmpUGE(ch, ConstantInt::get(i8, static_cast<unsigned>('1')));
    Value *leNine =
        DCB.CreateICmpULE(ch, ConstantInt::get(i8, static_cast<unsigned>('9')));
    DCB.CreateCondBr(DCB.CreateAnd(geOne, leNine), ret1, digitMaybeNlBB);

    IRBuilder<> DNB(digitMaybeNlBB);
    DNB.CreateCondBr(DNB.CreateICmpEQ(ch, ConstantInt::get(i8, '\n')), rf.ret0,
                     digitNextBB);

    IRBuilder<> DXB(digitNextBB);
    Value *digitNext = DXB.CreateAdd(digitIdx, ConstantInt::get(ip, 1));
    DXB.CreateBr(digitBB);
    digitIdx->addIncoming(digitNext, digitNextBB);

    finishI32Ret(rf.ret0, 0);
    finishI32Ret(ret1, 1);
    return fn;
}

Function *linuxStatField4Check(Module &M, ir::IRRandom &rng, const Triple &TT) {
    if (Function *existing = M.getFunction("morok.antidbg.linux.stat4"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);

    auto *fn = Function::Create(FunctionType::get(i32, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antidbg.linux.stat4", &M);
    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    IRBuilder<> B(entry);
    ReadFileIR rf =
        emitReadSmallFile(B, M, fn, "/proc/self/stat", 1024, rng, TT);

    auto *findBB = BasicBlock::Create(ctx, "find.close", fn);
    auto *findCharBB = BasicBlock::Create(ctx, "find.char", fn);
    auto *findNextBB = BasicBlock::Create(ctx, "find.next", fn);
    auto *digitBB = BasicBlock::Create(ctx, "digit", fn);
    auto *digitCharBB = BasicBlock::Create(ctx, "digit.char", fn);
    auto *digitStopBB = BasicBlock::Create(ctx, "digit.stop", fn);
    auto *digitNextBB = BasicBlock::Create(ctx, "digit.next", fn);
    auto *ret1 = BasicBlock::Create(ctx, "ret1", fn);

    IRBuilder<> RB(rf.afterRead);
    Value *hasAny = RB.CreateICmpSGT(rf.n, ConstantInt::get(ip, 4));
    Value *lastIdx = RB.CreateSub(rf.n, ConstantInt::get(ip, 1));
    RB.CreateCondBr(hasAny, findBB, rf.ret0);

    IRBuilder<> FB(findBB);
    auto *idx = FB.CreatePHI(ip, 2, "morok.antidbg.stat.idx");
    idx->addIncoming(lastIdx, rf.afterRead);
    Value *valid = FB.CreateICmpSGE(idx, ConstantInt::get(ip, 0));
    FB.CreateCondBr(valid, findCharBB, rf.ret0);

    IRBuilder<> FCB(findCharBB);
    Value *ptr = arrayBytePtr(FCB, rf.bufTy, rf.buf, idx);
    Value *ch = FCB.CreateLoad(i8, ptr);
    Value *ppidStart = FCB.CreateAdd(idx, ConstantInt::get(ip, 4));
    FCB.CreateCondBr(FCB.CreateICmpEQ(ch, ConstantInt::get(i8, ')')), digitBB,
                     findNextBB);

    IRBuilder<> FNB(findNextBB);
    Value *idxPrev = FNB.CreateSub(idx, ConstantInt::get(ip, 1));
    FNB.CreateBr(findBB);
    idx->addIncoming(idxPrev, findNextBB);

    IRBuilder<> DB(digitBB);
    auto *digitIdx = DB.CreatePHI(ip, 2, "morok.antidbg.stat4");
    digitIdx->addIncoming(ppidStart, findCharBB);
    Value *digitInRange = DB.CreateICmpULT(digitIdx, rf.n);
    DB.CreateCondBr(digitInRange, digitCharBB, rf.ret0);

    IRBuilder<> DCB(digitCharBB);
    Value *dptr = arrayBytePtr(DCB, rf.bufTy, rf.buf, digitIdx);
    Value *dch = DCB.CreateLoad(i8, dptr);
    Value *geOne = DCB.CreateICmpUGE(
        dch, ConstantInt::get(i8, static_cast<unsigned>('1')));
    Value *leNine = DCB.CreateICmpULE(
        dch, ConstantInt::get(i8, static_cast<unsigned>('9')));
    DCB.CreateCondBr(DCB.CreateAnd(geOne, leNine), ret1, digitStopBB);

    IRBuilder<> DSB(digitStopBB);
    Value *isSpace = DSB.CreateICmpEQ(dch, ConstantInt::get(i8, ' '));
    Value *isNl = DSB.CreateICmpEQ(dch, ConstantInt::get(i8, '\n'));
    DSB.CreateCondBr(DSB.CreateOr(isSpace, isNl), rf.ret0, digitNextBB);

    IRBuilder<> DXB(digitNextBB);
    Value *digitNext = DXB.CreateAdd(digitIdx, ConstantInt::get(ip, 1));
    DXB.CreateBr(digitBB);
    digitIdx->addIncoming(digitNext, digitNextBB);

    finishI32Ret(rf.ret0, 0);
    finishI32Ret(ret1, 1);
    return fn;
}

bool linuxBuddyLivenessSyscalls(const Triple &TT, std::uint32_t &Kill,
                                std::uint32_t &Wait4);

Function *linuxWatchThread(Module &M, Function *StatusFn, Function *StatFn,
                           GlobalVariable *State, GlobalVariable *BuddyPid,
                           GlobalVariable *SentinelActive, const Triple &TT,
                           bool AllowSelfTrace) {
    if (Function *existing = M.getFunction("morok.antidbg.linux.watch"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    std::uint32_t killNr = 0;
    std::uint32_t wait4Nr = 0;
    const bool watchBuddy =
        BuddyPid && linuxBuddyLivenessSyscalls(TT, killNr, wait4Nr);

    auto *fn = Function::Create(FunctionType::get(ptr, {ptr}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antidbg.linux.watch", &M);
    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *loopBB = BasicBlock::Create(ctx, "loop", fn);
    auto *bodyBB = BasicBlock::Create(ctx, "body", fn);
    auto *buddyCheckBB =
        watchBuddy ? BasicBlock::Create(ctx, "buddy.check", fn) : nullptr;
    auto *buddyLiveBB =
        watchBuddy ? BasicBlock::Create(ctx, "buddy.live", fn) : nullptr;
    auto *buddyMissingBB =
        watchBuddy ? BasicBlock::Create(ctx, "buddy.missing", fn) : nullptr;
    auto *nextBB = watchBuddy ? BasicBlock::Create(ctx, "next", fn) : nullptr;
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> EB(entry);
    AllocaInst *buddyStatus =
        watchBuddy ? EB.CreateAlloca(i32, nullptr, "morok.antidbg.buddy.status")
                   : nullptr;
    EB.CreateBr(loopBB);

    IRBuilder<> LB(loopBB);
    auto *iter = LB.CreatePHI(i32, 2, "morok.antidbg.iter");
    iter->addIncoming(ConstantInt::get(i32, 0), entry);
    const std::uint32_t limit = watchBuddy ? kWatchdogMaxIterations : 8u;
    LB.CreateCondBr(
        LB.CreateICmpULT(iter, ConstantInt::get(i32, limit),
                         "morok.antidbg.watch.keep"),
        bodyBB, retBB);

    IRBuilder<> BB(bodyBB);
    FunctionCallee sleepFn =
        M.getOrInsertFunction("sleep", FunctionType::get(i32, {i32}, false));
    BB.CreateCall(sleepFn, {ConstantInt::get(i32, 1)});
    if (AllowSelfTrace)
        emitLinuxSelfTraceFallback(BB, M, State, SentinelActive, TT,
                                   "morok.antidbg.watch.ptrace",
                                   0x6FAE31D54B8C9721ULL);
    Value *status = BB.CreateCall(StatusFn);
    Value *stat4 = BB.CreateCall(StatFn);
    foldFlag(BB, State, BB.CreateICmpNE(status, ConstantInt::get(i32, 0)),
             0x64C2D0B6D8F44A2DULL, "morok.antidbg.watch.status");
    foldState(BB, State, stat4, 0x8CB92BA72F3D8DD7ULL,
              "morok.antidbg.watch.stat4");
    if (watchBuddy) {
        BB.CreateBr(buddyCheckBB);

        IRBuilder<> CB(buddyCheckBB);
        auto *pid = CB.CreateLoad(ip, BuddyPid, "morok.antidbg.buddy.pid.load");
        pid->setVolatile(true);
        CB.CreateCondBr(
            CB.CreateICmpSGT(pid, ConstantInt::get(ip, 1),
                             "morok.antidbg.buddy.pid.valid"),
            buddyLiveBB, buddyMissingBB);

        IRBuilder<> BuddyB(buddyLiveBB);
        Value *killRc =
            emitLinuxSyscall(BuddyB, M, TT, killNr,
                             {pid, ConstantInt::get(ip, 0)});
        killRc->setName("morok.antidbg.buddy.kill");
        Value *waitRc = emitLinuxSyscall(
            BuddyB, M, TT, wait4Nr,
            {pid, buddyStatus, ConstantInt::get(ip, 1),
             ConstantPointerNull::get(ptr)});
        waitRc->setName("morok.antidbg.buddy.wait");
        Value *missing = BuddyB.CreateOr(
            BuddyB.CreateICmpNE(killRc, ConstantInt::get(ip, 0)),
            BuddyB.CreateICmpEQ(waitRc, pid), "morok.antidbg.buddy.missing");
        foldState(BuddyB, State, waitRc, 0x5B47E91D2C806A3FULL,
                  "morok.antidbg.buddy.wait");
        BuddyB.CreateCondBr(missing, buddyMissingBB, nextBB);

        IRBuilder<> MissingB(buddyMissingBB);
        foldFlag(MissingB, State, ConstantInt::getTrue(ctx),
                 0xDF0E7318A649C2B5ULL, "morok.antidbg.buddy.missing");
        if (SentinelActive) {
            auto *inactive = MissingB.CreateStore(ConstantInt::getFalse(ctx),
                                                  SentinelActive);
            inactive->setVolatile(true);
            inactive->setAlignment(Align(1));
            if (AllowSelfTrace)
                emitLinuxSelfTraceFallback(MissingB, M, State, SentinelActive,
                                           TT,
                                           "morok.antidbg.buddy.ptrace",
                                           0x3E42A7168C9D50BFULL);
        }
        MissingB.CreateBr(nextBB);

        IRBuilder<> NB(nextBB);
        Value *next =
            NB.CreateAdd(iter, ConstantInt::get(i32, 1), "morok.antidbg.next");
        NB.CreateBr(loopBB);
        iter->addIncoming(next, nextBB);
    } else {
        Value *next = BB.CreateAdd(iter, ConstantInt::get(i32, 1));
        BB.CreateBr(loopBB);
        iter->addIncoming(next, bodyBB);
    }

    IRBuilder<> RB(retBB);
    RB.CreateRet(ConstantPointerNull::get(ptr));
    return fn;
}

bool linuxDrSentinelSyscalls(const Triple &TT, std::uint32_t &Fork,
                             std::uint32_t &Getppid, std::uint32_t &Getdents64,
                             std::uint32_t &Wait4, std::uint32_t &Nanosleep,
                             std::uint32_t &Exit) {
    if (TT.getArch() != Triple::x86_64)
        return false;
    Fork = 57;
    Getppid = 110;
    Getdents64 = 217;
    Wait4 = 61;
    Nanosleep = 35;
    Exit = 60;
    return true;
}

bool linuxBuddyLivenessSyscalls(const Triple &TT, std::uint32_t &Kill,
                                std::uint32_t &Wait4) {
    if (TT.getArch() != Triple::x86_64)
        return false;
    Kill = 62;
    Wait4 = 61;
    return true;
}

Value *emitLinuxPtraceRaw(IRBuilder<> &B, Module &M, const Triple &TT,
                          std::uint64_t Request, Value *Pid, Value *Addr,
                          Value *Data, const Twine &Name) {
    std::uint32_t ptraceNr = 0;
    std::uint32_t prctlNr = 0;
    std::uint32_t openatNr = 0;
    std::uint32_t readNr = 0;
    std::uint32_t closeNr = 0;
    auto *ip = intPtrTy(M);
    if (!linuxCoreSyscalls(TT, ptraceNr, prctlNr, openatNr, readNr, closeNr))
        return ConstantInt::getSigned(ip, -1);
    Value *rc = emitLinuxSyscall(
        B, M, TT, ptraceNr, {ConstantInt::get(ip, Request), Pid, Addr, Data});
    rc->setName(Name);
    return rc;
}

Function *linuxDrScrubThread(Module &M, const Triple &TT) {
    if (Function *existing = M.getFunction("morok.antidbg.linux.dr.scrub"))
        return existing;
    std::uint32_t forkNr = 0;
    std::uint32_t getppidNr = 0;
    std::uint32_t getdentsNr = 0;
    std::uint32_t wait4Nr = 0;
    std::uint32_t nanosleepNr = 0;
    std::uint32_t exitNr = 0;
    if (!linuxDrSentinelSyscalls(TT, forkNr, getppidNr, getdentsNr, wait4Nr,
                                 nanosleepNr, exitNr))
        return nullptr;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(i64, {ip, ip, ip}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antidbg.linux.dr.scrub", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    Argument *tid = fn->getArg(0);
    tid->setName("tid");
    Argument *leader = fn->getArg(1);
    leader->setName("leader");
    Argument *mirrorTarget = fn->getArg(2);
    mirrorTarget->setName("mirror.target");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *seizeBB = BasicBlock::Create(ctx, "seize", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);
    IRBuilder<> B(entry);
    B.CreateCondBr(B.CreateICmpSGT(tid, ConstantInt::get(ip, 1)), seizeBB,
                   retBB);

    IRBuilder<> SB(seizeBB);
    Value *seize =
        emitLinuxPtraceRaw(SB, M, TT, 0x4206, tid, ConstantInt::get(ip, 0),
                           ConstantInt::get(ip, 0), "morok.antidbg.dr.seize");
    Value *interrupt = emitLinuxPtraceRaw(SB, M, TT, 0x4207, tid,
                                          ConstantInt::get(ip, 0),
                                          ConstantInt::get(ip, 0),
                                          "morok.antidbg.dr.interrupt");
    auto *pokeBB = BasicBlock::Create(ctx, "poke", fn);
    SB.CreateCondBr(SB.CreateICmpEQ(interrupt, ConstantInt::get(ip, 0)), pokeBB,
                    retBB);

    IRBuilder<> PB(pokeBB);
    auto *status = PB.CreateAlloca(i32, nullptr, "morok.antidbg.dr.status");
    Value *waitRc = emitLinuxSyscall(
        PB, M, TT, wait4Nr,
        {tid, status, ConstantInt::get(ip, 0), ConstantPointerNull::get(ptr)});
    waitRc->setName("morok.antidbg.dr.wait");
    Value *acc = PB.CreateXor(PB.CreateZExtOrTrunc(waitRc, i64),
                              PB.CreateZExtOrTrunc(seize, i64),
                              "morok.antidbg.dr.acc");
    acc = PB.CreateXor(acc, PB.CreateZExtOrTrunc(interrupt, i64),
                       "morok.antidbg.dr.acc.interrupt");
    Value *canInspect = PB.CreateAnd(
        PB.CreateICmpEQ(waitRc, tid),
        PB.CreateICmpEQ(interrupt, ConstantInt::get(ip, 0)),
        "morok.antidbg.buddy.inspect");
    constexpr std::uint64_t kDebugReg0Offset = 848;
    Value *allZeroed = ConstantInt::getTrue(ctx);
    for (std::uint64_t i = 0; i < 8; ++i) {
        Value *rc = emitLinuxPtraceRaw(
            PB, M, TT, 6, tid, ConstantInt::get(ip, kDebugReg0Offset + i * 8),
            ConstantInt::get(ip, 0), "morok.antidbg.dr.poke");
        allZeroed = PB.CreateAnd(
            allZeroed, PB.CreateICmpEQ(rc, ConstantInt::get(ip, 0)),
            "morok.negative.dr.zero.acc");
        acc = PB.CreateXor(acc, PB.CreateZExtOrTrunc(rc, i64),
                           "morok.antidbg.dr.acc.poke");
    }
    Value *drNotZeroed =
        PB.CreateNot(allZeroed, "morok.negative.dr.notzero");
    acc = PB.CreateXor(acc, PB.CreateZExt(drNotZeroed, i64),
                       "morok.antidbg.dr.acc.negative");
    Value *mirrorDiff = ConstantInt::getFalse(ctx);
    for (std::uint64_t i = 0; i < 4; ++i) {
        Value *addr =
            PB.CreateAdd(mirrorTarget, ConstantInt::get(ip, i * 8),
                         "morok.antidbg.buddy.addr");
        Value *remote =
            emitLinuxPtraceRaw(PB, M, TT, 2, tid, addr, ConstantInt::get(ip, 0),
                               "morok.antidbg.buddy.peek");
        auto *local =
            loadUnaligned(PB, ip, PB.CreateIntToPtr(addr, ptr),
                          "morok.antidbg.buddy.local");
        local->setVolatile(true);
        mirrorDiff = PB.CreateOr(
            mirrorDiff, PB.CreateICmpNE(remote, local),
            "morok.antidbg.buddy.mirror.diff");
    }
    Value *mirrorBad = PB.CreateAnd(
        PB.CreateAnd(canInspect, PB.CreateICmpEQ(tid, leader)),
        mirrorDiff, "morok.antidbg.buddy.mirror.bad");
    Value *cont =
        emitLinuxPtraceRaw(PB, M, TT, 7, tid, ConstantInt::get(ip, 0),
                           ConstantInt::get(ip, 0), "morok.antidbg.dr.cont");
    acc = PB.CreateXor(acc, PB.CreateZExtOrTrunc(cont, i64),
                       "morok.antidbg.dr.acc.cont");
    Value *drBad =
        PB.CreateAnd(canInspect, drNotZeroed, "morok.antidbg.buddy.dr.bad");
    Value *bad = PB.CreateOr(drBad, mirrorBad, "morok.antidbg.buddy.bad");
    PB.CreateRet(PB.CreateZExt(bad, i64));

    IRBuilder<> RB(retBB);
    RB.CreateRet(ConstantInt::get(i64, 0));
    return fn;
}

Function *linuxDrSentinelProcess(Module &M, ir::IRRandom &rng,
                                 const Triple &TT) {
    if (Function *existing = M.getFunction("morok.antidbg.linux.dr.sentinel"))
        return existing;
    std::uint32_t forkNr = 0;
    std::uint32_t getppidNr = 0;
    std::uint32_t getdentsNr = 0;
    std::uint32_t wait4Nr = 0;
    std::uint32_t nanosleepNr = 0;
    std::uint32_t exitNr = 0;
    if (!linuxDrSentinelSyscalls(TT, forkNr, getppidNr, getdentsNr, wait4Nr,
                                 nanosleepNr, exitNr))
        return nullptr;
    Function *scrub = linuxDrScrubThread(M, TT);
    if (!scrub)
        return nullptr;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i16 = Type::getInt16Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(Type::getVoidTy(ctx), false),
                                GlobalValue::PrivateLinkage,
                                "morok.antidbg.linux.dr.sentinel", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *loopBB = BasicBlock::Create(ctx, "loop", fn);
    auto *bodyBB = BasicBlock::Create(ctx, "body", fn);
    auto *openOkBB = BasicBlock::Create(ctx, "open.ok", fn);
    auto *readBB = BasicBlock::Create(ctx, "read", fn);
    auto *scanLoopBB = BasicBlock::Create(ctx, "scan.loop", fn);
    auto *scanBodyBB = BasicBlock::Create(ctx, "scan.body", fn);
    auto *scanNextBB = BasicBlock::Create(ctx, "scan.next", fn);
    auto *closeBB = BasicBlock::Create(ctx, "close", fn);
    auto *nextBB = BasicBlock::Create(ctx, "next", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    auto *pathTy = ArrayType::get(i8, 96);
    auto *dirTy = ArrayType::get(i8, 4096);
    auto *tsTy = StructType::get(ctx, {i64, i64});
    AllocaInst *path = B.CreateAlloca(pathTy, nullptr, "morok.antidbg.dr.path");
    AllocaInst *dirBuf =
        B.CreateAlloca(dirTy, nullptr, "morok.antidbg.dr.dirents");
    AllocaInst *ts = B.CreateAlloca(tsTy, nullptr, "morok.antidbg.dr.sleep");
    B.CreateStore(ConstantInt::get(i64, 0), B.CreateStructGEP(tsTy, ts, 0));
    B.CreateStore(ConstantInt::get(i64, 200000000),
                  B.CreateStructGEP(tsTy, ts, 1));
    Value *ppid = emitLinuxSyscall(B, M, TT, getppidNr, {});
    ppid->setName("morok.antidbg.dr.ppid");
    Function *mirrorFn = M.getFunction("main");
    if (!mirrorFn || mirrorFn->isDeclaration())
        mirrorFn = scrub;
    Value *mirrorTarget =
        B.CreatePtrToInt(mirrorFn, ip, "morok.antidbg.buddy.mirror");
    Value *pathPtr = B.CreateInBoundsGEP(
        pathTy, path, {ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)});
    Value *fmt = ir::emitCloakedSymbol(B, M, "/proc/%ld/task", rng);
    FunctionCallee snprintfFn = M.getOrInsertFunction(
        "snprintf", FunctionType::get(i32, {ptr, ip, ptr}, true));
    B.CreateCall(snprintfFn, {pathPtr, ConstantInt::get(ip, 96), fmt, ppid},
                 "morok.antidbg.dr.path.n");
    B.CreateBr(loopBB);

    IRBuilder<> LB(loopBB);
    auto *iter = LB.CreatePHI(i32, 2, "morok.antidbg.dr.iter");
    iter->addIncoming(ConstantInt::get(i32, 0), entry);
    LB.CreateCondBr(
        LB.CreateICmpULT(iter, ConstantInt::get(i32, kWatchdogMaxIterations),
                         "morok.antidbg.dr.keep"),
        bodyBB, retBB);

    IRBuilder<> BB(bodyBB);
    std::uint32_t ptraceNr = 0;
    std::uint32_t prctlNr = 0;
    std::uint32_t openatNr = 0;
    std::uint32_t readNr = 0;
    std::uint32_t closeNr = 0;
    linuxCoreSyscalls(TT, ptraceNr, prctlNr, openatNr, readNr, closeNr);
    Value *fdLong = emitLinuxSyscall(BB, M, TT, openatNr,
                                     {ConstantInt::getSigned(ip, -100), pathPtr,
                                      ConstantInt::get(ip, 0x10000),
                                      ConstantInt::get(ip, 0)});
    fdLong->setName("morok.antidbg.dr.fd");
    BB.CreateCondBr(BB.CreateICmpSGE(fdLong, ConstantInt::get(ip, 0)), openOkBB,
                    nextBB);

    IRBuilder<> OKB(openOkBB);
    OKB.CreateBr(readBB);

    IRBuilder<> RB(readBB);
    Value *bufPtr = RB.CreateInBoundsGEP(
        dirTy, dirBuf, {ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)});
    Value *nread = emitLinuxSyscall(
        RB, M, TT, getdentsNr, {fdLong, bufPtr, ConstantInt::get(ip, 4096)});
    nread->setName("morok.antidbg.dr.getdents");
    RB.CreateCondBr(RB.CreateICmpSGT(nread, ConstantInt::get(ip, 0)),
                    scanLoopBB, closeBB);

    IRBuilder<> SLB(scanLoopBB);
    auto *off = SLB.CreatePHI(ip, 2, "morok.antidbg.dr.dir.off");
    off->addIncoming(ConstantInt::get(ip, 0), readBB);
    SLB.CreateCondBr(SLB.CreateICmpULT(off, nread), scanBodyBB, readBB);

    IRBuilder<> SB(scanBodyBB);
    Value *reclenOff = SB.CreateAdd(off, ConstantInt::get(ip, 16),
                                    "morok.antidbg.dr.reclen.off");
    Value *reclen =
        loadAt(SB, M, i16, dirBuf, reclenOff, "morok.antidbg.dr.reclen");
    Value *nameBase = SB.CreateAdd(off, ConstantInt::get(ip, 19),
                                   "morok.antidbg.dr.name.off");
    Value *tid = ConstantInt::get(ip, 0);
    Value *active = ConstantInt::getTrue(ctx);
    Value *any = ConstantInt::getFalse(ctx);
    for (std::uint64_t i = 0; i < 12; ++i) {
        Value *ch = loadAt(SB, M, i8, dirBuf,
                           SB.CreateAdd(nameBase, ConstantInt::get(ip, i)),
                           "morok.antidbg.dr.name.ch");
        Value *ge0 = SB.CreateICmpUGE(ch, ConstantInt::get(i8, '0'));
        Value *le9 = SB.CreateICmpULE(ch, ConstantInt::get(i8, '9'));
        Value *digit = SB.CreateAnd(active, SB.CreateAnd(ge0, le9),
                                    "morok.antidbg.dr.name.digit");
        Value *dval = SB.CreateZExt(SB.CreateSub(ch, ConstantInt::get(i8, '0')),
                                    ip, "morok.antidbg.dr.name.dval");
        Value *nextTid =
            SB.CreateAdd(SB.CreateMul(tid, ConstantInt::get(ip, 10)), dval,
                         "morok.antidbg.dr.name.tid.next");
        tid = SB.CreateSelect(digit, nextTid, tid, "morok.antidbg.dr.name.tid");
        any = SB.CreateOr(any, digit, "morok.antidbg.dr.name.any");
        active = digit;
    }
    Value *validTid = SB.CreateAnd(any, SB.CreateICmpUGE(tid, ppid),
                                   "morok.antidbg.dr.tid.valid");
    Value *scrubTid = SB.CreateSelect(validTid, tid, ConstantInt::get(ip, 0),
                                      "morok.antidbg.dr.tid");
    Value *scrubBad = SB.CreateCall(scrub->getFunctionType(), scrub,
                                    {scrubTid, ppid, mirrorTarget},
                                    "morok.antidbg.buddy.scrub");
    auto *badBB = BasicBlock::Create(ctx, "buddy.bad", fn);
    SB.CreateCondBr(SB.CreateICmpNE(scrubBad, ConstantInt::get(i64, 0)), badBB,
                    scanNextBB);

    IRBuilder<> BadB(badBB);
    emitLinuxSyscall(BadB, M, TT, exitNr, {ConstantInt::get(ip, 77)});
    BadB.CreateUnreachable();

    IRBuilder<> SNB(scanNextBB);
    Value *safeReclen = SNB.CreateSelect(
        SNB.CreateICmpUGT(reclen, ConstantInt::get(i16, 0)),
        SNB.CreateZExt(reclen, ip), nread, "morok.antidbg.dr.reclen.safe");
    Value *nextOff =
        SNB.CreateAdd(off, safeReclen, "morok.antidbg.dr.dir.next");
    SNB.CreateBr(scanLoopBB);
    off->addIncoming(nextOff, scanNextBB);

    IRBuilder<> CB(closeBB);
    emitLinuxSyscall(CB, M, TT, closeNr, {fdLong});
    CB.CreateBr(nextBB);

    IRBuilder<> NB(nextBB);
    emitLinuxSyscall(NB, M, TT, nanosleepNr,
                     {ts, ConstantPointerNull::get(ptr)});
    Value *livePpid = emitLinuxSyscall(NB, M, TT, getppidNr, {});
    livePpid->setName("morok.antidbg.buddy.ppid.live");
    auto *parentGoneBB = BasicBlock::Create(ctx, "parent.gone", fn);
    auto *parentLiveBB = BasicBlock::Create(ctx, "parent.live", fn);
    NB.CreateCondBr(NB.CreateICmpSLE(livePpid, ConstantInt::get(ip, 1)),
                    parentGoneBB, parentLiveBB);

    IRBuilder<> GoneB(parentGoneBB);
    emitLinuxSyscall(GoneB, M, TT, exitNr, {ConstantInt::get(ip, 0)});
    GoneB.CreateUnreachable();

    IRBuilder<> LiveB(parentLiveBB);
    Value *next =
        LiveB.CreateAdd(iter, ConstantInt::get(i32, 1), "morok.antidbg.dr.next");
    LiveB.CreateBr(loopBB);
    iter->addIncoming(next, parentLiveBB);

    IRBuilder<> RetB(retBB);
    RetB.CreateRetVoid();
    return fn;
}

bool emitLinuxDrSentinelStart(IRBuilder<> &B, Module &M, GlobalVariable *State,
                              GlobalVariable *BuddyPid,
                              GlobalVariable *SentinelActive,
                              ir::IRRandom &rng, const Triple &TT) {
    std::uint32_t forkNr = 0;
    std::uint32_t getppidNr = 0;
    std::uint32_t getdentsNr = 0;
    std::uint32_t wait4Nr = 0;
    std::uint32_t nanosleepNr = 0;
    std::uint32_t exitNr = 0;
    if (!linuxDrSentinelSyscalls(TT, forkNr, getppidNr, getdentsNr, wait4Nr,
                                 nanosleepNr, exitNr))
        return false;
    Function *helper = linuxDrSentinelProcess(M, rng, TT);
    if (!helper || !BuddyPid || !SentinelActive)
        return false;

    LLVMContext &ctx = M.getContext();
    auto *ip = intPtrTy(M);
    Function *ctor = B.GetInsertBlock()->getParent();
    Value *pid = emitLinuxSyscall(B, M, TT, forkNr, {});
    pid->setName("morok.antidbg.dr.fork");
    foldState(B, State, pid, 0xD8A18F4C2E7B6A95ULL, "morok.antidbg.dr.fork");

    auto *childBB = BasicBlock::Create(ctx, "morok.antidbg.dr.child", ctor);
    auto *parentBB = BasicBlock::Create(ctx, "morok.antidbg.dr.parent", ctor);
    auto *setPtracerBB =
        BasicBlock::Create(ctx, "morok.antidbg.dr.ptracer", ctor);
    auto *contBB = BasicBlock::Create(ctx, "morok.antidbg.dr.cont", ctor);
    B.CreateCondBr(B.CreateICmpEQ(pid, ConstantInt::get(ip, 0)), childBB,
                   parentBB);

    IRBuilder<> ChildB(childBB);
    Value *childDumpable = emitLinuxPrctl(ChildB, M, TT, 4, 0, 0, 0, 0);
    childDumpable->setName("morok.antidbg.dr.child.dumpable");
    Value *childPtracer =
        emitLinuxPrctl(ChildB, M, TT, 0x59616D61, 0, 0, 0, 0);
    childPtracer->setName("morok.antidbg.dr.child.ptracer");
    Value *childNoNewPrivs = emitLinuxPrctl(ChildB, M, TT, 38, 1, 0, 0, 0);
    childNoNewPrivs->setName("morok.antidbg.dr.child.no_new_privs");
    ChildB.CreateCall(helper->getFunctionType(), helper, {});
    emitLinuxSyscall(ChildB, M, TT, exitNr, {ConstantInt::get(ip, 0)});
    ChildB.CreateUnreachable();

    IRBuilder<> ParentB(parentBB);
    auto *buddyStore = ParentB.CreateStore(pid, BuddyPid);
    buddyStore->setVolatile(true);
    auto *inactive =
        ParentB.CreateStore(ConstantInt::getFalse(ctx), SentinelActive);
    inactive->setVolatile(true);
    inactive->setAlignment(Align(1));
    ParentB.CreateCondBr(
        ParentB.CreateICmpSGT(pid, ConstantInt::get(ip, 0),
                              "morok.antidbg.dr.pid.valid"),
        setPtracerBB, contBB);

    IRBuilder<> PB(setPtracerBB);
    std::uint32_t ptraceNr = 0;
    std::uint32_t prctlNr = 0;
    std::uint32_t openatNr = 0;
    std::uint32_t readNr = 0;
    std::uint32_t closeNr = 0;
    linuxCoreSyscalls(TT, ptraceNr, prctlNr, openatNr, readNr, closeNr);
    Value *prctlRc = emitLinuxSyscall(
        PB, M, TT, prctlNr,
        {ConstantInt::get(ip, 0x59616D61), pid, ConstantInt::get(ip, 0),
         ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)});
    prctlRc->setName("morok.antidbg.dr.ptracer.rc");
    // PR_SET_PTRACER can be denied by Yama, seccomp, or container policy on a
    // clean host.  That denial disables the DR sentinel; later /proc checks
    // provide the corroborated debugger evidence that may poison State.
    Value *ptracerRestricted =
        PB.CreateICmpNE(prctlRc, ConstantInt::get(ip, 0),
                        "morok.antidbg.dr.ptracer.restricted");
    Value *ptracerOk =
        PB.CreateNot(ptracerRestricted, "morok.antidbg.dr.ptracer.ok");
    auto *activeStore = PB.CreateStore(ptracerOk, SentinelActive);
    activeStore->setVolatile(true);
    activeStore->setAlignment(Align(1));
    PB.CreateBr(contBB);

    B.SetInsertPoint(contBB);
    return true;
}

void emitLinuxHardening(IRBuilder<> &B, Module &M, const Triple &TT,
                        bool PreservePtracer = false) {
    emitLinuxPrctl(B, M, TT, 4, 0, 0, 0, 0);          // PR_SET_DUMPABLE
    if (!PreservePtracer)
        emitLinuxPrctl(B, M, TT, 0x59616D61, 0, 0, 0, 0); // PR_SET_PTRACER
    emitLinuxPrctl(B, M, TT, 38, 1, 0, 0, 0);         // PR_SET_NO_NEW_PRIVS
}

bool linuxSyscallNumbers(const Triple &TT, std::uint32_t &Ptrace,
                         std::uint32_t &ProcessVmReadv,
                         std::uint32_t &ProcessVmWritev) {
    switch (TT.getArch()) {
    case Triple::x86_64:
        Ptrace = 101;
        ProcessVmReadv = 310;
        ProcessVmWritev = 311;
        return true;
    case Triple::aarch64:
        Ptrace = 117;
        ProcessVmReadv = 270;
        ProcessVmWritev = 271;
        return true;
    default:
        return false;
    }
}

bool linuxSeccompInstall(const Triple &TT, std::uint32_t &Seccomp,
                         std::uint32_t &AuditArch, bool &RejectX32) {
    switch (TT.getArch()) {
    case Triple::x86_64:
        Seccomp = 317;
        AuditArch = 0xC000003E; // AUDIT_ARCH_X86_64
        RejectX32 = true;
        return true;
    case Triple::aarch64:
        Seccomp = 277;
        AuditArch = 0xC00000B7; // AUDIT_ARCH_AARCH64
        RejectX32 = false;
        return true;
    default:
        return false;
    }
}

bool linuxLandlockSyscalls(const Triple &TT, std::uint32_t &CreateRuleset,
                           std::uint32_t &RestrictSelf) {
    switch (TT.getArch()) {
    case Triple::x86_64:
    case Triple::aarch64:
        CreateRuleset = 444;
        RestrictSelf = 446;
        return true;
    default:
        return false;
    }
}

void emitLinuxLandlockSandbox(IRBuilder<> &B, Module &M, GlobalVariable *State,
                              const Triple &TT) {
    std::uint32_t createRulesetNr = 0;
    std::uint32_t restrictSelfNr = 0;
    if (!linuxLandlockSyscalls(TT, createRulesetNr, restrictSelfNr))
        return;

    LLVMContext &ctx = M.getContext();
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    Function *ctor = B.GetInsertBlock()->getParent();

    constexpr std::uint32_t kCreateRulesetVersion = 1;
    constexpr std::uint64_t kWriteFile = 1ULL << 1;
    constexpr std::uint64_t kRemoveDir = 1ULL << 4;
    constexpr std::uint64_t kRemoveFile = 1ULL << 5;
    constexpr std::uint64_t kMakeChar = 1ULL << 6;
    constexpr std::uint64_t kMakeDir = 1ULL << 7;
    constexpr std::uint64_t kMakeReg = 1ULL << 8;
    constexpr std::uint64_t kMakeSock = 1ULL << 9;
    constexpr std::uint64_t kMakeFifo = 1ULL << 10;
    constexpr std::uint64_t kMakeBlock = 1ULL << 11;
    constexpr std::uint64_t kMakeSym = 1ULL << 12;
    constexpr std::uint64_t kRefer = 1ULL << 13;
    constexpr std::uint64_t kTruncate = 1ULL << 14;
    constexpr std::uint64_t kIoctlDev = 1ULL << 15;
    constexpr std::uint64_t kBaseHandled =
        kWriteFile | kRemoveDir | kRemoveFile | kMakeChar | kMakeDir |
        kMakeReg | kMakeSock | kMakeFifo | kMakeBlock | kMakeSym;

    Value *version = emitLinuxSyscall(
        B, M, TT, createRulesetNr,
        {ConstantPointerNull::get(ptr), ConstantInt::get(ip, 0),
         ConstantInt::get(ip, kCreateRulesetVersion)});
    version->setName("morok.landlock.abi");
    foldState(B, State, version, 0x3A1E58C96D2740B5ULL, "morok.landlock.abi");

    auto *applyBB = BasicBlock::Create(ctx, "morok.landlock.apply", ctor);
    auto *contBB = BasicBlock::Create(ctx, "morok.landlock.cont", ctor);
    B.CreateCondBr(B.CreateICmpSGT(version, ConstantInt::get(ip, 0)), applyBB,
                   contBB);

    IRBuilder<> LB(applyBB);
    Value *handled = ConstantInt::get(i64, kBaseHandled);
    handled =
        LB.CreateSelect(LB.CreateICmpUGE(version, ConstantInt::get(ip, 2)),
                        LB.CreateOr(handled, ConstantInt::get(i64, kRefer)),
                        handled, "morok.landlock.handled.refer");
    handled =
        LB.CreateSelect(LB.CreateICmpUGE(version, ConstantInt::get(ip, 3)),
                        LB.CreateOr(handled, ConstantInt::get(i64, kTruncate)),
                        handled, "morok.landlock.handled.truncate");
    handled =
        LB.CreateSelect(LB.CreateICmpUGE(version, ConstantInt::get(ip, 5)),
                        LB.CreateOr(handled, ConstantInt::get(i64, kIoctlDev)),
                        handled, "morok.landlock.handled.ioctl");

    auto *attrTy = StructType::get(i64);
    auto *attr =
        LB.CreateAlloca(attrTy, nullptr, "morok.landlock.ruleset.attr");
    LB.CreateStore(handled, LB.CreateStructGEP(attrTy, attr, 0));

    Value *fd = emitLinuxSyscall(
        LB, M, TT, createRulesetNr,
        {attr, ConstantInt::get(ip, 8), ConstantInt::get(ip, 0)});
    fd->setName("morok.landlock.fd");
    Value *restrictRc = emitLinuxSyscall(LB, M, TT, restrictSelfNr,
                                         {fd, ConstantInt::get(ip, 0)});
    restrictRc->setName("morok.landlock.restrict");
    foldState(LB, State, fd, 0x7124D8C90AE53B6FULL, "morok.landlock.fd");
    foldState(LB, State, restrictRc, 0xE95B2D47A6813C0BULL,
              "morok.landlock.restrict");
    foldFlag(LB, State,
             LB.CreateICmpEQ(restrictRc, ConstantInt::getSigned(ip, 0)),
             0xC64FB9182D70A5E3ULL, "morok.landlock.active");
    std::uint32_t ptraceNr = 0;
    std::uint32_t prctlNr = 0;
    std::uint32_t openatNr = 0;
    std::uint32_t readNr = 0;
    std::uint32_t closeNr = 0;
    if (linuxCoreSyscalls(TT, ptraceNr, prctlNr, openatNr, readNr, closeNr))
        emitLinuxSyscall(LB, M, TT, closeNr, {fd});
    else
        LB.CreateCall(closeDecl(M),
                      {LB.CreateTruncOrBitCast(fd, LB.getInt32Ty())});
    LB.CreateBr(contBB);

    B.SetInsertPoint(contBB);
}

void emitLinuxSeccompFilter(IRBuilder<> &B, Module &M, const Triple &TT,
                            bool AllowSelfTrace) {
    std::uint32_t ptraceNr = 0;
    std::uint32_t readvNr = 0;
    std::uint32_t writevNr = 0;
    if (!linuxSyscallNumbers(TT, ptraceNr, readvNr, writevNr))
        return;
    std::uint32_t seccompNr = 0;
    std::uint32_t auditArch = 0;
    bool rejectX32 = false;
    if (!linuxSeccompInstall(TT, seccompNr, auditArch, rejectX32))
        return;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i16 = Type::getInt16Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);

    constexpr std::uint16_t kBpfLdWAbs = 0x20;
    constexpr std::uint16_t kBpfJmpJeqK = 0x15;
    constexpr std::uint16_t kBpfAluAndK = 0x54;
    constexpr std::uint16_t kBpfRetK = 0x06;
    constexpr std::uint32_t kSeccompDataNr = 0;
    constexpr std::uint32_t kSeccompDataArch = 4;
    constexpr std::uint32_t kSeccompRetKillProcess = 0x80000000U;
    constexpr std::uint32_t kSeccompRetAllow = 0x7fff0000U;
    constexpr std::uint32_t kSeccompSetModeFilter = 1;
    constexpr std::uint32_t kSeccompFilterFlagTsync = 1;
    constexpr std::uint32_t kX32SyscallBit = 0x40000000U;
    constexpr std::uint32_t kFilterCapacity = 17;

    auto *filterTy = StructType::get(ctx, {i16, i8, i8, i32});
    auto *filtersTy = ArrayType::get(filterTy, kFilterCapacity);
    auto *progTy = StructType::get(ctx, {i16, ptr});
    auto *filters =
        B.CreateAlloca(filtersTy, nullptr, "morok.antidbg.seccomp.filters");
    auto *prog = B.CreateAlloca(progTy, nullptr, "morok.antidbg.seccomp.prog");

    auto storeFilter = [&](std::uint32_t index, std::uint16_t code,
                           std::uint8_t jt, std::uint8_t jf, std::uint32_t k) {
        Value *slot = B.CreateInBoundsGEP(
            filtersTy, filters,
            {ConstantInt::get(ip, 0), ConstantInt::get(ip, index)});
        B.CreateStore(ConstantInt::get(i16, code),
                      B.CreateStructGEP(filterTy, slot, 0));
        B.CreateStore(ConstantInt::get(i8, jt),
                      B.CreateStructGEP(filterTy, slot, 1));
        B.CreateStore(ConstantInt::get(i8, jf),
                      B.CreateStructGEP(filterTy, slot, 2));
        B.CreateStore(ConstantInt::get(i32, k),
                      B.CreateStructGEP(filterTy, slot, 3));
    };
    std::uint32_t filterCount = 0;
    auto appendFilter = [&](std::uint16_t code, std::uint8_t jt,
                            std::uint8_t jf, std::uint32_t k) {
        storeFilter(filterCount++, code, jt, jf, k);
    };

    appendFilter(kBpfLdWAbs, 0, 0, kSeccompDataArch);
    appendFilter(kBpfJmpJeqK, 1, 0, auditArch);
    appendFilter(kBpfRetK, 0, 0, kSeccompRetKillProcess);
    if (rejectX32) {
        appendFilter(kBpfLdWAbs, 0, 0, kSeccompDataNr);
        appendFilter(kBpfAluAndK, 0, 0, kX32SyscallBit);
        appendFilter(kBpfJmpJeqK, 1, 0, 0);
        appendFilter(kBpfRetK, 0, 0, kSeccompRetKillProcess);
    }
    appendFilter(kBpfLdWAbs, 0, 0, kSeccompDataNr);
    if (AllowSelfTrace) {
        constexpr std::uint32_t kSeccompDataArg0 = 16;
        constexpr std::uint32_t kPtraceTraceme = 0;
        appendFilter(kBpfJmpJeqK, 0, 3, ptraceNr);
        appendFilter(kBpfLdWAbs, 0, 0, kSeccompDataArg0);
        appendFilter(kBpfJmpJeqK, 5, 0, kPtraceTraceme);
        appendFilter(kBpfRetK, 0, 0, kSeccompRetKillProcess);
        appendFilter(kBpfLdWAbs, 0, 0, kSeccompDataNr);
        appendFilter(kBpfJmpJeqK, 1, 0, readvNr);
        appendFilter(kBpfJmpJeqK, 0, 1, writevNr);
        appendFilter(kBpfRetK, 0, 0, kSeccompRetKillProcess);
    } else {
        appendFilter(kBpfJmpJeqK, 2, 0, ptraceNr);
        appendFilter(kBpfJmpJeqK, 1, 0, readvNr);
        appendFilter(kBpfJmpJeqK, 0, 1, writevNr);
        appendFilter(kBpfRetK, 0, 0, kSeccompRetKillProcess);
    }
    appendFilter(kBpfRetK, 0, 0, kSeccompRetAllow);

    Value *filterPtr = B.CreateInBoundsGEP(
        filtersTy, filters, {ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)});
    B.CreateStore(ConstantInt::get(i16, filterCount),
                  B.CreateStructGEP(progTy, prog, 0));
    B.CreateStore(filterPtr, B.CreateStructGEP(progTy, prog, 1));

    Value *rc = emitLinuxSyscall(
        B, M, TT, seccompNr,
        {ConstantInt::get(ip, kSeccompSetModeFilter),
         ConstantInt::get(ip, kSeccompFilterFlagTsync), prog});
    rc->setName("morok.antidbg.seccomp.tsync");
}

void emitLinuxWatcherStart(IRBuilder<> &B, Module &M, Function *WatchFn) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    Function *ctor = B.GetInsertBlock()->getParent();

    FunctionCallee pthreadCreate = M.getOrInsertFunction(
        "pthread_create", FunctionType::get(i32, {ptr, ptr, ptr, ptr}, false));
    FunctionCallee pthreadDetach = M.getOrInsertFunction(
        "pthread_detach", FunctionType::get(i32, {ip}, false));

    AllocaInst *thread = B.CreateAlloca(ip, nullptr, "morok.antidbg.thread");
    Value *rc =
        B.CreateCall(pthreadCreate, {thread, ConstantPointerNull::get(ptr),
                                     WatchFn, ConstantPointerNull::get(ptr)});
    Value *ok = B.CreateICmpEQ(rc, ConstantInt::get(i32, 0));

    auto *detachBB = BasicBlock::Create(ctx, "detach", ctor);
    auto *contBB = BasicBlock::Create(ctx, "cont", ctor);
    B.CreateCondBr(ok, detachBB, contBB);

    IRBuilder<> DB(detachBB);
    Value *tid = DB.CreateLoad(ip, thread);
    DB.CreateCall(pthreadDetach, {tid});
    DB.CreateBr(contBB);

    B.SetInsertPoint(contBB);
}

Function *antiDebugProbe(Module &M, GlobalVariable *State, ir::IRRandom &rng,
                         const Triple &TT);

Function *probeWatchThread(Module &M, Function *Probe, GlobalVariable *Heartbeat,
                           ir::IRRandom &rng) {
    if (Function *existing = M.getFunction("morok.antidbg.probe.watch"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);

    auto *fn = Function::Create(FunctionType::get(ptr, {ptr}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antidbg.probe.watch", &M);
    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *loopBB = BasicBlock::Create(ctx, "loop", fn);
    auto *bodyBB = BasicBlock::Create(ctx, "body", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);
    const std::uint32_t cadenceMul =
        static_cast<std::uint32_t>(rng.next() | 1ULL);
    const std::uint32_t cadenceAdd =
        static_cast<std::uint32_t>((rng.next() | 1ULL) & 0xffffu);
    const std::uint64_t beatMul = rng.next() | 1ULL;
    const std::uint64_t beatSalt = rng.next();

    IRBuilder<> EB(entry);
    EB.CreateBr(loopBB);

    IRBuilder<> LB(loopBB);
    auto *iter = LB.CreatePHI(i32, 2, "morok.antidbg.probe.iter");
    iter->addIncoming(ConstantInt::get(i32, 0), entry);
    LB.CreateCondBr(
        LB.CreateICmpULT(iter, ConstantInt::get(i32, kWatchdogMaxIterations)),
        bodyBB, retBB);

    IRBuilder<> BB(bodyBB);
    FunctionCallee sleepFn =
        M.getOrInsertFunction("sleep", FunctionType::get(i32, {i32}, false));
    Value *cadence = BB.CreateAdd(
        BB.CreateAnd(BB.CreateAdd(BB.CreateMul(iter, ConstantInt::get(i32, cadenceMul)),
                                  ConstantInt::get(i32, cadenceAdd)),
                     ConstantInt::get(i32, 3)),
        ConstantInt::get(i32, 1), "morok.watchdog.cadence");
    BB.CreateCall(sleepFn, {cadence});
    Value *tag = BB.CreateAdd(BB.CreateZExt(iter, i64),
                              ConstantInt::get(i64, 0xD14B2E3520B47A11ULL),
                              "morok.antidbg.probe.watch.tag");
    BB.CreateCall(Probe->getFunctionType(), Probe, {tag});
    auto *oldBeat = BB.CreateLoad(i64, Heartbeat, "morok.watchdog.heartbeat.old");
    oldBeat->setVolatile(true);
    oldBeat->setAtomic(AtomicOrdering::Monotonic);
    oldBeat->setAlignment(Align(8));
    Value *beat = BB.CreateXor(
        BB.CreateAdd(BB.CreateMul(oldBeat, ConstantInt::get(i64, beatMul)), tag),
        ConstantInt::get(i64, beatSalt), "morok.watchdog.heartbeat.beat");
    auto *beatStore = BB.CreateStore(beat, Heartbeat);
    beatStore->setVolatile(true);
    beatStore->setAtomic(AtomicOrdering::Monotonic);
    beatStore->setAlignment(Align(8));
    Value *next = BB.CreateAdd(iter, ConstantInt::get(i32, 1));
    BB.CreateBr(loopBB);
    iter->addIncoming(next, bodyBB);

    IRBuilder<> RB(retBB);
    RB.CreateRet(ConstantPointerNull::get(ptr));
    return fn;
}

Function *heartbeatWatchThread(Module &M, GlobalVariable *State,
                               GlobalVariable *Heartbeat,
                               GlobalVariable *Crypto, ir::IRRandom &rng) {
    if (Function *existing = M.getFunction("morok.watchdog.heartbeat.watch"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(ptr, {ptr}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.watchdog.heartbeat.watch", &M);
    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *loopBB = BasicBlock::Create(ctx, "loop", fn);
    auto *bodyBB = BasicBlock::Create(ctx, "body", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);
    const std::uint32_t cadenceMul =
        static_cast<std::uint32_t>(rng.next() | 1ULL);
    const std::uint32_t cadenceAdd =
        static_cast<std::uint32_t>((rng.next() | 1ULL) & 0xffffu);

    IRBuilder<> EB(entry);
    auto *initialBeat =
        EB.CreateLoad(i64, Heartbeat, "morok.watchdog.heartbeat.initial");
    initialBeat->setVolatile(true);
    initialBeat->setAtomic(AtomicOrdering::Monotonic);
    initialBeat->setAlignment(Align(8));
    EB.CreateBr(loopBB);

    IRBuilder<> LB(loopBB);
    auto *iter = LB.CreatePHI(i32, 2, "morok.watchdog.heartbeat.iter");
    auto *last = LB.CreatePHI(i64, 2, "morok.watchdog.heartbeat.last");
    auto *staleCount = LB.CreatePHI(i32, 2, "morok.watchdog.heartbeat.stale");
    iter->addIncoming(ConstantInt::get(i32, 0), entry);
    last->addIncoming(initialBeat, entry);
    staleCount->addIncoming(ConstantInt::get(i32, 0), entry);
    LB.CreateCondBr(
        LB.CreateICmpULT(iter, ConstantInt::get(i32, kWatchdogMaxIterations)),
        bodyBB, retBB);

    IRBuilder<> BB(bodyBB);
    FunctionCallee sleepFn =
        M.getOrInsertFunction("sleep", FunctionType::get(i32, {i32}, false));
    Value *cadence = BB.CreateAdd(
        BB.CreateAnd(BB.CreateAdd(BB.CreateMul(iter, ConstantInt::get(i32, cadenceMul)),
                                  ConstantInt::get(i32, cadenceAdd)),
                     ConstantInt::get(i32, 3)),
        ConstantInt::get(i32, 2), "morok.watchdog.heartbeat.cadence");
    Value *sleepLeft =
        BB.CreateCall(sleepFn, {cadence},
                      "morok.watchdog.heartbeat.sleep.left");
    Value *sleepComplete = BB.CreateICmpEQ(
        sleepLeft, ConstantInt::get(i32, 0),
        "morok.watchdog.heartbeat.sleep.complete");
    auto *cur = BB.CreateLoad(i64, Heartbeat, "morok.watchdog.heartbeat.cur");
    cur->setVolatile(true);
    cur->setAtomic(AtomicOrdering::Monotonic);
    cur->setAlignment(Align(8));
    Value *armed =
        BB.CreateICmpNE(last, ConstantInt::get(i64, 0), "morok.watchdog.armed");
    Value *sampleStable = BB.CreateAnd(
        sleepComplete, BB.CreateICmpEQ(cur, last),
        "morok.watchdog.heartbeat.sample.stable");
    Value *stale = BB.CreateAnd(armed, sampleStable,
                                "morok.watchdog.heartbeat.same");
    Value *staleNext = BB.CreateSelect(
        stale, BB.CreateAdd(staleCount, ConstantInt::get(i32, 1)),
        ConstantInt::get(i32, 0), "morok.watchdog.heartbeat.stale.next");
    Value *missing = BB.CreateICmpUGE(
        staleNext, ConstantInt::get(i32, kWatchdogCryptoStaleThreshold),
        "morok.watchdog.heartbeat.missing");
    foldState(BB, State, cur, 0x35A8F179C46D20B3ULL,
              "morok.watchdog.heartbeat.sample");
    foldFlag(BB, State, missing, 0xC7D2841AF09B53E6ULL,
             "morok.watchdog.heartbeat.missing");
    auto *cryptoOld =
        BB.CreateLoad(i64, Crypto, "morok.watchdog.crypto.old");
    cryptoOld->setVolatile(true);
    cryptoOld->setAtomic(AtomicOrdering::Monotonic);
    cryptoOld->setAlignment(Align(8));
    Value *cryptoDrift = BB.CreateXor(
        BB.CreateMul(cur, ConstantInt::get(i64, rng.next() | 1ULL)),
        BB.CreateAdd(BB.CreateZExt(staleNext, i64),
                     ConstantInt::get(i64, rng.next())),
        "morok.watchdog.crypto.drift");
    Value *cryptoNext = BB.CreateSelect(
        missing, BB.CreateXor(cryptoOld, cryptoDrift),
        cryptoOld, "morok.watchdog.crypto.next");
    auto *cryptoStore = BB.CreateStore(cryptoNext, Crypto);
    cryptoStore->setVolatile(true);
    cryptoStore->setAtomic(AtomicOrdering::Monotonic);
    cryptoStore->setAlignment(Align(8));
    Value *next = BB.CreateAdd(iter, ConstantInt::get(i32, 1));
    BB.CreateBr(loopBB);
    iter->addIncoming(next, bodyBB);
    last->addIncoming(cur, bodyBB);
    staleCount->addIncoming(staleNext, bodyBB);

    IRBuilder<> RB(retBB);
    RB.CreateRet(ConstantPointerNull::get(ptr));
    return fn;
}

void emitAntiDebugWatchdogStart(Module &M, Function *Probe, GlobalVariable *State,
                                ir::IRRandom &rng, const Triple &TT) {
    if (!TT.isOSLinux() && !TT.isOSDarwin())
        return;
    GlobalVariable *heartbeat = antiDebugWatchdogHeartbeat(M, rng);
    GlobalVariable *crypto = watchdogCryptoState(M);
    Function *probeWatch = probeWatchThread(M, Probe, heartbeat, rng);
    Function *heartbeatWatch = heartbeatWatchThread(M, State, heartbeat,
                                                    crypto, rng);
    Function *ctor = makeCtorShell(M, "morok.watchdog");
    IRBuilder<> B(&ctor->getEntryBlock());
    emitLinuxWatcherStart(B, M, probeWatch);
    emitLinuxWatcherStart(B, M, heartbeatWatch);
    B.CreateRetVoid();
    appendToGlobalCtors(M, ctor, 0);
}

void emitLinuxAntiDebug(Module &M, Function *Ctor, GlobalVariable *State,
                        ir::IRRandom &rng, const Triple &TT,
                        bool AllowSelfTrace, bool StartLiveWatchers) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    IRBuilder<> B(&Ctor->getEntryBlock());

    GlobalVariable *buddyPid = nullptr;
    GlobalVariable *drActive = nullptr;
    bool drSentinel = false;
    if (StartLiveWatchers) {
        buddyPid = antiDebugBuddyPid(M);
        drActive = antiDebugDrActive(M);
        drSentinel =
            emitLinuxDrSentinelStart(B, M, State, buddyPid, drActive, rng, TT);
        if (!drSentinel) {
            buddyPid = nullptr;
            drActive = nullptr;
        }
    }
    emitLinuxHardening(B, M, TT, drSentinel);
    if (AllowSelfTrace)
        emitLinuxSelfTraceFallback(B, M, State, drActive, TT,
                                   "morok.antidbg.ptrace.init",
                                   0x3D2D7F2BAE63D5C9ULL);

    Function *statusFn = linuxStatusTracerCheck(M, rng, TT);
    Function *statFn = linuxStatField4Check(M, rng, TT);
    Value *status = B.CreateCall(statusFn);
    Value *stat4 = B.CreateCall(statFn);
    foldFlag(B, State, B.CreateICmpNE(status, ConstantInt::get(i32, 0)),
             0xA4756E49F2D31219ULL, "morok.antidbg.status");
    foldState(B, State, stat4, 0xDA942042E4DD58B5ULL, "morok.antidbg.stat4");
    emitLinuxLandlockSandbox(B, M, State, TT);
    emitLinuxSeccompFilter(B, M, TT, AllowSelfTrace);

    if (StartLiveWatchers) {
        Function *watch = linuxWatchThread(M, statusFn, statFn, State, buddyPid,
                                           drActive, TT, AllowSelfTrace);
        emitLinuxWatcherStart(B, M, watch);
    }
    B.CreateRetVoid();
}

void emitDarwinSysctlCheck(IRBuilder<> &B, Module &M, GlobalVariable *State,
                           const Triple &TT) {
    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);

    auto *mibTy = ArrayType::get(i32, 4);
    auto *mib = B.CreateAlloca(mibTy, nullptr, "morok.antidbg.mib");
    auto storeMib = [&](std::uint32_t idx, Value *V) {
        B.CreateStore(V, B.CreateInBoundsGEP(mibTy, mib,
                                             {ConstantInt::get(ip, 0),
                                              ConstantInt::get(ip, idx)}));
    };
    storeMib(0, ConstantInt::get(i32, 1));  // CTL_KERN
    storeMib(1, ConstantInt::get(i32, 14)); // KERN_PROC
    storeMib(2, ConstantInt::get(i32, 1));  // KERN_PROC_PID
    storeMib(3, emitDarwinGetpid(B, M, TT));

    constexpr std::uint64_t kKinfoProcBytes = 648;
    constexpr std::uint64_t kPFlagOffset = 32;
    auto *bufTy = ArrayType::get(i8, kKinfoProcBytes);
    auto *buf = B.CreateAlloca(bufTy, nullptr, "morok.antidbg.kinfo");
    auto *len = B.CreateAlloca(ip, nullptr, "morok.antidbg.kinfo.len");
    B.CreateStore(ConstantInt::get(ip, kKinfoProcBytes), len);
    Value *pflagPtr = B.CreateInBoundsGEP(
        bufTy, buf,
        {ConstantInt::get(ip, 0), ConstantInt::get(ip, kPFlagOffset)});
    B.CreateStore(ConstantInt::get(i32, 0), pflagPtr);

    Value *mibPtr = B.CreateInBoundsGEP(
        mibTy, mib, {ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)});
    Value *bufPtr = B.CreateInBoundsGEP(
        bufTy, buf, {ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)});
    Value *rc = emitDarwinSysctl(B, M, TT, mibPtr, ConstantInt::get(i32, 4),
                                 bufPtr, len, ConstantPointerNull::get(ptr),
                                 ConstantInt::get(ip, 0));
    Value *pflag = B.CreateLoad(i32, pflagPtr);
    Value *traced =
        B.CreateICmpNE(B.CreateAnd(pflag, ConstantInt::get(i32, 0x800)),
                       ConstantInt::get(i32, 0));
    Value *ok = B.CreateICmpEQ(rc, ConstantInt::get(i32, 0));
    Value *tracedFlag = B.CreateAnd(ok, traced);
    foldFlag(B, State, tracedFlag, 0xBD6A33A5F07A4E31ULL, "morok.antidbg.sysctl");
    sealFold(B, tracedFlag, 0xBD6A33A5F07A4E31ULL);

    // M5: parent-identity check.  e_ppid sits at offset 560 of the kinfo just
    // read; re-query the PARENT's kinfo and compare its p_comm (offset 243) to
    // debugger launchers.  We key on the parent NAME, not ppid==1 — a normal
    // shell/CLI launch has a shell parent (ppid != 1), so a launchd check would
    // false-positive; "debugserver"/"lldb" are absent on a clean run.
    constexpr std::uint64_t kEppidOffset = 560;
    constexpr std::uint64_t kPCommOffset = 243;
    Value *eppidPtr = B.CreateInBoundsGEP(
        bufTy, buf, {ConstantInt::get(ip, 0), ConstantInt::get(ip, kEppidOffset)});
    Value *eppid = B.CreateLoad(i32, eppidPtr);
    storeMib(3, eppid);
    B.CreateStore(ConstantInt::get(ip, kKinfoProcBytes), len);
    Value *rc2 = emitDarwinSysctl(B, M, TT, mibPtr, ConstantInt::get(i32, 4),
                                  bufPtr, len, ConstantPointerNull::get(ptr),
                                  ConstantInt::get(ip, 0));
    Value *pcommPtr = B.CreateInBoundsGEP(
        bufTy, buf, {ConstantInt::get(ip, 0), ConstantInt::get(ip, kPCommOffset)});
    Value *pcomm8 = B.CreateAlignedLoad(B.getInt64Ty(), pcommPtr, Align(1));
    // "debugser" (prefix of debugserver) and "lldb\0\0\0\0", little-endian.
    Value *isDbgsrv =
        B.CreateICmpEQ(pcomm8, ConstantInt::get(B.getInt64Ty(), 0x7265736775626564ULL));
    Value *isLldb =
        B.CreateICmpEQ(pcomm8, ConstantInt::get(B.getInt64Ty(), 0x0000000062646c6cULL));
    Value *ok2 = B.CreateICmpEQ(rc2, ConstantInt::get(i32, 0));
    Value *dbgParent = B.CreateAnd(ok2, B.CreateOr(isDbgsrv, isLldb));
    foldFlag(B, State, dbgParent, 0x53A1D7F0C46B82E9ULL, "morok.antidbg.ppid");
    sealFold(B, dbgParent, 0x53A1D7F0C46B82E9ULL);
}

void emitDarwinCsopsCheck(IRBuilder<> &B, Module &M, GlobalVariable *State,
                          const Triple &TT) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);

    auto *status = B.CreateAlloca(i32, nullptr, "morok.antidbg.cs");
    B.CreateStore(ConstantInt::get(i32, 0), status);
    Value *rc = emitDarwinCsops(B, M, TT, emitDarwinGetpid(B, M, TT),
                                ConstantInt::get(i32, 0), status,
                                ConstantInt::get(ip, 4));
    Value *flags = B.CreateLoad(i32, status);
    Value *debugged =
        B.CreateICmpNE(B.CreateAnd(flags, ConstantInt::get(i32, 0x10000000)),
                       ConstantInt::get(i32, 0));
    Value *ok = B.CreateICmpEQ(rc, ConstantInt::get(i32, 0));
    Value *dbgFlag = B.CreateAnd(ok, debugged);
    foldFlag(B, State, dbgFlag, 0xF1D88C6C72195307ULL, "morok.antidbg.csops");
    sealFold(B, dbgFlag, 0xF1D88C6C72195307ULL);
}

void emitDarwinDyldCensus(IRBuilder<> &B, Module &M, GlobalVariable *State,
                          ir::IRRandom &rng) {
    LLVMContext &ctx = M.getContext();
    auto *ptr = PointerType::getUnqual(ctx);
    FunctionCallee getenv =
        M.getOrInsertFunction("getenv", FunctionType::get(ptr, {ptr}, false));

    constexpr std::array<StringLiteral, 8> names = {
        StringLiteral("DYLD_INSERT_LIBRARIES"),
        StringLiteral("DYLD_PRINT_LIBRARIES"),
        StringLiteral("DYLD_PRINT_APIS"),
        StringLiteral("DYLD_PRINT_BINDINGS"),
        StringLiteral("DYLD_PRINT_INITIALIZERS"),
        StringLiteral("DYLD_PRINT_SEGMENTS"),
        StringLiteral("DYLD_PRINT_STATISTICS"),
        StringLiteral("DYLD_PRINT_RPATHS"),
    };
    constexpr std::array<std::uint64_t, 8> salts = {
        0x7758194AE9A77863ULL, 0xB4B38D68C02F02A5ULL, 0x219CA03416830A21ULL,
        0x1B8E6F5EA72EF761ULL, 0x5CA7FB879A46141DULL, 0x87C23393A30D56A9ULL,
        0xE4B80E501C94AB33ULL, 0xC09D8F3BA1F6C6EFULL,
    };

    for (std::size_t i = 0; i < names.size(); ++i) {
        Value *name = ir::emitCloakedSymbol(B, M, names[i], rng);
        Value *found = B.CreateICmpNE(B.CreateCall(getenv, {name}),
                                      ConstantPointerNull::get(ptr));
        foldFlag(B, State, found, salts[i], "morok.antidbg.dyld");
        foldPoisonFlag(B, found, salts[i] ^ 0x7DA3B94C6E1025F1ULL,
                       "morok.antianalysis.dyld");
        // Any DYLD_* instrumentation var is absent on a clean run, so binding it
        // into the verdict seal is safe and corrupts an injected/keygen run.
        sealFold(B, found, salts[i]);
    }
}

// M3: enumerate loaded images and flag any that is NOT the main executable
// (index 0) and whose path is not under /usr/lib/ or /System/Library/.  An
// injected dylib (the keygen ships one via DYLD_INSERT_LIBRARIES) loads from an
// arbitrary path and is caught even if the attacker scrubs the DYLD_* env var.
// Folded into the seal so the foreign image silently poisons the verdict.
void emitDarwinImageCensus(IRBuilder<> &B, Module &M, GlobalVariable *State) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);
    FunctionCallee imgCount =
        M.getOrInsertFunction("_dyld_image_count", FunctionType::get(i32, false));
    FunctionCallee imgName = M.getOrInsertFunction(
        "_dyld_get_image_name", FunctionType::get(ptr, {i32}, false));

    Function *F = B.GetInsertBlock()->getParent();
    Value *count = B.CreateCall(imgCount, {}, "morok.imgcensus.count");
    BasicBlock *pre = B.GetInsertBlock();
    BasicBlock *loop = BasicBlock::Create(ctx, "morok.imgcensus.loop", F);
    BasicBlock *done = BasicBlock::Create(ctx, "morok.imgcensus.done", F);
    // Skip index 0 (the main executable, whose path is arbitrary).
    B.CreateCondBr(B.CreateICmpUGT(count, ConstantInt::get(i32, 1)), loop, done);

    IRBuilder<> LB(loop);
    PHINode *i = LB.CreatePHI(i32, 2, "morok.imgcensus.i");
    i->addIncoming(ConstantInt::get(i32, 1), pre);
    Value *name = LB.CreateCall(imgName, {i}, "morok.imgcensus.name");
    // First 8 bytes of the path; dyld paths are long, so an 8-byte read is in
    // bounds within the contiguous load-command string table.
    Value *first8 = LB.CreateAlignedLoad(i64, name, Align(1));
    Value *isUsrLib = // "/usr/lib"
        LB.CreateICmpEQ(first8, ConstantInt::get(i64, 0x62696c2f7273752fULL));
    Value *isSystem = // "/System/"
        LB.CreateICmpEQ(first8, ConstantInt::get(i64, 0x2f6d65747379532fULL));
    Value *foreign = LB.CreateNot(LB.CreateOr(isUsrLib, isSystem));
    foldFlag(LB, State, foreign, 0x2D9E64B0A7135CC1ULL, "morok.antidbg.image");
    foldPoisonFlag(LB, foreign, 0xE57A2C6819D403BFULL,
                   "morok.antianalysis.image");
    sealFold(LB, foreign, 0x2D9E64B0A7135CC1ULL);
    Value *next = LB.CreateAdd(i, ConstantInt::get(i32, 1), "morok.imgcensus.next");
    i->addIncoming(next, loop);
    LB.CreateCondBr(LB.CreateICmpULT(next, count), loop, done);

    B.SetInsertPoint(done);
}

bool darwinDebugStateShape(const Triple &TT, std::uint32_t &Flavor,
                           std::uint32_t &Count32, std::uint32_t &Words64) {
    switch (TT.getArch()) {
    case Triple::x86_64:
        Flavor = 11;  // x86_DEBUG_STATE64
        Count32 = 16; // sizeof(x86_debug_state64_t) / sizeof(int)
        Words64 = 8;
        return true;
    case Triple::aarch64:
        Flavor = 15;   // ARM_DEBUG_STATE64
        Count32 = 130; // sizeof(arm_debug_state64_t) / sizeof(uint32_t)
        Words64 = 65;
        return true;
    default:
        return false;
    }
}

Function *darwinDrScrubThread(Module &M, const Triple &TT) {
    if (Function *existing = M.getFunction("morok.antidbg.darwin.dr.scrub"))
        return existing;
    std::uint32_t flavor = 0;
    std::uint32_t count32 = 0;
    std::uint32_t words64 = 0;
    if (!darwinDebugStateShape(TT, flavor, count32, words64))
        return nullptr;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *stateTy = ArrayType::get(i64, words64);
    auto *fn = Function::Create(FunctionType::get(i32, {i32}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antidbg.darwin.dr.scrub", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    Argument *thread = fn->getArg(0);
    thread->setName("thread");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *clearBB = BasicBlock::Create(ctx, "clear", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);
    IRBuilder<> B(entry);
    AllocaInst *state =
        B.CreateAlloca(stateTy, nullptr, "morok.antidbg.dr.state");
    AllocaInst *count = B.CreateAlloca(i32, nullptr, "morok.antidbg.dr.count");
    B.CreateStore(ConstantInt::get(i32, count32), count);
    Value *statePtr = B.CreateInBoundsGEP(
        stateTy, state, {ConstantInt::get(i32, 0), ConstantInt::get(i32, 0)},
        "morok.antidbg.dr.state.ptr");
    FunctionCallee getState = M.getOrInsertFunction(
        "thread_get_state",
        FunctionType::get(i32, {i32, i32, ptr, ptr}, false));
    FunctionCallee setState = M.getOrInsertFunction(
        "thread_set_state",
        FunctionType::get(i32, {i32, i32, ptr, i32}, false));
    Value *getRc = B.CreateCall(
        getState, {thread, ConstantInt::get(i32, flavor), statePtr, count},
        "morok.antidbg.dr.thread.get");
    B.CreateCondBr(B.CreateICmpEQ(getRc, ConstantInt::get(i32, 0)), clearBB,
                   retBB);

    IRBuilder<> CB(clearBB);
    for (std::uint32_t i = 0; i < words64; ++i) {
        Value *slot = CB.CreateInBoundsGEP(
            stateTy, state,
            {ConstantInt::get(i32, 0), ConstantInt::get(i32, i)},
            "morok.antidbg.dr.slot");
        auto *store = CB.CreateStore(ConstantInt::get(i64, 0), slot);
        store->setVolatile(true);
    }
    Value *setRc = CB.CreateCall(setState,
                                 {thread, ConstantInt::get(i32, flavor),
                                  statePtr, ConstantInt::get(i32, count32)},
                                 "morok.antidbg.dr.thread.set");
    CB.CreateBr(retBB);

    IRBuilder<> RB(retBB);
    auto *rc = RB.CreatePHI(i32, 2, "morok.antidbg.dr.rc");
    rc->addIncoming(getRc, entry);
    rc->addIncoming(setRc, clearBB);
    RB.CreateRet(rc);
    return fn;
}

Function *darwinDrWatchThread(Module &M, const Triple &TT) {
    if (Function *existing = M.getFunction("morok.antidbg.darwin.dr.watch"))
        return existing;
    Function *scrub = darwinDrScrubThread(M, TT);
    if (!scrub)
        return nullptr;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(ptr, {ptr}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antidbg.darwin.dr.watch", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *loopBB = BasicBlock::Create(ctx, "loop", fn);
    auto *bodyBB = BasicBlock::Create(ctx, "body", fn);
    auto *scanBB = BasicBlock::Create(ctx, "scan", fn);
    auto *threadBB = BasicBlock::Create(ctx, "thread", fn);
    auto *threadNextBB = BasicBlock::Create(ctx, "thread.next", fn);
    auto *deallocBB = BasicBlock::Create(ctx, "dealloc", fn);
    auto *nextBB = BasicBlock::Create(ctx, "next", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    AllocaInst *threads =
        B.CreateAlloca(ptr, nullptr, "morok.antidbg.dr.threads");
    AllocaInst *count =
        B.CreateAlloca(i32, nullptr, "morok.antidbg.dr.thread.count");
    B.CreateStore(ConstantPointerNull::get(ptr), threads);
    B.CreateStore(ConstantInt::get(i32, 0), count);
    B.CreateBr(loopBB);

    IRBuilder<> LB(loopBB);
    auto *iter = LB.CreatePHI(i32, 2, "morok.antidbg.dr.iter");
    iter->addIncoming(ConstantInt::get(i32, 0), entry);
    LB.CreateCondBr(LB.CreateICmpULT(iter, ConstantInt::get(i32, 8)), bodyBB,
                    retBB);

    IRBuilder<> BB(bodyBB);
    FunctionCallee sleepFn =
        M.getOrInsertFunction("sleep", FunctionType::get(i32, {i32}, false));
    BB.CreateCall(sleepFn, {ConstantInt::get(i32, 1)});
    GlobalVariable *selfGV =
        cast<GlobalVariable>(M.getOrInsertGlobal("mach_task_self_", i32));
    Value *task = BB.CreateLoad(i32, selfGV, "morok.antidbg.dr.task");
    FunctionCallee taskThreads = M.getOrInsertFunction(
        "task_threads", FunctionType::get(i32, {i32, ptr, ptr}, false));
    Value *taskRc = BB.CreateCall(taskThreads, {task, threads, count},
                                  "morok.antidbg.dr.task.threads");
    BB.CreateCondBr(BB.CreateICmpEQ(taskRc, ConstantInt::get(i32, 0)), scanBB,
                    nextBB);

    IRBuilder<> SB(scanBB);
    Value *nthreads = SB.CreateLoad(i32, count, "morok.antidbg.dr.thread.n");
    Value *threadArray =
        SB.CreateLoad(ptr, threads, "morok.antidbg.dr.thread.array");
    SB.CreateCondBr(SB.CreateICmpNE(threadArray, ConstantPointerNull::get(ptr)),
                    threadBB, nextBB);

    IRBuilder<> TB(threadBB);
    auto *idx = TB.CreatePHI(i32, 2, "morok.antidbg.dr.thread.idx");
    idx->addIncoming(ConstantInt::get(i32, 0), scanBB);
    TB.CreateCondBr(TB.CreateICmpULT(idx, nthreads), threadNextBB, deallocBB);

    IRBuilder<> TNB(threadNextBB);
    Value *threadSlot =
        TNB.CreateGEP(i32, threadArray, {idx}, "morok.antidbg.dr.thread.ptr");
    Value *thread = TNB.CreateLoad(i32, threadSlot, "morok.antidbg.dr.thread");
    TNB.CreateCall(scrub->getFunctionType(), scrub, {thread});
    Value *nextThread = TNB.CreateAdd(idx, ConstantInt::get(i32, 1),
                                      "morok.antidbg.dr.thread.next");
    TNB.CreateBr(threadBB);
    idx->addIncoming(nextThread, threadNextBB);

    IRBuilder<> DB(deallocBB);
    FunctionCallee vmDeallocate = M.getOrInsertFunction(
        "vm_deallocate", FunctionType::get(i32, {i32, ip, ip}, false));
    Value *bytes =
        DB.CreateMul(DB.CreateZExt(nthreads, ip), ConstantInt::get(ip, 4),
                     "morok.antidbg.dr.thread.bytes");
    DB.CreateCall(vmDeallocate,
                  {task, DB.CreatePtrToInt(threadArray, ip), bytes},
                  "morok.antidbg.dr.vm.deallocate");
    DB.CreateBr(nextBB);

    IRBuilder<> NB(nextBB);
    Value *next =
        NB.CreateAdd(iter, ConstantInt::get(i32, 1), "morok.antidbg.dr.next");
    NB.CreateBr(loopBB);
    iter->addIncoming(next, nextBB);

    IRBuilder<> RB(retBB);
    RB.CreateRet(ConstantPointerNull::get(ptr));
    return fn;
}

void emitDarwinAntiDebug(Module &M, Function *Ctor, GlobalVariable *State,
                         ir::IRRandom &rng, const Triple &TT,
                         bool StartLiveWatchers) {
    IRBuilder<> B(&Ctor->getEntryBlock());
    // PT_DENY_ATTACH via direct svc (no imported ptrace to interpose).  Bind its
    // result to the verdict: it returns 0 on an untraced process, so a nonzero
    // return (already traced, or a forced result) folds into the seal and poisons
    // the verdict rather than being discarded.
    Value *ptraceRc = emitDarwinPtrace(B, M, TT, 31);
    sealFold(B,
             B.CreateICmpNE(ptraceRc, ConstantInt::get(ptraceRc->getType(), 0)),
             0x9C2F71A6E5B30D4FULL);
    emitDarwinSysctlCheck(B, M, State, TT);
    emitDarwinCsopsCheck(B, M, State, TT);
    emitDarwinDyldCensus(B, M, State, rng);
    emitDarwinImageCensus(B, M, State);
    if (StartLiveWatchers) {
        if (Function *drWatch = darwinDrWatchThread(M, TT))
            emitLinuxWatcherStart(B, M, drWatch);
    }
    B.CreateRetVoid();
}

void emitRetDiff(IRBuilder<> &B, AllocaInst *Diff) {
    auto *load = B.CreateLoad(B.getInt64Ty(), Diff, "morok.clean.diff.ret");
    load->setVolatile(true);
    B.CreateRet(load);
}

void emitByteDiffLoop(IRBuilder<> &B, Module &M, Function *Fn, Value *MemAddr,
                      Value *CleanPtr, Value *Len, AllocaInst *Diff,
                      BasicBlock *Done) {
    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);

    auto *loopBB = BasicBlock::Create(ctx, "morok.clean.byte.loop", Fn);
    auto *bodyBB = BasicBlock::Create(ctx, "morok.clean.byte.body", Fn);
    B.CreateBr(loopBB);

    IRBuilder<> LB(loopBB);
    auto *idx = LB.CreatePHI(ip, 2, "morok.clean.byte.idx");
    idx->addIncoming(ConstantInt::get(ip, 0), B.GetInsertBlock());
    LB.CreateCondBr(LB.CreateICmpULT(idx, Len), bodyBB, Done);

    IRBuilder<> BB(bodyBB);
    Value *memPtr =
        BB.CreateIntToPtr(BB.CreateAdd(MemAddr, idx, "morok.clean.mem.addr"),
                          ptr, "morok.clean.mem.ptr");
    auto *memByte = BB.CreateLoad(i8, memPtr, "morok.clean.mem.byte");
    memByte->setVolatile(true);
    Value *cleanByte =
        BB.CreateLoad(i8, gepI8(BB, M, CleanPtr, idx, "morok.clean.file.ptr"),
                      "morok.clean.file.byte");
    Value *foreignInt3 = BB.CreateAnd(
        BB.CreateICmpEQ(memByte, ConstantInt::get(i8, 0xCC)),
        BB.CreateICmpNE(cleanByte, ConstantInt::get(i8, 0xCC)),
        "morok.negative.text.int3");
    incrementDiff(BB, Diff, foreignInt3, "morok.negative.text.int3.hit");
    incrementDiff(BB, Diff, BB.CreateICmpNE(memByte, cleanByte),
                  "morok.clean.byte.diff");
    Value *next =
        BB.CreateAdd(idx, ConstantInt::get(ip, 1), "morok.clean.byte.next");
    BB.CreateBr(loopBB);
    idx->addIncoming(next, bodyBB);
}

void emitFunctionMacLoop(IRBuilder<> &B, Module &M, Function *Fn,
                         Value *MemAddr, Value *CleanPtr, Value *Len,
                         AllocaInst *Diff, GlobalVariable *Targets,
                         std::uint64_t Key, BasicBlock *Done);

Function *linuxCleanCopyProbe(Module &M, ir::IRRandom &rng, const Triple &TT) {
    if (!TT.isOSLinux())
        return nullptr;
    if (intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.antihook.clean.elf"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i16 = Type::getInt16Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    GlobalVariable *macTargets =
        M.getGlobalVariable("morok.antihook.mac.targets",
                            /*AllowInternal=*/true);
    const std::uint64_t macKey = rng.next();

    auto *fn = Function::Create(FunctionType::get(i64, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.clean.elf", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *openBB = BasicBlock::Create(ctx, "open", fn);
    auto *sizeBB = BasicBlock::Create(ctx, "size", fn);
    auto *badSizeBB = BasicBlock::Create(ctx, "bad.size", fn);
    auto *mapBB = BasicBlock::Create(ctx, "map", fn);
    auto *badMapBB = BasicBlock::Create(ctx, "bad.map", fn);
    auto *parseBB = BasicBlock::Create(ctx, "parse", fn);
    auto *badElfBB = BasicBlock::Create(ctx, "bad.elf", fn);
    auto *phLoopBB = BasicBlock::Create(ctx, "ph.loop", fn);
    auto *phBodyBB = BasicBlock::Create(ctx, "ph.body", fn);
    auto *phCompareBB = BasicBlock::Create(ctx, "ph.compare", fn);
    auto *phNextBB = BasicBlock::Create(ctx, "ph.next", fn);
    auto *unmapBB = BasicBlock::Create(ctx, "unmap", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    auto *pathTy = ArrayType::get(i8, 4096);
    AllocaInst *path = B.CreateAlloca(pathTy, nullptr, "morok.clean.path");
    AllocaInst *diff = B.CreateAlloca(i64, nullptr, "morok.clean.diff");
    B.CreateStore(ConstantInt::get(i64, 0), diff)->setVolatile(true);
    Value *pathBuf = B.CreateInBoundsGEP(
        pathTy, path, {ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)},
        "morok.clean.path.buf");
    Value *selfPath = ir::emitCloakedSymbol(B, M, "/proc/self/exe", rng);
    Value *pathLen = emitLinuxReadlink(B, M, TT, selfPath, pathBuf,
                                       ConstantInt::get(ip, 4095));
    Value *lenOk =
        B.CreateAnd(B.CreateICmpSGT(pathLen, ConstantInt::get(ip, 0)),
                    B.CreateICmpULT(pathLen, ConstantInt::get(ip, 4095)));
    B.CreateCondBr(lenOk, openBB, retBB);

    IRBuilder<> OB(openBB);
    OB.CreateStore(ConstantInt::get(i8, 0),
                   gepI8(OB, M, pathBuf, pathLen, "morok.clean.path.nul"));
    std::uint32_t ptraceNr = 0;
    std::uint32_t prctlNr = 0;
    std::uint32_t openatNr = 0;
    std::uint32_t readNr = 0;
    std::uint32_t closeNr = 0;
    Value *fdLong = nullptr;
    if (linuxCoreSyscalls(TT, ptraceNr, prctlNr, openatNr, readNr, closeNr)) {
        fdLong = emitLinuxSyscall(OB, M, TT, openatNr,
                                  {constSignedIp(M, -100), pathBuf,
                                   ConstantInt::get(i32, 0),
                                   ConstantInt::get(i32, 0)});
    } else {
        fdLong = OB.CreateSExtOrTrunc(
            OB.CreateCall(openDecl(M), {pathBuf, ConstantInt::get(i32, 0)}),
            ip);
    }
    Value *fd = OB.CreateTruncOrBitCast(fdLong, i32, "morok.clean.fd");
    OB.CreateCondBr(OB.CreateICmpSLT(fd, ConstantInt::getSigned(i32, 0)), retBB,
                    sizeBB);

    IRBuilder<> SB(sizeBB);
    Value *fileSize = emitLinuxLseek(SB, M, TT, fd, 0, 2 /* SEEK_END */);
    SB.CreateCondBr(SB.CreateICmpSGT(fileSize, ConstantInt::get(ip, 64)), mapBB,
                    badSizeBB);

    IRBuilder<> BSB(badSizeBB);
    emitLinuxClose(BSB, M, TT, fd);
    BSB.CreateBr(retBB);

    IRBuilder<> MB(mapBB);
    Value *mapAddr = emitLinuxMmapAddr(MB, M, TT, fileSize, fd);
    emitLinuxClose(MB, M, TT, fd);
    Value *mapFailed =
        MB.CreateOr(MB.CreateICmpSLT(mapAddr, ConstantInt::getSigned(ip, 0)),
                    MB.CreateICmpEQ(mapAddr, ConstantInt::get(ip, 0)));
    MB.CreateCondBr(mapFailed, badMapBB, parseBB);

    IRBuilder<> BMB(badMapBB);
    BMB.CreateBr(retBB);

    IRBuilder<> PB(parseBB);
    Value *mapPtr = PB.CreateIntToPtr(mapAddr, ptr, "morok.clean.map.ptr");
    Value *magic = loadAt(PB, M, i32, mapPtr, 0ULL, "morok.clean.elf.magic");
    Value *elfType = loadAt(PB, M, i16, mapPtr, 16, "morok.clean.elf.type");
    Value *isElf64 = PB.CreateICmpEQ(magic, ConstantInt::get(i32, 0x464C457F));
    Value *phOff = loadAt(PB, M, i64, mapPtr, 32, "morok.clean.elf.phoff");
    Value *phEntRaw =
        loadAt(PB, M, i16, mapPtr, 54, "morok.clean.elf.phentsize");
    Value *phNumRaw = loadAt(PB, M, i16, mapPtr, 56, "morok.clean.elf.phnum");
    Value *phEnt = PB.CreateZExt(phEntRaw, ip, "morok.clean.elf.phent");
    Value *phNum = PB.CreateZExt(phNumRaw, ip, "morok.clean.elf.phnum.w");
    FunctionCallee getauxval =
        M.getOrInsertFunction("getauxval", FunctionType::get(ip, {ip}, false));
    Value *atPhdr = PB.CreateCall(getauxval, {ConstantInt::get(ip, 3)},
                                  "morok.clean.atphdr");
    Value *phBytes = PB.CreateMul(phEnt, phNum, "morok.clean.elf.phbytes");
    Value *phEnd = PB.CreateAdd(phOff, phBytes, "morok.clean.elf.phend");
    Value *validPh =
        PB.CreateAnd(PB.CreateICmpUGE(phEnt, ConstantInt::get(ip, 56)),
                     PB.CreateICmpULE(phEnd, fileSize));
    Value *valid = PB.CreateAnd(
        isElf64, PB.CreateAnd(validPh, PB.CreateICmpNE(
                                           atPhdr, ConstantInt::get(ip, 0))));
    PB.CreateCondBr(valid, phLoopBB, badElfBB);

    IRBuilder<> BEB(badElfBB);
    BEB.CreateBr(unmapBB);

    IRBuilder<> PLB(phLoopBB);
    auto *phIdx = PLB.CreatePHI(ip, 2, "morok.clean.ph.idx");
    phIdx->addIncoming(ConstantInt::get(ip, 0), parseBB);
    PLB.CreateCondBr(PLB.CreateICmpULT(phIdx, phNum), phBodyBB, unmapBB);

    IRBuilder<> PBB(phBodyBB);
    Value *phPtr = gepI8(
        PBB, M, mapPtr,
        PBB.CreateAdd(phOff, PBB.CreateMul(phIdx, phEnt), "morok.clean.ph.off"),
        "morok.clean.ph.ptr");
    Value *pType = loadAt(PBB, M, i32, phPtr, 0ULL, "morok.clean.ph.type");
    Value *pFlags = loadAt(PBB, M, i32, phPtr, 4, "morok.clean.ph.flags");
    Value *pOffset = loadAt(PBB, M, i64, phPtr, 8, "morok.clean.ph.fileoff");
    Value *pVaddr = loadAt(PBB, M, i64, phPtr, 16, "morok.clean.ph.vaddr");
    Value *pFilesz = loadAt(PBB, M, i64, phPtr, 32, "morok.clean.ph.filesz");
    Value *isLoad = PBB.CreateICmpEQ(pType, ConstantInt::get(i32, 1),
                                     "morok.clean.ph.load");
    Value *isExec =
        PBB.CreateICmpNE(PBB.CreateAnd(pFlags, ConstantInt::get(i32, 1)),
                         ConstantInt::get(i32, 0), "morok.clean.ph.exec");
    Value *hasBytes = PBB.CreateICmpUGT(pFilesz, ConstantInt::get(ip, 0),
                                        "morok.clean.ph.bytes");
    Value *fileEnd = PBB.CreateAdd(pOffset, pFilesz, "morok.clean.ph.fileend");
    Value *inFile =
        PBB.CreateICmpULE(fileEnd, fileSize, "morok.clean.ph.infile");
    Value *shouldCompare =
        PBB.CreateAnd(PBB.CreateAnd(isLoad, isExec),
                      PBB.CreateAnd(hasBytes, inFile), "morok.clean.ph.should");
    PBB.CreateCondBr(shouldCompare, phCompareBB, phNextBB);

    IRBuilder<> PCB(phCompareBB);
    Value *dynLoadBase = PCB.CreateSub(atPhdr, phOff, "morok.clean.load.base");
    Value *loadBase = PCB.CreateSelect(
        PCB.CreateICmpEQ(elfType, ConstantInt::get(i16, 3)), dynLoadBase,
        ConstantInt::get(ip, 0), "morok.clean.load.bias");
    Value *memAddr = PCB.CreateAdd(loadBase, pVaddr, "morok.clean.ph.mem.addr");
    Value *cleanPtr =
        gepI8(PCB, M, mapPtr, pOffset, "morok.clean.ph.clean.ptr");
    auto *afterMacBB = BasicBlock::Create(ctx, "morok.clean.mac.done", fn);
    emitFunctionMacLoop(PCB, M, fn, memAddr, cleanPtr, pFilesz, diff,
                        macTargets, macKey, afterMacBB);
    IRBuilder<> AMB(afterMacBB);
    emitByteDiffLoop(AMB, M, fn, memAddr, cleanPtr, pFilesz, diff, phNextBB);

    IRBuilder<> PNB(phNextBB);
    Value *phNext =
        PNB.CreateAdd(phIdx, ConstantInt::get(ip, 1), "morok.clean.ph.next");
    PNB.CreateBr(phLoopBB);
    phIdx->addIncoming(phNext, phNextBB);

    IRBuilder<> UB(unmapBB);
    emitLinuxMunmap(UB, M, TT, mapAddr, fileSize);
    UB.CreateBr(retBB);

    IRBuilder<> RB(retBB);
    emitRetDiff(RB, diff);
    return fn;
}

Function *darwinCleanCopyProbe(Module &M, ir::IRRandom &rng) {
    const Triple TT(M.getTargetTriple());
    if (!TT.isOSDarwin())
        return nullptr;
    if (intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.antihook.clean.macho"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    GlobalVariable *macTargets =
        M.getGlobalVariable("morok.antihook.mac.targets",
                            /*AllowInternal=*/true);
    const std::uint64_t macKey = rng.next();

    auto *fn = Function::Create(FunctionType::get(i64, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.clean.macho", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *openBB = BasicBlock::Create(ctx, "open", fn);
    auto *sizeBB = BasicBlock::Create(ctx, "size", fn);
    auto *badSizeBB = BasicBlock::Create(ctx, "bad.size", fn);
    auto *mapBB = BasicBlock::Create(ctx, "map", fn);
    auto *parseBB = BasicBlock::Create(ctx, "parse", fn);
    auto *badMachBB = BasicBlock::Create(ctx, "bad.mach", fn);
    auto *cmdLoopBB = BasicBlock::Create(ctx, "cmd.loop", fn);
    auto *cmdBodyBB = BasicBlock::Create(ctx, "cmd.body", fn);
    auto *cmdCompareBB = BasicBlock::Create(ctx, "cmd.compare", fn);
    auto *cmdNextBB = BasicBlock::Create(ctx, "cmd.next", fn);
    auto *unmapBB = BasicBlock::Create(ctx, "unmap", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    auto *pathTy = ArrayType::get(i8, 4096);
    AllocaInst *path = B.CreateAlloca(pathTy, nullptr, "morok.clean.path");
    AllocaInst *pathSize =
        B.CreateAlloca(i32, nullptr, "morok.clean.path.size");
    AllocaInst *diff = B.CreateAlloca(i64, nullptr, "morok.clean.diff");
    B.CreateStore(ConstantInt::get(i32, 4096), pathSize);
    B.CreateStore(ConstantInt::get(i64, 0), diff)->setVolatile(true);
    Value *pathBuf = B.CreateInBoundsGEP(
        pathTy, path, {ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)},
        "morok.clean.path.buf");
    FunctionCallee nsGetPath = M.getOrInsertFunction(
        "_NSGetExecutablePath", FunctionType::get(i32, {ptr, ptr}, false));
    Value *pathRc =
        B.CreateCall(nsGetPath, {pathBuf, pathSize}, "morok.clean.nsgetpath");
    B.CreateCondBr(B.CreateICmpEQ(pathRc, ConstantInt::get(i32, 0)), openBB,
                   retBB);

    IRBuilder<> OB(openBB);
    Value *fd = emitDarwinOpen(OB, M, TT, pathBuf, 0, 0);
    OB.CreateCondBr(OB.CreateICmpSLT(fd, ConstantInt::getSigned(i32, 0)), retBB,
                    sizeBB);

    IRBuilder<> SB(sizeBB);
    Value *fileSize = emitDarwinLseek(SB, M, TT, fd, 0, 2);
    SB.CreateCondBr(SB.CreateICmpSGT(fileSize, ConstantInt::get(ip, 64)), mapBB,
                    badSizeBB);

    IRBuilder<> BSB(badSizeBB);
    emitDarwinClose(BSB, M, TT, fd);
    BSB.CreateBr(retBB);

    IRBuilder<> MB(mapBB);
    Value *mapped = emitDarwinMmap(MB, M, TT, fileSize, fd);
    emitDarwinClose(MB, M, TT, fd);
    Value *mapAddr = MB.CreatePtrToInt(mapped, ip, "morok.clean.map.addr");
    Value *mapFailed =
        MB.CreateOr(MB.CreateICmpEQ(mapped, ConstantPointerNull::get(ptr)),
                    MB.CreateICmpEQ(mapAddr, ConstantInt::getSigned(ip, -1)));
    MB.CreateCondBr(mapFailed, retBB, parseBB);

    IRBuilder<> PB(parseBB);
    Value *magic = loadAt(PB, M, i32, mapped, 0ULL, "morok.clean.macho.magic");
    Value *ncmds = loadAt(PB, M, i32, mapped, 16, "morok.clean.macho.ncmds");
    FunctionCallee imageHeader = M.getOrInsertFunction(
        "_dyld_get_image_header", FunctionType::get(ptr, {i32}, false));
    FunctionCallee imageSlide = M.getOrInsertFunction(
        "_dyld_get_image_vmaddr_slide", FunctionType::get(ip, {i32}, false));
    Value *hdr = PB.CreateCall(imageHeader, {ConstantInt::get(i32, 0)},
                               "morok.clean.hdr");
    Value *slide = PB.CreateCall(imageSlide, {ConstantInt::get(i32, 0)},
                                 "morok.clean.slide");
    Value *valid =
        PB.CreateAnd(PB.CreateICmpEQ(magic, ConstantInt::get(i32, 0xFEEDFACF)),
                     PB.CreateICmpNE(hdr, ConstantPointerNull::get(ptr)));
    PB.CreateCondBr(valid, cmdLoopBB, badMachBB);

    IRBuilder<> BMB(badMachBB);
    BMB.CreateBr(unmapBB);

    IRBuilder<> CLB(cmdLoopBB);
    auto *cmdIdx = CLB.CreatePHI(i32, 2, "morok.clean.cmd.idx");
    auto *cmdOff = CLB.CreatePHI(ip, 2, "morok.clean.cmd.off");
    cmdIdx->addIncoming(ConstantInt::get(i32, 0), parseBB);
    cmdOff->addIncoming(ConstantInt::get(ip, 32), parseBB);
    CLB.CreateCondBr(CLB.CreateICmpULT(cmdIdx, ncmds), cmdBodyBB, unmapBB);

    IRBuilder<> CBB(cmdBodyBB);
    Value *cmdPtr = gepI8(CBB, M, mapped, cmdOff, "morok.clean.cmd.ptr");
    Value *cmd = loadAt(CBB, M, i32, cmdPtr, 0ULL, "morok.clean.cmd.kind");
    Value *cmdSize32 = loadAt(CBB, M, i32, cmdPtr, 4, "morok.clean.cmd.size");
    Value *cmdSize = CBB.CreateZExt(cmdSize32, ip, "morok.clean.cmd.size.w");
    Value *vmaddr = loadAt(CBB, M, i64, cmdPtr, 24, "morok.clean.seg.vmaddr");
    Value *fileoff = loadAt(CBB, M, i64, cmdPtr, 40, "morok.clean.seg.fileoff");
    Value *filesize =
        loadAt(CBB, M, i64, cmdPtr, 48, "morok.clean.seg.filesize");
    Value *initprot =
        loadAt(CBB, M, i32, cmdPtr, 60, "morok.clean.seg.initprot");
    Value *isSegment = CBB.CreateICmpEQ(cmd, ConstantInt::get(i32, 0x19));
    Value *isExec =
        CBB.CreateICmpNE(CBB.CreateAnd(initprot, ConstantInt::get(i32, 4)),
                         ConstantInt::get(i32, 0));
    Value *hasBytes = CBB.CreateICmpUGT(filesize, ConstantInt::get(ip, 0));
    Value *fileEnd =
        CBB.CreateAdd(fileoff, filesize, "morok.clean.seg.fileend");
    Value *inFile = CBB.CreateICmpULE(fileEnd, fileSize);
    Value *cmdInFile =
        CBB.CreateICmpULE(CBB.CreateAdd(cmdOff, cmdSize), fileSize);
    Value *shouldCompare = CBB.CreateAnd(
        CBB.CreateAnd(isSegment, isExec),
        CBB.CreateAnd(CBB.CreateAnd(hasBytes, inFile), cmdInFile));
    CBB.CreateCondBr(shouldCompare, cmdCompareBB, cmdNextBB);

    IRBuilder<> CCB(cmdCompareBB);
    Value *memAddr = CCB.CreateAdd(slide, vmaddr, "morok.clean.seg.mem.addr");
    Value *cleanPtr =
        gepI8(CCB, M, mapped, fileoff, "morok.clean.seg.clean.ptr");
    auto *afterMacBB = BasicBlock::Create(ctx, "morok.clean.mac.done", fn);
    emitFunctionMacLoop(CCB, M, fn, memAddr, cleanPtr, filesize, diff,
                        macTargets, macKey, afterMacBB);
    IRBuilder<> AMB(afterMacBB);
    emitByteDiffLoop(AMB, M, fn, memAddr, cleanPtr, filesize, diff, cmdNextBB);

    IRBuilder<> CNB(cmdNextBB);
    Value *nextCmdIdx =
        CNB.CreateAdd(cmdIdx, ConstantInt::get(i32, 1), "morok.clean.cmd.next");
    Value *nextCmdOff =
        CNB.CreateAdd(cmdOff, cmdSize, "morok.clean.cmd.next.off");
    CNB.CreateBr(cmdLoopBB);
    cmdIdx->addIncoming(nextCmdIdx, cmdNextBB);
    cmdOff->addIncoming(nextCmdOff, cmdNextBB);

    IRBuilder<> UB(unmapBB);
    emitDarwinMunmap(UB, M, TT, mapped, fileSize);
    UB.CreateBr(retBB);

    IRBuilder<> RB(retBB);
    emitRetDiff(RB, diff);
    return fn;
}

Function *cleanCopyProbe(Module &M, ir::IRRandom &rng, const Triple &TT) {
    if (TT.isOSLinux())
        return linuxCleanCopyProbe(M, rng, TT);
    if (TT.isOSDarwin())
        return darwinCleanCopyProbe(M, rng);
    return nullptr;
}

bool isPrologueProbeCandidate(Function &F) {
    if (F.isDeclaration() || F.hasAvailableExternallyLinkage() ||
        F.isIntrinsic() || F.empty())
        return false;
    if (F.getName().starts_with("morok.") || F.getName().starts_with("llvm."))
        return false;
    return true;
}

LoadInst *loadCodeByte(IRBuilder<> &B, Module &M, Value *Base,
                       std::uint64_t Offset, const Twine &Name) {
    auto *LI = loadUnaligned(
        B, Type::getInt8Ty(M.getContext()),
        gepI8(B, M, Base, constIp(M, Offset), Name + ".ptr"), Name);
    LI->setVolatile(true);
    return LI;
}

LoadInst *loadCodeWord(IRBuilder<> &B, Module &M, Value *Base,
                       std::uint64_t Offset, const Twine &Name) {
    auto *LI = loadUnaligned(
        B, Type::getInt32Ty(M.getContext()),
        gepI8(B, M, Base, constIp(M, Offset), Name + ".ptr"), Name);
    LI->setVolatile(true);
    return LI;
}

Value *byteInRange(IRBuilder<> &B, Value *Byte, std::uint8_t Lo,
                   std::uint8_t Hi, const Twine &Name) {
    auto *i8 = Type::getInt8Ty(B.getContext());
    return B.CreateAnd(B.CreateICmpUGE(Byte, ConstantInt::get(i8, Lo)),
                       B.CreateICmpULE(Byte, ConstantInt::get(i8, Hi)), Name);
}

Value *emitX86ProloguePattern(IRBuilder<> &B, Module &M, Function *Target) {
    auto *i8 = Type::getInt8Ty(M.getContext());
    Value *b0 = loadCodeByte(B, M, Target, 0, "morok.antihook.prologue.b0");
    Value *b1 = loadCodeByte(B, M, Target, 1, "morok.antihook.prologue.b1");
    Value *b5 = loadCodeByte(B, M, Target, 5, "morok.antihook.prologue.b5");

    Value *relJmp = B.CreateICmpEQ(b0, ConstantInt::get(i8, 0xE9),
                                   "morok.antihook.prologue.e9");
    Value *ripJmp = B.CreateAnd(B.CreateICmpEQ(b0, ConstantInt::get(i8, 0xFF)),
                                B.CreateICmpEQ(b1, ConstantInt::get(i8, 0x25)),
                                "morok.antihook.prologue.ff25");
    Value *pushRet = B.CreateAnd(B.CreateICmpEQ(b0, ConstantInt::get(i8, 0x68)),
                                 B.CreateICmpEQ(b5, ConstantInt::get(i8, 0xC3)),
                                 "morok.antihook.prologue.pushret");
    Value *shortJmp = B.CreateICmpEQ(b0, ConstantInt::get(i8, 0xEB),
                                     "morok.antihook.prologue.eb");
    Value *shortJcc =
        byteInRange(B, b0, 0x70, 0x7F, "morok.antihook.prologue.jcc8");
    Value *nearJcc = B.CreateAnd(
        B.CreateICmpEQ(b0, ConstantInt::get(i8, 0x0F)),
        byteInRange(B, b1, 0x80, 0x8F, "morok.antihook.prologue.jcc32"),
        "morok.antihook.prologue.0fjcc");

    return B.CreateOr(
        B.CreateOr(B.CreateOr(relJmp, ripJmp), B.CreateOr(pushRet, shortJmp)),
        B.CreateOr(shortJcc, nearJcc), "morok.antihook.prologue.x86.hit");
}

Value *wordMaskEq(IRBuilder<> &B, Value *Word, std::uint32_t Mask,
                  std::uint32_t Expected, const Twine &Name) {
    auto *i32 = Type::getInt32Ty(B.getContext());
    return B.CreateICmpEQ(B.CreateAnd(Word, ConstantInt::get(i32, Mask)),
                          ConstantInt::get(i32, Expected), Name);
}

Value *emitArm64ProloguePattern(IRBuilder<> &B, Module &M, Function *Target) {
    Value *w0 = loadCodeWord(B, M, Target, 0, "morok.antihook.prologue.w0");
    Value *w1 = loadCodeWord(B, M, Target, 4, "morok.antihook.prologue.w1");

    Value *branchImm = wordMaskEq(B, w0, 0xFC000000U, 0x14000000U,
                                  "morok.antihook.prologue.arm64.b");
    Value *branchReg = wordMaskEq(B, w0, 0xFFFFFC1FU, 0xD61F0000U,
                                  "morok.antihook.prologue.arm64.br");
    Value *literalX16OrX17 =
        B.CreateAnd(wordMaskEq(B, w0, 0xFF000000U, 0x58000000U,
                               "morok.antihook.prologue.arm64.ldr"),
                    wordMaskEq(B, w0, 0x0000001EU, 0x00000010U,
                               "morok.antihook.prologue.arm64.rt"));
    Value *nextBranchReg = wordMaskEq(B, w1, 0xFFFFFC1FU, 0xD61F0000U,
                                      "morok.antihook.prologue.arm64.nextbr");
    Value *literalBranch = B.CreateAnd(literalX16OrX17, nextBranchReg,
                                       "morok.antihook.prologue.arm64.ldrbr");

    return B.CreateOr(B.CreateOr(branchImm, branchReg), literalBranch,
                      "morok.antihook.prologue.arm64.hit");
}

GlobalVariable *functionMacTargetTable(Module &M,
                                       const std::vector<Function *> &Targets) {
    if (auto *existing = M.getGlobalVariable("morok.antihook.mac.targets",
                                             /*AllowInternal=*/true))
        return existing;
    if (Targets.empty())
        return nullptr;
    LLVMContext &ctx = M.getContext();
    auto *ptr = PointerType::getUnqual(ctx);
    auto *arrTy = ArrayType::get(ptr, Targets.size());
    std::vector<Constant *> init;
    init.reserve(Targets.size());
    for (Function *target : Targets)
        init.push_back(target);
    auto *gv = new GlobalVariable(
        M, arrTy, /*isConstant=*/true, GlobalValue::PrivateLinkage,
        ConstantArray::get(arrTy, init), "morok.antihook.mac.targets");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

void mixMacByte(IRBuilder<> &B, Value *&Mac, Value *Byte, std::uint64_t Salt,
                const Twine &Name) {
    auto *i64 = B.getInt64Ty();
    Value *wide = B.CreateZExt(Byte, i64, Name + ".wide");
    Mac = B.CreateMul(
        B.CreateXor(B.CreateAdd(Mac, ConstantInt::get(i64, Salt)), wide),
        ConstantInt::get(i64, 0x100000001B3ULL), Name);
}

void emitFunctionMacLoop(IRBuilder<> &B, Module &M, Function *Fn,
                         Value *MemAddr, Value *CleanPtr, Value *Len,
                         AllocaInst *Diff, GlobalVariable *Targets,
                         std::uint64_t Key, BasicBlock *Done) {
    if (!Targets) {
        B.CreateBr(Done);
        return;
    }

    auto *arrTy = dyn_cast<ArrayType>(Targets->getValueType());
    if (!arrTy || arrTy->getNumElements() == 0) {
        B.CreateBr(Done);
        return;
    }

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    constexpr std::uint64_t kWindow = 32;

    auto *loopBB = BasicBlock::Create(ctx, "morok.antihook.mac.loop", Fn);
    auto *bodyBB = BasicBlock::Create(ctx, "morok.antihook.mac.body", Fn);
    auto *hashBB = BasicBlock::Create(ctx, "morok.antihook.mac.hash", Fn);
    auto *nextBB = BasicBlock::Create(ctx, "morok.antihook.mac.next", Fn);
    B.CreateBr(loopBB);

    IRBuilder<> LB(loopBB);
    auto *idx = LB.CreatePHI(ip, 2, "morok.antihook.mac.idx");
    idx->addIncoming(ConstantInt::get(ip, 0), B.GetInsertBlock());
    LB.CreateCondBr(
        LB.CreateICmpULT(idx, ConstantInt::get(ip, arrTy->getNumElements())),
        bodyBB, Done);

    IRBuilder<> BB(bodyBB);
    Value *slot =
        BB.CreateInBoundsGEP(arrTy, Targets, {ConstantInt::get(ip, 0), idx},
                             "morok.antihook.mac.target.slot");
    Value *target = BB.CreateLoad(ptr, slot, "morok.antihook.mac.target");
    Value *targetAddr =
        BB.CreatePtrToInt(target, ip, "morok.antihook.mac.target.addr");
    Value *windowEnd = BB.CreateAdd(targetAddr, ConstantInt::get(ip, kWindow),
                                    "morok.antihook.mac.target.end");
    Value *segEnd = BB.CreateAdd(MemAddr, Len, "morok.antihook.mac.seg.end");
    Value *inSeg = BB.CreateAnd(
        BB.CreateICmpUGE(targetAddr, MemAddr),
        BB.CreateAnd(BB.CreateICmpULE(windowEnd, segEnd),
                     BB.CreateICmpUGE(Len, ConstantInt::get(ip, kWindow))));
    BB.CreateCondBr(inSeg, hashBB, nextBB);

    IRBuilder<> HB(hashBB);
    Value *fileDelta =
        HB.CreateSub(targetAddr, MemAddr, "morok.antihook.mac.file.delta");
    Value *fileBase =
        gepI8(HB, M, CleanPtr, fileDelta, "morok.antihook.mac.file.base");
    Value *memMac = ConstantInt::get(i64, Key ^ 0xA0761D6478BD642FULL);
    Value *fileMac = ConstantInt::get(i64, Key ^ 0xA0761D6478BD642FULL);
    for (std::uint64_t i = 0; i < kWindow; ++i) {
        Value *memPtr =
            HB.CreateIntToPtr(HB.CreateAdd(targetAddr, ConstantInt::get(ip, i)),
                              ptr, "morok.antihook.mac.mem.ptr");
        auto *memByte =
            HB.CreateLoad(i8, memPtr, "morok.antihook.mac.mem.byte");
        memByte->setVolatile(true);
        Value *fileByte =
            HB.CreateLoad(i8,
                          gepI8(HB, M, fileBase, ConstantInt::get(ip, i),
                                "morok.antihook.mac.file.ptr"),
                          "morok.antihook.mac.file.byte");
        std::uint64_t salt = 0x9E3779B97F4A7C15ULL + i * 0xD1B54A32D192ED03ULL;
        mixMacByte(HB, memMac, memByte, salt, "morok.antihook.mac.mem.mix");
        mixMacByte(HB, fileMac, fileByte, salt, "morok.antihook.mac.file.mix");
    }
    incrementDiff(HB, Diff, HB.CreateICmpNE(memMac, fileMac),
                  "morok.antihook.mac.diff");
    HB.CreateBr(nextBB);

    IRBuilder<> NB(nextBB);
    Value *next =
        NB.CreateAdd(idx, ConstantInt::get(ip, 1), "morok.antihook.mac.next");
    NB.CreateBr(loopBB);
    idx->addIncoming(next, nextBB);
}

Value *normalizeElfAddress(IRBuilderBase &B, Module &M, Value *Base,
                           Value *Addr, const Twine &Name) {
    auto *ip = intPtrTy(M);
    Value *zero = ConstantInt::get(ip, 0);
    Value *needsBias = B.CreateAnd(
        B.CreateICmpNE(Addr, zero),
        B.CreateAnd(B.CreateICmpNE(Base, zero), B.CreateICmpULT(Addr, Base)));
    return B.CreateSelect(needsBias, B.CreateAdd(Base, Addr), Addr, Name);
}

Value *emitElfExecSegmentHit(IRBuilder<> &B, Module &M, Value *Target,
                             Value *RuntimeBase, Value *PhPtr,
                             const Twine &Name) {
    auto *i32 = Type::getInt32Ty(M.getContext());
    auto *ip = intPtrTy(M);
    Value *pType = loadAt(B, M, i32, PhPtr, 0ULL, Name + ".type");
    Value *pFlags = loadAt(B, M, i32, PhPtr, 4, Name + ".flags");
    Value *pVaddr = loadAt(B, M, ip, PhPtr, 16, Name + ".vaddr");
    Value *pMemsz = loadAt(B, M, ip, PhPtr, 40, Name + ".memsz");
    Value *segStart = B.CreateAdd(RuntimeBase, pVaddr, Name + ".start");
    Value *segEnd = B.CreateAdd(segStart, pMemsz, Name + ".end");
    Value *isLoad =
        B.CreateICmpEQ(pType, ConstantInt::get(i32, 1), Name + ".load");
    Value *isExec =
        B.CreateICmpNE(B.CreateAnd(pFlags, ConstantInt::get(i32, 1)),
                       ConstantInt::get(i32, 0), Name + ".exec");
    Value *hasBytes =
        B.CreateICmpUGT(pMemsz, ConstantInt::get(ip, 0), Name + ".bytes");
    Value *inRange =
        B.CreateAnd(B.CreateICmpUGE(Target, segStart),
                    B.CreateICmpULT(Target, segEnd), Name + ".range");
    return B.CreateAnd(B.CreateAnd(isLoad, isExec),
                       B.CreateAnd(hasBytes, inRange), Name + ".hit");
}

Function *linuxGotTargetInRx(Module &M) {
    if (Function *existing = M.getFunction("morok.antihook.elf.rx"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);

    auto *fn = Function::Create(
        FunctionType::get(i32, {ip, ip, ip, ip, ip, ptr}, false),
        GlobalValue::PrivateLinkage, "morok.antihook.elf.rx", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    auto *target = fn->getArg(0);
    target->setName("target");
    auto *atPhdr = fn->getArg(1);
    atPhdr->setName("phdr");
    auto *phNum = fn->getArg(2);
    phNum->setName("phnum");
    auto *phEnt = fn->getArg(3);
    phEnt->setName("phent");
    auto *selfBase = fn->getArg(4);
    selfBase->setName("base");
    auto *debug = fn->getArg(5);
    debug->setName("debug");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *selfLoopBB = BasicBlock::Create(ctx, "self.loop", fn);
    auto *selfBodyBB = BasicBlock::Create(ctx, "self.body", fn);
    auto *selfNextBB = BasicBlock::Create(ctx, "self.next", fn);
    auto *ret1BB = BasicBlock::Create(ctx, "ret1", fn);
    auto *ret0BB = BasicBlock::Create(ctx, "ret0", fn);

    IRBuilder<> EB(entry);
    Value *hasSelfPhdr =
        EB.CreateAnd(EB.CreateICmpNE(atPhdr, ConstantInt::get(ip, 0)),
                     EB.CreateICmpUGE(phEnt, ConstantInt::get(ip, 56)),
                     "morok.antihook.got.self.phdr");
    EB.CreateCondBr(hasSelfPhdr, selfLoopBB, ret0BB);

    IRBuilder<> SLB(selfLoopBB);
    auto *selfIdx = SLB.CreatePHI(ip, 2, "morok.antihook.got.self.idx");
    selfIdx->addIncoming(ConstantInt::get(ip, 0), entry);
    Value *selfInRange =
        SLB.CreateAnd(SLB.CreateICmpULT(selfIdx, phNum),
                      SLB.CreateICmpULT(selfIdx, ConstantInt::get(ip, 128)));
    SLB.CreateCondBr(selfInRange, selfBodyBB, ret0BB);

    IRBuilder<> SBB(selfBodyBB);
    Value *selfPhPtr =
        SBB.CreateIntToPtr(SBB.CreateAdd(atPhdr, SBB.CreateMul(selfIdx, phEnt)),
                           ptr, "morok.antihook.got.self.ph");
    SBB.CreateCondBr(emitElfExecSegmentHit(SBB, M, target, selfBase, selfPhPtr,
                                           "morok.antihook.got.self.seg"),
                     ret1BB, selfNextBB);

    IRBuilder<> SNB(selfNextBB);
    Value *selfNext = SNB.CreateAdd(selfIdx, ConstantInt::get(ip, 1),
                                    "morok.antihook.got.self.next");
    SNB.CreateBr(selfLoopBB);
    selfIdx->addIncoming(selfNext, selfNextBB);

    IRBuilder<> R1(ret1BB);
    R1.CreateRet(ConstantInt::get(i32, 1));

    IRBuilder<> R0(ret0BB);
    R0.CreateRet(ConstantInt::get(i32, 0));
    return fn;
}

Function *linuxGotLazyPltTarget(Module &M) {
    if (Function *existing = M.getFunction("morok.antihook.got.lazy"))
        return existing;

    // x86_64 lazy PLT slots initially point to the push/jmp tail of their own
    // PLT entry.  Accept only that slot-local shape; any other self-RX target is
    // still a violation for external imports.
    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);

    auto *fn = Function::Create(
        FunctionType::get(i32, {ip, ip, ip, ip, ip, ip}, false),
        GlobalValue::PrivateLinkage, "morok.antihook.got.lazy", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    auto *target = fn->getArg(0);
    target->setName("target");
    auto *slot = fn->getArg(1);
    slot->setName("slot");
    auto *atPhdr = fn->getArg(2);
    atPhdr->setName("phdr");
    auto *phNum = fn->getArg(3);
    phNum->setName("phnum");
    auto *phEnt = fn->getArg(4);
    phEnt->setName("phent");
    auto *selfBase = fn->getArg(5);
    selfBase->setName("base");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    if (Triple(M.getTargetTriple()).getArch() != Triple::x86_64) {
        IRBuilder<> B(entry);
        B.CreateRet(ConstantInt::get(i32, 0));
        return fn;
    }

    auto *loopBB = BasicBlock::Create(ctx, "ph.loop", fn);
    auto *bodyBB = BasicBlock::Create(ctx, "ph.body", fn);
    auto *checkBB = BasicBlock::Create(ctx, "plt.check", fn);
    auto *nextBB = BasicBlock::Create(ctx, "ph.next", fn);
    auto *ret1BB = BasicBlock::Create(ctx, "ret1", fn);
    auto *ret0BB = BasicBlock::Create(ctx, "ret0", fn);

    IRBuilder<> EB(entry);
    Value *hasSelfPhdr =
        EB.CreateAnd(EB.CreateICmpNE(atPhdr, ConstantInt::get(ip, 0)),
                     EB.CreateAnd(EB.CreateICmpUGE(phEnt, ConstantInt::get(ip, 56)),
                                  EB.CreateICmpUGT(phNum, ConstantInt::get(ip, 0))),
                     "morok.antihook.got.lazy.phdr");
    Value *validTarget =
        EB.CreateAnd(EB.CreateICmpUGE(target, ConstantInt::get(ip, 6)),
                     EB.CreateICmpNE(slot, ConstantInt::get(ip, 0)),
                     "morok.antihook.got.lazy.valid");
    Value *inst = EB.CreateSub(target, ConstantInt::get(ip, 6),
                               "morok.antihook.got.lazy.inst");
    EB.CreateCondBr(EB.CreateAnd(hasSelfPhdr, validTarget,
                                 "morok.antihook.got.lazy.active"),
                    loopBB, ret0BB);

    IRBuilder<> LB(loopBB);
    auto *idx = LB.CreatePHI(ip, 2, "morok.antihook.got.lazy.idx");
    idx->addIncoming(ConstantInt::get(ip, 0), entry);
    Value *inRange =
        LB.CreateAnd(LB.CreateICmpULT(idx, phNum),
                     LB.CreateICmpULT(idx, ConstantInt::get(ip, 128)));
    LB.CreateCondBr(inRange, bodyBB, ret0BB);

    IRBuilder<> BB(bodyBB);
    Value *phPtr =
        BB.CreateIntToPtr(BB.CreateAdd(atPhdr, BB.CreateMul(idx, phEnt)), ptr,
                          "morok.antihook.got.lazy.ph");
    Value *pType = loadAt(BB, M, i32, phPtr, 0ULL,
                          "morok.antihook.got.lazy.ph.type");
    Value *pFlags = loadAt(BB, M, i32, phPtr, 4,
                           "morok.antihook.got.lazy.ph.flags");
    Value *pVaddr = loadAt(BB, M, ip, phPtr, 16,
                           "morok.antihook.got.lazy.ph.vaddr");
    Value *pMemsz = loadAt(BB, M, ip, phPtr, 40,
                           "morok.antihook.got.lazy.ph.memsz");
    Value *segStart = BB.CreateAdd(selfBase, pVaddr,
                                   "morok.antihook.got.lazy.seg.start");
    Value *segEnd =
        BB.CreateAdd(segStart, pMemsz, "morok.antihook.got.lazy.seg.end");
    Value *isLoad =
        BB.CreateICmpEQ(pType, ConstantInt::get(i32, 1),
                       "morok.antihook.got.lazy.seg.load");
    Value *isExec = BB.CreateICmpNE(
        BB.CreateAnd(pFlags, ConstantInt::get(i32, 1)),
        ConstantInt::get(i32, 0), "morok.antihook.got.lazy.seg.exec");
    Value *containsInst =
        BB.CreateAnd(BB.CreateICmpUGE(inst, segStart),
                     BB.CreateICmpULE(target, segEnd),
                     "morok.antihook.got.lazy.seg.range");
    Value *eligible =
        BB.CreateAnd(BB.CreateAnd(isLoad, isExec),
                     BB.CreateAnd(BB.CreateICmpUGT(pMemsz, ConstantInt::get(ip, 0)),
                                  containsInst),
                     "morok.antihook.got.lazy.seg.hit");
    BB.CreateCondBr(eligible, checkBB, nextBB);

    IRBuilder<> CB(checkBB);
    Value *instPtr = CB.CreateIntToPtr(inst, ptr, "morok.antihook.got.lazy.ptr");
    Value *op0 = loadAt(CB, M, i8, instPtr, 0ULL,
                        "morok.antihook.got.lazy.jmp.op0");
    Value *op1 = loadAt(CB, M, i8, instPtr, 1,
                        "morok.antihook.got.lazy.jmp.op1");
    Value *disp = loadAt(CB, M, i32, instPtr, 2,
                         "morok.antihook.got.lazy.jmp.disp");
    Value *slotFromJmp =
        CB.CreateAdd(target, CB.CreateSExt(disp, ip),
                     "morok.antihook.got.lazy.jmp.slot");
    Value *bytesOk =
        CB.CreateAnd(CB.CreateICmpEQ(op0, ConstantInt::get(i8, 0xFF)),
                     CB.CreateICmpEQ(op1, ConstantInt::get(i8, 0x25)),
                     "morok.antihook.got.lazy.jmp.bytes");
    Value *slotOk = CB.CreateICmpEQ(slotFromJmp, slot,
                                    "morok.antihook.got.lazy.slot.match");
    CB.CreateCondBr(CB.CreateAnd(bytesOk, slotOk,
                                 "morok.antihook.got.lazy.match"),
                    ret1BB, nextBB);

    IRBuilder<> NB(nextBB);
    Value *next =
        NB.CreateAdd(idx, ConstantInt::get(ip, 1),
                     "morok.antihook.got.lazy.next");
    NB.CreateBr(loopBB);
    idx->addIncoming(next, nextBB);

    IRBuilder<> R1(ret1BB);
    R1.CreateRet(ConstantInt::get(i32, 1));

    IRBuilder<> R0(ret0BB);
    R0.CreateRet(ConstantInt::get(i32, 0));
    return fn;
}

Function *linuxGotTargetInNeeded(Module &M) {
    if (Function *existing = M.getFunction("morok.antihook.got.needed"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);

    auto *fn = Function::Create(
        FunctionType::get(ptr, {ptr, ip, ip}, false),
        GlobalValue::PrivateLinkage, "morok.antihook.got.needed", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    auto *name = fn->getArg(0);
    name->setName("name");
    auto *dynamic = fn->getArg(1);
    dynamic->setName("dynamic");
    auto *strTab = fn->getArg(2);
    strTab->setName("strtab");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *loopBB = BasicBlock::Create(ctx, "needed.loop", fn);
    auto *bodyBB = BasicBlock::Create(ctx, "needed.body", fn);
    auto *resolveBB = BasicBlock::Create(ctx, "needed.resolve", fn);
    auto *symBB = BasicBlock::Create(ctx, "needed.sym", fn);
    auto *nextBB = BasicBlock::Create(ctx, "needed.next", fn);
    auto *retSymBB = BasicBlock::Create(ctx, "needed.ret", fn);
    auto *ret0BB = BasicBlock::Create(ctx, "ret0", fn);

    FunctionCallee dlopen = M.getOrInsertFunction(
        "dlopen", FunctionType::get(ptr, {ptr, i32}, false));
    FunctionCallee dlsym =
        M.getOrInsertFunction("dlsym", FunctionType::get(ptr, {ptr, ptr}, false));

    IRBuilder<> EB(entry);
    Value *valid = EB.CreateAnd(
        EB.CreateICmpNE(name, ConstantPointerNull::get(ptr)),
        EB.CreateAnd(EB.CreateICmpNE(dynamic, ConstantInt::get(ip, 0)),
                     EB.CreateICmpNE(strTab, ConstantInt::get(ip, 0))),
        "morok.antihook.got.needed.valid");
    EB.CreateCondBr(valid, loopBB, ret0BB);

    IRBuilder<> LB(loopBB);
    auto *idx = LB.CreatePHI(ip, 2, "morok.antihook.got.needed.idx");
    idx->addIncoming(ConstantInt::get(ip, 0), entry);
    LB.CreateCondBr(LB.CreateICmpULT(idx, ConstantInt::get(ip, 256)), bodyBB,
                    ret0BB);

    IRBuilder<> BB(bodyBB);
    Value *dynPtr = BB.CreateIntToPtr(
        BB.CreateAdd(dynamic, BB.CreateMul(idx, ConstantInt::get(ip, 16))),
        ptr, "morok.antihook.got.needed.dynamic");
    Value *tag = loadAt(BB, M, i64, dynPtr, 0ULL,
                        "morok.antihook.got.needed.tag");
    Value *val = loadAt(BB, M, i64, dynPtr, 8,
                        "morok.antihook.got.needed.val");
    BB.CreateCondBr(BB.CreateICmpEQ(tag, ConstantInt::get(i64, 1)), resolveBB,
                    nextBB);

    IRBuilder<> RB(resolveBB);
    Value *neededName = RB.CreateIntToPtr(
        RB.CreateAdd(strTab, val), ptr, "morok.antihook.got.needed.name");
    Value *handle = RB.CreateCall(
        dlopen, {neededName, ConstantInt::get(i32, 0x5)},
        "morok.antihook.got.needed.handle");
    RB.CreateCondBr(RB.CreateICmpNE(handle, ConstantPointerNull::get(ptr)),
                    symBB, nextBB);

    IRBuilder<> SB(symBB);
    Value *expected =
        SB.CreateCall(dlsym, {handle, name}, "morok.antihook.got.needed.sym");
    Value *matches = SB.CreateICmpNE(expected, ConstantPointerNull::get(ptr),
                                     "morok.antihook.got.needed.match");
    SB.CreateCondBr(matches, retSymBB, nextBB);

    IRBuilder<> NB(nextBB);
    Value *next = NB.CreateAdd(idx, ConstantInt::get(ip, 1),
                               "morok.antihook.got.needed.next");
    NB.CreateBr(loopBB);
    idx->addIncoming(next, nextBB);

    IRBuilder<> R1(retSymBB);
    R1.CreateRet(expected);

    IRBuilder<> R0(ret0BB);
    R0.CreateRet(ConstantPointerNull::get(ptr));
    return fn;
}

Function *linuxGotRecheckProbe(Module &M, Function *Got,
                               GlobalVariable *State) {
    if (!Got || !State)
        return nullptr;
    if (Function *existing = M.getFunction("morok.antihook.got.recheck"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i64 = Type::getInt64Ty(ctx);
    auto *voidTy = Type::getVoidTy(ctx);
    auto *fn = Function::Create(FunctionType::get(voidTy, {i64}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.got.recheck", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    auto *tag = fn->getArg(0);
    tag->setName("tag");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    IRBuilder<> B(entry);
    Value *diff = B.CreateCall(Got, {}, "morok.antihook.got.recheck.diff");
    Value *changed =
        B.CreateICmpNE(diff, ConstantInt::get(i64, 0),
                       "morok.antihook.got.recheck.changed");
    foldState(B, State, B.CreateXor(diff, tag, "morok.antihook.got.recheck.mix"),
              0x6F13D9C4B825A7E1ULL, "morok.antihook.got.recheck");
    foldEnforcedFlag(B, State, changed, 0xA6C12D8F49E35B70ULL,
                     "morok.antihook.got.recheck.changed");
    B.CreateRetVoid();
    return fn;
}

void insertAntiHookGotRecheckSite(Module &M, Instruction &I, Function *Probe,
                                  std::uint64_t Tag, std::uint8_t ArmedByte,
                                  std::uint32_t SiteId) {
    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);

    auto *gate = new GlobalVariable(
        M, i8, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(i8, 0), "morok.antihook.got.site");
    gate->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

    Function *parent = I.getFunction();
    BasicBlock *headBB = I.getParent();
    BasicBlock *contBB = headBB->splitBasicBlock(
        I.getIterator(), "morok.antihook.got.site.cont");
    headBB->getTerminator()->eraseFromParent();
    auto *callBB =
        BasicBlock::Create(ctx, "morok.antihook.got.site.call", parent, contBB);

    IRBuilder<> HB(headBB);
    auto *seen = HB.CreateLoad(i8, gate, "morok.antihook.got.site.seen");
    seen->setVolatile(true);
    Value *shouldRun = HB.CreateICmpEQ(seen, ConstantInt::get(i8, 0),
                                       "morok.antihook.got.site.armed");
    HB.CreateCondBr(shouldRun, callBB, contBB);

    IRBuilder<> CB(callBB);
    auto *armed = CB.CreateStore(ConstantInt::get(i8, ArmedByte), gate);
    armed->setVolatile(true);
    CB.CreateCall(
        Probe->getFunctionType(), Probe,
        {ConstantInt::get(CB.getInt64Ty(),
                          Tag ^ (0x9E3779B97F4A7C15ULL * SiteId))});
    CB.CreateBr(contBB);
}

bool insertAntiHookGotRecheckSites(Module &M, Function *Probe,
                                   ir::IRRandom &rng) {
    if (!Probe)
        return false;
    constexpr std::uint32_t kMaxProbeSites = 16;

    std::vector<Instruction *> sites;
    sites.reserve(kMaxProbeSites);
    for (Function &F : M) {
        if (sites.size() >= kMaxProbeSites)
            break;
        if (!isPrologueProbeCandidate(F) || directlyRecursive(F))
            continue;
        SmallPtrSet<BasicBlock *, 32> loopBlocks = naturalLoopBlocks(F);
        for (BasicBlock &BB : F) {
            if (sites.size() >= kMaxProbeSites)
                break;
            if (BB.isEHPad() || BB.isLandingPad() || loopBlocks.contains(&BB))
                continue;
            if (auto *ret = dyn_cast<ReturnInst>(BB.getTerminator()))
                sites.push_back(ret);
        }
    }

    std::uint32_t siteId = 1;
    for (Instruction *I : sites)
        insertAntiHookGotRecheckSite(
            M, *I, Probe, rng.next(),
            static_cast<std::uint8_t>((rng.next() | 1) & 0xffu), siteId++);
    return !sites.empty();
}

Function *linuxGotPltProbe(Module &M, const Triple &TT) {
    if (!TT.isOSLinux())
        return nullptr;
    if (intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.antihook.got.plt"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *rxCheck = linuxGotTargetInRx(M);
    auto *lazyCheck = linuxGotLazyPltTarget(M);
    auto *neededCheck = linuxGotTargetInNeeded(M);

    auto *fn = Function::Create(FunctionType::get(i64, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.got.plt", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *phLoopBB = BasicBlock::Create(ctx, "ph.loop", fn);
    auto *phBodyBB = BasicBlock::Create(ctx, "ph.body", fn);
    auto *phNextBB = BasicBlock::Create(ctx, "ph.next", fn);
    auto *dynPrepBB = BasicBlock::Create(ctx, "dyn.prep", fn);
    auto *dynLoopBB = BasicBlock::Create(ctx, "dyn.loop", fn);
    auto *dynBodyBB = BasicBlock::Create(ctx, "dyn.body", fn);
    auto *dynNextBB = BasicBlock::Create(ctx, "dyn.next", fn);
    auto *relPrepBB = BasicBlock::Create(ctx, "rel.prep", fn);
    auto *relLoopBB = BasicBlock::Create(ctx, "rel.loop", fn);
    auto *relBodyBB = BasicBlock::Create(ctx, "rel.body", fn);
    auto *relValidateBB = BasicBlock::Create(ctx, "rel.validate", fn);
    auto *protectBB = BasicBlock::Create(ctx, "rel.protect", fn);
    auto *relNextBB = BasicBlock::Create(ctx, "rel.next", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    AllocaInst *diff = B.CreateAlloca(i64, nullptr, "morok.antihook.got.diff");
    AllocaInst *baseSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.got.base");
    AllocaInst *dynVaddrSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.got.dynamic.vaddr");
    AllocaInst *relroVaddrSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.got.relro.vaddr");
    AllocaInst *relroMemszSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.got.relro.memsz");
    AllocaInst *jmpRelSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.got.jmprel");
    AllocaInst *pltRelSzSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.got.pltrelsz");
    AllocaInst *pltRelSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.got.pltrel");
    AllocaInst *symTabSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.got.symtab");
    AllocaInst *strTabSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.got.strtab");
    AllocaInst *symEntSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.got.syment");
    AllocaInst *debugSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.got.debug");
    AllocaInst *bindNowSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.got.bindnow");
    AllocaInst *flagsSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.got.flags");
    AllocaInst *flags1Slot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.got.flags1");
    for (AllocaInst *slot :
         {diff, baseSlot, dynVaddrSlot, relroVaddrSlot, relroMemszSlot,
          jmpRelSlot, pltRelSzSlot, pltRelSlot, symTabSlot, strTabSlot,
          symEntSlot, debugSlot, bindNowSlot, flagsSlot, flags1Slot})
        B.CreateStore(ConstantInt::get(ip, 0), slot);

    FunctionCallee getauxval =
        M.getOrInsertFunction("getauxval", FunctionType::get(ip, {ip}, false));
    Value *atPhdr =
        B.CreateCall(getauxval, {ConstantInt::get(ip, 3)}, "morok.got.atphdr");
    Value *phEnt =
        B.CreateCall(getauxval, {ConstantInt::get(ip, 4)}, "morok.got.phent");
    Value *phNum =
        B.CreateCall(getauxval, {ConstantInt::get(ip, 5)}, "morok.got.phnum");
    Value *pageRaw =
        B.CreateCall(getauxval, {ConstantInt::get(ip, 6)}, "morok.got.pagesz");
    Value *pageSize = B.CreateSelect(
        B.CreateICmpUGT(pageRaw, ConstantInt::get(ip, 0)), pageRaw,
        ConstantInt::get(ip, 4096), "morok.antihook.got.pagesz");
    Value *validPhdr = B.CreateAnd(
        B.CreateICmpNE(atPhdr, ConstantInt::get(ip, 0)),
        B.CreateAnd(B.CreateICmpUGE(phEnt, ConstantInt::get(ip, 56)),
                    B.CreateICmpUGT(phNum, ConstantInt::get(ip, 0))));
    B.CreateCondBr(validPhdr, phLoopBB, retBB);

    IRBuilder<> PLB(phLoopBB);
    auto *phIdx = PLB.CreatePHI(ip, 2, "morok.antihook.got.ph.idx");
    phIdx->addIncoming(ConstantInt::get(ip, 0), entry);
    Value *phInRange =
        PLB.CreateAnd(PLB.CreateICmpULT(phIdx, phNum),
                      PLB.CreateICmpULT(phIdx, ConstantInt::get(ip, 128)));
    PLB.CreateCondBr(phInRange, phBodyBB, dynPrepBB);

    IRBuilder<> PBB(phBodyBB);
    Value *phPtr =
        PBB.CreateIntToPtr(PBB.CreateAdd(atPhdr, PBB.CreateMul(phIdx, phEnt)),
                           ptr, "morok.antihook.got.ph.ptr");
    Value *pType = loadAt(PBB, M, Type::getInt32Ty(ctx), phPtr, 0ULL,
                          "morok.antihook.got.ph.type");
    Value *pVaddr =
        loadAt(PBB, M, ip, phPtr, 16, "morok.antihook.got.ph.vaddr");
    Value *pMemsz =
        loadAt(PBB, M, ip, phPtr, 40, "morok.antihook.got.ph.memsz");
    Value *baseOld =
        PBB.CreateLoad(ip, baseSlot, "morok.antihook.got.base.old");
    Value *baseNew = PBB.CreateSelect(
        PBB.CreateICmpEQ(pType, ConstantInt::get(Type::getInt32Ty(ctx), 6)),
        PBB.CreateSub(atPhdr, pVaddr), baseOld, "morok.antihook.got.base.new");
    PBB.CreateStore(baseNew, baseSlot);
    Value *dynOld =
        PBB.CreateLoad(ip, dynVaddrSlot, "morok.antihook.got.dynamic.old");
    Value *dynNew = PBB.CreateSelect(
        PBB.CreateICmpEQ(pType, ConstantInt::get(Type::getInt32Ty(ctx), 2)),
        pVaddr, dynOld, "morok.antihook.got.dynamic.new");
    PBB.CreateStore(dynNew, dynVaddrSlot);
    Value *relroOld =
        PBB.CreateLoad(ip, relroVaddrSlot, "morok.antihook.got.relro.old");
    Value *relroMemszOld =
        PBB.CreateLoad(ip, relroMemszSlot, "morok.antihook.got.relro.mem.old");
    Value *isRelro = PBB.CreateICmpEQ(
        pType, ConstantInt::get(Type::getInt32Ty(ctx), 0x6474E552));
    PBB.CreateStore(PBB.CreateSelect(isRelro, pVaddr, relroOld),
                    relroVaddrSlot);
    PBB.CreateStore(PBB.CreateSelect(isRelro, pMemsz, relroMemszOld),
                    relroMemszSlot);
    PBB.CreateBr(phNextBB);

    IRBuilder<> PNB(phNextBB);
    Value *phNext = PNB.CreateAdd(phIdx, ConstantInt::get(ip, 1),
                                  "morok.antihook.got.ph.next");
    PNB.CreateBr(phLoopBB);
    phIdx->addIncoming(phNext, phNextBB);

    IRBuilder<> DPB(dynPrepBB);
    Value *base = DPB.CreateLoad(ip, baseSlot, "morok.antihook.got.base.final");
    Value *dynVaddr =
        DPB.CreateLoad(ip, dynVaddrSlot, "morok.antihook.got.dynamic.final");
    Value *dynAddr =
        DPB.CreateAdd(base, dynVaddr, "morok.antihook.got.dynamic.addr");
    DPB.CreateCondBr(DPB.CreateICmpNE(dynVaddr, ConstantInt::get(ip, 0)),
                     dynLoopBB, retBB);

    IRBuilder<> DLB(dynLoopBB);
    auto *dynIdx = DLB.CreatePHI(ip, 2, "morok.antihook.got.dynamic.idx");
    dynIdx->addIncoming(ConstantInt::get(ip, 0), dynPrepBB);
    DLB.CreateCondBr(DLB.CreateICmpULT(dynIdx, ConstantInt::get(ip, 256)),
                     dynBodyBB, relPrepBB);

    IRBuilder<> DBB(dynBodyBB);
    Value *dynPtr = DBB.CreateIntToPtr(
        DBB.CreateAdd(dynAddr, DBB.CreateMul(dynIdx, ConstantInt::get(ip, 16))),
        ptr, "morok.antihook.got.dynamic.ptr");
    Value *tag = loadAt(DBB, M, i64, dynPtr, 0ULL, "morok.antihook.got.dtag");
    Value *val = loadAt(DBB, M, i64, dynPtr, 8, "morok.antihook.got.dval");
    auto storeIfTag = [&](AllocaInst *Slot, std::uint64_t Tag) {
        Value *old = DBB.CreateLoad(ip, Slot);
        DBB.CreateStore(
            DBB.CreateSelect(DBB.CreateICmpEQ(tag, ConstantInt::get(i64, Tag)),
                             val, old),
            Slot);
    };
    storeIfTag(pltRelSzSlot, 2);        // DT_PLTRELSZ
    storeIfTag(strTabSlot, 5);          // DT_STRTAB
    storeIfTag(symTabSlot, 6);          // DT_SYMTAB
    storeIfTag(symEntSlot, 11);         // DT_SYMENT
    storeIfTag(jmpRelSlot, 23);         // DT_JMPREL
    storeIfTag(pltRelSlot, 20);         // DT_PLTREL
    storeIfTag(debugSlot, 21);          // DT_DEBUG
    storeIfTag(bindNowSlot, 24);        // DT_BIND_NOW
    storeIfTag(flagsSlot, 30);          // DT_FLAGS
    storeIfTag(flags1Slot, 0x6FFFFFFB); // DT_FLAGS_1
    Value *bindNowOld = DBB.CreateLoad(ip, bindNowSlot);
    DBB.CreateStore(
        DBB.CreateSelect(DBB.CreateICmpEQ(tag, ConstantInt::get(i64, 24)),
                         ConstantInt::get(ip, 1), bindNowOld),
        bindNowSlot);
    DBB.CreateCondBr(DBB.CreateICmpEQ(tag, ConstantInt::get(i64, 0)), relPrepBB,
                     dynNextBB);

    IRBuilder<> DNB(dynNextBB);
    Value *dynNext = DNB.CreateAdd(dynIdx, ConstantInt::get(ip, 1),
                                   "morok.antihook.got.dynamic.next");
    DNB.CreateBr(dynLoopBB);
    dynIdx->addIncoming(dynNext, dynNextBB);

    IRBuilder<> RPB(relPrepBB);
    Value *jmpRelRaw =
        RPB.CreateLoad(ip, jmpRelSlot, "morok.antihook.got.jmprel.raw");
    Value *jmpRel = normalizeElfAddress(RPB, M, base, jmpRelRaw,
                                        "morok.antihook.got.jmprel.addr");
    Value *pltRelSz =
        RPB.CreateLoad(ip, pltRelSzSlot, "morok.antihook.got.pltrelsz.final");
    Value *pltRel =
        RPB.CreateLoad(ip, pltRelSlot, "morok.antihook.got.pltrel.final");
    Value *symTabRaw =
        RPB.CreateLoad(ip, symTabSlot, "morok.antihook.got.symtab.raw");
    Value *strTabRaw =
        RPB.CreateLoad(ip, strTabSlot, "morok.antihook.got.strtab.raw");
    Value *symTab = normalizeElfAddress(RPB, M, base, symTabRaw,
                                        "morok.antihook.got.symtab.addr");
    Value *strTab = normalizeElfAddress(RPB, M, base, strTabRaw,
                                        "morok.antihook.got.strtab.addr");
    Value *symEntRaw =
        RPB.CreateLoad(ip, symEntSlot, "morok.antihook.got.syment.raw");
    Value *symEnt = RPB.CreateSelect(
        RPB.CreateICmpUGE(symEntRaw, ConstantInt::get(ip, 24)), symEntRaw,
        ConstantInt::get(ip, 24), "morok.antihook.got.syment");
    Value *debugRaw =
        RPB.CreateLoad(ip, debugSlot, "morok.antihook.got.debug.raw");
    Value *debugPtr =
        RPB.CreateIntToPtr(debugRaw, ptr, "morok.antihook.got.debug.ptr");
    Value *isRela = RPB.CreateICmpEQ(pltRel, ConstantInt::get(ip, 7),
                                     "morok.antihook.got.rela");
    Value *isRel = RPB.CreateICmpEQ(pltRel, ConstantInt::get(ip, 17),
                                    "morok.antihook.got.rel");
    Value *entrySize = RPB.CreateSelect(isRela, ConstantInt::get(ip, 24),
                                        ConstantInt::get(ip, 16),
                                        "morok.antihook.got.rel.ent");
    Value *relCount =
        RPB.CreateUDiv(pltRelSz, entrySize, "morok.antihook.got.rel.count");
    Value *flags = RPB.CreateLoad(ip, flagsSlot, "morok.antihook.got.flags.v");
    Value *flags1 =
        RPB.CreateLoad(ip, flags1Slot, "morok.antihook.got.flags1.v");
    Value *bindNow =
        RPB.CreateLoad(ip, bindNowSlot, "morok.antihook.got.bindnow.v");
    Value *hasNow = RPB.CreateOr(
        RPB.CreateOr(
            RPB.CreateICmpNE(bindNow, ConstantInt::get(ip, 0)),
            RPB.CreateICmpNE(RPB.CreateAnd(flags, ConstantInt::get(ip, 8)),
                             ConstantInt::get(ip, 0))),
        RPB.CreateICmpNE(RPB.CreateAnd(flags1, ConstantInt::get(ip, 1)),
                         ConstantInt::get(ip, 0)),
        "morok.antihook.got.now");
    Value *validRelocs = RPB.CreateAnd(
        RPB.CreateICmpNE(jmpRelRaw, ConstantInt::get(ip, 0)),
        RPB.CreateAnd(RPB.CreateICmpUGT(pltRelSz, ConstantInt::get(ip, 0)),
                      RPB.CreateAnd(
                          RPB.CreateOr(isRela, isRel),
                          RPB.CreateAnd(
                              RPB.CreateICmpNE(symTabRaw,
                                               ConstantInt::get(ip, 0)),
                              RPB.CreateICmpNE(strTabRaw,
                                               ConstantInt::get(ip, 0))))),
        "morok.antihook.got.valid");
    RPB.CreateCondBr(validRelocs, relLoopBB, retBB);

    IRBuilder<> RLB(relLoopBB);
    auto *relIdx = RLB.CreatePHI(ip, 2, "morok.antihook.got.rel.idx");
    relIdx->addIncoming(ConstantInt::get(ip, 0), relPrepBB);
    Value *relInRange =
        RLB.CreateAnd(RLB.CreateICmpULT(relIdx, relCount),
                      RLB.CreateICmpULT(relIdx, ConstantInt::get(ip, 4096)));
    RLB.CreateCondBr(relInRange, relBodyBB, retBB);

    IRBuilder<> RBB(relBodyBB);
    Value *relPtr = RBB.CreateIntToPtr(
        RBB.CreateAdd(jmpRel, RBB.CreateMul(relIdx, entrySize)), ptr,
        "morok.antihook.got.rel.ptr");
    Value *relOff =
        loadAt(RBB, M, i64, relPtr, 0ULL, "morok.antihook.got.rel.offset");
    Value *relInfo =
        loadAt(RBB, M, i64, relPtr, 8, "morok.antihook.got.rel.info");
    Value *symIdx =
        RBB.CreateLShr(relInfo, ConstantInt::get(i64, 32),
                       "morok.antihook.got.rel.sym");
    Value *symPtr = RBB.CreateIntToPtr(
        RBB.CreateAdd(symTab, RBB.CreateMul(symIdx, symEnt)),
        ptr, "morok.antihook.got.sym.ptr");
    Value *nameOff32 =
        loadAt(RBB, M, Type::getInt32Ty(ctx), symPtr, 0ULL,
               "morok.antihook.got.sym.name");
    Value *symShndx =
        loadAt(RBB, M, Type::getInt16Ty(ctx), symPtr, 6,
               "morok.antihook.got.sym.shndx");
    Value *nameOff =
        RBB.CreateZExt(nameOff32, ip, "morok.antihook.got.sym.name.w");
    Value *namePtr = RBB.CreateIntToPtr(
        RBB.CreateAdd(strTab, nameOff), ptr, "morok.antihook.got.sym.name.ptr");
    Value *slotAddr =
        normalizeElfAddress(RBB, M, base, relOff, "morok.antihook.got.slot");
    Value *slotPtr =
        RBB.CreateIntToPtr(slotAddr, ptr, "morok.antihook.got.slot.ptr");
    auto *targetPtr = RBB.CreateLoad(ptr, slotPtr, "morok.antihook.got.target");
    targetPtr->setVolatile(true);
    Value *targetAddr =
        RBB.CreatePtrToInt(targetPtr, ip, "morok.antihook.got.target.addr");
    Value *rxOk = RBB.CreateCall(
        rxCheck, {targetAddr, atPhdr, phNum, phEnt, base, debugPtr},
        "morok.antihook.got.rx");
    Value *expectedPtr = RBB.CreateCall(
        neededCheck, {namePtr, dynAddr, strTab}, "morok.antihook.got.expected");
    Value *hasExpected =
        RBB.CreateICmpNE(expectedPtr, ConstantPointerNull::get(ptr),
                         "morok.antihook.got.expected.present");
    Value *expectedOk = RBB.CreateAnd(
        hasExpected,
        RBB.CreateICmpEQ(expectedPtr, targetPtr,
                         "morok.antihook.got.expected.eq"),
        "morok.antihook.got.expected.ok");
    Value *externalSym =
        RBB.CreateICmpEQ(symShndx, ConstantInt::get(Type::getInt16Ty(ctx), 0),
                         "morok.antihook.got.sym.external");
    Value *lazy = RBB.CreateCall(
        lazyCheck, {targetAddr, slotAddr, atPhdr, phNum, phEnt, base},
        "morok.antihook.got.lazy");
    Value *lazyShape = RBB.CreateAnd(
        RBB.CreateAnd(RBB.CreateNot(hasNow, "morok.antihook.got.lazy.notnow"),
                      externalSym),
        RBB.CreateICmpNE(lazy, ConstantInt::get(Type::getInt32Ty(ctx), 0)),
        "morok.antihook.got.lazy.shape");
    Value *relroV =
        RBB.CreateLoad(ip, relroVaddrSlot, "morok.antihook.got.relro.v");
    Value *relroSize =
        RBB.CreateLoad(ip, relroMemszSlot, "morok.antihook.got.relro.sz");
    Value *relroStart =
        RBB.CreateAdd(base, relroV, "morok.antihook.got.relro.start");
    Value *relroEnd =
        RBB.CreateAdd(relroStart, relroSize, "morok.antihook.got.relro.end");
    Value *slotInAnyRelro = RBB.CreateAnd(
        RBB.CreateICmpNE(relroV, ConstantInt::get(ip, 0)),
        RBB.CreateAnd(RBB.CreateICmpUGE(slotAddr, relroStart),
                      RBB.CreateICmpULT(slotAddr, relroEnd)),
        "morok.antihook.got.relro.slot");
    Value *lazyWritable = RBB.CreateNot(slotInAnyRelro,
                                        "morok.antihook.got.lazy.writable");
    Value *lazyPending = RBB.CreateAnd(lazyShape, lazyWritable,
                                       "morok.antihook.got.lazy.pending");
    Value *localRxOk = RBB.CreateAnd(
        RBB.CreateNot(externalSym, "morok.antihook.got.sym.local"),
        RBB.CreateICmpNE(rxOk, ConstantInt::get(Type::getInt32Ty(ctx), 0)),
        "morok.antihook.got.local.rx");
    Value *targetOk = RBB.CreateOr(
        expectedOk, RBB.CreateOr(localRxOk, lazyPending,
                                 "morok.antihook.got.local.or.lazy.pending"),
        "morok.antihook.got.target.ok");
    RBB.CreateBr(relValidateBB);

    IRBuilder<> RVB(relValidateBB);
    incrementDiff(
        RVB, diff,
        RVB.CreateNot(targetOk, "morok.antihook.got.violation.pred"),
        "morok.antihook.got.violation");

    Value *slotInRelro = RVB.CreateAnd(
        hasNow, slotInAnyRelro,
        "morok.antihook.got.protect");
    Value *protectOk =
        RVB.CreateAnd(slotInRelro, targetOk, "morok.antihook.got.protect.ok");
    RVB.CreateCondBr(protectOk, protectBB, relNextBB);

    IRBuilder<> PRB(protectBB);
    Value *pageMask =
        PRB.CreateNot(PRB.CreateSub(pageSize, ConstantInt::get(ip, 1)),
                      "morok.antihook.got.page.mask");
    Value *pageStart =
        PRB.CreateAnd(slotAddr, pageMask, "morok.antihook.got.page");
    Value *mprotectRc = emitLinuxMprotect(PRB, M, TT, pageStart, pageSize,
                                          ConstantInt::get(ip, 1));
    mprotectRc->setName("morok.antihook.got.mprotect");
    incrementDiff(PRB, diff,
                  PRB.CreateICmpSLT(mprotectRc, ConstantInt::getSigned(
                                                    Type::getInt32Ty(ctx), 0)),
                  "morok.antihook.got.mprotect.fail");
    PRB.CreateBr(relNextBB);

    IRBuilder<> RNB(relNextBB);
    Value *relNext = RNB.CreateAdd(relIdx, ConstantInt::get(ip, 1),
                                   "morok.antihook.got.rel.next");
    RNB.CreateBr(relLoopBB);
    relIdx->addIncoming(relNext, relNextBB);

    IRBuilder<> RB(retBB);
    emitRetDiff(RB, diff);
    return fn;
}

Function *darwinDylibNameForOrdinal(Module &M) {
    if (Function *existing = M.getFunction("morok.antihook.macho.dylib.ordinal"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);

    auto *fn = Function::Create(FunctionType::get(ptr, {ptr, i32}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.macho.dylib.ordinal", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    auto *hdr = fn->getArg(0);
    hdr->setName("hdr");
    auto *wantedOrdinal = fn->getArg(1);
    wantedOrdinal->setName("ordinal");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *loopBB = BasicBlock::Create(ctx, "loop", fn);
    auto *bodyBB = BasicBlock::Create(ctx, "body", fn);
    auto *matchBB = BasicBlock::Create(ctx, "match", fn);
    auto *nextBB = BasicBlock::Create(ctx, "next", fn);
    auto *ret0BB = BasicBlock::Create(ctx, "ret0", fn);

    IRBuilder<> B(entry);
    Value *ncmds = loadAt(B, M, i32, hdr, 16, "morok.antihook.macho.dylib.ncmds");
    Value *valid = B.CreateAnd(
        B.CreateICmpNE(hdr, ConstantPointerNull::get(ptr)),
        B.CreateAnd(B.CreateICmpUGT(wantedOrdinal, ConstantInt::get(i32, 0)),
                    B.CreateICmpULT(wantedOrdinal, ConstantInt::get(i32, 0xFE)),
                    "morok.antihook.macho.dylib.ordinal.public"),
        "morok.antihook.macho.dylib.valid");
    B.CreateCondBr(valid, loopBB, ret0BB);

    IRBuilder<> LB(loopBB);
    auto *cmdIdx = LB.CreatePHI(i32, 2, "morok.antihook.macho.dylib.cmd.idx");
    auto *cmdOff = LB.CreatePHI(ip, 2, "morok.antihook.macho.dylib.cmd.off");
    auto *ordinal = LB.CreatePHI(i32, 2, "morok.antihook.macho.dylib.ordinal.cur");
    cmdIdx->addIncoming(ConstantInt::get(i32, 0), entry);
    cmdOff->addIncoming(ConstantInt::get(ip, 32), entry);
    ordinal->addIncoming(ConstantInt::get(i32, 0), entry);
    Value *cmdInRange =
        LB.CreateAnd(LB.CreateICmpULT(cmdIdx, ncmds),
                     LB.CreateICmpULT(cmdIdx, ConstantInt::get(i32, 128)),
                     "morok.antihook.macho.dylib.cmd.range");
    LB.CreateCondBr(cmdInRange, bodyBB, ret0BB);

    IRBuilder<> BB(bodyBB);
    Value *cmdPtr = gepI8(BB, M, hdr, cmdOff, "morok.antihook.macho.dylib.cmd");
    Value *cmd = loadAt(BB, M, i32, cmdPtr, 0ULL,
                        "morok.antihook.macho.dylib.cmd.id");
    Value *cmdSize32 = loadAt(BB, M, i32, cmdPtr, 4,
                              "morok.antihook.macho.dylib.cmd.size");
    Value *cmdSize =
        BB.CreateZExt(cmdSize32, ip, "morok.antihook.macho.dylib.cmd.size.w");
    Value *cmdBase = BB.CreateAnd(
        cmd, ConstantInt::get(i32, 0x7FFFFFFF),
        "morok.antihook.macho.dylib.cmd.base");
    Value *isLoadDylib =
        BB.CreateOr(BB.CreateOr(BB.CreateICmpEQ(cmdBase, ConstantInt::get(i32, 0xC)),
                                BB.CreateICmpEQ(cmdBase, ConstantInt::get(i32, 0x18))),
                    BB.CreateOr(
                        BB.CreateICmpEQ(cmdBase, ConstantInt::get(i32, 0x1F)),
                        BB.CreateOr(
                            BB.CreateICmpEQ(cmdBase, ConstantInt::get(i32, 0x20)),
                            BB.CreateICmpEQ(cmdBase, ConstantInt::get(i32, 0x23)))),
                    "morok.antihook.macho.dylib.loadcmd");
    Value *nextOrdinal =
        BB.CreateAdd(ordinal, BB.CreateZExt(isLoadDylib, i32),
                     "morok.antihook.macho.dylib.ordinal.next");
    Value *wanted = BB.CreateAnd(
        isLoadDylib, BB.CreateICmpEQ(nextOrdinal, wantedOrdinal),
        "morok.antihook.macho.dylib.ordinal.match");
    BB.CreateCondBr(wanted, matchBB, nextBB);

    IRBuilder<> MB(matchBB);
    Value *nameOff32 =
        loadAt(MB, M, i32, cmdPtr, 8, "morok.antihook.macho.dylib.name.off");
    Value *nameOff =
        MB.CreateZExt(nameOff32, ip, "morok.antihook.macho.dylib.name.off.w");
    Value *nameValid = MB.CreateICmpULT(nameOff, cmdSize,
                                        "morok.antihook.macho.dylib.name.valid");
    Value *namePtr = gepI8(MB, M, cmdPtr, nameOff,
                           "morok.antihook.macho.dylib.name");
    MB.CreateRet(MB.CreateSelect(nameValid, namePtr,
                                 ConstantPointerNull::get(ptr)));

    IRBuilder<> NB(nextBB);
    Value *nextCmdIdx = NB.CreateAdd(cmdIdx, ConstantInt::get(i32, 1),
                                     "morok.antihook.macho.dylib.cmd.next");
    Value *nextCmdOff =
        NB.CreateAdd(cmdOff, cmdSize, "morok.antihook.macho.dylib.off.next");
    NB.CreateBr(loopBB);
    cmdIdx->addIncoming(nextCmdIdx, nextBB);
    cmdOff->addIncoming(nextCmdOff, nextBB);
    ordinal->addIncoming(nextOrdinal, nextBB);

    IRBuilder<> R0(ret0BB);
    R0.CreateRet(ConstantPointerNull::get(ptr));
    return fn;
}

Function *boundedRuntimeStringEq(Module &M) {
    if (Function *existing = M.getFunction("morok.antihook.str.eq"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);

    auto *fn = Function::Create(FunctionType::get(i32, {ptr, ptr}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.str.eq", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    auto *lhs = fn->getArg(0);
    lhs->setName("lhs");
    auto *rhs = fn->getArg(1);
    rhs->setName("rhs");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *loopBB = BasicBlock::Create(ctx, "loop", fn);
    auto *nextBB = BasicBlock::Create(ctx, "next", fn);
    auto *ret1BB = BasicBlock::Create(ctx, "ret1", fn);
    auto *ret0BB = BasicBlock::Create(ctx, "ret0", fn);

    IRBuilder<> B(entry);
    Value *valid = B.CreateAnd(
        B.CreateICmpNE(lhs, ConstantPointerNull::get(ptr)),
        B.CreateICmpNE(rhs, ConstantPointerNull::get(ptr)),
        "morok.antihook.str.eq.valid");
    B.CreateCondBr(valid, loopBB, ret0BB);

    IRBuilder<> LB(loopBB);
    auto *idx = LB.CreatePHI(ip, 2, "morok.antihook.str.eq.idx");
    idx->addIncoming(ConstantInt::get(ip, 0), entry);
    Value *lhsCh = LB.CreateAlignedLoad(
        i8, gepI8(LB, M, lhs, idx, "morok.antihook.str.eq.lhs.ptr"), Align(1),
        "morok.antihook.str.eq.lhs");
    Value *rhsCh = LB.CreateAlignedLoad(
        i8, gepI8(LB, M, rhs, idx, "morok.antihook.str.eq.rhs.ptr"), Align(1),
        "morok.antihook.str.eq.rhs");
    Value *same =
        LB.CreateICmpEQ(lhsCh, rhsCh, "morok.antihook.str.eq.byte");
    Value *atEnd =
        LB.CreateICmpEQ(lhsCh, ConstantInt::get(i8, 0),
                        "morok.antihook.str.eq.end");
    Value *done =
        LB.CreateAnd(same, atEnd, "morok.antihook.str.eq.done");
    LB.CreateCondBr(done, ret1BB, nextBB);

    IRBuilder<> NB(nextBB);
    Value *next = NB.CreateAdd(idx, ConstantInt::get(ip, 1),
                               "morok.antihook.str.eq.next");
    Value *keepGoing = NB.CreateAnd(
        same, NB.CreateICmpULT(idx, ConstantInt::get(ip, 511)),
        "morok.antihook.str.eq.keep");
    NB.CreateCondBr(keepGoing, loopBB, ret0BB);
    idx->addIncoming(next, nextBB);

    IRBuilder<> R1(ret1BB);
    R1.CreateRet(ConstantInt::get(i32, 1));

    IRBuilder<> R0(ret0BB);
    R0.CreateRet(ConstantInt::get(i32, 0));
    return fn;
}

Function *darwinTextTargetInImageIndex(Module &M) {
    if (Function *existing = M.getFunction("morok.antihook.macho.image.text"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);

    auto *fn = Function::Create(FunctionType::get(i32, {ip, i32}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.macho.image.text", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    auto *target = fn->getArg(0);
    target->setName("target");
    auto *imageIdx = fn->getArg(1);
    imageIdx->setName("image");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *cmdLoopBB = BasicBlock::Create(ctx, "cmd.loop", fn);
    auto *cmdBodyBB = BasicBlock::Create(ctx, "cmd.body", fn);
    auto *cmdNextBB = BasicBlock::Create(ctx, "cmd.next", fn);
    auto *ret1BB = BasicBlock::Create(ctx, "ret1", fn);
    auto *ret0BB = BasicBlock::Create(ctx, "ret0", fn);

    FunctionCallee imageCount = M.getOrInsertFunction(
        "_dyld_image_count", FunctionType::get(i32, false));
    FunctionCallee imageHeader = M.getOrInsertFunction(
        "_dyld_get_image_header", FunctionType::get(ptr, {i32}, false));
    FunctionCallee imageSlide = M.getOrInsertFunction(
        "_dyld_get_image_vmaddr_slide", FunctionType::get(ip, {i32}, false));

    IRBuilder<> B(entry);
    Value *count = B.CreateCall(imageCount, {}, "morok.macho.image.text.count");
    Value *hdr = B.CreateCall(imageHeader, {imageIdx},
                              "morok.macho.image.text.hdr");
    Value *slide = B.CreateCall(imageSlide, {imageIdx},
                                "morok.macho.image.text.slide");
    Value *magic =
        loadAt(B, M, i32, hdr, 0ULL, "morok.antihook.macho.image.text.magic");
    Value *ncmds =
        loadAt(B, M, i32, hdr, 16, "morok.antihook.macho.image.text.ncmds");
    Value *valid = B.CreateAnd(
        B.CreateAnd(B.CreateICmpNE(target, ConstantInt::get(ip, 0)),
                    B.CreateICmpULT(imageIdx, count)),
        B.CreateAnd(B.CreateICmpNE(hdr, ConstantPointerNull::get(ptr)),
                    B.CreateICmpEQ(magic, ConstantInt::get(i32, 0xFEEDFACF))),
        "morok.antihook.macho.image.text.valid");
    B.CreateCondBr(valid, cmdLoopBB, ret0BB);

    IRBuilder<> CLB(cmdLoopBB);
    auto *cmdIdx = CLB.CreatePHI(i32, 2, "morok.antihook.macho.image.text.cmd.idx");
    auto *cmdOff = CLB.CreatePHI(ip, 2, "morok.antihook.macho.image.text.cmd.off");
    cmdIdx->addIncoming(ConstantInt::get(i32, 0), entry);
    cmdOff->addIncoming(ConstantInt::get(ip, 32), entry);
    Value *cmdInRange =
        CLB.CreateAnd(CLB.CreateICmpULT(cmdIdx, ncmds),
                      CLB.CreateICmpULT(cmdIdx, ConstantInt::get(i32, 128)),
                      "morok.antihook.macho.image.text.cmd.range");
    CLB.CreateCondBr(cmdInRange, cmdBodyBB, ret0BB);

    IRBuilder<> CBB(cmdBodyBB);
    Value *cmdPtr =
        gepI8(CBB, M, hdr, cmdOff, "morok.antihook.macho.image.text.cmd.ptr");
    Value *cmd = loadAt(CBB, M, i32, cmdPtr, 0ULL,
                        "morok.antihook.macho.image.text.cmd");
    Value *cmdSize32 = loadAt(CBB, M, i32, cmdPtr, 4,
                              "morok.antihook.macho.image.text.cmd.size");
    Value *cmdSize =
        CBB.CreateZExt(cmdSize32, ip, "morok.antihook.macho.image.text.cmd.size.w");
    Value *vmaddr =
        loadAt(CBB, M, i64, cmdPtr, 24,
               "morok.antihook.macho.image.text.seg.vmaddr");
    Value *vmsize =
        loadAt(CBB, M, i64, cmdPtr, 32,
               "morok.antihook.macho.image.text.seg.vmsize");
    Value *initprot =
        loadAt(CBB, M, i32, cmdPtr, 60,
               "morok.antihook.macho.image.text.seg.initprot");
    Value *isSegment = CBB.CreateICmpEQ(cmd, ConstantInt::get(i32, 0x19),
                                        "morok.antihook.macho.image.text.seg");
    Value *isExec = CBB.CreateICmpNE(
        CBB.CreateAnd(initprot, ConstantInt::get(i32, 4)),
        ConstantInt::get(i32, 0), "morok.antihook.macho.image.text.exec");
    Value *segStart =
        CBB.CreateAdd(slide, vmaddr, "morok.antihook.macho.image.text.start");
    Value *segEnd =
        CBB.CreateAdd(segStart, vmsize, "morok.antihook.macho.image.text.end");
    Value *hit =
        CBB.CreateAnd(CBB.CreateAnd(isSegment, isExec),
                      CBB.CreateAnd(CBB.CreateICmpUGE(target, segStart),
                                    CBB.CreateICmpULT(target, segEnd)),
                      "morok.antihook.macho.image.text.hit");
    CBB.CreateCondBr(hit, ret1BB, cmdNextBB);

    IRBuilder<> CNB(cmdNextBB);
    Value *nextCmdIdx = CNB.CreateAdd(cmdIdx, ConstantInt::get(i32, 1),
                                      "morok.antihook.macho.image.text.cmd.next");
    Value *nextCmdOff =
        CNB.CreateAdd(cmdOff, cmdSize,
                      "morok.antihook.macho.image.text.cmd.off.next");
    CNB.CreateBr(cmdLoopBB);
    cmdIdx->addIncoming(nextCmdIdx, cmdNextBB);
    cmdOff->addIncoming(nextCmdOff, cmdNextBB);

    IRBuilder<> R1(ret1BB);
    R1.CreateRet(ConstantInt::get(i32, 1));

    IRBuilder<> R0(ret0BB);
    R0.CreateRet(ConstantInt::get(i32, 0));
    return fn;
}

Function *darwinTargetMatchesExpectedDylibSymbol(Module &M) {
    if (Function *existing = M.getFunction("morok.antihook.macho.expected.symbol"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    Function *stringEq = boundedRuntimeStringEq(M);

    auto *fn = Function::Create(FunctionType::get(i32, {ip, ptr, ptr}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.macho.expected.symbol", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    auto *target = fn->getArg(0);
    target->setName("target");
    auto *symName = fn->getArg(1);
    symName->setName("symbol");
    auto *dylibName = fn->getArg(2);
    dylibName->setName("dylib");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *imageLoopBB = BasicBlock::Create(ctx, "image.loop", fn);
    auto *imageBodyBB = BasicBlock::Create(ctx, "image.body", fn);
    auto *cmdLoopBB = BasicBlock::Create(ctx, "cmd.loop", fn);
    auto *cmdBodyBB = BasicBlock::Create(ctx, "cmd.body", fn);
    auto *cmdNextBB = BasicBlock::Create(ctx, "cmd.next", fn);
    auto *symPrepBB = BasicBlock::Create(ctx, "sym.prep", fn);
    auto *symLoopBB = BasicBlock::Create(ctx, "sym.loop", fn);
    auto *symBodyBB = BasicBlock::Create(ctx, "sym.body", fn);
    auto *symNextBB = BasicBlock::Create(ctx, "sym.next", fn);
    auto *imageNextBB = BasicBlock::Create(ctx, "image.next", fn);
    auto *ret1BB = BasicBlock::Create(ctx, "ret1", fn);
    auto *ret0BB = BasicBlock::Create(ctx, "ret0", fn);

    FunctionCallee imageCount = M.getOrInsertFunction(
        "_dyld_image_count", FunctionType::get(i32, false));
    FunctionCallee imageName = M.getOrInsertFunction(
        "_dyld_get_image_name", FunctionType::get(ptr, {i32}, false));
    FunctionCallee imageHeader = M.getOrInsertFunction(
        "_dyld_get_image_header", FunctionType::get(ptr, {i32}, false));
    FunctionCallee imageSlide = M.getOrInsertFunction(
        "_dyld_get_image_vmaddr_slide", FunctionType::get(ip, {i32}, false));

    IRBuilder<> B(entry);
    AllocaInst *linkeditVmSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.macho.expected.linkedit.vm");
    AllocaInst *linkeditFileSlot =
        B.CreateAlloca(ip, nullptr,
                       "morok.antihook.macho.expected.linkedit.file");
    AllocaInst *symOffSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.macho.expected.symoff");
    AllocaInst *nSymsSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.macho.expected.nsyms");
    AllocaInst *strOffSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.macho.expected.stroff");
    for (AllocaInst *slot :
         {linkeditVmSlot, linkeditFileSlot, symOffSlot, nSymsSlot, strOffSlot})
        B.CreateStore(ConstantInt::get(ip, 0), slot);
    Value *count =
        B.CreateCall(imageCount, {}, "morok.antihook.macho.expected.count");
    Value *valid = B.CreateAnd(
        B.CreateICmpNE(target, ConstantInt::get(ip, 0)),
        B.CreateAnd(
            B.CreateICmpNE(symName, ConstantPointerNull::get(ptr)),
            B.CreateAnd(B.CreateICmpNE(dylibName, ConstantPointerNull::get(ptr)),
                        B.CreateICmpUGT(count, ConstantInt::get(i32, 0)))),
        "morok.antihook.macho.expected.valid");
    B.CreateCondBr(valid, imageLoopBB, ret0BB);

    IRBuilder<> ILB(imageLoopBB);
    auto *imageIdx =
        ILB.CreatePHI(i32, 2, "morok.antihook.macho.expected.image.idx");
    imageIdx->addIncoming(ConstantInt::get(i32, 0), entry);
    Value *imageInRange =
        ILB.CreateAnd(ILB.CreateICmpULT(imageIdx, count),
                      ILB.CreateICmpULT(imageIdx, ConstantInt::get(i32, 128)),
                      "morok.antihook.macho.expected.image.range");
    ILB.CreateCondBr(imageInRange, imageBodyBB, ret0BB);

    IRBuilder<> IBB(imageBodyBB);
    Value *loadedName = IBB.CreateCall(
        imageName, {imageIdx}, "morok.antihook.macho.expected.image.name");
    Value *nameMatch = IBB.CreateCall(
        stringEq, {loadedName, dylibName},
        "morok.antihook.macho.expected.image.name.eq");
    Value *hdr = IBB.CreateCall(imageHeader, {imageIdx},
                                "morok.antihook.macho.expected.hdr");
    Value *slide = IBB.CreateCall(imageSlide, {imageIdx},
                                  "morok.antihook.macho.expected.slide");
    Value *magic =
        loadAt(IBB, M, i32, hdr, 0ULL, "morok.antihook.macho.expected.magic");
    Value *ncmds =
        loadAt(IBB, M, i32, hdr, 16, "morok.antihook.macho.expected.ncmds");
    for (AllocaInst *slot :
         {linkeditVmSlot, linkeditFileSlot, symOffSlot, nSymsSlot, strOffSlot})
        IBB.CreateStore(ConstantInt::get(ip, 0), slot);
    Value *imageValid = IBB.CreateAnd(
        IBB.CreateICmpNE(nameMatch, ConstantInt::get(i32, 0),
                         "morok.antihook.macho.expected.image.match"),
        IBB.CreateAnd(IBB.CreateICmpNE(hdr, ConstantPointerNull::get(ptr)),
                      IBB.CreateICmpEQ(magic, ConstantInt::get(i32, 0xFEEDFACF))),
        "morok.antihook.macho.expected.image.valid");
    IBB.CreateCondBr(imageValid, cmdLoopBB, imageNextBB);

    IRBuilder<> CLB(cmdLoopBB);
    auto *cmdIdx =
        CLB.CreatePHI(i32, 2, "morok.antihook.macho.expected.cmd.idx");
    auto *cmdOff =
        CLB.CreatePHI(ip, 2, "morok.antihook.macho.expected.cmd.off");
    cmdIdx->addIncoming(ConstantInt::get(i32, 0), imageBodyBB);
    cmdOff->addIncoming(ConstantInt::get(ip, 32), imageBodyBB);
    Value *cmdInRange =
        CLB.CreateAnd(CLB.CreateICmpULT(cmdIdx, ncmds),
                      CLB.CreateICmpULT(cmdIdx, ConstantInt::get(i32, 128)),
                      "morok.antihook.macho.expected.cmd.range");
    CLB.CreateCondBr(cmdInRange, cmdBodyBB, symPrepBB);

    IRBuilder<> CBB(cmdBodyBB);
    Value *cmdPtr =
        gepI8(CBB, M, hdr, cmdOff, "morok.antihook.macho.expected.cmd.ptr");
    Value *cmd = loadAt(CBB, M, i32, cmdPtr, 0ULL,
                        "morok.antihook.macho.expected.cmd");
    Value *cmdSize32 = loadAt(CBB, M, i32, cmdPtr, 4,
                              "morok.antihook.macho.expected.cmd.size");
    Value *cmdSize =
        CBB.CreateZExt(cmdSize32, ip,
                       "morok.antihook.macho.expected.cmd.size.w");
    Value *cmdBase = CBB.CreateAnd(
        cmd, ConstantInt::get(i32, 0x7FFFFFFF),
        "morok.antihook.macho.expected.cmd.base");
    Value *isSymtab =
        CBB.CreateICmpEQ(cmdBase, ConstantInt::get(i32, 0x2),
                         "morok.antihook.macho.expected.symtab.cmd");
    Value *isSegment =
        CBB.CreateICmpEQ(cmd, ConstantInt::get(i32, 0x19),
                         "morok.antihook.macho.expected.segment");
    Value *segName8 = CBB.CreateAlignedLoad(
        i64, gepI8(CBB, M, cmdPtr, constIp(M, 8),
                   "morok.antihook.macho.expected.segname.ptr"),
        Align(1), "morok.antihook.macho.expected.segname8");
    Value *isLinkedit = CBB.CreateAnd(
        isSegment,
        CBB.CreateICmpEQ(segName8, ConstantInt::get(i64, 0x44454B4E494C5F5FULL)),
        "morok.antihook.macho.expected.linkedit.segment");
    Value *symOff32 = loadAt(CBB, M, i32, cmdPtr, 8,
                             "morok.antihook.macho.expected.symoff.cmd");
    Value *nSyms32 = loadAt(CBB, M, i32, cmdPtr, 12,
                            "morok.antihook.macho.expected.nsyms.cmd");
    Value *strOff32 = loadAt(CBB, M, i32, cmdPtr, 16,
                             "morok.antihook.macho.expected.stroff.cmd");
    Value *segVmaddr =
        loadAt(CBB, M, i64, cmdPtr, 24,
               "morok.antihook.macho.expected.seg.vmaddr");
    Value *segFileoff =
        loadAt(CBB, M, i64, cmdPtr, 40,
               "morok.antihook.macho.expected.seg.fileoff");
    auto storeIf = [&](AllocaInst *Slot, Value *Condition, Value *NewValue) {
        Value *old = CBB.CreateLoad(ip, Slot);
        CBB.CreateStore(CBB.CreateSelect(Condition, NewValue, old), Slot);
    };
    storeIf(symOffSlot, isSymtab,
            CBB.CreateZExt(symOff32, ip,
                           "morok.antihook.macho.expected.symoff.w"));
    storeIf(nSymsSlot, isSymtab,
            CBB.CreateZExt(nSyms32, ip,
                           "morok.antihook.macho.expected.nsyms.w"));
    storeIf(strOffSlot, isSymtab,
            CBB.CreateZExt(strOff32, ip,
                           "morok.antihook.macho.expected.stroff.w"));
    storeIf(linkeditVmSlot, isLinkedit,
            CBB.CreateZExtOrTrunc(segVmaddr, ip,
                                  "morok.antihook.macho.expected.linkedit.vm.w"));
    storeIf(linkeditFileSlot, isLinkedit,
            CBB.CreateZExtOrTrunc(segFileoff, ip,
                                  "morok.antihook.macho.expected.linkedit.file.w"));
    CBB.CreateBr(cmdNextBB);

    IRBuilder<> CNB(cmdNextBB);
    Value *nextCmdIdx =
        CNB.CreateAdd(cmdIdx, ConstantInt::get(i32, 1),
                      "morok.antihook.macho.expected.cmd.next");
    Value *nextCmdOff =
        CNB.CreateAdd(cmdOff, cmdSize,
                      "morok.antihook.macho.expected.cmd.off.next");
    CNB.CreateBr(cmdLoopBB);
    cmdIdx->addIncoming(nextCmdIdx, cmdNextBB);
    cmdOff->addIncoming(nextCmdOff, cmdNextBB);

    IRBuilder<> SPB(symPrepBB);
    Value *linkeditVm = SPB.CreateLoad(
        ip, linkeditVmSlot, "morok.antihook.macho.expected.linkedit.vm.v");
    Value *linkeditFile = SPB.CreateLoad(
        ip, linkeditFileSlot, "morok.antihook.macho.expected.linkedit.file.v");
    Value *symOff =
        SPB.CreateLoad(ip, symOffSlot, "morok.antihook.macho.expected.symoff.v");
    Value *nSyms =
        SPB.CreateLoad(ip, nSymsSlot, "morok.antihook.macho.expected.nsyms.v");
    Value *strOff =
        SPB.CreateLoad(ip, strOffSlot, "morok.antihook.macho.expected.stroff.v");
    Value *linkeditBase =
        SPB.CreateSub(SPB.CreateAdd(slide, linkeditVm,
                                    "morok.antihook.macho.expected.linkedit.slide"),
                      linkeditFile,
                      "morok.antihook.macho.expected.linkedit.base");
    Value *hasTables = SPB.CreateAnd(
        SPB.CreateICmpNE(linkeditVm, ConstantInt::get(ip, 0)),
        SPB.CreateAnd(
            SPB.CreateICmpNE(symOff, ConstantInt::get(ip, 0)),
            SPB.CreateAnd(SPB.CreateICmpNE(strOff, ConstantInt::get(ip, 0)),
                          SPB.CreateICmpNE(nSyms, ConstantInt::get(ip, 0)))),
        "morok.antihook.macho.expected.tables.present");
    SPB.CreateCondBr(hasTables, symLoopBB, imageNextBB);

    IRBuilder<> SYLB(symLoopBB);
    auto *symIdx =
        SYLB.CreatePHI(ip, 2, "morok.antihook.macho.expected.sym.idx");
    symIdx->addIncoming(ConstantInt::get(ip, 0), symPrepBB);
    Value *symInRange = SYLB.CreateAnd(
        SYLB.CreateICmpULT(symIdx, nSyms),
        SYLB.CreateICmpULT(symIdx, ConstantInt::get(ip, 65536)),
        "morok.antihook.macho.expected.sym.range");
    SYLB.CreateCondBr(symInRange, symBodyBB, imageNextBB);

    IRBuilder<> SYBB(symBodyBB);
    Value *symPtr = SYBB.CreateIntToPtr(
        SYBB.CreateAdd(linkeditBase,
                       SYBB.CreateAdd(symOff,
                                      SYBB.CreateMul(symIdx,
                                                     ConstantInt::get(ip, 16))),
                       "morok.antihook.macho.expected.sym.ptr.addr"),
        ptr, "morok.antihook.macho.expected.sym.ptr");
    Value *strx32 = loadAt(SYBB, M, i32, symPtr, 0ULL,
                           "morok.antihook.macho.expected.sym.strx");
    Value *nValue = loadAt(SYBB, M, i64, symPtr, 8,
                           "morok.antihook.macho.expected.sym.value");
    Value *candidateName = SYBB.CreateIntToPtr(
        SYBB.CreateAdd(linkeditBase,
                       SYBB.CreateAdd(strOff, SYBB.CreateZExt(strx32, ip)),
                       "morok.antihook.macho.expected.sym.name.addr"),
        ptr, "morok.antihook.macho.expected.sym.name");
    Value *symNameMatch = SYBB.CreateCall(
        stringEq, {candidateName, symName},
        "morok.antihook.macho.expected.sym.name.eq");
    Value *candidateAddr = SYBB.CreateAdd(
        slide, SYBB.CreateZExtOrTrunc(nValue, ip),
        "morok.antihook.macho.expected.sym.addr");
    Value *exactHit = SYBB.CreateAnd(
        SYBB.CreateICmpNE(symNameMatch, ConstantInt::get(i32, 0),
                          "morok.antihook.macho.expected.sym.name.match"),
        SYBB.CreateAnd(SYBB.CreateICmpNE(nValue, ConstantInt::get(i64, 0)),
                       SYBB.CreateICmpEQ(candidateAddr, target,
                                         "morok.antihook.macho.expected.sym.eq")),
        "morok.antihook.macho.expected.symbol.hit");
    SYBB.CreateCondBr(exactHit, ret1BB, symNextBB);

    IRBuilder<> SYNB(symNextBB);
    Value *nextSym =
        SYNB.CreateAdd(symIdx, ConstantInt::get(ip, 1),
                       "morok.antihook.macho.expected.sym.next");
    SYNB.CreateBr(symLoopBB);
    symIdx->addIncoming(nextSym, symNextBB);

    IRBuilder<> INB(imageNextBB);
    Value *nextImage =
        INB.CreateAdd(imageIdx, ConstantInt::get(i32, 1),
                      "morok.antihook.macho.expected.image.next");
    INB.CreateBr(imageLoopBB);
    imageIdx->addIncoming(nextImage, imageNextBB);

    IRBuilder<> R1(ret1BB);
    R1.CreateRet(ConstantInt::get(i32, 1));

    IRBuilder<> R0(ret0BB);
    R0.CreateRet(ConstantInt::get(i32, 0));
    return fn;
}

Function *darwinTextTargetInDyldImages(Module &M) {
    if (Function *existing = M.getFunction("morok.antihook.macho.text"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);

    auto *fn = Function::Create(FunctionType::get(i32, {ip}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.macho.text", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    auto *target = fn->getArg(0);
    target->setName("target");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *imageLoopBB = BasicBlock::Create(ctx, "image.loop", fn);
    auto *imageBodyBB = BasicBlock::Create(ctx, "image.body", fn);
    auto *cmdLoopBB = BasicBlock::Create(ctx, "cmd.loop", fn);
    auto *cmdBodyBB = BasicBlock::Create(ctx, "cmd.body", fn);
    auto *cmdNextBB = BasicBlock::Create(ctx, "cmd.next", fn);
    auto *imageNextBB = BasicBlock::Create(ctx, "image.next", fn);
    auto *ret1BB = BasicBlock::Create(ctx, "ret1", fn);
    auto *ret0BB = BasicBlock::Create(ctx, "ret0", fn);

    FunctionCallee imageCount = M.getOrInsertFunction(
        "_dyld_image_count", FunctionType::get(i32, false));
    FunctionCallee imageHeader = M.getOrInsertFunction(
        "_dyld_get_image_header", FunctionType::get(ptr, {i32}, false));
    FunctionCallee imageSlide = M.getOrInsertFunction(
        "_dyld_get_image_vmaddr_slide", FunctionType::get(ip, {i32}, false));

    IRBuilder<> B(entry);
    Value *count = B.CreateCall(imageCount, {}, "morok.macho.image.count");
    B.CreateBr(imageLoopBB);

    IRBuilder<> ILB(imageLoopBB);
    auto *imageIdx = ILB.CreatePHI(i32, 2, "morok.antihook.macho.image.idx");
    imageIdx->addIncoming(ConstantInt::get(i32, 0), entry);
    Value *imageInRange =
        ILB.CreateAnd(ILB.CreateICmpULT(imageIdx, count),
                      ILB.CreateICmpULT(imageIdx, ConstantInt::get(i32, 128)));
    ILB.CreateCondBr(imageInRange, imageBodyBB, ret0BB);

    IRBuilder<> IBB(imageBodyBB);
    Value *hdr = IBB.CreateCall(imageHeader, {imageIdx}, "morok.macho.hdr");
    Value *slide = IBB.CreateCall(imageSlide, {imageIdx}, "morok.macho.slide");
    Value *magic = loadAt(IBB, M, i32, hdr, 0ULL, "morok.antihook.macho.magic");
    Value *ncmds = loadAt(IBB, M, i32, hdr, 16, "morok.antihook.macho.ncmds");
    // L2: only the main executable (image 0) or a system dylib (/usr/lib//System/)
    // counts as legit text.  Without this, an injected dylib (DYLD_INSERT) is a
    // loaded image too, so its text range satisfies the check and whitelists the
    // attacker's own code.  Path prefix compared as the first 8 bytes.
    FunctionCallee imageName = M.getOrInsertFunction(
        "_dyld_get_image_name", FunctionType::get(ptr, {i32}, false));
    Value *name = IBB.CreateCall(imageName, {imageIdx}, "morok.macho.name");
    Value *name8 = IBB.CreateAlignedLoad(i64, name, Align(1), "morok.macho.name8");
    Value *isMain = IBB.CreateICmpEQ(imageIdx, ConstantInt::get(i32, 0));
    Value *isUsrLib = // "/usr/lib"
        IBB.CreateICmpEQ(name8, ConstantInt::get(i64, 0x62696c2f7273752fULL));
    Value *isSystem = // "/System/"
        IBB.CreateICmpEQ(name8, ConstantInt::get(i64, 0x2f6d65747379532fULL));
    Value *legitPath =
        IBB.CreateOr(isMain, IBB.CreateOr(isUsrLib, isSystem), "morok.macho.legit");
    Value *validImage = IBB.CreateAnd(
        IBB.CreateAnd(IBB.CreateICmpNE(hdr, ConstantPointerNull::get(ptr)),
                      IBB.CreateICmpEQ(magic, ConstantInt::get(i32, 0xFEEDFACF))),
        legitPath);
    IBB.CreateCondBr(validImage, cmdLoopBB, imageNextBB);

    IRBuilder<> CLB(cmdLoopBB);
    auto *cmdIdx = CLB.CreatePHI(i32, 2, "morok.antihook.macho.cmd.idx");
    auto *cmdOff = CLB.CreatePHI(ip, 2, "morok.antihook.macho.cmd.off");
    cmdIdx->addIncoming(ConstantInt::get(i32, 0), imageBodyBB);
    cmdOff->addIncoming(ConstantInt::get(ip, 32), imageBodyBB);
    Value *cmdInRange =
        CLB.CreateAnd(CLB.CreateICmpULT(cmdIdx, ncmds),
                      CLB.CreateICmpULT(cmdIdx, ConstantInt::get(i32, 128)));
    CLB.CreateCondBr(cmdInRange, cmdBodyBB, imageNextBB);

    IRBuilder<> CBB(cmdBodyBB);
    Value *cmdPtr = gepI8(CBB, M, hdr, cmdOff, "morok.antihook.macho.cmd.ptr");
    Value *cmd = loadAt(CBB, M, i32, cmdPtr, 0ULL, "morok.antihook.macho.cmd");
    Value *cmdSize32 =
        loadAt(CBB, M, i32, cmdPtr, 4, "morok.antihook.macho.cmd.size");
    Value *cmdSize =
        CBB.CreateZExt(cmdSize32, ip, "morok.antihook.macho.cmd.size.w");
    Value *vmaddr =
        loadAt(CBB, M, i64, cmdPtr, 24, "morok.antihook.macho.seg.vmaddr");
    Value *vmsize =
        loadAt(CBB, M, i64, cmdPtr, 32, "morok.antihook.macho.seg.vmsize");
    Value *initprot =
        loadAt(CBB, M, i32, cmdPtr, 60, "morok.antihook.macho.seg.initprot");
    Value *isSegment = CBB.CreateICmpEQ(cmd, ConstantInt::get(i32, 0x19),
                                        "morok.antihook.macho.seg");
    Value *isExec = CBB.CreateICmpNE(
        CBB.CreateAnd(initprot, ConstantInt::get(i32, 4)),
        ConstantInt::get(i32, 0), "morok.antihook.macho.seg.exec");
    Value *segStart =
        CBB.CreateAdd(slide, vmaddr, "morok.antihook.macho.text.start");
    Value *segEnd =
        CBB.CreateAdd(segStart, vmsize, "morok.antihook.macho.text.end");
    Value *hit =
        CBB.CreateAnd(CBB.CreateAnd(isSegment, isExec),
                      CBB.CreateAnd(CBB.CreateICmpUGE(target, segStart),
                                    CBB.CreateICmpULT(target, segEnd)),
                      "morok.antihook.macho.text.hit");
    CBB.CreateCondBr(hit, ret1BB, cmdNextBB);

    IRBuilder<> CNB(cmdNextBB);
    Value *nextCmdIdx = CNB.CreateAdd(cmdIdx, ConstantInt::get(i32, 1),
                                      "morok.antihook.macho.cmd.next");
    Value *nextCmdOff =
        CNB.CreateAdd(cmdOff, cmdSize, "morok.antihook.macho.cmd.off.next");
    CNB.CreateBr(cmdLoopBB);
    cmdIdx->addIncoming(nextCmdIdx, cmdNextBB);
    cmdOff->addIncoming(nextCmdOff, cmdNextBB);

    IRBuilder<> INB(imageNextBB);
    Value *nextImageIdx = INB.CreateAdd(imageIdx, ConstantInt::get(i32, 1),
                                        "morok.antihook.macho.image.next");
    INB.CreateBr(imageLoopBB);
    imageIdx->addIncoming(nextImageIdx, imageNextBB);

    IRBuilder<> R1(ret1BB);
    R1.CreateRet(ConstantInt::get(i32, 1));

    IRBuilder<> R0(ret0BB);
    R0.CreateRet(ConstantInt::get(i32, 0));
    return fn;
}

Function *darwinFixupProbe(Module &M, const Triple &TT) {
    if (!TT.isOSDarwin())
        return nullptr;
    if (intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.antihook.macho.fixups"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    Function *dylibNameForOrdinal = darwinDylibNameForOrdinal(M);
    Function *expectedSymbol = darwinTargetMatchesExpectedDylibSymbol(M);
    Function *imageTextCheck = darwinTextTargetInImageIndex(M);

    auto *fn = Function::Create(FunctionType::get(i64, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.macho.fixups", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *cmdLoopBB = BasicBlock::Create(ctx, "cmd.loop", fn);
    auto *cmdBodyBB = BasicBlock::Create(ctx, "cmd.body", fn);
    auto *secLoopBB = BasicBlock::Create(ctx, "section.loop", fn);
    auto *secBodyBB = BasicBlock::Create(ctx, "section.body", fn);
    auto *entryLoopBB = BasicBlock::Create(ctx, "entry.loop", fn);
    auto *entryBodyBB = BasicBlock::Create(ctx, "entry.body", fn);
    auto *entryCheckBB = BasicBlock::Create(ctx, "entry.check", fn);
    auto *entryIndirectBB = BasicBlock::Create(ctx, "entry.indirect", fn);
    auto *entryExpectedBB = BasicBlock::Create(ctx, "entry.expected", fn);
    auto *entryValidateBB = BasicBlock::Create(ctx, "entry.validate", fn);
    auto *entryNextBB = BasicBlock::Create(ctx, "entry.next", fn);
    auto *secNextBB = BasicBlock::Create(ctx, "section.next", fn);
    auto *cmdNextBB = BasicBlock::Create(ctx, "cmd.next", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    AllocaInst *diff =
        B.CreateAlloca(i64, nullptr, "morok.antihook.macho.fixup.diff");
    B.CreateStore(ConstantInt::get(i64, 0), diff)->setVolatile(true);
    AllocaInst *linkeditVmaddrSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.fixup.linkedit.vmaddr");
    AllocaInst *linkeditFileoffSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.fixup.linkedit.fileoff");
    AllocaInst *symOffSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.fixup.symoff");
    AllocaInst *nSymsSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.fixup.nsyms");
    AllocaInst *strOffSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.fixup.stroff");
    AllocaInst *indirectSymOffSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.fixup.indirectsymoff");
    AllocaInst *nIndirectSymsSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.fixup.nindirectsyms");
    for (AllocaInst *slot :
         {linkeditVmaddrSlot, linkeditFileoffSlot, symOffSlot, nSymsSlot,
          strOffSlot, indirectSymOffSlot, nIndirectSymsSlot})
        B.CreateStore(ConstantInt::get(ip, 0), slot);
    FunctionCallee imageHeader = M.getOrInsertFunction(
        "_dyld_get_image_header", FunctionType::get(ptr, {i32}, false));
    FunctionCallee imageSlide = M.getOrInsertFunction(
        "_dyld_get_image_vmaddr_slide", FunctionType::get(ip, {i32}, false));
    Value *hdr = B.CreateCall(imageHeader, {ConstantInt::get(i32, 0)},
                              "morok.fixup.hdr");
    Value *slide = B.CreateCall(imageSlide, {ConstantInt::get(i32, 0)},
                                "morok.fixup.slide");
    Value *magic = loadAt(B, M, i32, hdr, 0ULL, "morok.antihook.fixup.magic");
    Value *ncmds = loadAt(B, M, i32, hdr, 16, "morok.antihook.fixup.ncmds");
    Value *valid =
        B.CreateAnd(B.CreateICmpNE(hdr, ConstantPointerNull::get(ptr)),
                    B.CreateICmpEQ(magic, ConstantInt::get(i32, 0xFEEDFACF)));
    B.CreateCondBr(valid, cmdLoopBB, retBB);

    IRBuilder<> CLB(cmdLoopBB);
    auto *cmdIdx = CLB.CreatePHI(i32, 2, "morok.antihook.fixup.cmd.idx");
    auto *cmdOff = CLB.CreatePHI(ip, 2, "morok.antihook.fixup.cmd.off");
    cmdIdx->addIncoming(ConstantInt::get(i32, 0), entry);
    cmdOff->addIncoming(ConstantInt::get(ip, 32), entry);
    Value *cmdInRange =
        CLB.CreateAnd(CLB.CreateICmpULT(cmdIdx, ncmds),
                      CLB.CreateICmpULT(cmdIdx, ConstantInt::get(i32, 128)));
    CLB.CreateCondBr(cmdInRange, cmdBodyBB, retBB);

    IRBuilder<> CBB(cmdBodyBB);
    Value *cmdPtr = gepI8(CBB, M, hdr, cmdOff, "morok.antihook.fixup.cmd.ptr");
    Value *cmd = loadAt(CBB, M, i32, cmdPtr, 0ULL, "morok.antihook.fixup.cmd");
    Value *cmdSize32 =
        loadAt(CBB, M, i32, cmdPtr, 4, "morok.antihook.fixup.cmd.size");
    Value *cmdSize =
        CBB.CreateZExt(cmdSize32, ip, "morok.antihook.fixup.cmd.size.w");
    Value *nsects =
        loadAt(CBB, M, i32, cmdPtr, 64, "morok.antihook.fixup.nsects");
    Value *isSegment = CBB.CreateICmpEQ(cmd, ConstantInt::get(i32, 0x19),
                                        "morok.antihook.fixup.segment");
    Value *cmdBase = CBB.CreateAnd(cmd, ConstantInt::get(i32, 0x7FFFFFFF),
                                   "morok.antihook.fixup.cmd.base");
    Value *isSymtab = CBB.CreateICmpEQ(cmdBase, ConstantInt::get(i32, 0x2),
                                       "morok.antihook.fixup.symtab.cmd");
    Value *isDysymtab = CBB.CreateICmpEQ(cmdBase, ConstantInt::get(i32, 0xB),
                                         "morok.antihook.fixup.dysymtab.cmd");
    Value *symOff32 =
        loadAt(CBB, M, i32, cmdPtr, 8, "morok.antihook.fixup.symoff.cmd");
    Value *nSyms32 =
        loadAt(CBB, M, i32, cmdPtr, 12, "morok.antihook.fixup.nsyms.cmd");
    Value *strOff32 =
        loadAt(CBB, M, i32, cmdPtr, 16, "morok.antihook.fixup.stroff.cmd");
    Value *indirectOff32 = loadAt(CBB, M, i32, cmdPtr, 56,
                                  "morok.antihook.fixup.indirectsymoff.cmd");
    Value *nIndirect32 = loadAt(CBB, M, i32, cmdPtr, 60,
                                "morok.antihook.fixup.nindirectsyms.cmd");
    auto storeIf = [&](AllocaInst *Slot, Value *Condition, Value *NewValue) {
        Value *old = CBB.CreateLoad(ip, Slot);
        CBB.CreateStore(CBB.CreateSelect(Condition, NewValue, old), Slot);
    };
    storeIf(symOffSlot, isSymtab,
            CBB.CreateZExt(symOff32, ip, "morok.antihook.fixup.symoff.w"));
    storeIf(nSymsSlot, isSymtab,
            CBB.CreateZExt(nSyms32, ip, "morok.antihook.fixup.nsyms.w"));
    storeIf(strOffSlot, isSymtab,
            CBB.CreateZExt(strOff32, ip, "morok.antihook.fixup.stroff.w"));
    storeIf(indirectSymOffSlot, isDysymtab,
            CBB.CreateZExt(indirectOff32, ip,
                           "morok.antihook.fixup.indirectsymoff.w"));
    storeIf(nIndirectSymsSlot, isDysymtab,
            CBB.CreateZExt(nIndirect32, ip,
                           "morok.antihook.fixup.nindirectsyms.w"));
    Value *segName8 = CBB.CreateAlignedLoad(
        i64, gepI8(CBB, M, cmdPtr, constIp(M, 8),
                   "morok.antihook.fixup.segname.ptr"),
        Align(1), "morok.antihook.fixup.segname8");
    Value *isLinkedit = CBB.CreateAnd(
        isSegment,
        CBB.CreateICmpEQ(segName8, ConstantInt::get(i64, 0x44454B4E494C5F5FULL)),
        "morok.antihook.fixup.linkedit.segment");
    Value *segVmaddr =
        loadAt(CBB, M, i64, cmdPtr, 24, "morok.antihook.fixup.seg.vmaddr");
    Value *segFileoff =
        loadAt(CBB, M, i64, cmdPtr, 40, "morok.antihook.fixup.seg.fileoff");
    storeIf(linkeditVmaddrSlot, isLinkedit,
            CBB.CreateZExtOrTrunc(segVmaddr, ip,
                                  "morok.antihook.fixup.linkedit.vmaddr.w"));
    storeIf(linkeditFileoffSlot, isLinkedit,
            CBB.CreateZExtOrTrunc(segFileoff, ip,
                                  "morok.antihook.fixup.linkedit.fileoff.w"));
    Value *canScanSections = CBB.CreateAnd(
        isSegment,
        CBB.CreateAnd(CBB.CreateICmpUGT(nsects, ConstantInt::get(i32, 0)),
                      CBB.CreateICmpUGE(cmdSize, ConstantInt::get(ip, 72))));
    Value *firstSecOff = CBB.CreateAdd(cmdOff, ConstantInt::get(ip, 72),
                                       "morok.antihook.fixup.section.first");
    CBB.CreateCondBr(canScanSections, secLoopBB, cmdNextBB);

    IRBuilder<> SLB(secLoopBB);
    auto *secIdx = SLB.CreatePHI(i32, 2, "morok.antihook.fixup.section.idx");
    auto *secOff = SLB.CreatePHI(ip, 2, "morok.antihook.fixup.section.off");
    secIdx->addIncoming(ConstantInt::get(i32, 0), cmdBodyBB);
    secOff->addIncoming(firstSecOff, cmdBodyBB);
    Value *secInRange =
        SLB.CreateAnd(SLB.CreateICmpULT(secIdx, nsects),
                      SLB.CreateICmpULT(secIdx, ConstantInt::get(i32, 64)));
    SLB.CreateCondBr(secInRange, secBodyBB, cmdNextBB);

    IRBuilder<> SBB(secBodyBB);
    Value *secPtr =
        gepI8(SBB, M, hdr, secOff, "morok.antihook.fixup.section.ptr");
    Value *secAddr =
        loadAt(SBB, M, i64, secPtr, 32, "morok.antihook.fixup.section.addr");
    Value *secSize =
        loadAt(SBB, M, i64, secPtr, 40, "morok.antihook.fixup.section.size");
    Value *secFlags =
        loadAt(SBB, M, i32, secPtr, 64, "morok.antihook.fixup.section.flags");
    Value *secType = SBB.CreateAnd(secFlags, ConstantInt::get(i32, 0xff),
                                   "morok.antihook.fixup.section.type");
    Value *isNonLazy = SBB.CreateICmpEQ(secType, ConstantInt::get(i32, 6),
                                        "morok.antihook.fixup.section.got");
    Value *isLazy = SBB.CreateICmpEQ(secType, ConstantInt::get(i32, 7),
                                     "morok.antihook.fixup.section.lazy");
    Value *entryCount = SBB.CreateUDiv(secSize, ConstantInt::get(i64, 8),
                                       "morok.antihook.fixup.entry.count");
    Value *sectionRuntime =
        SBB.CreateAdd(slide, secAddr, "morok.antihook.fixup.section.runtime");
    Value *scanSection =
        SBB.CreateAnd(SBB.CreateOr(isNonLazy, isLazy),
                      SBB.CreateICmpUGT(entryCount, ConstantInt::get(i64, 0)),
                      "morok.antihook.fixup.section.scan");
    SBB.CreateCondBr(scanSection, entryLoopBB, secNextBB);

    IRBuilder<> ELB(entryLoopBB);
    auto *entryIdx = ELB.CreatePHI(i64, 2, "morok.antihook.fixup.entry.idx");
    entryIdx->addIncoming(ConstantInt::get(i64, 0), secBodyBB);
    Value *entryInRange =
        ELB.CreateAnd(ELB.CreateICmpULT(entryIdx, entryCount),
                      ELB.CreateICmpULT(entryIdx, ConstantInt::get(i64, 4096)));
    ELB.CreateCondBr(entryInRange, entryBodyBB, secNextBB);

    IRBuilder<> EBB(entryBodyBB);
    Value *slotAddr = EBB.CreateAdd(
        sectionRuntime, EBB.CreateMul(entryIdx, ConstantInt::get(i64, 8)),
        "morok.antihook.fixup.slot");
    Value *slotPtr =
        EBB.CreateIntToPtr(slotAddr, ptr, "morok.antihook.fixup.slot.ptr");
    auto *targetPtr =
        EBB.CreateLoad(ptr, slotPtr, "morok.antihook.fixup.target");
    targetPtr->setVolatile(true);
    Value *targetAddr =
        EBB.CreatePtrToInt(targetPtr, ip, "morok.antihook.fixup.target.addr");
    EBB.CreateCondBr(EBB.CreateICmpNE(targetPtr, ConstantPointerNull::get(ptr)),
                     entryCheckBB, entryNextBB);

    IRBuilder<> ECB(entryCheckBB);
    Value *linkeditVm = ECB.CreateLoad(ip, linkeditVmaddrSlot,
                                       "morok.antihook.fixup.linkedit.vmaddr.v");
    Value *linkeditFile = ECB.CreateLoad(ip, linkeditFileoffSlot,
                                         "morok.antihook.fixup.linkedit.fileoff.v");
    Value *linkeditBase =
        ECB.CreateSub(ECB.CreateAdd(slide, linkeditVm,
                                    "morok.antihook.fixup.linkedit.slide"),
                      linkeditFile, "morok.antihook.fixup.linkedit.base");
    Value *symOff =
        ECB.CreateLoad(ip, symOffSlot, "morok.antihook.fixup.symoff.v");
    Value *nSyms = ECB.CreateLoad(ip, nSymsSlot,
                                  "morok.antihook.fixup.nsyms.v");
    Value *strOff =
        ECB.CreateLoad(ip, strOffSlot, "morok.antihook.fixup.stroff.v");
    Value *indirectOff = ECB.CreateLoad(
        ip, indirectSymOffSlot, "morok.antihook.fixup.indirectsymoff.v");
    Value *nIndirect = ECB.CreateLoad(
        ip, nIndirectSymsSlot, "morok.antihook.fixup.nindirectsyms.v");
    Value *reserved1Raw = loadAt(ECB, M, i32, secPtr, 68,
                                 "morok.antihook.fixup.section.reserved1");
    Value *indirectIndex = ECB.CreateAdd(
        ECB.CreateZExt(reserved1Raw, ip,
                       "morok.antihook.fixup.indirect.base"),
        entryIdx, "morok.antihook.fixup.indirect.index");
    Value *mainText =
        ECB.CreateCall(imageTextCheck, {targetAddr, ConstantInt::get(i32, 0)},
                       "morok.antihook.fixup.main.text");
    Value *hasTables = ECB.CreateAnd(
        ECB.CreateICmpNE(linkeditVm, ConstantInt::get(ip, 0)),
        ECB.CreateAnd(
            ECB.CreateICmpNE(symOff, ConstantInt::get(ip, 0)),
            ECB.CreateAnd(
                ECB.CreateICmpNE(strOff, ConstantInt::get(ip, 0)),
                ECB.CreateAnd(ECB.CreateICmpNE(indirectOff,
                                               ConstantInt::get(ip, 0)),
                              ECB.CreateICmpNE(nIndirect,
                                               ConstantInt::get(ip, 0))))),
        "morok.antihook.fixup.tables.present");
    Value *canReadIndirect = ECB.CreateAnd(
        hasTables, ECB.CreateICmpULT(indirectIndex, nIndirect),
        "morok.antihook.fixup.indirect.inrange");
    ECB.CreateCondBr(canReadIndirect, entryIndirectBB, entryValidateBB);

    IRBuilder<> EIB(entryIndirectBB);
    Value *indirectPtr = EIB.CreateIntToPtr(
        EIB.CreateAdd(linkeditBase,
                      EIB.CreateAdd(indirectOff,
                                    EIB.CreateMul(indirectIndex,
                                                  ConstantInt::get(ip, 4))),
                      "morok.antihook.fixup.indirect.ptr.addr"),
        ptr, "morok.antihook.fixup.indirect.ptr");
    Value *indirectRaw =
        loadAt(EIB, M, i32, indirectPtr, 0ULL,
               "morok.antihook.fixup.indirect.raw");
    Value *indirectLocal = EIB.CreateICmpNE(
        EIB.CreateAnd(indirectRaw, ConstantInt::get(i32, 0x80000000)),
        ConstantInt::get(i32, 0), "morok.antihook.fixup.indirect.local");
    Value *indirectAbs = EIB.CreateICmpNE(
        EIB.CreateAnd(indirectRaw, ConstantInt::get(i32, 0x40000000)),
        ConstantInt::get(i32, 0), "morok.antihook.fixup.indirect.abs");
    Value *indirectSpecial = EIB.CreateOr(
        indirectLocal, indirectAbs, "morok.antihook.fixup.indirect.special");
    Value *symIndex = EIB.CreateZExt(
        EIB.CreateAnd(indirectRaw, ConstantInt::get(i32, 0x3FFFFFFF)), ip,
        "morok.antihook.fixup.sym.index");
    Value *canReadSymbol = EIB.CreateAnd(
        EIB.CreateNot(indirectSpecial,
                      "morok.antihook.fixup.indirect.external"),
        EIB.CreateAnd(EIB.CreateICmpULT(symIndex, nSyms),
                      EIB.CreateICmpNE(nSyms, ConstantInt::get(ip, 0))),
        "morok.antihook.fixup.sym.inrange");
    EIB.CreateCondBr(canReadSymbol, entryExpectedBB, entryValidateBB);

    IRBuilder<> EXB(entryExpectedBB);
    Value *symPtr = EXB.CreateIntToPtr(
        EXB.CreateAdd(linkeditBase,
                      EXB.CreateAdd(symOff,
                                    EXB.CreateMul(symIndex,
                                                  ConstantInt::get(ip, 16))),
                      "morok.antihook.fixup.sym.ptr.addr"),
        ptr, "morok.antihook.fixup.sym.ptr");
    Value *strx32 =
        loadAt(EXB, M, i32, symPtr, 0ULL, "morok.antihook.fixup.sym.strx");
    Value *nDesc =
        loadAt(EXB, M, Type::getInt16Ty(ctx), symPtr, 6,
               "morok.antihook.fixup.sym.desc");
    Value *symName = EXB.CreateIntToPtr(
        EXB.CreateAdd(linkeditBase,
                      EXB.CreateAdd(strOff, EXB.CreateZExt(strx32, ip)),
                      "morok.antihook.fixup.sym.name.addr"),
        ptr, "morok.antihook.fixup.sym.name");
    Value *ordinal = EXB.CreateZExt(
        EXB.CreateLShr(nDesc, ConstantInt::get(Type::getInt16Ty(ctx), 8)),
        i32, "morok.antihook.fixup.sym.ordinal");
    Value *dylibName = EXB.CreateCall(
        dylibNameForOrdinal, {hdr, ordinal},
        "morok.antihook.fixup.expected.dylib");
    Value *expectedSymbolHit = EXB.CreateCall(
        expectedSymbol, {targetAddr, symName, dylibName},
        "morok.antihook.fixup.expected.symbol");
    Value *expectedOk =
        EXB.CreateICmpNE(expectedSymbolHit, ConstantInt::get(i32, 0),
                         "morok.antihook.fixup.expected.ok");
    EXB.CreateBr(entryValidateBB);

    IRBuilder<> EVB(entryValidateBB);
    auto *expectedOkPhi =
        EVB.CreatePHI(Type::getInt1Ty(ctx), 3,
                      "morok.antihook.fixup.expected.phi");
    expectedOkPhi->addIncoming(ConstantInt::getFalse(ctx), entryCheckBB);
    expectedOkPhi->addIncoming(ConstantInt::getFalse(ctx), entryIndirectBB);
    expectedOkPhi->addIncoming(expectedOk, entryExpectedBB);
    auto *specialPhi =
        EVB.CreatePHI(Type::getInt1Ty(ctx), 3,
                      "morok.antihook.fixup.special.phi");
    specialPhi->addIncoming(ConstantInt::getFalse(ctx), entryCheckBB);
    specialPhi->addIncoming(indirectSpecial, entryIndirectBB);
    specialPhi->addIncoming(ConstantInt::getFalse(ctx), entryExpectedBB);
    Value *mainTextOk =
        EVB.CreateICmpNE(mainText, ConstantInt::get(i32, 0),
                         "morok.antihook.fixup.main.text.ok");
    Value *lazyMainOk =
        EVB.CreateAnd(isLazy, mainTextOk, "morok.antihook.fixup.lazy.main");
    Value *localMainOk =
        EVB.CreateAnd(specialPhi, mainTextOk, "morok.antihook.fixup.local.main");
    Value *targetOk =
        EVB.CreateOr(expectedOkPhi, EVB.CreateOr(lazyMainOk, localMainOk),
                     "morok.antihook.fixup.target.ok");
    incrementDiff(EVB, diff,
                  EVB.CreateNot(targetOk, "morok.antihook.fixup.violation.pred"),
                  "morok.antihook.fixup.violation");
    EVB.CreateBr(entryNextBB);

    IRBuilder<> ENB(entryNextBB);
    Value *nextEntryIdx = ENB.CreateAdd(entryIdx, ConstantInt::get(i64, 1),
                                        "morok.antihook.fixup.entry.next");
    ENB.CreateBr(entryLoopBB);
    entryIdx->addIncoming(nextEntryIdx, entryNextBB);

    IRBuilder<> SNB(secNextBB);
    Value *nextSecIdx = SNB.CreateAdd(secIdx, ConstantInt::get(i32, 1),
                                      "morok.antihook.fixup.section.next");
    Value *nextSecOff = SNB.CreateAdd(secOff, ConstantInt::get(ip, 80),
                                      "morok.antihook.fixup.section.off.next");
    SNB.CreateBr(secLoopBB);
    secIdx->addIncoming(nextSecIdx, secNextBB);
    secOff->addIncoming(nextSecOff, secNextBB);

    IRBuilder<> CNB(cmdNextBB);
    Value *nextCmdIdx = CNB.CreateAdd(cmdIdx, ConstantInt::get(i32, 1),
                                      "morok.antihook.fixup.cmd.next");
    Value *nextCmdOff =
        CNB.CreateAdd(cmdOff, cmdSize, "morok.antihook.fixup.cmd.off.next");
    CNB.CreateBr(cmdLoopBB);
    cmdIdx->addIncoming(nextCmdIdx, cmdNextBB);
    cmdOff->addIncoming(nextCmdOff, cmdNextBB);

    IRBuilder<> RB(retBB);
    emitRetDiff(RB, diff);
    return fn;
}

Function *linuxMapsCensusProbe(Module &M, ir::IRRandom &rng,
                               const Triple &TT) {
    if (!TT.isOSLinux() || intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.antihook.maps.linux"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    constexpr std::uint64_t kEnvReadChunk = 8192;
    constexpr std::uint64_t kEnvMaxReads = 16;
    constexpr std::uint32_t kEnvStateDead = 255;

    auto *fn = Function::Create(FunctionType::get(i64, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.maps.linux", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *openOkBB = BasicBlock::Create(ctx, "open.ok", fn);
    auto *scanPrepBB = BasicBlock::Create(ctx, "scan.prep", fn);
    auto *scanLoopBB = BasicBlock::Create(ctx, "scan.loop", fn);
    auto *scanBodyBB = BasicBlock::Create(ctx, "scan.body", fn);
    auto *scanNextBB = BasicBlock::Create(ctx, "scan.next", fn);
    auto *closeBB = BasicBlock::Create(ctx, "close", fn);
    auto *envBB = BasicBlock::Create(ctx, "env", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    auto *bufTy = ArrayType::get(i8, kEnvReadChunk);
    AllocaInst *buf = B.CreateAlloca(bufTy, nullptr, "morok.antihook.maps.buf");
    AllocaInst *diff =
        B.CreateAlloca(i64, nullptr, "morok.antihook.maps.diff");
    AllocaInst *envReads =
        B.CreateAlloca(ip, nullptr, "morok.antihook.env.read.count");
    AllocaInst *envPreloadState =
        B.CreateAlloca(i32, nullptr, "morok.antihook.env.preload.state");
    AllocaInst *envAuditState =
        B.CreateAlloca(i32, nullptr, "morok.antihook.env.audit.state");
    B.CreateStore(ConstantInt::get(i64, 0), diff)->setVolatile(true);
    B.CreateStore(ConstantInt::get(ip, 0), envReads);
    B.CreateStore(ConstantInt::get(i32, 0), envPreloadState);
    B.CreateStore(ConstantInt::get(i32, 0), envAuditState);
    Value *path = ir::emitCloakedSymbol(B, M, "/proc/self/maps", rng);

    std::uint32_t ptraceNr = 0;
    std::uint32_t prctlNr = 0;
    std::uint32_t openatNr = 0;
    std::uint32_t readNr = 0;
    std::uint32_t closeNr = 0;
    const bool direct =
        linuxCoreSyscalls(TT, ptraceNr, prctlNr, openatNr, readNr, closeNr);
    Value *fdLong = nullptr;
    if (direct) {
        fdLong = emitLinuxSyscall(B, M, TT, openatNr,
                                  {constSignedIp(M, -100), path,
                                   ConstantInt::get(ip, 0),
                                   ConstantInt::get(ip, 0)});
    } else {
        fdLong = B.CreateSExtOrTrunc(
            B.CreateCall(openDecl(M), {path, ConstantInt::get(i32, 0)}), ip);
    }
    fdLong->setName("morok.antihook.maps.fd");
    B.CreateCondBr(B.CreateICmpSGE(fdLong, ConstantInt::get(ip, 0)), openOkBB,
                   envBB);

    IRBuilder<> OB(openOkBB);
    Value *bufPtr = OB.CreateInBoundsGEP(
        bufTy, buf, {ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)},
        "morok.antihook.maps.ptr");
    Value *nread = nullptr;
    if (direct) {
        nread = emitLinuxSyscall(
            OB, M, TT, readNr,
            {fdLong, bufPtr, ConstantInt::get(ip, kEnvReadChunk)});
    } else {
        nread = OB.CreateCall(readDecl(M),
                              {OB.CreateTruncOrBitCast(fdLong, i32), bufPtr,
                               ConstantInt::get(ip, kEnvReadChunk)});
    }
    nread->setName("morok.antihook.maps.read");
    OB.CreateCondBr(OB.CreateICmpSGT(nread, ConstantInt::get(ip, 86)),
                    scanPrepBB, closeBB);

    IRBuilder<> SPB(scanPrepBB);
    SPB.CreateBr(scanLoopBB);

    IRBuilder<> SLB(scanLoopBB);
    auto *idx = SLB.CreatePHI(ip, 2, "morok.antihook.maps.idx");
    idx->addIncoming(ConstantInt::get(ip, 1), scanPrepBB);
    Value *safeEnd =
        SLB.CreateICmpULT(SLB.CreateAdd(idx, ConstantInt::get(ip, 86)), nread);
    Value *bounded = SLB.CreateICmpULT(idx, ConstantInt::get(ip, 8100));
    SLB.CreateCondBr(SLB.CreateAnd(safeEnd, bounded), scanBodyBB, closeBB);

    IRBuilder<> MB(scanBodyBB);
    Value *prev = loadAt(MB, M, i8, buf, MB.CreateSub(idx, ConstantInt::get(ip, 1)),
                         "morok.antihook.maps.prev");
    Value *p0 = loadAt(MB, M, i8, buf, idx, "morok.antihook.maps.perm0");
    Value *p1 = loadAt(MB, M, i8, buf, MB.CreateAdd(idx, ConstantInt::get(ip, 1)),
                       "morok.antihook.maps.perm1");
    Value *p2 = loadAt(MB, M, i8, buf, MB.CreateAdd(idx, ConstantInt::get(ip, 2)),
                       "morok.antihook.maps.perm2");
    Value *p3 = loadAt(MB, M, i8, buf, MB.CreateAdd(idx, ConstantInt::get(ip, 3)),
                       "morok.antihook.maps.perm3");
    Value *after =
        loadAt(MB, M, i8, buf, MB.CreateAdd(idx, ConstantInt::get(ip, 4)),
               "morok.antihook.maps.after");
    auto isChar = [&](Value *V, char C) {
        return MB.CreateICmpEQ(V, ConstantInt::get(i8, static_cast<unsigned>(C)));
    };
    Value *permWindow = MB.CreateAnd(
        MB.CreateAnd(isChar(prev, ' '), isChar(after, ' ')),
        MB.CreateAnd(
            MB.CreateAnd(MB.CreateOr(isChar(p0, 'r'), isChar(p0, '-')),
                         MB.CreateOr(isChar(p1, 'w'), isChar(p1, '-'))),
            MB.CreateAnd(MB.CreateOr(isChar(p2, 'x'), isChar(p2, '-')),
                         MB.CreateOr(isChar(p3, 'p'), isChar(p3, 's')))),
        "morok.antihook.maps.perms");
    Value *isWritable = isChar(p1, 'w');
    Value *isExec = isChar(p2, 'x');
    Value *isPrivate = isChar(p3, 'p');
    Value *rwx = MB.CreateAnd(permWindow, MB.CreateAnd(isWritable, isExec),
                              "morok.antihook.maps.rwx");
    Value *execNoRead =
        MB.CreateAnd(permWindow, MB.CreateAnd(isExec, MB.CreateNot(isChar(p0, 'r'))),
                     "morok.antihook.maps.exec.noread");

    Value *seenSlash = ConstantInt::getFalse(ctx);
    Value *seenNewline = ConstantInt::getFalse(ctx);
    for (std::uint64_t off = 5; off < 86; ++off) {
        Value *ch =
            loadAt(MB, M, i8, buf, MB.CreateAdd(idx, ConstantInt::get(ip, off)),
                   "morok.antihook.maps.path.ch");
        Value *beforeNl = MB.CreateNot(seenNewline);
        seenSlash = MB.CreateOr(
            seenSlash, MB.CreateAnd(beforeNl, isChar(ch, '/')),
            "morok.antihook.maps.path.slash");
        seenNewline = MB.CreateOr(seenNewline, isChar(ch, '\n'),
                                  "morok.antihook.maps.path.nl");
    }
    Value *anonymousExec = MB.CreateAnd(
        permWindow,
        MB.CreateAnd(MB.CreateAnd(isExec, isPrivate), MB.CreateNot(seenSlash)),
        "morok.antihook.maps.anonymous.exec");
    incrementDiff(MB, diff, rwx, "morok.antihook.maps.rwx.hit");
    incrementDiff(MB, diff, execNoRead, "morok.antihook.maps.noread.hit");
    incrementDiff(MB, diff, anonymousExec, "morok.antihook.maps.anon.hit");
    MB.CreateBr(scanNextBB);

    IRBuilder<> SNB(scanNextBB);
    Value *nextIdx =
        SNB.CreateAdd(idx, ConstantInt::get(ip, 1), "morok.antihook.maps.next");
    SNB.CreateBr(scanLoopBB);
    idx->addIncoming(nextIdx, scanNextBB);

    IRBuilder<> CLB(closeBB);
    if (direct)
        emitLinuxSyscall(CLB, M, TT, closeNr, {fdLong});
    else
        CLB.CreateCall(closeDecl(M), {CLB.CreateTruncOrBitCast(fdLong, i32)});
    CLB.CreateBr(envBB);

    // The LD_PRELOAD / LD_AUDIT interposition the field report used hooks getenv
    // to hide itself, so the old getenv probe was blind to its own injector.
    // Stream the markers from /proc/self/environ via direct syscalls instead: it
    // is the kernel's exec-time copy of the environment, immune both to getenv
    // interposition and to a constructor that unsetenv()s the variable out of the
    // libc `environ` array.  The scanner is anchored to NUL-delimited entry
    // starts, carries marker state across chunk boundaries, and is capped so a
    // hostile environment cannot turn startup into unbounded I/O.
    auto *envReadBB = BasicBlock::Create(ctx, "env.read", fn);
    auto *envDoReadBB = BasicBlock::Create(ctx, "env.do.read", fn);
    auto *envScanLoopBB = BasicBlock::Create(ctx, "env.scan.loop", fn);
    auto *envScanBodyBB = BasicBlock::Create(ctx, "env.scan.body", fn);
    auto *envScanNextBB = BasicBlock::Create(ctx, "env.scan.next", fn);
    auto *envReadNextBB = BasicBlock::Create(ctx, "env.read.next", fn);
    auto *envCloseBB = BasicBlock::Create(ctx, "env.close", fn);

    IRBuilder<> EB(envBB);
    Value *envPath = ir::emitCloakedSymbol(EB, M, "/proc/self/environ", rng);
    Value *envFd = nullptr;
    if (direct) {
        envFd = emitLinuxSyscall(EB, M, TT, openatNr,
                                 {constSignedIp(M, -100), envPath,
                                  ConstantInt::get(ip, 0),
                                  ConstantInt::get(ip, 0)});
    } else {
        envFd = EB.CreateSExtOrTrunc(
            EB.CreateCall(openDecl(M), {envPath, ConstantInt::get(i32, 0)}), ip);
    }
    envFd->setName("morok.antihook.env.fd");
    EB.CreateCondBr(EB.CreateICmpSGE(envFd, ConstantInt::get(ip, 0)), envReadBB,
                    retBB);

    IRBuilder<> ERB(envReadBB);
    Value *envReadCount =
        ERB.CreateLoad(ip, envReads, "morok.antihook.env.read.count.cur");
    Value *envCanRead =
        ERB.CreateICmpULT(envReadCount, ConstantInt::get(ip, kEnvMaxReads),
                          "morok.antihook.env.read.limit");
    Value *envBufPtr = ERB.CreateInBoundsGEP(
        bufTy, buf, {ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)},
        "morok.antihook.env.ptr");
    ERB.CreateCondBr(envCanRead, envDoReadBB, envCloseBB);

    IRBuilder<> EDRB(envDoReadBB);
    Value *envNread = nullptr;
    if (direct) {
        envNread = emitLinuxSyscall(EDRB, M, TT, readNr,
                                    {envFd, envBufPtr,
                                     ConstantInt::get(ip, kEnvReadChunk)});
    } else {
        envNread = EDRB.CreateCall(
            readDecl(M), {EDRB.CreateTruncOrBitCast(envFd, i32), envBufPtr,
                          ConstantInt::get(ip, kEnvReadChunk)});
    }
    envNread->setName("morok.antihook.env.read");
    EDRB.CreateCondBr(EDRB.CreateICmpSGT(envNread, ConstantInt::get(ip, 0),
                                         "morok.antihook.env.read.nonempty"),
                      envScanLoopBB, envCloseBB);

    IRBuilder<> ESL(envScanLoopBB);
    auto *envIdx = ESL.CreatePHI(ip, 2, "morok.antihook.env.idx");
    envIdx->addIncoming(ConstantInt::get(ip, 0), envDoReadBB);
    Value *envInBounds =
        ESL.CreateICmpULT(envIdx, envNread, "morok.antihook.env.idx.live");
    ESL.CreateCondBr(envInBounds, envScanBodyBB, envReadNextBB);

    IRBuilder<> ESB(envScanBodyBB);
    Value *envCh = loadAt(ESB, M, i8, buf, envIdx, "morok.antihook.env.ch");
    Value *envIsNul = ESB.CreateICmpEQ(
        envCh, ConstantInt::get(i8, 0), "morok.antihook.env.nul");
    auto expectedMarkerByte = [&](Value *State, StringRef Marker,
                                  StringRef Prefix) -> Value * {
        Value *expected = ConstantInt::get(i8, 0);
        for (int k = static_cast<int>(Marker.size()) - 1; k >= 0; --k) {
            Value *atState = ESB.CreateICmpEQ(
                State, ConstantInt::get(i32, static_cast<unsigned>(k)),
                Twine(Prefix) + ".state." + Twine(k));
            expected = ESB.CreateSelect(
                atState,
                ConstantInt::get(
                    i8, static_cast<unsigned>(
                            static_cast<unsigned char>(
                                Marker[static_cast<std::size_t>(k)]))),
                expected, Twine(Prefix) + ".expected." + Twine(k));
        }
        return expected;
    };
    auto advanceMarker = [&](AllocaInst *StateSlot, StringRef Marker,
                             StringRef Prefix) -> Value * {
        Value *state =
            ESB.CreateLoad(i32, StateSlot, Twine(Prefix) + ".state.cur");
        Value *alive = ESB.CreateICmpNE(
            state, ConstantInt::get(i32, kEnvStateDead),
            Twine(Prefix) + ".state.live");
        Value *expected = expectedMarkerByte(state, Marker, Prefix);
        Value *matches =
            ESB.CreateICmpEQ(envCh, expected, Twine(Prefix) + ".match");
        Value *advance =
            ESB.CreateAnd(alive, matches, Twine(Prefix) + ".advance");
        Value *advancedState =
            ESB.CreateAdd(state, ConstantInt::get(i32, 1),
                          Twine(Prefix) + ".state.inc");
        Value *nonNulState = ESB.CreateSelect(
            advance, advancedState, ConstantInt::get(i32, kEnvStateDead),
            Twine(Prefix) + ".state.nonnull");
        Value *nextState = ESB.CreateSelect(
            envIsNul, ConstantInt::get(i32, 0), nonNulState,
            Twine(Prefix) + ".state.next");
        ESB.CreateStore(nextState, StateSlot);
        Value *hit =
            ESB.CreateICmpEQ(nextState,
                             ConstantInt::get(
                                 i32, static_cast<unsigned>(Marker.size())),
                             Twine(Prefix) + ".hit");
        return ESB.CreateAnd(ESB.CreateNot(envIsNul), hit,
                             Twine(Prefix) + ".hit.byte");
    };
    Value *hitPreload = advanceMarker(envPreloadState, "LD_PRELOAD=",
                                      "morok.antihook.env.preload");
    Value *hitAudit =
        advanceMarker(envAuditState, "LD_AUDIT=", "morok.antihook.env.audit");
    incrementDiff(ESB, diff, hitPreload, "morok.antihook.env.preload");
    incrementDiff(ESB, diff, hitAudit, "morok.antihook.env.audit");
    ESB.CreateBr(envScanNextBB);

    IRBuilder<> ESN(envScanNextBB);
    Value *envNext = ESN.CreateAdd(envIdx, ConstantInt::get(ip, 1),
                                   "morok.antihook.env.next");
    ESN.CreateBr(envScanLoopBB);
    envIdx->addIncoming(envNext, envScanNextBB);

    IRBuilder<> ERNB(envReadNextBB);
    Value *envReadNext =
        ERNB.CreateAdd(ERNB.CreateLoad(ip, envReads,
                                       "morok.antihook.env.read.count.done"),
                       ConstantInt::get(ip, 1),
                       "morok.antihook.env.read.next");
    ERNB.CreateStore(envReadNext, envReads);
    ERNB.CreateBr(envReadBB);

    IRBuilder<> ECB(envCloseBB);
    if (direct)
        emitLinuxSyscall(ECB, M, TT, closeNr, {envFd});
    else
        ECB.CreateCall(closeDecl(M), {ECB.CreateTruncOrBitCast(envFd, i32)});
    ECB.CreateBr(retBB);

    IRBuilder<> RB(retBB);
    emitRetDiff(RB, diff);
    return fn;
}

Function *darwinVmCensusProbe(Module &M) {
    const Triple TT(M.getTargetTriple());
    if (!TT.isOSDarwin() || intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.antihook.vm.darwin"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);
    Function *textCheck = darwinTextTargetInDyldImages(M);

    auto *fn = Function::Create(FunctionType::get(i64, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.vm.darwin", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *loopBB = BasicBlock::Create(ctx, "loop", fn);
    auto *bodyBB = BasicBlock::Create(ctx, "body", fn);
    auto *nextBB = BasicBlock::Create(ctx, "next", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    auto *infoTy = ArrayType::get(i32, 9);
    AllocaInst *addr = B.CreateAlloca(i64, nullptr, "morok.antihook.vm.addr");
    AllocaInst *size = B.CreateAlloca(i64, nullptr, "morok.antihook.vm.size");
    AllocaInst *info = B.CreateAlloca(infoTy, nullptr, "morok.antihook.vm.info");
    AllocaInst *count = B.CreateAlloca(i32, nullptr, "morok.antihook.vm.count");
    AllocaInst *object = B.CreateAlloca(i32, nullptr, "morok.antihook.vm.object");
    AllocaInst *diff = B.CreateAlloca(i64, nullptr, "morok.antihook.vm.diff");
    B.CreateStore(ConstantInt::get(i64, 1), addr);
    B.CreateStore(ConstantInt::get(i64, 0), size);
    B.CreateStore(ConstantInt::get(i64, 0), diff)->setVolatile(true);
    B.CreateBr(loopBB);

    IRBuilder<> LB(loopBB);
    auto *iter = LB.CreatePHI(i32, 2, "morok.antihook.vm.idx");
    iter->addIncoming(ConstantInt::get(i32, 0), entry);
    LB.CreateCondBr(LB.CreateICmpULT(iter, ConstantInt::get(i32, 128)), bodyBB,
                    retBB);

    IRBuilder<> VB(bodyBB);
    VB.CreateStore(ConstantInt::get(i32, 9), count);
    VB.CreateStore(ConstantInt::get(i32, 0), object);
    GlobalVariable *selfGV =
        cast<GlobalVariable>(M.getOrInsertGlobal("mach_task_self_", i32));
    Value *task = VB.CreateLoad(i32, selfGV, "morok.antihook.vm.task");
    Value *infoPtr = VB.CreateInBoundsGEP(
        infoTy, info, {ConstantInt::get(i32, 0), ConstantInt::get(i32, 0)},
        "morok.antihook.vm.info.ptr");
    FunctionCallee machVmRegion = M.getOrInsertFunction(
        "mach_vm_region",
        FunctionType::get(i32, {i32, ptr, ptr, i32, ptr, ptr, ptr}, false));
    Value *rc = VB.CreateCall(
        machVmRegion,
        {task, addr, size, ConstantInt::get(i32, 9), infoPtr, count, object},
        "morok.antihook.vm.region");
    VB.CreateCondBr(VB.CreateICmpEQ(rc, ConstantInt::get(i32, 0)), nextBB,
                    retBB);

    IRBuilder<> NB(nextBB);
    Value *prot = NB.CreateLoad(
        i32,
        NB.CreateInBoundsGEP(infoTy, info,
                             {ConstantInt::get(i32, 0), ConstantInt::get(i32, 0)}),
        "morok.antihook.vm.prot");
    Value *regionAddr = NB.CreateLoad(i64, addr, "morok.antihook.vm.base");
    Value *regionSize = NB.CreateLoad(i64, size, "morok.antihook.vm.len");
    Value *readable =
        NB.CreateICmpNE(NB.CreateAnd(prot, ConstantInt::get(i32, 1)),
                        ConstantInt::get(i32, 0));
    Value *writable =
        NB.CreateICmpNE(NB.CreateAnd(prot, ConstantInt::get(i32, 2)),
                        ConstantInt::get(i32, 0));
    Value *executable =
        NB.CreateICmpNE(NB.CreateAnd(prot, ConstantInt::get(i32, 4)),
                        ConstantInt::get(i32, 0));
    Value *rwx = NB.CreateAnd(writable, executable, "morok.antihook.vm.rwx");
    Value *largeRwx = NB.CreateAnd(
        rwx, NB.CreateICmpUGE(regionSize, ConstantInt::get(i64, 0x1000000)),
        "morok.antihook.vm.rwx.large");
    Value *noAccess = NB.CreateICmpEQ(prot, ConstantInt::get(i32, 0),
                                      "morok.antihook.vm.noaccess");
    Value *textHit =
        NB.CreateCall(textCheck, {regionAddr}, "morok.antihook.vm.text");
    Value *notDyldText = NB.CreateICmpEQ(textHit, ConstantInt::get(i32, 0));
    Value *privateExec =
        NB.CreateAnd(executable, notDyldText, "morok.antihook.vm.private.exec");
    Value *textWrongProt = NB.CreateAnd(
        NB.CreateICmpNE(textHit, ConstantInt::get(i32, 0)),
        NB.CreateOr(NB.CreateNot(readable), NB.CreateOr(writable, NB.CreateNot(executable))),
        "morok.antihook.vm.text.prot");
    incrementDiff(NB, diff, rwx, "morok.antihook.vm.rwx.hit");
    incrementDiff(NB, diff, largeRwx, "morok.antihook.vm.rwx.large.hit");
    incrementDiff(NB, diff, noAccess, "morok.antihook.vm.noaccess.hit");
    incrementDiff(NB, diff, privateExec, "morok.antihook.vm.private.hit");
    incrementDiff(NB, diff, textWrongProt, "morok.antihook.vm.text.hit");
    FunctionCallee portDeallocate = M.getOrInsertFunction(
        "mach_port_deallocate", FunctionType::get(i32, {i32, i32}, false));
    Value *objectName = NB.CreateLoad(i32, object, "morok.antihook.vm.object.v");
    NB.CreateCall(portDeallocate, {task, objectName});
    Value *step = NB.CreateSelect(NB.CreateICmpUGT(regionSize, ConstantInt::get(i64, 0)),
                                  regionSize, ConstantInt::get(i64, 0x1000));
    Value *nextAddr =
        NB.CreateAdd(regionAddr, step, "morok.antihook.vm.next.addr");
    NB.CreateStore(nextAddr, addr);
    Value *nextIter =
        NB.CreateAdd(iter, ConstantInt::get(i32, 1), "morok.antihook.vm.next");
    NB.CreateBr(loopBB);
    iter->addIncoming(nextIter, nextBB);

    IRBuilder<> RB(retBB);
    emitRetDiff(RB, diff);
    return fn;
}

Function *windowsVirtualQueryCensusProbe(Module &M) {
    const Triple TT(M.getTargetTriple());
    if (!TT.isOSWindows() || intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.antihook.vm.windows"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);

    auto *fn = Function::Create(FunctionType::get(i64, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.vm.windows", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *loopBB = BasicBlock::Create(ctx, "loop", fn);
    auto *bodyBB = BasicBlock::Create(ctx, "body", fn);
    auto *nextBB = BasicBlock::Create(ctx, "next", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    auto *mbiTy = ArrayType::get(i8, 64);
    AllocaInst *mbi = B.CreateAlloca(mbiTy, nullptr, "morok.antihook.win.mbi");
    AllocaInst *diff = B.CreateAlloca(i64, nullptr, "morok.antihook.win.diff");
    B.CreateStore(ConstantInt::get(i64, 0), diff)->setVolatile(true);
    FunctionCallee virtualQuery = M.getOrInsertFunction(
        "VirtualQuery", FunctionType::get(ip, {ptr, ptr, ip}, false));
    B.CreateBr(loopBB);

    IRBuilder<> LB(loopBB);
    auto *iter = LB.CreatePHI(i32, 2, "morok.antihook.win.idx");
    auto *addr = LB.CreatePHI(ip, 2, "morok.antihook.win.addr");
    iter->addIncoming(ConstantInt::get(i32, 0), entry);
    addr->addIncoming(ConstantInt::get(ip, 0), entry);
    LB.CreateCondBr(LB.CreateICmpULT(iter, ConstantInt::get(i32, 256)), bodyBB,
                    retBB);

    IRBuilder<> WB(bodyBB);
    Value *basePtr = WB.CreateInBoundsGEP(
        mbiTy, mbi, {ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)});
    Value *rc = WB.CreateCall(virtualQuery,
                              {WB.CreateIntToPtr(addr, ptr), basePtr,
                               ConstantInt::get(ip, 48)},
                              "morok.antihook.win.query");
    WB.CreateCondBr(WB.CreateICmpNE(rc, ConstantInt::get(ip, 0)), nextBB,
                    retBB);

    IRBuilder<> NB(nextBB);
    Value *regionSize =
        loadAt(NB, M, ip, mbi, 24, "morok.antihook.win.region.size");
    Value *state = loadAt(NB, M, i32, mbi, 32, "morok.antihook.win.state");
    Value *protect = loadAt(NB, M, i32, mbi, 36, "morok.antihook.win.protect");
    Value *type = loadAt(NB, M, i32, mbi, 40, "morok.antihook.win.type");
    Value *committed =
        NB.CreateICmpNE(NB.CreateAnd(state, ConstantInt::get(i32, 0x1000)),
                        ConstantInt::get(i32, 0));
    Value *guard =
        NB.CreateICmpNE(NB.CreateAnd(protect, ConstantInt::get(i32, 0x100)),
                        ConstantInt::get(i32, 0), "morok.antihook.win.guard");
    Value *noAccess =
        NB.CreateICmpNE(NB.CreateAnd(protect, ConstantInt::get(i32, 0x01)),
                        ConstantInt::get(i32, 0), "morok.antihook.win.noaccess");
    Value *rwx =
        NB.CreateICmpNE(NB.CreateAnd(protect, ConstantInt::get(i32, 0xC0)),
                        ConstantInt::get(i32, 0), "morok.antihook.win.rwx");
    Value *largeRwx = NB.CreateAnd(
        rwx, NB.CreateICmpUGE(regionSize, ConstantInt::get(ip, 0x1000000)),
        "morok.antihook.win.rwx.large");
    Value *exec =
        NB.CreateICmpNE(NB.CreateAnd(protect, ConstantInt::get(i32, 0xF0)),
                        ConstantInt::get(i32, 0), "morok.antihook.win.exec");
    Value *isPrivate =
        NB.CreateICmpNE(NB.CreateAnd(type, ConstantInt::get(i32, 0x20000)),
                        ConstantInt::get(i32, 0));
    incrementDiff(NB, diff, NB.CreateAnd(committed, guard),
                  "morok.antihook.win.guard.hit");
    incrementDiff(NB, diff, NB.CreateAnd(committed, noAccess),
                  "morok.antihook.win.noaccess.hit");
    incrementDiff(NB, diff, NB.CreateAnd(committed, rwx),
                  "morok.antihook.win.rwx.hit");
    incrementDiff(NB, diff, NB.CreateAnd(committed, largeRwx),
                  "morok.antihook.win.rwx.large.hit");
    incrementDiff(NB, diff, NB.CreateAnd(NB.CreateAnd(committed, exec), isPrivate),
                  "morok.antihook.win.private.hit");
    Value *step = NB.CreateSelect(NB.CreateICmpUGT(regionSize, ConstantInt::get(ip, 0)),
                                  regionSize, ConstantInt::get(ip, 0x1000));
    Value *nextAddr = NB.CreateAdd(addr, step, "morok.antihook.win.next.addr");
    Value *nextIter =
        NB.CreateAdd(iter, ConstantInt::get(i32, 1), "morok.antihook.win.next");
    NB.CreateBr(loopBB);
    iter->addIncoming(nextIter, nextBB);
    addr->addIncoming(nextAddr, nextBB);

    IRBuilder<> RB(retBB);
    emitRetDiff(RB, diff);
    return fn;
}

Function *addressSpaceCensusProbe(Module &M, ir::IRRandom &rng,
                                  const Triple &TT) {
    if (Function *linux = linuxMapsCensusProbe(M, rng, TT))
        return linux;
    if (Function *darwin = darwinVmCensusProbe(M))
        return darwin;
    return windowsVirtualQueryCensusProbe(M);
}

Function *linuxWxEnforceProbe(Module &M, const Triple &TT) {
    if (!TT.isOSLinux() || intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.antihook.wxorx.linux"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);

    auto *fn = Function::Create(FunctionType::get(i64, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.wxorx.linux", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *baseLoopBB = BasicBlock::Create(ctx, "base.loop", fn);
    auto *baseBodyBB = BasicBlock::Create(ctx, "base.body", fn);
    auto *baseNextBB = BasicBlock::Create(ctx, "base.next", fn);
    auto *protLoopBB = BasicBlock::Create(ctx, "prot.loop", fn);
    auto *protBodyBB = BasicBlock::Create(ctx, "prot.body", fn);
    auto *protectBB = BasicBlock::Create(ctx, "protect", fn);
    auto *protNextBB = BasicBlock::Create(ctx, "prot.next", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    AllocaInst *diff = B.CreateAlloca(i64, nullptr, "morok.antihook.wxorx.diff");
    AllocaInst *baseSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.wxorx.base");
    B.CreateStore(ConstantInt::get(i64, 0), diff)->setVolatile(true);
    B.CreateStore(ConstantInt::get(ip, 0), baseSlot);
    FunctionCallee getauxval =
        M.getOrInsertFunction("getauxval", FunctionType::get(ip, {ip}, false));
    Value *atPhdr = B.CreateCall(getauxval, {ConstantInt::get(ip, 3)},
                                 "morok.antihook.wxorx.atphdr");
    Value *phEnt = B.CreateCall(getauxval, {ConstantInt::get(ip, 4)},
                                "morok.antihook.wxorx.phent");
    Value *phNum = B.CreateCall(getauxval, {ConstantInt::get(ip, 5)},
                                "morok.antihook.wxorx.phnum");
    Value *pageRaw = B.CreateCall(getauxval, {ConstantInt::get(ip, 6)},
                                  "morok.antihook.wxorx.pagesz");
    Value *pageSize = B.CreateSelect(
        B.CreateICmpUGT(pageRaw, ConstantInt::get(ip, 0)), pageRaw,
        ConstantInt::get(ip, 4096), "morok.antihook.wxorx.pagesz.v");
    Value *valid =
        B.CreateAnd(B.CreateICmpNE(atPhdr, ConstantInt::get(ip, 0)),
                    B.CreateAnd(B.CreateICmpUGE(phEnt, ConstantInt::get(ip, 56)),
                                B.CreateICmpUGT(phNum, ConstantInt::get(ip, 0))));
    B.CreateCondBr(valid, baseLoopBB, retBB);

    IRBuilder<> BLB(baseLoopBB);
    auto *baseIdx = BLB.CreatePHI(ip, 2, "morok.antihook.wxorx.base.idx");
    baseIdx->addIncoming(ConstantInt::get(ip, 0), entry);
    BLB.CreateCondBr(BLB.CreateAnd(BLB.CreateICmpULT(baseIdx, phNum),
                                   BLB.CreateICmpULT(baseIdx, ConstantInt::get(ip, 128))),
                     baseBodyBB, protLoopBB);

    IRBuilder<> BBB(baseBodyBB);
    Value *basePhPtr = BBB.CreateIntToPtr(
        BBB.CreateAdd(atPhdr, BBB.CreateMul(baseIdx, phEnt)), ptr,
        "morok.antihook.wxorx.base.ph");
    Value *baseType = loadAt(BBB, M, i32, basePhPtr, 0ULL,
                             "morok.antihook.wxorx.base.type");
    Value *baseVaddr =
        loadAt(BBB, M, ip, basePhPtr, 16, "morok.antihook.wxorx.base.vaddr");
    Value *oldBase = BBB.CreateLoad(ip, baseSlot);
    Value *newBase = BBB.CreateSelect(
        BBB.CreateICmpEQ(baseType, ConstantInt::get(i32, 6)),
        BBB.CreateSub(atPhdr, baseVaddr), oldBase,
        "morok.antihook.wxorx.base.new");
    BBB.CreateStore(newBase, baseSlot);
    BBB.CreateBr(baseNextBB);

    IRBuilder<> BNB(baseNextBB);
    Value *nextBaseIdx =
        BNB.CreateAdd(baseIdx, ConstantInt::get(ip, 1), "morok.antihook.wxorx.base.next");
    BNB.CreateBr(baseLoopBB);
    baseIdx->addIncoming(nextBaseIdx, baseNextBB);

    IRBuilder<> PLB(protLoopBB);
    auto *phIdx = PLB.CreatePHI(ip, 2, "morok.antihook.wxorx.ph.idx");
    phIdx->addIncoming(ConstantInt::get(ip, 0), baseLoopBB);
    PLB.CreateCondBr(PLB.CreateAnd(PLB.CreateICmpULT(phIdx, phNum),
                                   PLB.CreateICmpULT(phIdx, ConstantInt::get(ip, 128))),
                     protBodyBB, retBB);

    IRBuilder<> PBB(protBodyBB);
    Value *phPtr = PBB.CreateIntToPtr(
        PBB.CreateAdd(atPhdr, PBB.CreateMul(phIdx, phEnt)), ptr,
        "morok.antihook.wxorx.ph");
    Value *pType = loadAt(PBB, M, i32, phPtr, 0ULL, "morok.antihook.wxorx.type");
    Value *pFlags = loadAt(PBB, M, i32, phPtr, 4, "morok.antihook.wxorx.flags");
    Value *pVaddr = loadAt(PBB, M, ip, phPtr, 16, "morok.antihook.wxorx.vaddr");
    Value *pMemsz = loadAt(PBB, M, ip, phPtr, 40, "morok.antihook.wxorx.memsz");
    Value *isLoad = PBB.CreateICmpEQ(pType, ConstantInt::get(i32, 1));
    Value *isExec =
        PBB.CreateICmpNE(PBB.CreateAnd(pFlags, ConstantInt::get(i32, 1)),
                         ConstantInt::get(i32, 0));
    Value *hasMem = PBB.CreateICmpUGT(pMemsz, ConstantInt::get(ip, 0));
    PBB.CreateCondBr(PBB.CreateAnd(PBB.CreateAnd(isLoad, isExec), hasMem),
                     protectBB, protNextBB);

    IRBuilder<> WB(protectBB);
    Value *base = WB.CreateLoad(ip, baseSlot, "morok.antihook.wxorx.base.v");
    Value *segStart = WB.CreateAdd(base, pVaddr, "morok.antihook.wxorx.start");
    Value *segEnd = WB.CreateAdd(segStart, pMemsz, "morok.antihook.wxorx.end");
    Value *mask = WB.CreateNot(WB.CreateSub(pageSize, ConstantInt::get(ip, 1)),
                               "morok.antihook.wxorx.mask");
    Value *pageStart = WB.CreateAnd(segStart, mask, "morok.antihook.wxorx.page");
    Value *pageEnd = WB.CreateAnd(WB.CreateAdd(segEnd, WB.CreateSub(pageSize, ConstantInt::get(ip, 1))),
                                  mask, "morok.antihook.wxorx.page.end");
    Value *protSize = WB.CreateSub(pageEnd, pageStart, "morok.antihook.wxorx.size");
    Value *rc = emitLinuxMprotect(WB, M, TT, pageStart, protSize,
                                  ConstantInt::get(ip, 5));
    rc->setName("morok.antihook.wxorx.mprotect");
    incrementDiff(WB, diff,
                  WB.CreateICmpSLT(rc, ConstantInt::getSigned(i32, 0)),
                  "morok.antihook.wxorx.fail");
    WB.CreateBr(protNextBB);

    IRBuilder<> PNB(protNextBB);
    Value *nextPh =
        PNB.CreateAdd(phIdx, ConstantInt::get(ip, 1), "morok.antihook.wxorx.next");
    PNB.CreateBr(protLoopBB);
    phIdx->addIncoming(nextPh, protNextBB);

    IRBuilder<> RB(retBB);
    emitRetDiff(RB, diff);
    return fn;
}

Function *darwinWxEnforceProbe(Module &M, const Triple &TT) {
    if (!TT.isOSDarwin() || intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.antihook.wxorx.darwin"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);

    auto *fn = Function::Create(FunctionType::get(i64, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.wxorx.darwin", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *cmdLoopBB = BasicBlock::Create(ctx, "cmd.loop", fn);
    auto *cmdBodyBB = BasicBlock::Create(ctx, "cmd.body", fn);
    auto *protectBB = BasicBlock::Create(ctx, "protect", fn);
    auto *cmdNextBB = BasicBlock::Create(ctx, "cmd.next", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    AllocaInst *diff = B.CreateAlloca(i64, nullptr, "morok.antihook.wxorx.diff");
    B.CreateStore(ConstantInt::get(i64, 0), diff)->setVolatile(true);
    FunctionCallee imageHeader = M.getOrInsertFunction(
        "_dyld_get_image_header", FunctionType::get(ptr, {i32}, false));
    FunctionCallee imageSlide = M.getOrInsertFunction(
        "_dyld_get_image_vmaddr_slide", FunctionType::get(ip, {i32}, false));
    FunctionCallee getpagesize =
        M.getOrInsertFunction("getpagesize", FunctionType::get(i32, false));
    Value *hdr = B.CreateCall(imageHeader, {ConstantInt::get(i32, 0)},
                              "morok.antihook.wxorx.hdr");
    Value *slide = B.CreateCall(imageSlide, {ConstantInt::get(i32, 0)},
                                "morok.antihook.wxorx.slide");
    Value *pageRaw =
        B.CreateZExt(B.CreateCall(getpagesize, {}, "morok.antihook.wxorx.pagesz"), ip);
    Value *pageSize = B.CreateSelect(
        B.CreateICmpUGT(pageRaw, ConstantInt::get(ip, 0)), pageRaw,
        ConstantInt::get(ip, 4096), "morok.antihook.wxorx.pagesz.v");
    Value *magic = loadAt(B, M, i32, hdr, 0ULL, "morok.antihook.wxorx.magic");
    Value *ncmds = loadAt(B, M, i32, hdr, 16, "morok.antihook.wxorx.ncmds");
    Value *valid =
        B.CreateAnd(B.CreateICmpNE(hdr, ConstantPointerNull::get(ptr)),
                    B.CreateICmpEQ(magic, ConstantInt::get(i32, 0xFEEDFACF)));
    B.CreateCondBr(valid, cmdLoopBB, retBB);

    IRBuilder<> CLB(cmdLoopBB);
    auto *cmdIdx = CLB.CreatePHI(i32, 2, "morok.antihook.wxorx.cmd.idx");
    auto *cmdOff = CLB.CreatePHI(ip, 2, "morok.antihook.wxorx.cmd.off");
    cmdIdx->addIncoming(ConstantInt::get(i32, 0), entry);
    cmdOff->addIncoming(ConstantInt::get(ip, 32), entry);
    CLB.CreateCondBr(CLB.CreateAnd(CLB.CreateICmpULT(cmdIdx, ncmds),
                                   CLB.CreateICmpULT(cmdIdx, ConstantInt::get(i32, 128))),
                     cmdBodyBB, retBB);

    IRBuilder<> CBB(cmdBodyBB);
    Value *cmdPtr = gepI8(CBB, M, hdr, cmdOff, "morok.antihook.wxorx.cmd.ptr");
    Value *cmd = loadAt(CBB, M, i32, cmdPtr, 0ULL, "morok.antihook.wxorx.cmd");
    Value *cmdSize32 =
        loadAt(CBB, M, i32, cmdPtr, 4, "morok.antihook.wxorx.cmd.size");
    Value *cmdSize = CBB.CreateZExt(cmdSize32, ip, "morok.antihook.wxorx.cmd.size.w");
    Value *vmaddr = loadAt(CBB, M, i64, cmdPtr, 24, "morok.antihook.wxorx.vmaddr");
    Value *vmsize = loadAt(CBB, M, i64, cmdPtr, 32, "morok.antihook.wxorx.vmsize");
    Value *initprot =
        loadAt(CBB, M, i32, cmdPtr, 60, "morok.antihook.wxorx.initprot");
    Value *isSegment = CBB.CreateICmpEQ(cmd, ConstantInt::get(i32, 0x19));
    Value *isExec =
        CBB.CreateICmpNE(CBB.CreateAnd(initprot, ConstantInt::get(i32, 4)),
                         ConstantInt::get(i32, 0));
    Value *hasMem = CBB.CreateICmpUGT(vmsize, ConstantInt::get(i64, 0));
    CBB.CreateCondBr(CBB.CreateAnd(CBB.CreateAnd(isSegment, isExec), hasMem),
                     protectBB, cmdNextBB);

    IRBuilder<> WB(protectBB);
    Value *segStart = WB.CreateAdd(slide, vmaddr, "morok.antihook.wxorx.start");
    Value *segEnd = WB.CreateAdd(segStart, vmsize, "morok.antihook.wxorx.end");
    Value *mask = WB.CreateNot(WB.CreateSub(pageSize, ConstantInt::get(ip, 1)),
                               "morok.antihook.wxorx.mask");
    Value *pageStart = WB.CreateAnd(segStart, mask, "morok.antihook.wxorx.page");
    Value *pageEnd = WB.CreateAnd(WB.CreateAdd(segEnd, WB.CreateSub(pageSize, ConstantInt::get(ip, 1))),
                                  mask, "morok.antihook.wxorx.page.end");
    Value *protSize = WB.CreateSub(pageEnd, pageStart, "morok.antihook.wxorx.size");
    Value *rc = emitDarwinMprotect(WB, M, TT, pageStart, protSize,
                                   ConstantInt::get(ip, 5));
    rc->setName("morok.antihook.wxorx.mprotect");
    incrementDiff(WB, diff,
                  WB.CreateICmpSLT(rc, ConstantInt::getSigned(i32, 0)),
                  "morok.antihook.wxorx.fail");
    WB.CreateBr(cmdNextBB);

    IRBuilder<> CNB(cmdNextBB);
    Value *nextCmdIdx =
        CNB.CreateAdd(cmdIdx, ConstantInt::get(i32, 1), "morok.antihook.wxorx.next");
    Value *nextCmdOff =
        CNB.CreateAdd(cmdOff, cmdSize, "morok.antihook.wxorx.cmd.off.next");
    CNB.CreateBr(cmdLoopBB);
    cmdIdx->addIncoming(nextCmdIdx, cmdNextBB);
    cmdOff->addIncoming(nextCmdOff, cmdNextBB);

    IRBuilder<> RB(retBB);
    emitRetDiff(RB, diff);
    return fn;
}

Function *windowsWxEnforceProbe(Module &M) {
    const Triple TT(M.getTargetTriple());
    if (!TT.isOSWindows() || intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.antihook.wxorx.windows"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);

    auto *fn = Function::Create(FunctionType::get(i64, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.wxorx.windows", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *loopBB = BasicBlock::Create(ctx, "loop", fn);
    auto *bodyBB = BasicBlock::Create(ctx, "body", fn);
    auto *protectBB = BasicBlock::Create(ctx, "protect", fn);
    auto *protectCallBB = BasicBlock::Create(ctx, "protect.call", fn);
    auto *nextBB = BasicBlock::Create(ctx, "next", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    auto *mbiTy = ArrayType::get(i8, 64);
    AllocaInst *mbi = B.CreateAlloca(mbiTy, nullptr, "morok.antihook.wxorx.mbi");
    AllocaInst *oldProt = B.CreateAlloca(i32, nullptr, "morok.antihook.wxorx.old");
    AllocaInst *diff = B.CreateAlloca(i64, nullptr, "morok.antihook.wxorx.diff");
    B.CreateStore(ConstantInt::get(i64, 0), diff)->setVolatile(true);
    FunctionCallee virtualQuery = M.getOrInsertFunction(
        "VirtualQuery", FunctionType::get(ip, {ptr, ptr, ip}, false));
    FunctionCallee virtualProtect = M.getOrInsertFunction(
        "VirtualProtect", FunctionType::get(i32, {ptr, ip, i32, ptr}, false));
    B.CreateBr(loopBB);

    IRBuilder<> LB(loopBB);
    auto *iter = LB.CreatePHI(i32, 2, "morok.antihook.wxorx.idx");
    auto *addr = LB.CreatePHI(ip, 2, "morok.antihook.wxorx.addr");
    iter->addIncoming(ConstantInt::get(i32, 0), entry);
    addr->addIncoming(ConstantInt::get(ip, 0), entry);
    LB.CreateCondBr(LB.CreateICmpULT(iter, ConstantInt::get(i32, 256)), bodyBB,
                    retBB);

    IRBuilder<> BB(bodyBB);
    Value *mbiPtr = BB.CreateInBoundsGEP(
        mbiTy, mbi, {ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)});
    Value *rc = BB.CreateCall(virtualQuery,
                              {BB.CreateIntToPtr(addr, ptr), mbiPtr,
                               ConstantInt::get(ip, 48)},
                              "morok.antihook.wxorx.query");
    BB.CreateCondBr(BB.CreateICmpNE(rc, ConstantInt::get(ip, 0)), protectBB,
                    retBB);

    IRBuilder<> WB(protectBB);
    Value *base = loadAt(WB, M, ip, mbi, 0ULL, "morok.antihook.wxorx.base");
    Value *regionSize =
        loadAt(WB, M, ip, mbi, 24, "morok.antihook.wxorx.region.size");
    Value *state = loadAt(WB, M, i32, mbi, 32, "morok.antihook.wxorx.state");
    Value *protect = loadAt(WB, M, i32, mbi, 36, "morok.antihook.wxorx.protect");
    Value *committed =
        WB.CreateICmpNE(WB.CreateAnd(state, ConstantInt::get(i32, 0x1000)),
                        ConstantInt::get(i32, 0));
    Value *rwx =
        WB.CreateICmpNE(WB.CreateAnd(protect, ConstantInt::get(i32, 0xC0)),
                        ConstantInt::get(i32, 0), "morok.antihook.wxorx.rwx");
    Value *shouldProtect = WB.CreateAnd(committed, rwx);
    WB.CreateCondBr(shouldProtect, protectCallBB, nextBB);

    IRBuilder<> VPB(protectCallBB);
    Value *protectRc =
        VPB.CreateCall(virtualProtect,
                       {VPB.CreateIntToPtr(base, ptr), regionSize,
                        ConstantInt::get(i32, 0x20), oldProt},
                       "morok.antihook.wxorx.virtualprotect");
    incrementDiff(VPB, diff, ConstantInt::getTrue(ctx),
                  "morok.antihook.wxorx.rwx.hit");
    incrementDiff(VPB, diff,
                  VPB.CreateICmpEQ(protectRc, ConstantInt::get(i32, 0)),
                  "morok.antihook.wxorx.fail");
    VPB.CreateBr(nextBB);

    IRBuilder<> NB(nextBB);
    Value *step = NB.CreateSelect(NB.CreateICmpUGT(regionSize, ConstantInt::get(ip, 0)),
                                  regionSize, ConstantInt::get(ip, 0x1000));
    Value *nextAddr = NB.CreateAdd(addr, step, "morok.antihook.wxorx.next.addr");
    Value *nextIter =
        NB.CreateAdd(iter, ConstantInt::get(i32, 1), "morok.antihook.wxorx.next");
    NB.CreateBr(loopBB);
    iter->addIncoming(nextIter, nextBB);
    addr->addIncoming(nextAddr, nextBB);

    IRBuilder<> RB(retBB);
    emitRetDiff(RB, diff);
    return fn;
}

Function *wxEnforceProbe(Module &M, const Triple &TT) {
    if (Function *linux = linuxWxEnforceProbe(M, TT))
        return linux;
    if (Function *darwin = darwinWxEnforceProbe(M, TT))
        return darwin;
    return windowsWxEnforceProbe(M);
}

Value *pageBase(IRBuilder<> &B, Module &M, Value *Addr, Value *PageSize,
                const Twine &Name) {
    auto *ip = intPtrTy(M);
    Value *Mask = B.CreateNot(B.CreateSub(PageSize, ConstantInt::get(ip, 1)),
                              Name + ".mask");
    return B.CreateAnd(Addr, Mask, Name);
}

void emitAntiDumpGuardPage(IRBuilder<> &B, Module &M, const Triple &TT,
                           Value *PageSize, AllocaInst *Diff,
                           std::uint32_t Magic, const Twine &Stem) {
    auto *i32 = Type::getInt32Ty(M.getContext());
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(M.getContext());
    const std::uint32_t mapAnon = TT.isOSDarwin() ? 0x1000u : 0x20u;
    Value *Mapped = emitPosixAnonMmapAddr(
        B, M, TT, PageSize, ConstantInt::get(ip, 3),
        ConstantInt::get(ip, 2u | mapAnon), Stem + ".mmap");
    Mapped->setName(Stem + ".mmap");
    Value *MappedOk = B.CreateAnd(
        B.CreateICmpUGT(Mapped, ConstantInt::get(ip, 4096)),
        B.CreateICmpULT(Mapped, ConstantInt::getSigned(ip, -4095)),
        Stem + ".mapped");
    BasicBlock *Current = B.GetInsertBlock();
    Function *Fn = Current->getParent();
    BasicBlock *WriteBB = BasicBlock::Create(M.getContext(), "guard.write", Fn);
    BasicBlock *DoneBB = BasicBlock::Create(M.getContext(), "guard.done", Fn);
    B.CreateCondBr(MappedOk, WriteBB, DoneBB);

    IRBuilder<> WB(WriteBB);
    Value *PagePtr = WB.CreateIntToPtr(Mapped, ptr, Stem + ".ptr");
    storeAt(WB, M, PagePtr, 0ULL, ConstantInt::get(i32, Magic),
            Stem + ".magic");
    Value *NoneRc = emitPosixMprotect(WB, M, TT, Mapped, PageSize,
                                      ConstantInt::get(ip, 0));
    NoneRc->setName(Stem + ".mprotect.none");
    incrementDiff(WB, Diff,
                  WB.CreateICmpSLT(NoneRc, ConstantInt::getSigned(i32, 0)),
                  Stem + ".none.fail");
    WB.CreateBr(DoneBB);

    B.SetInsertPoint(DoneBB);
}

Function *linuxAntiDumpProbe(Module &M, const Triple &TT) {
    if (!TT.isOSLinux() || intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.antihook.antidump.elf"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i16 = Type::getInt16Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);

    auto *fn = Function::Create(FunctionType::get(i64, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.antidump.elf", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *phLoopBB = BasicBlock::Create(ctx, "ph.loop", fn);
    auto *phBodyBB = BasicBlock::Create(ctx, "ph.body", fn);
    auto *phNextBB = BasicBlock::Create(ctx, "ph.next", fn);
    auto *protectBB = BasicBlock::Create(ctx, "protect", fn);
    auto *scrubBB = BasicBlock::Create(ctx, "scrub", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    AllocaInst *diff =
        B.CreateAlloca(i64, nullptr, "morok.antidump.elf.diff");
    AllocaInst *baseSlot =
        B.CreateAlloca(ip, nullptr, "morok.antidump.elf.base");
    AllocaInst *hdrVaddrSlot =
        B.CreateAlloca(ip, nullptr, "morok.antidump.elf.hdr.vaddr");
    AllocaInst *restoreProtSlot =
        B.CreateAlloca(ip, nullptr, "morok.antidump.elf.restore.prot");
    B.CreateStore(ConstantInt::get(i64, 0), diff)->setVolatile(true);
    B.CreateStore(ConstantInt::get(ip, 0), baseSlot);
    B.CreateStore(ConstantInt::get(ip, 0), hdrVaddrSlot);
    B.CreateStore(ConstantInt::get(ip, 1), restoreProtSlot);
    FunctionCallee getauxval =
        M.getOrInsertFunction("getauxval", FunctionType::get(ip, {ip}, false));
    Value *atPhdr =
        B.CreateCall(getauxval, {ConstantInt::get(ip, 3)}, "morok.antidump.atphdr");
    Value *phEnt =
        B.CreateCall(getauxval, {ConstantInt::get(ip, 4)}, "morok.antidump.phent");
    Value *phNum =
        B.CreateCall(getauxval, {ConstantInt::get(ip, 5)}, "morok.antidump.phnum");
    Value *pageRaw =
        B.CreateCall(getauxval, {ConstantInt::get(ip, 6)}, "morok.antidump.pagesz");
    Value *pageSize = B.CreateSelect(
        B.CreateICmpUGT(pageRaw, ConstantInt::get(ip, 0)), pageRaw,
        ConstantInt::get(ip, 4096), "morok.antidump.pagesz.v");
    Value *valid =
        B.CreateAnd(B.CreateICmpNE(atPhdr, ConstantInt::get(ip, 0)),
                    B.CreateAnd(B.CreateICmpUGE(phEnt, ConstantInt::get(ip, 56)),
                                B.CreateICmpUGT(phNum, ConstantInt::get(ip, 0))));
    B.CreateCondBr(valid, phLoopBB, retBB);

    IRBuilder<> PLB(phLoopBB);
    PHINode *phIdx = PLB.CreatePHI(ip, 2, "morok.antidump.elf.ph.idx");
    phIdx->addIncoming(ConstantInt::get(ip, 0), entry);
    PLB.CreateCondBr(PLB.CreateAnd(PLB.CreateICmpULT(phIdx, phNum),
                                   PLB.CreateICmpULT(phIdx, ConstantInt::get(ip, 128))),
                     phBodyBB, protectBB);

    IRBuilder<> PBB(phBodyBB);
    Value *phPtr = PBB.CreateIntToPtr(
        PBB.CreateAdd(atPhdr, PBB.CreateMul(phIdx, phEnt)), ptr,
        "morok.antidump.elf.ph");
    Value *pType = loadAt(PBB, M, i32, phPtr, 0ULL,
                          "morok.antidump.elf.ph.type");
    Value *pFlags = loadAt(PBB, M, i32, phPtr, 4,
                           "morok.antidump.elf.ph.flags");
    Value *pOffset = loadAt(PBB, M, ip, phPtr, 8,
                            "morok.antidump.elf.ph.offset");
    Value *pVaddr = loadAt(PBB, M, ip, phPtr, 16,
                           "morok.antidump.elf.ph.vaddr");
    Value *oldBase = PBB.CreateLoad(ip, baseSlot,
                                    "morok.antidump.elf.base.old");
    Value *newBase = PBB.CreateSelect(
        PBB.CreateICmpEQ(pType, ConstantInt::get(i32, 6)),
        PBB.CreateSub(atPhdr, pVaddr), oldBase,
        "morok.antidump.elf.base.new");
    PBB.CreateStore(newBase, baseSlot);
    Value *isHeaderLoad = PBB.CreateAnd(
        PBB.CreateICmpEQ(pType, ConstantInt::get(i32, 1)),
        PBB.CreateICmpEQ(pOffset, ConstantInt::get(ip, 0)),
        "morok.antidump.elf.header.load");
    Value *oldHdr = PBB.CreateLoad(ip, hdrVaddrSlot,
                                   "morok.antidump.elf.hdr.old");
    PBB.CreateStore(PBB.CreateSelect(isHeaderLoad, pVaddr, oldHdr),
                    hdrVaddrSlot);
    Value *oldProt = PBB.CreateLoad(ip, restoreProtSlot,
                                    "morok.antidump.elf.prot.old");
    Value *hasExec =
        PBB.CreateICmpNE(PBB.CreateAnd(pFlags, ConstantInt::get(i32, 1)),
                         ConstantInt::get(i32, 0),
                         "morok.antidump.elf.header.exec");
    Value *headerRestoreProt =
        PBB.CreateSelect(hasExec, ConstantInt::get(ip, 5),
                         ConstantInt::get(ip, 1),
                         "morok.antidump.elf.prot.new");
    PBB.CreateStore(PBB.CreateSelect(isHeaderLoad, headerRestoreProt, oldProt),
                    restoreProtSlot);
    PBB.CreateBr(phNextBB);

    IRBuilder<> PNB(phNextBB);
    Value *nextPh =
        PNB.CreateAdd(phIdx, ConstantInt::get(ip, 1),
                      "morok.antidump.elf.ph.next");
    PNB.CreateBr(phLoopBB);
    phIdx->addIncoming(nextPh, phNextBB);

    IRBuilder<> PB(protectBB);
    Value *base = PB.CreateLoad(ip, baseSlot, "morok.antidump.elf.base.v");
    Value *hdrVaddr =
        PB.CreateLoad(ip, hdrVaddrSlot, "morok.antidump.elf.hdr.vaddr.v");
    Value *hdrAddr = PB.CreateAdd(base, hdrVaddr, "morok.antidump.elf.hdr");
    Value *hdrOk = PB.CreateICmpNE(hdrAddr, ConstantInt::get(ip, 0),
                                   "morok.antidump.elf.hdr.ok");
    PB.CreateCondBr(hdrOk, scrubBB, retBB);

    IRBuilder<> SB(scrubBB);
    Value *hdrPtr = SB.CreateIntToPtr(hdrAddr, ptr, "morok.antidump.elf.ptr");
    Value *page = pageBase(SB, M, hdrAddr, pageSize, "morok.antidump.elf.page");
    Value *rwRc = emitLinuxMprotect(SB, M, TT, page, pageSize,
                                    ConstantInt::get(ip, 3));
    rwRc->setName("morok.antidump.elf.mprotect.rw");
    Value *rwFail =
        SB.CreateICmpSLT(rwRc, ConstantInt::getSigned(i32, 0),
                         "morok.antidump.elf.rw.fail");
    incrementDiff(SB, diff, rwFail, "morok.antidump.elf.rw.fail");
    BasicBlock *writeBB = BasicBlock::Create(ctx, "write", fn);
    BasicBlock *afterWriteBB = BasicBlock::Create(ctx, "after.write", fn);
    SB.CreateCondBr(rwFail, afterWriteBB, writeBB);

    IRBuilder<> WB(writeBB);
    storeAt(WB, M, hdrPtr, 0ULL, ConstantInt::get(i32, 0x4B4F524D),
            "morok.antidump.elf.magic");
    storeAt(WB, M, hdrPtr, 40, ConstantInt::get(i64, 0),
            "morok.antidump.elf.shoff");
    storeAt(WB, M, hdrPtr, 58, ConstantInt::get(i16, 0),
            "morok.antidump.elf.shentsize");
    storeAt(WB, M, hdrPtr, 60, ConstantInt::get(i16, 0),
            "morok.antidump.elf.shnum");
    storeAt(WB, M, hdrPtr, 62, ConstantInt::get(i16, 0),
            "morok.antidump.elf.shstrndx");
    Value *restoreProt =
        WB.CreateLoad(ip, restoreProtSlot, "morok.antidump.elf.prot.v");
    Value *roRc = emitLinuxMprotect(WB, M, TT, page, pageSize, restoreProt);
    roRc->setName("morok.antidump.elf.mprotect.restore");
    incrementDiff(WB, diff,
                  WB.CreateICmpSLT(roRc, ConstantInt::getSigned(i32, 0)),
                  "morok.antidump.elf.restore.fail");
    WB.CreateBr(afterWriteBB);

    IRBuilder<> AWB(afterWriteBB);
    emitAntiDumpGuardPage(AWB, M, TT, pageSize, diff, 0x464C457F,
                          "morok.antidump.guard.elf");
    AWB.CreateBr(retBB);

    IRBuilder<> RB(retBB);
    emitRetDiff(RB, diff);
    return fn;
}

Function *darwinAntiDumpProbe(Module &M, const Triple &TT) {
    if (!TT.isOSDarwin() || intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.antihook.antidump.macho"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);

    auto *fn = Function::Create(FunctionType::get(i64, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.antidump.macho", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *cmdLoopBB = BasicBlock::Create(ctx, "cmd.loop", fn);
    auto *cmdBodyBB = BasicBlock::Create(ctx, "cmd.body", fn);
    auto *sectionLoopBB = BasicBlock::Create(ctx, "section.loop", fn);
    auto *sectionBodyBB = BasicBlock::Create(ctx, "section.body", fn);
    auto *sectionNextBB = BasicBlock::Create(ctx, "section.next", fn);
    auto *cmdNextBB = BasicBlock::Create(ctx, "cmd.next", fn);
    auto *restoreBB = BasicBlock::Create(ctx, "restore", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    AllocaInst *diff =
        B.CreateAlloca(i64, nullptr, "morok.antidump.macho.diff");
    B.CreateStore(ConstantInt::get(i64, 0), diff)->setVolatile(true);
    FunctionCallee imageHeader = M.getOrInsertFunction(
        "_dyld_get_image_header", FunctionType::get(ptr, {i32}, false));
    FunctionCallee getpagesize =
        M.getOrInsertFunction("getpagesize", FunctionType::get(i32, false));
    Value *hdr =
        B.CreateCall(imageHeader, {ConstantInt::get(i32, 0)},
                     "morok.antidump.macho.hdr");
    Value *pageSize = B.CreateZExt(
        B.CreateCall(getpagesize, {}, "morok.antidump.macho.pagesz"), ip);
    pageSize = B.CreateSelect(B.CreateICmpUGT(pageSize, ConstantInt::get(ip, 0)),
                              pageSize, ConstantInt::get(ip, 4096),
                              "morok.antidump.macho.pagesz.v");
    Value *hdrAddr = B.CreatePtrToInt(hdr, ip, "morok.antidump.macho.hdr.addr");
    Value *magic = loadAt(B, M, i32, hdr, 0ULL, "morok.antidump.macho.magic.v");
    Value *ncmds = loadAt(B, M, i32, hdr, 16, "morok.antidump.macho.ncmds");
    Value *page = pageBase(B, M, hdrAddr, pageSize, "morok.antidump.macho.page");
    // The load commands (and the section_64 records this probe poisons) live in
    // [hdr + sizeof(mach_header_64), + sizeofcmds), which can extend well past
    // the first page on real binaries with many sections.  Make the whole
    // page-rounded range writable, not just one page, or the volatile name
    // stores fault (SIGSEGV) on the still-RX later __TEXT pages.  Clamp
    // sizeofcmds so a non-Mach-O / garbage header (validated only AFTER this
    // mprotect) cannot request an absurd length.
    Value *sizeofcmds =
        loadAt(B, M, i32, hdr, 20, "morok.antidump.macho.sizeofcmds");
    Value *cmds = B.CreateZExt(sizeofcmds, ip);
    Value *cmdsClamped = B.CreateSelect(
        B.CreateICmpULT(cmds, ConstantInt::get(ip, 0x100000)), cmds,
        ConstantInt::get(ip, 0x100000), "morok.antidump.macho.cmds.clamped");
    Value *span = B.CreateAdd(
        B.CreateAdd(B.CreateSub(hdrAddr, page), ConstantInt::get(ip, 32)),
        cmdsClamped, "morok.antidump.macho.span");
    Value *pm1 = B.CreateSub(pageSize, ConstantInt::get(ip, 1));
    Value *protLen = B.CreateAnd(B.CreateAdd(span, pm1), B.CreateNot(pm1),
                                 "morok.antidump.macho.protlen");
    Value *rwRc =
        emitDarwinMprotect(B, M, TT, page, protLen, ConstantInt::get(ip, 3));
    rwRc->setName("morok.antidump.macho.mprotect.rw");
    Value *valid =
        B.CreateAnd(B.CreateICmpNE(hdr, ConstantPointerNull::get(ptr)),
                    B.CreateICmpEQ(magic, ConstantInt::get(i32, 0xFEEDFACF)));
    Value *rwOk = B.CreateICmpSGE(rwRc, ConstantInt::getSigned(i32, 0),
                                  "morok.antidump.macho.rw.ok");
    incrementDiff(B, diff, B.CreateNot(rwOk),
                  "morok.antidump.macho.rw.fail");
    B.CreateCondBr(B.CreateAnd(valid, rwOk), cmdLoopBB, retBB);

    IRBuilder<> CLB(cmdLoopBB);
    PHINode *cmdIdx = CLB.CreatePHI(i32, 2, "morok.antidump.macho.cmd.idx");
    PHINode *cmdOff = CLB.CreatePHI(ip, 2, "morok.antidump.macho.cmd.off");
    cmdIdx->addIncoming(ConstantInt::get(i32, 0), entry);
    cmdOff->addIncoming(ConstantInt::get(ip, 32), entry);
    CLB.CreateCondBr(CLB.CreateAnd(CLB.CreateICmpULT(cmdIdx, ncmds),
                                   CLB.CreateICmpULT(cmdIdx, ConstantInt::get(i32, 128))),
                     cmdBodyBB, restoreBB);

    IRBuilder<> CBB(cmdBodyBB);
    Value *cmdPtr = gepI8(CBB, M, hdr, cmdOff, "morok.antidump.macho.cmd.ptr");
    Value *cmd = loadAt(CBB, M, i32, cmdPtr, 0ULL,
                        "morok.antidump.macho.cmd");
    Value *cmdSize32 = loadAt(CBB, M, i32, cmdPtr, 4,
                              "morok.antidump.macho.cmd.size");
    Value *cmdSize =
        CBB.CreateZExt(cmdSize32, ip, "morok.antidump.macho.cmd.size.w");
    Value *nsects = loadAt(CBB, M, i32, cmdPtr, 64,
                           "morok.antidump.macho.nsects");
    Value *isSegment = CBB.CreateICmpEQ(cmd, ConstantInt::get(i32, 0x19),
                                        "morok.antidump.macho.segment");
    CBB.CreateCondBr(CBB.CreateAnd(isSegment,
                                   CBB.CreateICmpUGT(nsects, ConstantInt::get(i32, 0))),
                     sectionLoopBB, cmdNextBB);

    IRBuilder<> SLB(sectionLoopBB);
    PHINode *secIdx = SLB.CreatePHI(i32, 2, "morok.antidump.macho.sec.idx");
    PHINode *secOff = SLB.CreatePHI(ip, 2, "morok.antidump.macho.sec.off");
    secIdx->addIncoming(ConstantInt::get(i32, 0), cmdBodyBB);
    secOff->addIncoming(ConstantInt::get(ip, 72), cmdBodyBB);
    SLB.CreateCondBr(SLB.CreateAnd(SLB.CreateICmpULT(secIdx, nsects),
                                   SLB.CreateICmpULT(secIdx, ConstantInt::get(i32, 96))),
                     sectionBodyBB, cmdNextBB);

    IRBuilder<> SBB(sectionBodyBB);
    Value *secPtr =
        gepI8(SBB, M, cmdPtr, secOff, "morok.antidump.macho.section.ptr");
    for (std::uint64_t i = 0; i < 32; i += 8) {
        storeAt(SBB, M, secPtr, i,
                ConstantInt::get(i64, 0xA5A5A5A5A5A5A5A5ULL),
                "morok.antidump.macho.section.name");
    }
    SBB.CreateBr(sectionNextBB);

    IRBuilder<> SNB(sectionNextBB);
    Value *nextSecIdx = SNB.CreateAdd(
        secIdx, ConstantInt::get(i32, 1), "morok.antidump.macho.sec.next");
    Value *nextSecOff = SNB.CreateAdd(
        secOff, ConstantInt::get(ip, 80), "morok.antidump.macho.sec.off.next");
    SNB.CreateBr(sectionLoopBB);
    secIdx->addIncoming(nextSecIdx, sectionNextBB);
    secOff->addIncoming(nextSecOff, sectionNextBB);

    IRBuilder<> CNB(cmdNextBB);
    Value *nextCmdIdx = CNB.CreateAdd(
        cmdIdx, ConstantInt::get(i32, 1), "morok.antidump.macho.cmd.next");
    Value *nextCmdOff = CNB.CreateAdd(
        cmdOff, cmdSize, "morok.antidump.macho.cmd.off.next");
    CNB.CreateBr(cmdLoopBB);
    cmdIdx->addIncoming(nextCmdIdx, cmdNextBB);
    cmdOff->addIncoming(nextCmdOff, cmdNextBB);

    IRBuilder<> RSB(restoreBB);
    Value *flagsPtr = gepI8(RSB, M, hdr, constIp(M, 24),
                            "morok.antidump.macho.flags.ptr");
    StoreInst *flagsStore =
        RSB.CreateStore(ConstantInt::get(i32, 0x4D524F4B), flagsPtr);
    flagsStore->setVolatile(true);
    flagsStore->setAlignment(Align(1));
    Value *rxRc =
        emitDarwinMprotect(RSB, M, TT, page, protLen, ConstantInt::get(ip, 5));
    rxRc->setName("morok.antidump.macho.mprotect.rx");
    incrementDiff(RSB, diff,
                  RSB.CreateICmpSLT(rxRc, ConstantInt::getSigned(i32, 0)),
                  "morok.antidump.macho.restore.fail");
    emitAntiDumpGuardPage(RSB, M, TT, pageSize, diff, 0xFEEDFACF,
                          "morok.antidump.guard.macho");
    RSB.CreateBr(retBB);

    IRBuilder<> RB(retBB);
    emitRetDiff(RB, diff);
    return fn;
}

Function *antiDumpProbe(Module &M, const Triple &TT) {
    if (Function *linux = linuxAntiDumpProbe(M, TT))
        return linux;
    return darwinAntiDumpProbe(M, TT);
}

Function *linuxStackOriginCheck(Module &M) {
    const Triple TT(M.getTargetTriple());
    if (!TT.isOSLinux() || intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.antihook.stack.linux"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    Function *rxCheck = linuxGotTargetInRx(M);

    auto *fn = Function::Create(FunctionType::get(i32, {ip}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.stack.linux", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    Argument *target = fn->getArg(0);
    target->setName("target");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *baseLoopBB = BasicBlock::Create(ctx, "base.loop", fn);
    auto *baseBodyBB = BasicBlock::Create(ctx, "base.body", fn);
    auto *baseNextBB = BasicBlock::Create(ctx, "base.next", fn);
    auto *checkBB = BasicBlock::Create(ctx, "check", fn);
    auto *ret0BB = BasicBlock::Create(ctx, "ret0", fn);

    IRBuilder<> B(entry);
    AllocaInst *baseSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.stack.base");
    B.CreateStore(ConstantInt::get(ip, 0), baseSlot);
    FunctionCallee getauxval =
        M.getOrInsertFunction("getauxval", FunctionType::get(ip, {ip}, false));
    Value *atPhdr =
        B.CreateCall(getauxval, {ConstantInt::get(ip, 3)}, "morok.stack.atphdr");
    Value *phEnt =
        B.CreateCall(getauxval, {ConstantInt::get(ip, 4)}, "morok.stack.phent");
    Value *phNum =
        B.CreateCall(getauxval, {ConstantInt::get(ip, 5)}, "morok.stack.phnum");
    Value *valid =
        B.CreateAnd(B.CreateICmpNE(target, ConstantInt::get(ip, 0)),
                    B.CreateAnd(B.CreateICmpNE(atPhdr, ConstantInt::get(ip, 0)),
                                B.CreateICmpUGE(phEnt, ConstantInt::get(ip, 56))));
    B.CreateCondBr(valid, baseLoopBB, ret0BB);

    IRBuilder<> LB(baseLoopBB);
    auto *idx = LB.CreatePHI(ip, 2, "morok.antihook.stack.base.idx");
    idx->addIncoming(ConstantInt::get(ip, 0), entry);
    LB.CreateCondBr(LB.CreateAnd(LB.CreateICmpULT(idx, phNum),
                                 LB.CreateICmpULT(idx, ConstantInt::get(ip, 128))),
                    baseBodyBB, checkBB);

    IRBuilder<> BB(baseBodyBB);
    Value *phPtr =
        BB.CreateIntToPtr(BB.CreateAdd(atPhdr, BB.CreateMul(idx, phEnt)), ptr,
                          "morok.antihook.stack.ph");
    Value *pType = loadAt(BB, M, i32, phPtr, 0ULL,
                          "morok.antihook.stack.ph.type");
    Value *pVaddr =
        loadAt(BB, M, ip, phPtr, 16, "morok.antihook.stack.ph.vaddr");
    Value *oldBase = BB.CreateLoad(ip, baseSlot);
    Value *newBase = BB.CreateSelect(
        BB.CreateICmpEQ(pType, ConstantInt::get(i32, 6)),
        BB.CreateSub(atPhdr, pVaddr), oldBase, "morok.antihook.stack.base.new");
    BB.CreateStore(newBase, baseSlot);
    BB.CreateBr(baseNextBB);

    IRBuilder<> BNB(baseNextBB);
    Value *next =
        BNB.CreateAdd(idx, ConstantInt::get(ip, 1), "morok.antihook.stack.next");
    BNB.CreateBr(baseLoopBB);
    idx->addIncoming(next, baseNextBB);

    IRBuilder<> CB(checkBB);
    Value *base = CB.CreateLoad(ip, baseSlot, "morok.antihook.stack.base.v");
    Value *ok = CB.CreateCall(
        rxCheck, {target, atPhdr, phNum, phEnt, base, ConstantPointerNull::get(ptr)},
        "morok.antihook.stack.rx");
    CB.CreateRet(ok);

    IRBuilder<> R0(ret0BB);
    R0.CreateRet(ConstantInt::get(i32, 0));
    return fn;
}

Function *darwinStackOriginCheck(Module &M) {
    const Triple TT(M.getTargetTriple());
    if (!TT.isOSDarwin() || intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.antihook.stack.darwin"))
        return existing;
    Function *textCheck = darwinTextTargetInDyldImages(M);

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *fn = Function::Create(FunctionType::get(i32, {ip}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.stack.darwin", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    Argument *target = fn->getArg(0);
    target->setName("target");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    IRBuilder<> B(entry);
    Value *nonNull = B.CreateICmpNE(target, ConstantInt::get(ip, 0));
    Value *ok = B.CreateCall(textCheck, {target}, "morok.antihook.stack.text");
    B.CreateRet(B.CreateSelect(nonNull, ok, ConstantInt::get(i32, 0)));
    return fn;
}

Function *windowsStackOriginCheck(Module &M) {
    const Triple TT(M.getTargetTriple());
    if (!TT.isOSWindows() || intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.antihook.stack.windows"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);

    auto *fn = Function::Create(FunctionType::get(i32, {ip}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.stack.windows", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    Argument *target = fn->getArg(0);
    target->setName("target");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *checkBB = BasicBlock::Create(ctx, "check", fn);
    auto *ret0BB = BasicBlock::Create(ctx, "ret0", fn);
    IRBuilder<> B(entry);
    auto *mbiTy = ArrayType::get(i8, 64);
    AllocaInst *mbi = B.CreateAlloca(mbiTy, nullptr, "morok.antihook.stack.mbi");
    FunctionCallee virtualQuery = M.getOrInsertFunction(
        "VirtualQuery", FunctionType::get(ip, {ptr, ptr, ip}, false));
    Value *mbiPtr = B.CreateInBoundsGEP(
        mbiTy, mbi, {ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)});
    Value *rc =
        B.CreateCall(virtualQuery,
                     {B.CreateIntToPtr(target, ptr), mbiPtr,
                      ConstantInt::get(ip, 48)},
                     "morok.antihook.stack.query");
    B.CreateCondBr(B.CreateAnd(B.CreateICmpNE(target, ConstantInt::get(ip, 0)),
                               B.CreateICmpNE(rc, ConstantInt::get(ip, 0))),
                   checkBB, ret0BB);

    IRBuilder<> WB(checkBB);
    Value *state = loadAt(WB, M, i32, mbi, 32, "morok.antihook.stack.state");
    Value *protect =
        loadAt(WB, M, i32, mbi, 36, "morok.antihook.stack.protect");
    Value *committed =
        WB.CreateICmpNE(WB.CreateAnd(state, ConstantInt::get(i32, 0x1000)),
                        ConstantInt::get(i32, 0));
    Value *exec =
        WB.CreateICmpNE(WB.CreateAnd(protect, ConstantInt::get(i32, 0xF0)),
                        ConstantInt::get(i32, 0));
    Value *guard =
        WB.CreateICmpNE(WB.CreateAnd(protect, ConstantInt::get(i32, 0x100)),
                        ConstantInt::get(i32, 0));
    Value *noaccess =
        WB.CreateICmpNE(WB.CreateAnd(protect, ConstantInt::get(i32, 0x01)),
                        ConstantInt::get(i32, 0));
    Value *rwx =
        WB.CreateICmpNE(WB.CreateAnd(protect, ConstantInt::get(i32, 0xC0)),
                        ConstantInt::get(i32, 0));
    Value *ok =
        WB.CreateAnd(WB.CreateAnd(committed, exec),
                     WB.CreateNot(WB.CreateOr(guard, WB.CreateOr(noaccess, rwx))),
                     "morok.antihook.stack.ok");
    WB.CreateRet(WB.CreateZExt(ok, i32));

    IRBuilder<> R0(ret0BB);
    R0.CreateRet(ConstantInt::get(i32, 0));
    return fn;
}

Function *stackOriginCheck(Module &M) {
    if (Function *linux = linuxStackOriginCheck(M))
        return linux;
    if (Function *darwin = darwinStackOriginCheck(M))
        return darwin;
    return windowsStackOriginCheck(M);
}

bool insertStackOriginChecks(Module &M, Function *Check, GlobalVariable *State,
                             const std::vector<Function *> &Targets,
                             ir::IRRandom &rng) {
    if (!Check)
        return false;
    auto *i32 = Type::getInt32Ty(M.getContext());
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(M.getContext());
    // Always request the canonical declaration for llvm.returnaddress via
    // Intrinsic::getOrInsertDeclaration so the backend recognizes and lowers it.
    // Whether the canonical name carries a pointer-mangling suffix depends on
    // the LLVM version: older releases declare returnaddress with a fixed ptr
    // return (non-overloaded, name "llvm.returnaddress"), while newer ones make
    // it overloaded on the return pointer's address space (name
    // "llvm.returnaddress.p0"). Hardcoding either form — or passing an overload
    // type to a non-overloaded intrinsic — yields a function the backend never
    // recognizes; it then survives codegen as an undefined external symbol and
    // breaks linking (e.g. lld-link: undefined symbol: llvm.returnaddress.p0).
    // Pass the overload type only when this LLVM actually overloads the
    // intrinsic, so the right canonical name is produced on every version.
    SmallVector<Type *, 1> raOverloads;
    if (Intrinsic::isOverloaded(Intrinsic::returnaddress))
        raOverloads.push_back(ptr);
    Function *returnAddressFn = Intrinsic::getOrInsertDeclaration(
        &M, Intrinsic::returnaddress, raOverloads);
    FunctionCallee returnAddress(returnAddressFn->getFunctionType(),
                                 returnAddressFn);
    bool changed = false;
    std::uint32_t site = 1;
    for (Function *target : Targets) {
        if (!target || !isPrologueProbeCandidate(*target) ||
            target->getName() == "main")
            continue;
        BasicBlock &entry = target->getEntryBlock();
        auto it = entry.getFirstInsertionPt();
        if (it == entry.end())
            continue;
        IRBuilder<> B(&*it);
        Value *ra = B.CreateCall(returnAddress, {ConstantInt::get(i32, 0)},
                                 "morok.antihook.stack.ra");
        Value *addr = B.CreatePtrToInt(ra, ip, "morok.antihook.stack.addr");
        Value *ok =
            B.CreateCall(Check->getFunctionType(), Check, {addr},
                         "morok.antihook.stack.origin");
        Value *bad = B.CreateICmpEQ(ok, ConstantInt::get(i32, 0),
                                    "morok.antihook.stack.bad");
        foldEnforcedFlag(B, State, bad,
                         rng.next() ^ (0xD6E8FEB86659FD93ULL * site++),
                         "morok.antihook.stack.bad");
        changed = true;
    }
    return changed;
}

Value *emitWrapperPid(IRBuilder<> &B, Module &M, FunctionCallee Callee,
                      const Twine &Name) {
    return B.CreateSExtOrTrunc(B.CreateCall(Callee), intPtrTy(M), Name);
}

Function *methodDivergenceProbe(Module &M, const Triple &TT) {
    const bool linux = useDirectLinuxSyscalls(M, TT);
    const bool darwin = useDirectDarwinSyscalls(M, TT);
    if (!linux && !darwin)
        return nullptr;
    if (Function *existing = M.getFunction("morok.antihook.diverge.posix"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i64 = Type::getInt64Ty(ctx);
    auto *fn = Function::Create(FunctionType::get(i64, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.diverge.posix", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    IRBuilder<> B(entry);
    AllocaInst *diff =
        B.CreateAlloca(i64, nullptr, "morok.antihook.diverge.diff");
    B.CreateStore(ConstantInt::get(i64, 0), diff)->setVolatile(true);

    auto comparePidPrimitive = [&](StringRef Stem, std::uint32_t SysNo,
                                   FunctionCallee Wrapper) {
        Value *direct = linux ? emitLinuxSyscall(B, M, TT, SysNo, {})
                              : emitDarwinSyscall(B, M, TT, SysNo, {});
        direct->setName(Twine("morok.antihook.diverge.") + Stem + ".direct");
        Value *wrapped = emitWrapperPid(
            B, M, Wrapper,
            Twine("morok.antihook.diverge.") + Stem + ".wrapper");
        incrementDiff(B, diff, B.CreateICmpNE(direct, wrapped),
                      Twine("morok.antihook.diverge.") + Stem);
    };

    comparePidPrimitive("getpid", linux ? 39 : 20, getpidDecl(M));
    comparePidPrimitive("getppid", linux ? 110 : 39, getppidDecl(M));
    emitRetDiff(B, diff);
    return fn;
}

FunctionCallee sysconfDecl(Module &M) {
    auto *i32 = Type::getInt32Ty(M.getContext());
    auto *ip = intPtrTy(M);
    return M.getOrInsertFunction("sysconf", FunctionType::get(ip, {i32}, false));
}

FunctionCallee nanosleepDecl(Module &M) {
    auto *i32 = Type::getInt32Ty(M.getContext());
    auto *ptr = PointerType::getUnqual(M.getContext());
    return M.getOrInsertFunction("nanosleep",
                                 FunctionType::get(i32, {ptr, ptr}, false));
}

GlobalVariable *sandboxTripwireGate(Module &M) {
    if (auto *existing = M.getGlobalVariable(
            "morok.antihook.sandbox.tripwire", /*AllowInternal=*/true))
        return existing;
    auto *i8 = Type::getInt8Ty(M.getContext());
    auto *gv = new GlobalVariable(
        M, i8, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(i8, 0), "morok.antihook.sandbox.tripwire");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

Value *emitCpuid(IRBuilder<> &B, Module &M, Value *Leaf, Value *Subleaf) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *cpuidTy = StructType::get(ctx, {i32, i32, i32, i32});
    auto *asmTy = FunctionType::get(cpuidTy, {i32, i32}, false);
    InlineAsm *cpuid = InlineAsm::get(
        asmTy, "cpuid",
        "={eax},={ebx},={ecx},={edx},{eax},{ecx},~{dirflag},~{fpsr},~{flags}",
        /*hasSideEffects=*/true);
    return B.CreateCall(asmTy, cpuid, {Leaf, Subleaf},
                        "morok.antihook.sandbox.cpuid");
}

Value *cpuidReg(IRBuilder<> &B, Value *Cpuid, unsigned Index,
                const Twine &Name) {
    return B.CreateExtractValue(Cpuid, {Index}, Name);
}

void emitDescriptorStore(IRBuilder<> &B, Value *Ptr, StringRef Asm,
                         const Twine &Name) {
    auto *asmTy =
        FunctionType::get(Type::getVoidTy(B.getContext()),
                          {PointerType::getUnqual(B.getContext())}, false);
    InlineAsm *IA = InlineAsm::get(
        asmTy, Asm, "r,~{memory},~{dirflag},~{fpsr},~{flags}",
        /*hasSideEffects=*/true);
    (void)Name;
    B.CreateCall(asmTy, IA, {Ptr});
}

Value *emitVmwareBackdoor(IRBuilder<> &B, Module &M) {
    auto *i32 = Type::getInt32Ty(M.getContext());
    auto *asmTy = FunctionType::get(i32, {i32, i32, i32}, false);
    InlineAsm *backdoor = InlineAsm::get(
        asmTy, "inl %dx, %eax",
        "={ebx},{eax},{ecx},{edx},~{memory},~{dirflag},~{fpsr},~{flags}",
        /*hasSideEffects=*/true);
    return B.CreateCall(
        asmTy, backdoor,
        {ConstantInt::get(i32, 0x564D5868u), ConstantInt::get(i32, 0x0au),
         ConstantInt::get(i32, 0x5658u)},
        "morok.antihook.sandbox.vmware.backdoor");
}

Function *sandboxHeuristicProbe(Module &M, const Triple &TT) {
    const bool X86 =
        TT.getArch() == Triple::x86 || TT.getArch() == Triple::x86_64;
    const bool Posix = TT.isOSLinux() || TT.isOSDarwin();
    if (!X86 && !Posix)
        return nullptr;
    if (Function *existing = M.getFunction("morok.antihook.sandbox"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i16 = Type::getInt16Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *fn = Function::Create(FunctionType::get(i64, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.sandbox", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    IRBuilder<> B(entry);
    AllocaInst *score =
        B.CreateAlloca(i64, nullptr, "morok.antihook.sandbox.score");
    B.CreateStore(ConstantInt::get(i64, 0), score)->setVolatile(true);

    if (X86) {
        auto *tripwire = B.CreateLoad(i8, sandboxTripwireGate(M),
                                      "morok.antihook.sandbox.tripwire.load");
        tripwire->setVolatile(true);
        Value *tripwireArmed = B.CreateICmpNE(
            tripwire, ConstantInt::get(i8, 0),
            "morok.antihook.sandbox.tripwire.armed");

        Value *leaf1 = emitCpuid(B, M, ConstantInt::get(i32, 1),
                                 ConstantInt::get(i32, 0));
        Value *ecx =
            cpuidReg(B, leaf1, 2, "morok.antihook.sandbox.cpuid.ecx");
        Value *hypervisor = B.CreateICmpNE(
            B.CreateAnd(ecx, ConstantInt::get(i32, 1u << 31),
                        "morok.antihook.sandbox.cpuid.hypervisor.bit"),
            ConstantInt::get(i32, 0),
            "morok.antihook.sandbox.cpuid.hypervisor");
        incrementDiff(B, score, hypervisor,
                      "morok.antihook.sandbox.cpuid.hypervisor");

        Value *hvLeaf = emitCpuid(B, M, ConstantInt::get(i32, 0x40000000u),
                                  ConstantInt::get(i32, 0));
        Value *hvMax =
            cpuidReg(B, hvLeaf, 0, "morok.antihook.sandbox.cpuid.hv.max");
        Value *hvEbx =
            cpuidReg(B, hvLeaf, 1, "morok.antihook.sandbox.cpuid.hv.ebx");
        Value *hvEcx =
            cpuidReg(B, hvLeaf, 2, "morok.antihook.sandbox.cpuid.hv.ecx");
        Value *hvEdx =
            cpuidReg(B, hvLeaf, 3, "morok.antihook.sandbox.cpuid.hv.edx");
        Value *hvVendor = B.CreateICmpNE(
            hvMax, ConstantInt::get(i32, 0),
            "morok.antihook.sandbox.cpuid.hv.vendor");
        incrementDiff(B, score, B.CreateAnd(hypervisor, hvVendor),
                      "morok.antihook.sandbox.cpuid.vendor");
        Value *vmwareVendor = B.CreateAnd(
            B.CreateAnd(B.CreateICmpEQ(hvEbx, ConstantInt::get(i32, 0x61774D56u)),
                        B.CreateICmpEQ(hvEcx,
                                       ConstantInt::get(i32, 0x4D566572u))),
            B.CreateICmpEQ(hvEdx, ConstantInt::get(i32, 0x65726177u)),
            "morok.antihook.sandbox.vmware.vendor");
        incrementDiff(B, score, vmwareVendor,
                      "morok.antihook.sandbox.vmware.vendor");
        Value *tcgVendor = B.CreateAnd(
            B.CreateAnd(B.CreateICmpEQ(hvEbx, ConstantInt::get(i32, 0x54474354u)),
                        B.CreateICmpEQ(hvEcx,
                                       ConstantInt::get(i32, 0x43544743u))),
            B.CreateICmpEQ(hvEdx, ConstantInt::get(i32, 0x47435447u)),
            "morok.antihook.sandbox.tcg.vendor");
        incrementDiff(B, score, tcgVendor,
                      "morok.antihook.sandbox.tcg.vendor");

        auto *backdoorBB =
            BasicBlock::Create(ctx, "morok.antihook.sandbox.vmware", fn);
        auto *afterBackdoorBB =
            BasicBlock::Create(ctx, "morok.antihook.sandbox.after.vmware", fn);
        B.CreateCondBr(B.CreateAnd(B.CreateAnd(hypervisor, vmwareVendor),
                                   tripwireArmed),
                       backdoorBB, afterBackdoorBB);

        IRBuilder<> VB(backdoorBB);
        Value *reply = emitVmwareBackdoor(VB, M);
        incrementDiff(VB, score,
                      VB.CreateICmpEQ(reply, ConstantInt::get(i32, 0x564D5868u),
                                      "morok.antihook.sandbox.vmware.reply"),
                      "morok.antihook.sandbox.vmware.backdoor");
        VB.CreateBr(afterBackdoorBB);
        B.SetInsertPoint(afterBackdoorBB);

        auto *descriptorBB =
            BasicBlock::Create(ctx, "morok.antihook.sandbox.descriptor", fn);
        auto *afterDescriptorBB = BasicBlock::Create(
            ctx, "morok.antihook.sandbox.after.descriptor", fn);
        B.CreateCondBr(tripwireArmed, descriptorBB, afterDescriptorBB);

        IRBuilder<> DB(descriptorBB);
        auto *descTy = ArrayType::get(i8, 16);
        AllocaInst *idt = DB.CreateAlloca(descTy, nullptr,
                                          "morok.antihook.sandbox.sidt.buf");
        AllocaInst *gdt = DB.CreateAlloca(descTy, nullptr,
                                          "morok.antihook.sandbox.sgdt.buf");
        AllocaInst *ldt = DB.CreateAlloca(descTy, nullptr,
                                          "morok.antihook.sandbox.sldt.buf");
        emitDescriptorStore(DB, idt, "sidt ($0)",
                            "morok.antihook.sandbox.sidt");
        emitDescriptorStore(DB, gdt, "sgdt ($0)",
                            "morok.antihook.sandbox.sgdt");
        emitDescriptorStore(DB, ldt, "sldt ($0)",
                            "morok.antihook.sandbox.sldt");

        Value *idtBase =
            loadAt(DB, M, i64, idt, 2, "morok.antihook.sandbox.sidt.base");
        Value *gdtBase =
            loadAt(DB, M, i64, gdt, 2, "morok.antihook.sandbox.sgdt.base");
        Value *ldtSel =
            loadAt(DB, M, i16, ldt, 0ULL, "morok.antihook.sandbox.sldt.sel");
        Value *lowIdt = DB.CreateICmpULT(
            idtBase, ConstantInt::get(i64, 0x100000000ULL),
            "morok.antihook.sandbox.sidt.low");
        Value *lowGdt = DB.CreateICmpULT(
            gdtBase, ConstantInt::get(i64, 0x100000000ULL),
            "morok.antihook.sandbox.sgdt.low");
        Value *ldtSet = DB.CreateICmpNE(
            ldtSel, ConstantInt::get(i16, 0),
            "morok.antihook.sandbox.sldt.set");
        incrementDiff(DB, score, DB.CreateOr(lowIdt, lowGdt),
                      "morok.antihook.sandbox.redpill");
        incrementDiff(DB, score, ldtSet, "morok.antihook.sandbox.ldt");
        DB.CreateBr(afterDescriptorBB);
        B.SetInsertPoint(afterDescriptorBB);
    }

    if (TT.isOSLinux()) {
        FunctionCallee sysconf = sysconfDecl(M);
        Value *cpus = B.CreateCall(sysconf, {ConstantInt::get(i32, 84)},
                                   "morok.antihook.sandbox.cpu.count");
        Value *pages = B.CreateCall(sysconf, {ConstantInt::get(i32, 85)},
                                    "morok.antihook.sandbox.ram.pages");
        Value *oneCpu = B.CreateICmpSLE(
            cpus, ConstantInt::getSigned(ip, 1),
            "morok.antihook.sandbox.cpu.low");
        Value *lowPages = B.CreateICmpULT(
            B.CreateZExtOrTrunc(pages, i64), ConstantInt::get(i64, 262144),
            "morok.antihook.sandbox.ram.low");
        incrementDiff(B, score, oneCpu, "morok.antihook.sandbox.cpu");
        incrementDiff(B, score, lowPages, "morok.antihook.sandbox.ram");

        // The clock_gettime/nanosleep heuristics below model `struct timespec`
        // as two 64-bit fields and read it back with emitClockGettimeNanos's
        // LP64 layout.  That is only correct where `long` is 64-bit (LP64);
        // on a 32-bit linux-gnu ABI timespec is two 32-bit longs, so nanosleep
        // would read tv_sec/tv_nsec from the wrong offsets and clock_gettime
        // would fold tv_nsec into the seconds load — corrupting the sandbox
        // score (false tamper state or defeated sleep-skip checks).  Skip the
        // timing heuristics there; the sysconf CPU/RAM checks above still run.
        if (TT.isArch64Bit()) {
        Value *boot =
            emitClockGettimeNanos(B, M, 7, "morok.antihook.sandbox.boottime");
        Value *shortUptime = B.CreateAnd(
            B.CreateICmpNE(boot, ConstantInt::get(i64, 0),
                           "morok.antihook.sandbox.uptime.ok"),
            B.CreateICmpULT(boot, ConstantInt::get(i64, 300000000000ULL),
                            "morok.antihook.sandbox.uptime.short"),
            "morok.antihook.sandbox.uptime.flag");
        incrementDiff(B, score, shortUptime, "morok.antihook.sandbox.uptime");

        Value *sleepStart = emitClockGettimeNanos(
            B, M, 1, "morok.antihook.sandbox.sleep.start");
        auto *tsTy = StructType::get(ctx, {i64, i64});
        auto *req = B.CreateAlloca(tsTy, nullptr,
                                   "morok.antihook.sandbox.sleep.req");
        B.CreateStore(ConstantInt::get(i64, 0), B.CreateStructGEP(tsTy, req, 0));
        B.CreateStore(ConstantInt::get(i64, 5000000),
                      B.CreateStructGEP(tsTy, req, 1));
        Value *sleepRc = B.CreateCall(
            nanosleepDecl(M),
            {req, ConstantPointerNull::get(PointerType::getUnqual(ctx))},
            "morok.antihook.sandbox.sleep.rc");
        Value *sleepEnd =
            emitClockGettimeNanos(B, M, 1, "morok.antihook.sandbox.sleep.end");
        Value *sleepDelta = B.CreateSub(
            sleepEnd, sleepStart, "morok.antihook.sandbox.sleep.delta");
        Value *sleepClockOk = B.CreateAnd(
            B.CreateICmpNE(sleepStart, ConstantInt::get(i64, 0)),
            B.CreateICmpUGT(sleepEnd, sleepStart),
            "morok.antihook.sandbox.sleep.clock.ok");
        Value *sleepSkipped = B.CreateAnd(
            B.CreateAnd(sleepClockOk,
                        B.CreateICmpEQ(sleepRc, ConstantInt::get(i32, 0))),
            B.CreateICmpULT(sleepDelta, ConstantInt::get(i64, 1000000)),
            "morok.antihook.sandbox.sleep.skip");
        incrementDiff(B, score, sleepSkipped, "morok.antihook.sandbox.sleep");
        } // TT.isArch64Bit()
    }

    auto *out = B.CreateLoad(i64, score, "morok.antihook.sandbox.score.ret");
    out->setVolatile(true);
    B.CreateRet(out);
    return fn;
}

Function *emulationDivergenceProbe(Module &M, const Triple &TT) {
    if (TT.getArch() != Triple::x86_64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.antihook.emu.x86"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i64 = Type::getInt64Ty(ctx);
    auto *fn = Function::Create(FunctionType::get(i64, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.emu.x86", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    IRBuilder<> B(entry);
    AllocaInst *diff = B.CreateAlloca(i64, nullptr, "morok.antihook.emu.diff");
    B.CreateStore(ConstantInt::get(i64, 0), diff)->setVolatile(true);

    auto *flagsTy = FunctionType::get(i64, false);
    auto *i32 = Type::getInt32Ty(ctx);
    InlineAsm *flagsAsm = InlineAsm::get(
        flagsTy, "xorq %rax, %rax\n\tpushfq\n\tpopq $0",
        "=r,~{rax},~{memory},~{dirflag},~{fpsr},~{flags}",
        /*hasSideEffects=*/true);
    Value *flags =
        B.CreateCall(flagsTy, flagsAsm, {}, "morok.antihook.emu.flags.raw");
    constexpr std::uint64_t kStableXorFlagMask =
        (1ull << 0) | (1ull << 2) | (1ull << 6) | (1ull << 7) | (1ull << 11);
    constexpr std::uint64_t kExpectedXorFlags = (1ull << 2) | (1ull << 6);
    Value *masked = B.CreateAnd(
        flags, ConstantInt::get(i64, kStableXorFlagMask),
        "morok.antihook.emu.flags.masked");
    Value *mismatch =
        B.CreateICmpNE(masked, ConstantInt::get(i64, kExpectedXorFlags),
                       "morok.antihook.emu.flags.mismatch");
    incrementDiff(B, diff, mismatch, "morok.antihook.emu.flags");

    InlineAsm *cmpFlagsAsm = InlineAsm::get(
        flagsTy,
        "xorq %rax, %rax\n\tmovq %rax, %rcx\n\tincq %rcx\n\tcmpq %rcx, "
        "%rax\n\tpushfq\n\tpopq $0",
        "=r,~{rax},~{rcx},~{memory},~{dirflag},~{fpsr},~{flags}",
        /*hasSideEffects=*/true);
    Value *cmpFlags = B.CreateCall(flagsTy, cmpFlagsAsm, {},
                                   "morok.antihook.emu.cmp.flags.raw");
    constexpr std::uint64_t kExpectedCmpFlags =
        (1ull << 0) | (1ull << 2) | (1ull << 7);
    Value *cmpMasked = B.CreateAnd(
        cmpFlags, ConstantInt::get(i64, kStableXorFlagMask),
        "morok.antihook.emu.cmp.flags.masked");
    Value *cmpMismatch =
        B.CreateICmpNE(cmpMasked, ConstantInt::get(i64, kExpectedCmpFlags),
                       "morok.antihook.emu.cmp.flags.mismatch");
    incrementDiff(B, diff, cmpMismatch, "morok.antihook.emu.cmp.flags");

    auto *setccTy = StructType::get(ctx, {i32, i32, i32, i32});
    auto *setccFnTy = FunctionType::get(setccTy, false);
    InlineAsm *setccAsm = InlineAsm::get(
        setccFnTy,
        "xorq %rax, %rax\n\tmovq %rax, %rcx\n\tincq %rcx\n\tcmpq %rcx, "
        "%rax\n\tsetb %al\n\tsetz %cl\n\tsetl %dl\n\tsetg %bl\n\tmovzbl "
        "%al, %eax\n\tmovzbl %cl, %ecx\n\tmovzbl %dl, %edx\n\tmovzbl %bl, "
        "%ebx",
        "={eax},={ecx},={edx},={ebx},~{memory},~{dirflag},~{fpsr},~{flags}",
        /*hasSideEffects=*/true);
    Value *setcc =
        B.CreateCall(setccFnTy, setccAsm, {}, "morok.antihook.emu.setcc.raw");
    Value *setb = B.CreateExtractValue(setcc, {0}, "morok.antihook.emu.setb");
    Value *setz = B.CreateExtractValue(setcc, {1}, "morok.antihook.emu.setz");
    Value *setl = B.CreateExtractValue(setcc, {2}, "morok.antihook.emu.setl");
    Value *setg = B.CreateExtractValue(setcc, {3}, "morok.antihook.emu.setg");
    Value *setccMismatch = B.CreateOr(
        B.CreateOr(B.CreateICmpNE(setb, ConstantInt::get(i32, 1)),
                   B.CreateICmpNE(setz, ConstantInt::get(i32, 0))),
        B.CreateOr(B.CreateICmpNE(setl, ConstantInt::get(i32, 1)),
                   B.CreateICmpNE(setg, ConstantInt::get(i32, 0))),
        "morok.antihook.emu.setcc.mismatch");
    incrementDiff(B, diff, setccMismatch, "morok.antihook.emu.setcc");

    Value *leaf0 = emitCpuid(B, M, ConstantInt::get(i32, 0),
                             ConstantInt::get(i32, 0));
    Value *maxBasic = cpuidReg(B, leaf0, 0, "morok.antihook.emu.cpuid.max");
    Value *vendorBits = B.CreateOr(
        cpuidReg(B, leaf0, 1, "morok.antihook.emu.cpuid.ebx"),
        B.CreateOr(cpuidReg(B, leaf0, 2, "morok.antihook.emu.cpuid.ecx"),
                   cpuidReg(B, leaf0, 3, "morok.antihook.emu.cpuid.edx")),
        "morok.antihook.emu.cpuid.vendor.bits");
    Value *leaf0Bad = B.CreateOr(
        B.CreateICmpEQ(maxBasic, ConstantInt::get(i32, 0)),
        B.CreateICmpEQ(vendorBits, ConstantInt::get(i32, 0)),
        "morok.antihook.emu.cpuid.leaf0.bad");
    Value *leaf1 = emitCpuid(B, M, ConstantInt::get(i32, 1),
                             ConstantInt::get(i32, 0));
    Value *edx = cpuidReg(B, leaf1, 3, "morok.antihook.emu.cpuid.edx1");
    constexpr std::uint32_t kX86_64BaselineFeatures =
        (1u << 0) | (1u << 15) | (1u << 26); // FPU, CMOV, SSE2.
    Value *baseline =
        B.CreateAnd(edx, ConstantInt::get(i32, kX86_64BaselineFeatures),
                    "morok.antihook.emu.cpuid.baseline");
    Value *baselineBad = B.CreateICmpNE(
        baseline, ConstantInt::get(i32, kX86_64BaselineFeatures),
        "morok.antihook.emu.cpuid.baseline.bad");
    Value *cpuidMismatch = B.CreateOr(leaf0Bad, baselineBad,
                                      "morok.antihook.emu.cpuid.mismatch");
    incrementDiff(B, diff, cpuidMismatch, "morok.antihook.emu.cpuid");
    emitRetDiff(B, diff);
    return fn;
}

Value *bufferHasLiteral(IRBuilder<> &B, Module &M, AllocaInst *Buf, Value *N,
                        std::initializer_list<unsigned char> Literal,
                        std::uint64_t MaxBytes, const Twine &Name) {
    LLVMContext &ctx = M.getContext();
    Function *fn = B.GetInsertBlock()->getParent();
    auto *i1 = Type::getInt1Ty(ctx);
    auto *i8 = Type::getInt8Ty(ctx);
    auto *ip = intPtrTy(M);
    if (Literal.size() == 0 || MaxBytes < Literal.size())
        return ConstantInt::getFalse(ctx);

    std::vector<unsigned char> bytes(Literal.begin(), Literal.end());
    auto *foundSlot = B.CreateAlloca(i1, nullptr, Name + ".found");
    auto *idxSlot = B.CreateAlloca(ip, nullptr, Name + ".idx.slot");
    B.CreateStore(ConstantInt::getFalse(ctx), foundSlot)->setVolatile(true);
    B.CreateStore(ConstantInt::get(ip, 0), idxSlot)->setVolatile(true);

    auto *loopBB = BasicBlock::Create(ctx, (Name + ".loop").str(), fn);
    auto *bodyBB = BasicBlock::Create(ctx, (Name + ".body").str(), fn);
    auto *hitBB = BasicBlock::Create(ctx, (Name + ".hit").str(), fn);
    auto *nextBB = BasicBlock::Create(ctx, (Name + ".next").str(), fn);
    auto *doneBB = BasicBlock::Create(ctx, (Name + ".done").str(), fn);
    B.CreateBr(loopBB);

    IRBuilder<> LB(loopBB);
    auto *found = LB.CreateLoad(i1, foundSlot, Name + ".found.v");
    found->setVolatile(true);
    auto *idx = LB.CreateLoad(ip, idxSlot, Name + ".idx");
    idx->setVolatile(true);
    Value *end = LB.CreateAdd(idx, ConstantInt::get(ip, bytes.size()),
                              Name + ".end");
    Value *withinRead = LB.CreateICmpSLE(end, N, Name + ".within.read");
    Value *withinBuf = LB.CreateICmpULE(end, ConstantInt::get(ip, MaxBytes),
                                        Name + ".within.buf");
    LB.CreateCondBr(LB.CreateAnd(LB.CreateAnd(withinRead, withinBuf),
                                 LB.CreateNot(found)),
                    bodyBB, doneBB);

    IRBuilder<> MB(bodyBB);
    Value *match = ConstantInt::getTrue(ctx);
    for (std::uint64_t j = 0; j < bytes.size(); ++j) {
        Value *ch = loadAt(MB, M, i8, Buf,
                           MB.CreateAdd(idx, ConstantInt::get(ip, j)),
                           Name + ".ch");
        match = MB.CreateAnd(
            match, MB.CreateICmpEQ(ch, ConstantInt::get(i8, bytes[j])),
            Name + ".match");
    }
    MB.CreateCondBr(match, hitBB, nextBB);

    IRBuilder<> HB(hitBB);
    HB.CreateStore(ConstantInt::getTrue(ctx), foundSlot)->setVolatile(true);
    HB.CreateBr(doneBB);

    IRBuilder<> NB(nextBB);
    NB.CreateStore(NB.CreateAdd(idx, ConstantInt::get(ip, 1), Name + ".idx.next"),
                   idxSlot)
        ->setVolatile(true);
    NB.CreateBr(loopBB);

    B.SetInsertPoint(doneBB);
    auto *out = B.CreateLoad(i1, foundSlot, Name + ".out");
    out->setVolatile(true);
    return out;
}

GlobalVariable *dbiSmcGate(Module &M) {
    if (auto *existing = M.getGlobalVariable("morok.antihook.dbi.smc.gate",
                                             /*AllowInternal=*/true))
        return existing;
    auto *i8 = Type::getInt8Ty(M.getContext());
    auto *gv = new GlobalVariable(
        M, i8, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(i8, 0), "morok.antihook.dbi.smc.gate");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

Function *dbiSmcTarget(Module &M) {
    if (Function *existing = M.getFunction("morok.antihook.dbi.smc.target"))
        return existing;
    auto *i32 = Type::getInt32Ty(M.getContext());
    auto *fn = Function::Create(FunctionType::get(i32, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.dbi.smc.target", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    auto *entry = BasicBlock::Create(M.getContext(), "entry", fn);
    IRBuilder<> B(entry);
    B.CreateRet(ConstantInt::get(i32, 0x13579BDFu));
    return fn;
}

Function *dbiSmcTripwireProbe(Module &M, const Triple &TT) {
    if (Function *existing = M.getFunction("morok.antihook.dbi.smc"))
        return existing;
    if (intPtrTy(M)->getBitWidth() != 64)
        return nullptr;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    Function *target = dbiSmcTarget(M);

    auto *fn = Function::Create(FunctionType::get(i64, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.dbi.smc", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *hotBB = BasicBlock::Create(ctx, "hot", fn);
    auto *writeBB = BasicBlock::Create(ctx, "write", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    AllocaInst *diff = B.CreateAlloca(i64, nullptr, "morok.antihook.dbi.smc.diff");
    B.CreateStore(ConstantInt::get(i64, 0), diff)->setVolatile(true);
    GlobalVariable *smcGate = dbiSmcGate(M);
    Value *gateSeed =
        B.CreatePtrToInt(target, ip, "morok.antihook.dbi.smc.gate.seed");
    Value *gateArm = B.CreateOr(
        B.CreateTrunc(gateSeed, i8, "morok.antihook.dbi.smc.gate.seed8"),
        ConstantInt::get(i8, 1), "morok.antihook.dbi.smc.gate.arm");
    B.CreateStore(gateArm, smcGate)->setVolatile(true);
    auto *gate = B.CreateLoad(i8, smcGate, "morok.antihook.dbi.smc.load");
    gate->setVolatile(true);
    B.CreateCondBr(B.CreateICmpNE(gate, ConstantInt::get(i8, 0),
                                  "morok.antihook.dbi.smc.armed"),
                   hotBB, retBB);

    IRBuilder<> HB(hotBB);
    Value *targetAddr = HB.CreatePtrToInt(target, ip, "morok.antihook.dbi.smc.addr");
    Value *page = HB.CreateAnd(targetAddr, ConstantInt::get(ip, ~0xfffULL),
                               "morok.antihook.dbi.smc.page");
    Value *codePtr = HB.CreateIntToPtr(targetAddr, ptr, "morok.antihook.dbi.smc.ptr");
    Value *protectOk = ConstantInt::getTrue(ctx);
    if (TT.isOSLinux()) {
        Value *rc = emitLinuxMprotect(HB, M, TT, page, ConstantInt::get(ip, 4096),
                                      ConstantInt::get(i32, 7));
        rc->setName("morok.antihook.dbi.smc.mprotect.rwx");
        protectOk = HB.CreateICmpEQ(rc, ConstantInt::get(i32, 0),
                                    "morok.antihook.dbi.smc.rwx.ok");
    } else if (TT.isOSDarwin()) {
        Value *rc = emitDarwinMprotect(HB, M, TT, page, ConstantInt::get(ip, 4096),
                                       ConstantInt::get(i32, 7));
        rc->setName("morok.antihook.dbi.smc.mprotect.rwx");
        protectOk = HB.CreateICmpEQ(rc, ConstantInt::get(i32, 0),
                                    "morok.antihook.dbi.smc.rwx.ok");
    } else if (TT.isOSWindows()) {
        auto *oldProt = HB.CreateAlloca(i32, nullptr, "morok.antihook.dbi.smc.old");
        FunctionCallee virtualProtect = M.getOrInsertFunction(
            "VirtualProtect", FunctionType::get(i32, {ptr, ip, i32, ptr}, false));
        Value *rc = HB.CreateCall(
            virtualProtect,
            {HB.CreateIntToPtr(page, ptr), ConstantInt::get(ip, 4096),
             ConstantInt::get(i32, 0x40), oldProt},
            "morok.antihook.dbi.smc.virtualprotect.rwx");
        protectOk = HB.CreateICmpNE(rc, ConstantInt::get(i32, 0),
                                    "morok.antihook.dbi.smc.rwx.ok");
    }
    HB.CreateCondBr(protectOk, writeBB, retBB);

    IRBuilder<> WB(writeBB);
    auto *oldByte = WB.CreateLoad(i8, codePtr, "morok.antihook.dbi.smc.byte");
    oldByte->setVolatile(true);
    auto *touch = WB.CreateStore(oldByte, codePtr);
    touch->setVolatile(true);
    if (TT.isOSLinux()) {
        Value *rc = emitLinuxMprotect(WB, M, TT, page, ConstantInt::get(ip, 4096),
                                      ConstantInt::get(i32, 5));
        rc->setName("morok.antihook.dbi.smc.mprotect.rx");
    } else if (TT.isOSDarwin()) {
        Value *rc = emitDarwinMprotect(WB, M, TT, page, ConstantInt::get(ip, 4096),
                                       ConstantInt::get(i32, 5));
        rc->setName("morok.antihook.dbi.smc.mprotect.rx");
    } else if (TT.isOSWindows()) {
        auto *oldProt2 =
            WB.CreateAlloca(i32, nullptr, "morok.antihook.dbi.smc.old2");
        FunctionCallee virtualProtect = M.getOrInsertFunction(
            "VirtualProtect", FunctionType::get(i32, {ptr, ip, i32, ptr}, false));
        WB.CreateCall(virtualProtect,
                      {WB.CreateIntToPtr(page, ptr), ConstantInt::get(ip, 4096),
                       ConstantInt::get(i32, 0x20), oldProt2},
                      "morok.antihook.dbi.smc.virtualprotect.rx");
    }
    Value *result = WB.CreateCall(target, {}, "morok.antihook.dbi.smc.result");
    incrementDiff(WB, diff,
                  WB.CreateICmpNE(result, ConstantInt::get(i32, 0x13579BDFu),
                                  "morok.antihook.dbi.smc.trip"),
                  "morok.antihook.dbi.smc.trip");
    WB.CreateBr(retBB);

    IRBuilder<> RB(retBB);
    emitRetDiff(RB, diff);
    return fn;
}

Function *linuxDbiSignatureProbe(Module &M, ir::IRRandom &rng,
                                 const Triple &TT) {
    if (!TT.isOSLinux() || intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.antihook.dbi.linux"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);

    auto *fn = Function::Create(FunctionType::get(i64, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.dbi.linux", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *afterMapsBB = BasicBlock::Create(ctx, "after.maps", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    AllocaInst *diff = B.CreateAlloca(i64, nullptr, "morok.antihook.dbi.diff");
    B.CreateStore(ConstantInt::get(i64, 0), diff)->setVolatile(true);
    ReadFileIR maps =
        emitReadSmallFile(B, M, fn, "/proc/self/maps", 8192, rng, TT);

    IRBuilder<> MFB(maps.ret0);
    MFB.CreateBr(afterMapsBB);

    IRBuilder<> MB(maps.afterRead);
    Value *mapSig0 = bufferHasLiteral(
        MB, M, maps.buf, maps.n,
        {0x66, 0x72, 0x69, 0x64, 0x61}, 8192,
        "morok.antihook.dbi.maps.sig0");
    Value *mapSig1 = bufferHasLiteral(
        MB, M, maps.buf, maps.n,
        {0x67, 0x61, 0x64, 0x67, 0x65, 0x74}, 8192,
        "morok.antihook.dbi.maps.sig1");
    Value *mapSig2 = bufferHasLiteral(
        MB, M, maps.buf, maps.n,
        {0x72, 0x65, 0x2e, 0x66, 0x72, 0x69, 0x64, 0x61}, 8192,
        "morok.antihook.dbi.maps.sig2");
    Value *mapSig = MB.CreateOr(MB.CreateOr(mapSig0, mapSig1), mapSig2,
                                "morok.antihook.dbi.maps.sig");
    incrementDiff(MB, diff, mapSig, "morok.antihook.dbi.maps");
    MB.CreateBr(afterMapsBB);

    IRBuilder<> TB(afterMapsBB);
    auto *nameTy = ArrayType::get(i8, 16);
    AllocaInst *name =
        TB.CreateAlloca(nameTy, nullptr, "morok.antihook.dbi.thread.name");
    Value *namePtr = TB.CreateInBoundsGEP(
        nameTy, name, {ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)},
        "morok.antihook.dbi.thread.ptr");
    for (unsigned i = 0; i < 16; ++i)
        TB.CreateStore(ConstantInt::get(i8, 0),
                       TB.CreateInBoundsGEP(nameTy, name,
                                            {ConstantInt::get(ip, 0),
                                             ConstantInt::get(ip, i)}));
    std::uint32_t ptraceNr = 0;
    std::uint32_t prctlNr = 0;
    std::uint32_t openatNr = 0;
    std::uint32_t readNr = 0;
    std::uint32_t closeNr = 0;
    if (linuxCoreSyscalls(TT, ptraceNr, prctlNr, openatNr, readNr, closeNr)) {
        emitLinuxSyscall(TB, M, TT, prctlNr,
                         {ConstantInt::get(i32, 16), namePtr,
                          ConstantInt::get(ip, 0), ConstantInt::get(ip, 0),
                          ConstantInt::get(ip, 0)});
    }
    Value *threadSig0 = bufferHasLiteral(
        TB, M, name, ConstantInt::get(ip, 16),
        {0x67, 0x75, 0x6d, 0x2d, 0x6a, 0x73, 0x2d, 0x6c, 0x6f, 0x6f, 0x70},
        16, "morok.antihook.dbi.thread.sig0");
    Value *threadSig1 = bufferHasLiteral(
        TB, M, name, ConstantInt::get(ip, 16),
        {0x67, 0x6d, 0x61, 0x69, 0x6e}, 16,
        "morok.antihook.dbi.thread.sig1");
    Value *threadSig2 = bufferHasLiteral(
        TB, M, name, ConstantInt::get(ip, 16),
        {0x66, 0x72, 0x69, 0x64, 0x61, 0x2d, 0x61, 0x67, 0x65, 0x6e, 0x74},
        16, "morok.antihook.dbi.thread.sig2");
    Value *threadSig =
        TB.CreateOr(TB.CreateOr(threadSig0, threadSig1), threadSig2,
                    "morok.antihook.dbi.thread.sig");
    incrementDiff(TB, diff, threadSig, "morok.antihook.dbi.thread");

    ReadFileIR tcp = emitReadSmallFile(TB, M, fn, "/proc/net/tcp", 4096, rng, TT);

    IRBuilder<> TFB(tcp.ret0);
    TFB.CreateBr(retBB);

    IRBuilder<> PB(tcp.afterRead);
    Value *portSig0 = bufferHasLiteral(
        PB, M, tcp.buf, tcp.n, {0x36, 0x39, 0x41, 0x32}, 4096,
        "morok.antihook.dbi.port.sig0");
    Value *portSig1 = bufferHasLiteral(
        PB, M, tcp.buf, tcp.n, {0x36, 0x39, 0x61, 0x32}, 4096,
        "morok.antihook.dbi.port.sig1");
    incrementDiff(PB, diff, PB.CreateOr(portSig0, portSig1),
                  "morok.antihook.dbi.port");
    PB.CreateBr(retBB);

    IRBuilder<> RB(retBB);
    emitRetDiff(RB, diff);
    return fn;
}

void emitProloguePatternChecks(IRBuilder<> &B, Module &M, const Triple &TT,
                               GlobalVariable *State,
                               const std::vector<Function *> &Targets,
                               ir::IRRandom &rng) {
    if (Targets.empty())
        return;

    const bool x86 =
        TT.getArch() == Triple::x86 || TT.getArch() == Triple::x86_64;
    const bool arm64 =
        TT.getArch() == Triple::aarch64 || TT.getArch() == Triple::aarch64_32;
    if (!x86 && !arm64)
        return;

    std::uint32_t site = 1;
    for (Function *target : Targets) {
        Value *hit = x86 ? emitX86ProloguePattern(B, M, target)
                         : emitArm64ProloguePattern(B, M, target);
        foldEnforcedFlag(
            B, State, hit, rng.next() ^ (0x9E3779B97F4A7C15ULL * site++),
            "morok.antihook.prologue");
    }
}

Function *antiDebugProbe(Module &M, GlobalVariable *State, ir::IRRandom &rng,
                         const Triple &TT) {
    if (Function *existing = M.getFunction("morok.antidbg.probe"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i64 = Type::getInt64Ty(ctx);
    auto *voidTy = Type::getVoidTy(ctx);
    auto *fn = Function::Create(FunctionType::get(voidTy, {i64}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antidbg.probe", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    Argument *tag = fn->getArg(0);
    tag->setName("tag");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    IRBuilder<> B(entry);
    foldState(B, State, tag, 0x9A86B1D32F4C79E5ULL, "morok.antidbg.probe.tag");

    if (TT.isOSLinux()) {
        auto *i32 = Type::getInt32Ty(ctx);
        Function *statusFn = linuxStatusTracerCheck(M, rng, TT);
        Function *statFn = linuxStatField4Check(M, rng, TT);
        Value *status = B.CreateCall(statusFn);
        Value *stat4 = B.CreateCall(statFn);
        foldFlag(B, State, B.CreateICmpNE(status, ConstantInt::get(i32, 0)),
                 0x3FEC9A6245A7DB13ULL, "morok.antidbg.probe.status");
        foldState(B, State, stat4, 0x84379D6FA21708C9ULL,
                  "morok.antidbg.probe.stat4");
    } else if (TT.isOSDarwin()) {
        emitDarwinSysctlCheck(B, M, State, TT);
        emitDarwinCsopsCheck(B, M, State, TT);
    } else if (!TT.isOSWindows()) {
        auto *i32 = Type::getInt32Ty(ctx);
        Value *rc = emitPtrace(B, M, 0);
        foldFlag(B, State, B.CreateICmpSLT(rc, ConstantInt::getSigned(i32, 0)),
                 0xA082B7C1D94E530FULL, "morok.antidbg.probe.ptrace");
    }

    B.CreateRetVoid();
    return fn;
}

bool isProbeInsertionPoint(Instruction &I) {
    if (isa<PHINode>(I) || isa<AllocaInst>(I) || I.isTerminator() ||
        I.isEHPad())
        return false;
    return true;
}

void insertGuardedProbeCall(Module &M, Instruction &I, Function *Probe,
                            std::uint64_t Tag, std::uint8_t ArmedByte,
                            std::uint32_t SiteId) {
    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);

    auto *gate = new GlobalVariable(
        M, i8, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(i8, 0), "morok.antidbg.site");
    gate->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

    Function *parent = I.getFunction();
    BasicBlock *headBB = I.getParent();
    BasicBlock *contBB =
        headBB->splitBasicBlock(I.getIterator(), "morok.antidbg.site.cont");
    headBB->getTerminator()->eraseFromParent();
    auto *callBB =
        BasicBlock::Create(ctx, "morok.antidbg.site.call", parent, contBB);

    IRBuilder<> HB(headBB);
    auto *seen = HB.CreateLoad(i8, gate, "morok.antidbg.site.seen");
    seen->setVolatile(true);
    Value *shouldRun = HB.CreateICmpEQ(seen, ConstantInt::get(i8, 0));
    HB.CreateCondBr(shouldRun, callBB, contBB);

    IRBuilder<> CB(callBB);
    auto *armed = CB.CreateStore(ConstantInt::get(i8, ArmedByte), gate);
    armed->setVolatile(true);
    CB.CreateCall(Probe->getFunctionType(), Probe,
                  {ConstantInt::get(CB.getInt64Ty(),
                                    Tag ^ (0x9E3779B97F4A7C15ULL * SiteId))});
    CB.CreateBr(contBB);
}

bool insertAntiDebugCallsiteProbes(Module &M, Function *Probe,
                                   ir::IRRandom &rng) {
    constexpr std::uint32_t kMaxProbeSites = 32;
    constexpr std::uint32_t kFunctionChance = 100;

    std::vector<Instruction *> sites;
    sites.reserve(kMaxProbeSites);
    for (Function &F : M) {
        if (sites.size() >= kMaxProbeSites)
            break;
        if (F.isDeclaration() || F.hasAvailableExternallyLinkage() ||
            F.getName().starts_with("morok."))
            continue;
        if (directlyRecursive(F))
            continue;
        if (!rng.chance(kFunctionChance))
            continue;

        SmallPtrSet<BasicBlock *, 32> LoopBlocks = naturalLoopBlocks(F);
        std::vector<Instruction *> candidates;
        candidates.reserve(8);
        for (BasicBlock &BB : F) {
            if (BB.isEHPad() || BB.isLandingPad())
                continue;
            if (LoopBlocks.contains(&BB))
                continue;
            for (Instruction &I : BB)
                if (isProbeInsertionPoint(I))
                    candidates.push_back(&I);
        }
        if (candidates.empty())
            continue;
        sites.push_back(candidates[rng.range(
            static_cast<std::uint32_t>(candidates.size()))]);
    }

    std::uint32_t siteId = 1;
    for (Instruction *I : sites)
        insertGuardedProbeCall(
            M, *I, Probe, rng.next(),
            static_cast<std::uint8_t>((rng.next() | 1) & 0xffu), siteId++);
    return !sites.empty();
}

GlobalVariable *timingOracleState(Module &M, ir::IRRandom &rng) {
    if (auto *existing =
            M.getGlobalVariable("morok.timing.state", /*AllowInternal=*/true))
        return existing;
    auto *i64 = Type::getInt64Ty(M.getContext());
    auto *gv = new GlobalVariable(
        M, i64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(i64, rng.next()), "morok.timing.state");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

GlobalVariable *schedulerStepOracleState(Module &M, ir::IRRandom &rng) {
    if (auto *existing =
            M.getGlobalVariable("morok.step.state", /*AllowInternal=*/true))
        return existing;
    auto *i64 = Type::getInt64Ty(M.getContext());
    auto *gv = new GlobalVariable(
        M, i64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(i64, rng.next()), "morok.step.state");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

bool isX86Target(const Triple &TT) {
    return TT.getArch() == Triple::x86 || TT.getArch() == Triple::x86_64;
}

// Combine the EDX:EAX timestamp pair returned by an rdtsc/rdtscp asm into i64.
Value *combineTscPair(IRBuilder<> &B, Value *pair) {
    auto *i64 = Type::getInt64Ty(B.getContext());
    Value *lo = B.CreateExtractValue(pair, {0}, "morok.timing.tsc.lo");
    Value *hi = B.CreateExtractValue(pair, {1}, "morok.timing.tsc.hi");
    return B.CreateOr(
        B.CreateZExt(lo, i64),
        B.CreateShl(B.CreateZExt(hi, i64), ConstantInt::get(i64, 32)),
        "morok.timing.tsc");
}

// A noinline helper that reads the timestamp counter, gating RDTSCP behind a
// CPUID(0x80000001).EDX[27] feature test.  RDTSCP raises #UD on x86 CPUs (old
// or deliberately masked virtual machines) that lack it, which would crash the
// protected binary on the first timing probe; when the feature bit is clear we
// fall back to plain RDTSC (baseline since the original Pentium, never #UD).
// Both paths bracket the read with lfence for serialization and consume only
// the EDX:EAX timestamp.  The branch caches nothing per call, but the CPUID
// cost is constant across the paired start/end reads so it cancels in the delta.
Function *getOrCreateTscHelper(Module &M) {
    if (Function *Existing = M.getFunction("morok.timing.tsc.read"))
        return Existing;
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *pairTy = StructType::get(ctx, {i32, i32});
    auto *asmTy = FunctionType::get(pairTy, false);

    auto *Fn = Function::Create(FunctionType::get(i64, false),
                                GlobalValue::InternalLinkage,
                                "morok.timing.tsc.read", &M);
    Fn->addFnAttr(Attribute::NoInline);
    Fn->setDSOLocal(true);

    BasicBlock *Entry = BasicBlock::Create(ctx, "entry", Fn);
    BasicBlock *PBB = BasicBlock::Create(ctx, "rdtscp", Fn);
    BasicBlock *RBB = BasicBlock::Create(ctx, "rdtsc", Fn);
    BasicBlock *Merge = BasicBlock::Create(ctx, "merge", Fn);

    IRBuilder<> EB(Entry);
    Value *cpuid = emitCpuid(EB, M, ConstantInt::get(i32, 0x80000001u),
                             ConstantInt::get(i32, 0));
    Value *edx = cpuidReg(EB, cpuid, 3, "morok.timing.feat.edx");
    Value *bit = EB.CreateAnd(EB.CreateLShr(edx, ConstantInt::get(i32, 27)),
                              ConstantInt::get(i32, 1), "morok.timing.feat.rdtscp");
    EB.CreateCondBr(EB.CreateICmpNE(bit, ConstantInt::get(i32, 0)), PBB, RBB);

    IRBuilder<> PB(PBB);
    InlineAsm *rdtscp =
        InlineAsm::get(asmTy, "lfence\nrdtscp\nlfence",
                       "={eax},={edx},~{ecx},~{dirflag},~{fpsr},~{flags}",
                       /*hasSideEffects=*/true);
    Value *tscP =
        combineTscPair(PB, PB.CreateCall(asmTy, rdtscp, {}, "morok.timing.rdtscp"));
    PB.CreateBr(Merge);

    IRBuilder<> RB(RBB);
    InlineAsm *rdtsc =
        InlineAsm::get(asmTy, "lfence\nrdtsc\nlfence",
                       "={eax},={edx},~{dirflag},~{fpsr},~{flags}",
                       /*hasSideEffects=*/true);
    Value *tscR =
        combineTscPair(RB, RB.CreateCall(asmTy, rdtsc, {}, "morok.timing.rdtsc"));
    RB.CreateBr(Merge);

    IRBuilder<> MB(Merge);
    PHINode *Phi = MB.CreatePHI(i64, 2, "morok.timing.tsc.val");
    Phi->addIncoming(tscP, PBB);
    Phi->addIncoming(tscR, RBB);
    MB.CreateRet(Phi);
    return Fn;
}

Value *emitRdtscp(IRBuilder<> &B, Module &M) {
    Function *H = getOrCreateTscHelper(M);
    return B.CreateCall(H->getFunctionType(), H, {}, "morok.timing.tsc");
}

Value *emitClockGettimeNanos(IRBuilder<> &B, Module &M, std::int32_t ClockId,
                             const Twine &Name) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *tsTy = StructType::get(ctx, {i64, i64});
    auto *ts = B.CreateAlloca(tsTy, nullptr, Name + ".ts");

    Value *secPtr = B.CreateStructGEP(tsTy, ts, 0, Name + ".sec.ptr");
    Value *nsecPtr = B.CreateStructGEP(tsTy, ts, 1, Name + ".nsec.ptr");
    B.CreateStore(ConstantInt::get(i64, 0), secPtr);
    B.CreateStore(ConstantInt::get(i64, 0), nsecPtr);

    FunctionCallee clockGettime = M.getOrInsertFunction(
        "clock_gettime",
        FunctionType::get(i32, {i32, PointerType::getUnqual(ctx)}, false));
    Value *rc = B.CreateCall(
        clockGettime, {ConstantInt::getSigned(i32, ClockId), ts}, Name + ".rc");
    Value *sec = B.CreateLoad(i64, secPtr, Name + ".sec");
    Value *nsec = B.CreateLoad(i64, nsecPtr, Name + ".nsec");
    Value *nanos =
        B.CreateAdd(B.CreateMul(sec, ConstantInt::get(i64, 1000000000ULL)),
                    nsec, Name + ".nanos");
    return B.CreateSelect(B.CreateICmpEQ(rc, ConstantInt::get(i32, 0)), nanos,
                          ConstantInt::get(i64, 0), Name + ".ok");
}

Value *emitMachAbsoluteTime(IRBuilder<> &B, Module &M, const Twine &Name) {
    FunctionCallee mach = M.getOrInsertFunction(
        "mach_absolute_time", FunctionType::get(B.getInt64Ty(), false));
    return B.CreateCall(mach, {}, Name);
}

Value *emitWindowsQpc(IRBuilder<> &B, Module &M, const Twine &Name) {
    auto *i32 = Type::getInt32Ty(M.getContext());
    auto *i64 = Type::getInt64Ty(M.getContext());
    auto *slot = B.CreateAlloca(i64, nullptr, Name + ".slot");
    B.CreateStore(ConstantInt::get(i64, 0), slot);
    FunctionCallee qpc = M.getOrInsertFunction(
        "QueryPerformanceCounter",
        FunctionType::get(i32, {PointerType::getUnqual(M.getContext())},
                          false));
    Value *rc = B.CreateCall(qpc, {slot}, Name + ".rc");
    Value *ticks = B.CreateLoad(i64, slot, Name + ".ticks");
    return B.CreateSelect(B.CreateICmpNE(rc, ConstantInt::get(i32, 0)), ticks,
                          ConstantInt::get(i64, 0), Name + ".ok");
}

Value *emitTimingPrimaryClock(IRBuilder<> &B, Module &M, const Triple &TT,
                              const Twine &Name) {
    if (isX86Target(TT))
        return emitRdtscp(B, M);
    if (TT.isOSDarwin())
        return emitMachAbsoluteTime(B, M, Name + ".mach");
    if (TT.isOSWindows())
        return emitWindowsQpc(B, M, Name + ".qpc");
    return emitClockGettimeNanos(B, M, 1, Name + ".mono");
}

Value *emitTimingSecondaryClock(IRBuilder<> &B, Module &M, const Triple &TT,
                                const Twine &Name) {
    if (TT.isOSDarwin() && isX86Target(TT))
        return emitMachAbsoluteTime(B, M, Name + ".mach");
    if (TT.isOSWindows())
        return emitWindowsQpc(B, M, Name + ".qpc");
    return emitClockGettimeNanos(B, M, 4, Name + ".raw");
}

void emitShortTimingSpan(IRBuilder<> &B, AllocaInst *Acc, std::uint64_t Salt) {
    auto *i64 = B.getInt64Ty();
    for (unsigned i = 0; i < 16; ++i) {
        auto *load = B.CreateLoad(i64, Acc, "morok.timing.span.load");
        load->setVolatile(true);
        Value *mixed = B.CreateXor(
            B.CreateAdd(load, ConstantInt::get(
                                  i64, Salt + 0xD6E8FEB86659FD93ULL * (i + 1))),
            B.CreateLShr(load, ConstantInt::get(i64, (i % 17) + 1)));
        mixed = B.CreateMul(
            mixed,
            ConstantInt::get(i64, (Salt | 1ULL) ^ (0x9E3779B97F4A7C15ULL * i)));
        auto *store = B.CreateStore(mixed, Acc);
        store->setVolatile(true);
    }
}

Function *timingOracleProbe(Module &M, GlobalVariable *State, ir::IRRandom &rng,
                            const Triple &TT) {
    if (Function *existing = M.getFunction("morok.timing.oracle"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *fn = Function::Create(FunctionType::get(Type::getVoidTy(ctx), false),
                                GlobalValue::PrivateLinkage,
                                "morok.timing.oracle", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    IRBuilder<> B(entry);
    auto *acc = B.CreateAlloca(i64, nullptr, "morok.timing.span.acc");
    B.CreateStore(ConstantInt::get(i64, rng.next()), acc)->setVolatile(true);

    Value *badSamples = ConstantInt::get(i32, 0);
    Value *divergentSamples = ConstantInt::get(i32, 0);
    Value *mix = ConstantInt::get(i64, rng.next());
    const bool hasCycleClock = isX86Target(TT);
    const std::uint64_t primaryThreshold =
        hasCycleClock ? 20000000ULL : 10000000ULL;
    constexpr std::uint64_t secondaryThreshold = 10000000ULL;

    for (unsigned sample = 0; sample < 5; ++sample) {
        Value *primaryStart =
            emitTimingPrimaryClock(B, M, TT, "morok.timing.primary.start");
        Value *secondaryStart =
            emitTimingSecondaryClock(B, M, TT, "morok.timing.secondary.start");
        emitShortTimingSpan(B, acc, rng.next());
        Value *primaryEnd =
            emitTimingPrimaryClock(B, M, TT, "morok.timing.primary.end");
        Value *secondaryEnd =
            emitTimingSecondaryClock(B, M, TT, "morok.timing.secondary.end");

        Value *primaryDelta =
            B.CreateSub(primaryEnd, primaryStart, "morok.timing.primary.delta");
        Value *secondaryDelta = B.CreateSub(secondaryEnd, secondaryStart,
                                            "morok.timing.secondary.delta");
        Value *primarySlow = B.CreateICmpUGT(
            primaryDelta, ConstantInt::get(i64, primaryThreshold),
            "morok.timing.primary.slow");
        Value *secondarySlow = B.CreateICmpUGT(
            secondaryDelta, ConstantInt::get(i64, secondaryThreshold),
            "morok.timing.secondary.slow");
        Value *sampleSlow =
            B.CreateOr(primarySlow, secondarySlow, "morok.timing.sample.slow");
        Value *sampleDiverged = B.CreateXor(primarySlow, secondarySlow,
                                            "morok.timing.sample.diverged");
        badSamples = B.CreateAdd(badSamples, B.CreateZExt(sampleSlow, i32),
                                 "morok.timing.bad.n");
        divergentSamples =
            B.CreateAdd(divergentSamples, B.CreateZExt(sampleDiverged, i32),
                        "morok.timing.divergent.n");
        mix = B.CreateXor(
            B.CreateAdd(mix,
                        B.CreateMul(primaryDelta,
                                    ConstantInt::get(i64, rng.next() | 1ULL))),
            B.CreateMul(secondaryDelta,
                        ConstantInt::get(i64, rng.next() | 1ULL)),
            "morok.timing.mix");
    }

    foldState(B, State, mix, 0x275C92B4EF31D68BULL, "morok.timing.mix");
    foldState(B, State, badSamples, 0x7A6D2E10B94F35C1ULL,
              "morok.timing.bad.samples");
    foldState(B, State, divergentSamples, 0xC541A9E72318BE6FULL,
              "morok.timing.divergent.samples");
    Value *badDistribution = B.CreateICmpUGE(
        badSamples, ConstantInt::get(i32, 3),
        "morok.timing.bad.distribution");
    Value *divergentDistribution = B.CreateICmpUGE(
        divergentSamples, ConstantInt::get(i32, 2),
        "morok.timing.divergent.distribution");
    // Wall-clock spans are scheduler-sensitive; keep these verdicts telemetry.
    foldFlag(B, State, badDistribution, 0xA331D8B47E1C5905ULL,
             "morok.timing.bad.distribution");
    foldFlag(B, State, divergentDistribution, 0x5E74B29D13C8A60BULL,
             "morok.timing.divergent.distribution");
    B.CreateRetVoid();
    return fn;
}

struct SchedulerCounterSample {
    Value *value;
    Value *ready;
};

bool linuxSchedulerStepSyscalls(const Triple &TT, std::uint32_t &PerfOpen,
                                std::uint32_t &Read, std::uint32_t &Close) {
    switch (TT.getArch()) {
    case Triple::x86_64:
        PerfOpen = 298;
        Read = 0;
        Close = 3;
        return true;
    case Triple::aarch64:
        PerfOpen = 241;
        Read = 63;
        Close = 57;
        return true;
    default:
        return false;
    }
}

Value *gepI8Offset(IRBuilder<> &B, Module &M, Value *Base,
                   std::uint64_t Offset, const Twine &Name) {
    return B.CreateGEP(Type::getInt8Ty(M.getContext()), Base,
                       ConstantInt::get(intPtrTy(M), Offset), Name);
}

StoreInst *storeI32AtOffset(IRBuilder<> &B, Module &M, Value *Base,
                            std::uint64_t Offset, std::uint32_t V,
                            const Twine &Name) {
    auto *st = B.CreateStore(
        ConstantInt::get(Type::getInt32Ty(M.getContext()), V),
        gepI8Offset(B, M, Base, Offset, Name + ".ptr"));
    st->setAlignment(Align(4));
    return st;
}

StoreInst *storeI64AtOffset(IRBuilder<> &B, Module &M, Value *Base,
                            std::uint64_t Offset, std::uint64_t V,
                            const Twine &Name) {
    auto *st = B.CreateStore(
        ConstantInt::get(Type::getInt64Ty(M.getContext()), V),
        gepI8Offset(B, M, Base, Offset, Name + ".ptr"));
    st->setAlignment(Align(8));
    return st;
}

LoadInst *loadI64AtOffset(IRBuilder<> &B, Module &M, Value *Base,
                          std::uint64_t Offset, const Twine &Name) {
    auto *li = B.CreateLoad(Type::getInt64Ty(M.getContext()),
                            gepI8Offset(B, M, Base, Offset, Name + ".ptr"),
                            Name);
    li->setVolatile(true);
    li->setAlignment(Align(8));
    return li;
}

Value *emitLinuxPerfContextSwitchOpen(IRBuilder<> &B, Module &M,
                                      const Triple &TT, Value *&Ready) {
    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *attrTy = ArrayType::get(i8, 128);
    auto *attr = B.CreateAlloca(attrTy, nullptr, "morok.step.perf.attr");
    B.CreateMemSet(attr, ConstantInt::get(i8, 0), ConstantInt::get(ip, 128),
                   MaybeAlign(1));
    // struct perf_event_attr: type, size, config.
    storeI32AtOffset(B, M, attr, 0, 1, "morok.step.perf.type");
    storeI32AtOffset(B, M, attr, 4, 128, "morok.step.perf.size");
    storeI64AtOffset(B, M, attr, 8, 3, "morok.step.perf.config.ctxsw");

    std::uint32_t perfNr = 0;
    std::uint32_t readNr = 0;
    std::uint32_t closeNr = 0;
    if (!linuxSchedulerStepSyscalls(TT, perfNr, readNr, closeNr)) {
        Ready = ConstantInt::getFalse(ctx);
        return ConstantInt::getSigned(ip, -1);
    }

    // pid=0,cpu=-1 scopes the software event to the current thread on any CPU.
    Value *fd = emitLinuxSyscall(
        B, M, TT, perfNr,
        {attr, ConstantInt::getSigned(ip, 0), ConstantInt::getSigned(ip, -1),
         ConstantInt::getSigned(ip, -1), ConstantInt::get(ip, 0)});
    Ready = B.CreateICmpSGE(fd, ConstantInt::getSigned(ip, 0),
                            "morok.step.perf.open.ready");
    return fd;
}

SchedulerCounterSample emitLinuxPerfRead(IRBuilder<> &B, Module &M,
                                         const Triple &TT, Value *Fd,
                                         const Twine &Name) {
    LLVMContext &ctx = M.getContext();
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    std::uint32_t perfNr = 0;
    std::uint32_t readNr = 0;
    std::uint32_t closeNr = 0;
    if (!linuxSchedulerStepSyscalls(TT, perfNr, readNr, closeNr))
        return {ConstantInt::get(i64, 0), ConstantInt::getFalse(ctx)};

    auto *slot = B.CreateAlloca(i64, nullptr, Name + ".slot");
    B.CreateStore(ConstantInt::get(i64, 0), slot)->setVolatile(true);
    Value *rc = emitLinuxSyscall(B, M, TT, readNr,
                                 {Fd, slot, ConstantInt::get(ip, 8)});
    auto *value = B.CreateLoad(i64, slot, Name + ".value");
    value->setVolatile(true);
    value->setAlignment(Align(8));
    Value *ready =
        B.CreateICmpEQ(rc, ConstantInt::get(ip, 8), Name + ".ready");
    return {value, ready};
}

void emitLinuxPerfClose(IRBuilder<> &B, Module &M, const Triple &TT,
                        Value *Fd) {
    std::uint32_t perfNr = 0;
    std::uint32_t readNr = 0;
    std::uint32_t closeNr = 0;
    if (!linuxSchedulerStepSyscalls(TT, perfNr, readNr, closeNr))
        return;
    emitLinuxSyscall(B, M, TT, closeNr, {Fd});
}

SchedulerCounterSample emitLinuxRusageSwitches(IRBuilder<> &B, Module &M,
                                               const Twine &Name) {
    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *bufTy = ArrayType::get(i8, 144);
    auto *buf = B.CreateAlloca(bufTy, nullptr, Name + ".rusage");
    B.CreateMemSet(buf, ConstantInt::get(i8, 0), ConstantInt::get(ip, 144),
                   MaybeAlign(1));
    FunctionCallee getrusage = M.getOrInsertFunction(
        "getrusage", FunctionType::get(i32, {i32, PointerType::getUnqual(ctx)},
                                        false));
    Value *rc = B.CreateCall(getrusage, {ConstantInt::get(i32, 1), buf},
                             Name + ".rc");
    Value *nv = loadI64AtOffset(B, M, buf, 128, Name + ".nvcsw");
    Value *ni = loadI64AtOffset(B, M, buf, 136, Name + ".nivcsw");
    Value *total = B.CreateAdd(nv, ni, Name + ".total.raw");
    Value *ready =
        B.CreateICmpEQ(rc, ConstantInt::get(i32, 0), Name + ".ready");
    return {B.CreateSelect(ready, total, ConstantInt::get(i64, 0),
                           Name + ".total"),
            ready};
}

SchedulerCounterSample emitDarwinThreadCpuNanos(IRBuilder<> &B, Module &M,
                                                const Twine &Name) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *infoTy = ArrayType::get(i32, 10);
    auto *info = B.CreateAlloca(infoTy, nullptr, Name + ".basic");
    auto *count = B.CreateAlloca(i32, nullptr, Name + ".count");
    B.CreateMemSet(info, ConstantInt::get(Type::getInt8Ty(ctx), 0),
                   ConstantInt::get(ip, 40), MaybeAlign(4));
    B.CreateStore(ConstantInt::get(i32, 10), count);
    FunctionCallee self = M.getOrInsertFunction(
        "mach_thread_self", FunctionType::get(i32, false));
    FunctionCallee threadInfo = M.getOrInsertFunction(
        "thread_info",
        FunctionType::get(i32, {i32, i32, PointerType::getUnqual(ctx),
                                PointerType::getUnqual(ctx)},
                          false));
    Value *thread = B.CreateCall(self, {}, Name + ".thread");
    Value *rc = B.CreateCall(threadInfo,
                             {thread, ConstantInt::get(i32, 3), info, count},
                             Name + ".rc");
    auto loadWord = [&](unsigned idx, const Twine &WordName) -> Value * {
        auto *ptr = B.CreateGEP(i32, info, ConstantInt::get(ip, idx),
                                WordName + ".ptr");
        auto *li = B.CreateLoad(i32, ptr, WordName);
        li->setVolatile(true);
        li->setAlignment(Align(4));
        return B.CreateSExt(li, i64, WordName + ".i64");
    };
    Value *userSec = loadWord(0, Name + ".user.sec");
    Value *userUsec = loadWord(1, Name + ".user.usec");
    Value *sysSec = loadWord(2, Name + ".sys.sec");
    Value *sysUsec = loadWord(3, Name + ".sys.usec");
    Value *secs = B.CreateAdd(userSec, sysSec, Name + ".secs");
    Value *usecs = B.CreateAdd(userUsec, sysUsec, Name + ".usecs");
    Value *nanos = B.CreateAdd(
        B.CreateMul(secs, ConstantInt::get(i64, 1000000000ULL)),
        B.CreateMul(usecs, ConstantInt::get(i64, 1000ULL)), Name + ".nanos");
    Value *ready =
        B.CreateICmpEQ(rc, ConstantInt::get(i32, 0), Name + ".ready");
    return {B.CreateSelect(ready, nanos, ConstantInt::get(i64, 0),
                           Name + ".nanos.safe"),
            ready};
}

SchedulerCounterSample emitWindowsThreadTime100ns(IRBuilder<> &B, Module &M,
                                                  const Twine &Name) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);
    FunctionCallee getCurrentThread =
        M.getOrInsertFunction("GetCurrentThread", FunctionType::get(ptr, false));
    FunctionCallee getThreadTimes = M.getOrInsertFunction(
        "GetThreadTimes", FunctionType::get(i32, {ptr, ptr, ptr, ptr, ptr},
                                             false));
    Value *thread = B.CreateCall(getCurrentThread, {}, Name + ".thread");
    auto *creation = B.CreateAlloca(i64, nullptr, Name + ".creation");
    auto *exit = B.CreateAlloca(i64, nullptr, Name + ".exit");
    auto *kernel = B.CreateAlloca(i64, nullptr, Name + ".kernel");
    auto *user = B.CreateAlloca(i64, nullptr, Name + ".user");
    B.CreateStore(ConstantInt::get(i64, 0), creation)->setVolatile(true);
    B.CreateStore(ConstantInt::get(i64, 0), exit)->setVolatile(true);
    B.CreateStore(ConstantInt::get(i64, 0), kernel)->setVolatile(true);
    B.CreateStore(ConstantInt::get(i64, 0), user)->setVolatile(true);
    Value *rc = B.CreateCall(getThreadTimes,
                             {thread, creation, exit, kernel, user},
                             Name + ".rc");
    auto *k = B.CreateLoad(i64, kernel, Name + ".kernel.100ns");
    auto *u = B.CreateLoad(i64, user, Name + ".user.100ns");
    k->setVolatile(true);
    u->setVolatile(true);
    k->setAlignment(Align(4));
    u->setAlignment(Align(4));
    Value *total = B.CreateAdd(k, u, Name + ".total.100ns");
    Value *ready =
        B.CreateICmpNE(rc, ConstantInt::get(i32, 0), Name + ".ready");
    return {B.CreateSelect(ready, total, ConstantInt::get(i64, 0),
                           Name + ".total.safe"),
            ready};
}

SchedulerCounterSample emitWindowsThreadCycles(IRBuilder<> &B, Module &M,
                                               const Twine &Name) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);
    FunctionCallee getCurrentThread =
        M.getOrInsertFunction("GetCurrentThread", FunctionType::get(ptr, false));
    FunctionCallee queryCycles = M.getOrInsertFunction(
        "QueryThreadCycleTime", FunctionType::get(i32, {ptr, ptr}, false));
    auto *slot = B.CreateAlloca(i64, nullptr, Name + ".slot");
    B.CreateStore(ConstantInt::get(i64, 0), slot)->setVolatile(true);
    Value *thread = B.CreateCall(getCurrentThread, {}, Name + ".thread");
    Value *rc = B.CreateCall(queryCycles, {thread, slot}, Name + ".rc");
    auto *cycles = B.CreateLoad(i64, slot, Name + ".cycles");
    cycles->setVolatile(true);
    cycles->setAlignment(Align(8));
    Value *ready =
        B.CreateICmpNE(rc, ConstantInt::get(i32, 0), Name + ".ready");
    return {B.CreateSelect(ready, cycles, ConstantInt::get(i64, 0),
                           Name + ".cycles.safe"),
            ready};
}

Value *emitWindowsQpcFrequency(IRBuilder<> &B, Module &M, const Twine &Name) {
    auto *i32 = Type::getInt32Ty(M.getContext());
    auto *i64 = Type::getInt64Ty(M.getContext());
    auto *slot = B.CreateAlloca(i64, nullptr, Name + ".slot");
    B.CreateStore(ConstantInt::get(i64, 0), slot);
    FunctionCallee qpf = M.getOrInsertFunction(
        "QueryPerformanceFrequency",
        FunctionType::get(i32, {PointerType::getUnqual(M.getContext())},
                          false));
    Value *rc = B.CreateCall(qpf, {slot}, Name + ".rc");
    Value *freq = B.CreateLoad(i64, slot, Name + ".freq");
    return B.CreateSelect(B.CreateICmpNE(rc, ConstantInt::get(i32, 0)), freq,
                          ConstantInt::get(i64, 0), Name + ".ok");
}

void emitSchedulerStepSpan(IRBuilder<> &B, AllocaInst *Acc,
                           ir::IRRandom &rng) {
    for (unsigned part = 0; part < 8; ++part)
        emitShortTimingSpan(B, Acc,
                            rng.next() ^ (0xD1B54A32D192ED03ULL * (part + 1)));
}

Function *schedulerStepOracleProbe(Module &M, GlobalVariable *State,
                                   ir::IRRandom &rng, const Triple &TT) {
    if (intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (!TT.isOSLinux() && !TT.isOSDarwin() && !TT.isOSWindows())
        return nullptr;
    if (Function *existing = M.getFunction("morok.step.oracle"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *fn = Function::Create(FunctionType::get(Type::getVoidTy(ctx), false),
                                GlobalValue::PrivateLinkage,
                                "morok.step.oracle", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    IRBuilder<> B(entry);
    auto *acc = B.CreateAlloca(i64, nullptr, "morok.step.span.acc");
    B.CreateStore(ConstantInt::get(i64, rng.next()), acc)->setVolatile(true);

    Value *anomalousSamples = ConstantInt::get(i32, 0);
    Value *availableSamples = ConstantInt::get(i32, 0);
    Value *mix = ConstantInt::get(i64, rng.next());

    if (TT.isOSLinux()) {
        Value *perfReady = nullptr;
        Value *perfFd = emitLinuxPerfContextSwitchOpen(B, M, TT, perfReady);
        for (unsigned sample = 0; sample < 3; ++sample) {
            SchedulerCounterSample perfBefore =
                emitLinuxPerfRead(B, M, TT, perfFd,
                                  "morok.step.perf.before");
            SchedulerCounterSample usageBefore =
                emitLinuxRusageSwitches(B, M, "morok.step.getrusage.before");
            emitSchedulerStepSpan(B, acc, rng);
            SchedulerCounterSample perfAfter =
                emitLinuxPerfRead(B, M, TT, perfFd, "morok.step.perf.after");
            SchedulerCounterSample usageAfter =
                emitLinuxRusageSwitches(B, M, "morok.step.getrusage.after");

            Value *perfSampleReady = B.CreateAnd(
                perfReady, B.CreateAnd(perfBefore.ready, perfAfter.ready),
                "morok.step.perf.sample.ready");
            Value *usageSampleReady =
                B.CreateAnd(usageBefore.ready, usageAfter.ready,
                            "morok.step.getrusage.sample.ready");
            Value *perfDelta = B.CreateSub(perfAfter.value, perfBefore.value,
                                           "morok.step.perf.delta");
            Value *usageDelta =
                B.CreateSub(usageAfter.value, usageBefore.value,
                            "morok.step.getrusage.delta");
            Value *counterReady =
                B.CreateOr(perfSampleReady, usageSampleReady,
                           "morok.step.counter.ready");
            Value *counterDelta =
                B.CreateSelect(perfSampleReady, perfDelta, usageDelta,
                               "morok.step.counter.delta.raw");
            counterDelta = B.CreateSelect(counterReady, counterDelta,
                                          ConstantInt::get(i64, 0),
                                          "morok.step.counter.delta");
            Value *sampleBad = B.CreateAnd(
                counterReady,
                B.CreateICmpUGE(counterDelta, ConstantInt::get(i64, 16),
                                "morok.step.switch.anomaly"),
                "morok.step.switch.anomaly.ready");
            anomalousSamples =
                B.CreateAdd(anomalousSamples, B.CreateZExt(sampleBad, i32),
                            "morok.step.anomalous.n");
            availableSamples =
                B.CreateAdd(availableSamples, B.CreateZExt(counterReady, i32),
                            "morok.step.available.n");
            mix = B.CreateXor(
                B.CreateAdd(mix,
                            B.CreateMul(counterDelta,
                                        ConstantInt::get(i64, rng.next() | 1ULL))),
                B.CreateZExt(counterReady, i64), "morok.step.counter.mix");
        }
        emitLinuxPerfClose(B, M, TT, perfFd);
    } else if (TT.isOSDarwin()) {
        for (unsigned sample = 0; sample < 3; ++sample) {
            SchedulerCounterSample cpuBefore =
                emitDarwinThreadCpuNanos(B, M, "morok.step.thread.before");
            Value *wallBefore =
                emitClockGettimeNanos(B, M, 4, "morok.step.wall.before");
            emitSchedulerStepSpan(B, acc, rng);
            SchedulerCounterSample cpuAfter =
                emitDarwinThreadCpuNanos(B, M, "morok.step.thread.after");
            Value *wallAfter =
                emitClockGettimeNanos(B, M, 4, "morok.step.wall.after");

            Value *wallOrdered =
                B.CreateICmpUGE(wallAfter, wallBefore,
                                "morok.step.wall.ordered");
            Value *wallDelta = B.CreateSelect(
                wallOrdered, B.CreateSub(wallAfter, wallBefore),
                ConstantInt::get(i64, 0), "morok.step.wall.delta");
            Value *cpuDelta = B.CreateSub(cpuAfter.value, cpuBefore.value,
                                          "morok.step.cpu.delta");
            Value *cpuReady =
                B.CreateAnd(cpuBefore.ready, cpuAfter.ready,
                            "morok.step.cpu.ready");
            Value *sampleReady = B.CreateAnd(
                cpuReady,
                B.CreateAnd(wallOrdered,
                            B.CreateICmpNE(cpuDelta, ConstantInt::get(i64, 0),
                                           "morok.step.cpu.nonzero")),
                "morok.step.sample.ready");
            Value *limit = B.CreateAdd(
                B.CreateMul(cpuDelta, ConstantInt::get(i64, 256),
                            "morok.step.cpu.scaled"),
                ConstantInt::get(i64, 50000000ULL), "morok.step.wall.limit");
            Value *sampleBad =
                B.CreateAnd(sampleReady,
                            B.CreateICmpUGT(wallDelta, limit,
                                            "morok.step.thread.skew"),
                            "morok.step.thread.skew.ready");
            anomalousSamples =
                B.CreateAdd(anomalousSamples, B.CreateZExt(sampleBad, i32),
                            "morok.step.anomalous.n");
            availableSamples =
                B.CreateAdd(availableSamples, B.CreateZExt(sampleReady, i32),
                            "morok.step.available.n");
            mix = B.CreateXor(
                B.CreateAdd(mix,
                            B.CreateMul(wallDelta,
                                        ConstantInt::get(i64, rng.next() | 1ULL))),
                B.CreateMul(cpuDelta, ConstantInt::get(i64, rng.next() | 1ULL)),
                "morok.step.thread.mix");
        }
    } else {
        Value *qpcFreq = emitWindowsQpcFrequency(B, M, "morok.step.qpc.freq");
        for (unsigned sample = 0; sample < 3; ++sample) {
            SchedulerCounterSample cpuBefore =
                emitWindowsThreadTime100ns(B, M, "morok.step.thread.before");
            SchedulerCounterSample cyclesBefore =
                emitWindowsThreadCycles(B, M, "morok.step.cycles.before");
            Value *wallBefore = emitWindowsQpc(B, M, "morok.step.qpc.before");
            emitSchedulerStepSpan(B, acc, rng);
            SchedulerCounterSample cpuAfter =
                emitWindowsThreadTime100ns(B, M, "morok.step.thread.after");
            SchedulerCounterSample cyclesAfter =
                emitWindowsThreadCycles(B, M, "morok.step.cycles.after");
            Value *wallAfter = emitWindowsQpc(B, M, "morok.step.qpc.after");

            Value *wallOrdered =
                B.CreateICmpUGE(wallAfter, wallBefore,
                                "morok.step.qpc.ordered");
            Value *wallDelta = B.CreateSelect(
                wallOrdered, B.CreateSub(wallAfter, wallBefore),
                ConstantInt::get(i64, 0), "morok.step.qpc.delta");
            Value *cpuDelta = B.CreateSub(cpuAfter.value, cpuBefore.value,
                                          "morok.step.cpu.delta.100ns");
            Value *cpuReady =
                B.CreateAnd(cpuBefore.ready, cpuAfter.ready,
                            "morok.step.cpu.ready");
            Value *sampleReady = B.CreateAnd(
                B.CreateAnd(cpuReady, wallOrdered),
                B.CreateAnd(B.CreateICmpNE(cpuDelta, ConstantInt::get(i64, 0),
                                           "morok.step.cpu.nonzero"),
                            B.CreateICmpNE(qpcFreq, ConstantInt::get(i64, 0),
                                           "morok.step.qpc.freq.nonzero")),
                "morok.step.sample.ready");
            Value *cpuTicks = B.CreateUDiv(
                B.CreateMul(cpuDelta, qpcFreq, "morok.step.cpu.qpc.product"),
                ConstantInt::get(i64, 10000000ULL), "morok.step.cpu.qpc");
            Value *limit = B.CreateAdd(
                B.CreateMul(cpuTicks, ConstantInt::get(i64, 256),
                            "morok.step.cpu.qpc.scaled"),
                B.CreateUDiv(qpcFreq, ConstantInt::get(i64, 20),
                             "morok.step.qpc.floor"),
                "morok.step.qpc.limit");
            Value *sampleBad =
                B.CreateAnd(sampleReady,
                            B.CreateICmpUGT(wallDelta, limit,
                                            "morok.step.thread.skew"),
                            "morok.step.thread.skew.ready");
            Value *cyclesReady =
                B.CreateAnd(cyclesBefore.ready, cyclesAfter.ready,
                            "morok.step.cycles.ready");
            Value *cyclesDelta = B.CreateSelect(
                cyclesReady, B.CreateSub(cyclesAfter.value, cyclesBefore.value),
                ConstantInt::get(i64, 0), "morok.step.cycles.delta");
            anomalousSamples =
                B.CreateAdd(anomalousSamples, B.CreateZExt(sampleBad, i32),
                            "morok.step.anomalous.n");
            availableSamples =
                B.CreateAdd(availableSamples, B.CreateZExt(sampleReady, i32),
                            "morok.step.available.n");
            mix = B.CreateXor(
                B.CreateAdd(mix,
                            B.CreateMul(wallDelta,
                                        ConstantInt::get(i64, rng.next() | 1ULL))),
                B.CreateXor(
                    B.CreateMul(cpuDelta, ConstantInt::get(i64, rng.next() | 1ULL)),
                    B.CreateMul(cyclesDelta,
                                ConstantInt::get(i64, rng.next() | 1ULL))),
                "morok.step.thread.mix");
        }
    }

    foldState(B, State, mix, 0x9C07D36E4A12B5F1ULL, "morok.step.mix");
    foldState(B, State, availableSamples, 0x71AF63C49E20D8B5ULL,
              "morok.step.available.samples");
    foldState(B, State, anomalousSamples, 0xC2E4B8A1975D306FULL,
              "morok.step.anomalous.samples");
    Value *anomaly = B.CreateICmpUGE(anomalousSamples, ConstantInt::get(i32, 2),
                                     "morok.step.anomaly.distribution");
    // Telemetry only, NOT foldEnforcedFlag (#98): context-switch counts and
    // thread-time skew are host/jitter-sensitive — a loaded host, a VM/container
    // scheduler, or ordinary preemption trips this anomaly on a legitimate,
    // untraced run.  foldEnforcedFlag would fold that false positive into the
    // CONSUMED anti_debug seal channel (via sealFold), permanently moving the
    // seal off S0 and making VM bytecode / sealed data decode garbage at
    // startup.  Per the foldEnforcedFlag contract, host/jitter-sensitive probes
    // must stay foldFlag telemetry (recorded in the per-probe state, never the
    // consumed seal); only verdicts proven false on every clean run may enforce.
    foldFlag(B, State, anomaly, 0xF18D47A6C2B9035EULL,
             "morok.step.anomaly.distribution");
    B.CreateRetVoid();
    return fn;
}

Function *negativeTimingProbe(Module &M, ir::IRRandom &rng, const Triple &TT) {
    if (Function *existing = M.getFunction("morok.negative.timing"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i64 = Type::getInt64Ty(ctx);
    auto *fn = Function::Create(FunctionType::get(i64, false),
                                GlobalValue::PrivateLinkage,
                                "morok.negative.timing", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    IRBuilder<> B(entry);
    auto *diff = B.CreateAlloca(i64, nullptr, "morok.negative.timing.diff");
    auto *acc = B.CreateAlloca(i64, nullptr, "morok.negative.timing.acc");
    B.CreateStore(ConstantInt::get(i64, 0), diff)->setVolatile(true);
    B.CreateStore(ConstantInt::get(i64, rng.next()), acc)->setVolatile(true);

    Value *primaryStart =
        emitTimingPrimaryClock(B, M, TT, "morok.negative.timing.primary.start");
    Value *secondaryStart = emitTimingSecondaryClock(
        B, M, TT, "morok.negative.timing.secondary.start");
    emitShortTimingSpan(B, acc, rng.next());
    Value *primaryEnd =
        emitTimingPrimaryClock(B, M, TT, "morok.negative.timing.primary.end");
    Value *secondaryEnd =
        emitTimingSecondaryClock(B, M, TT, "morok.negative.timing.secondary.end");

    Value *primaryDelta = B.CreateSub(primaryEnd, primaryStart,
                                      "morok.negative.timing.primary.delta");
    Value *secondaryDelta = B.CreateSub(
        secondaryEnd, secondaryStart, "morok.negative.timing.secondary.delta");
    const bool hasCycleClock = isX86Target(TT);
    const std::uint64_t primaryThreshold =
        hasCycleClock ? 25000000ULL : 15000000ULL;
    constexpr std::uint64_t secondaryThreshold = 15000000ULL;
    Value *primarySlow = B.CreateICmpUGT(
        primaryDelta, ConstantInt::get(i64, primaryThreshold),
        "morok.negative.timing.primary.slow");
    Value *secondarySlow = B.CreateICmpUGT(
        secondaryDelta, ConstantInt::get(i64, secondaryThreshold),
        "morok.negative.timing.secondary.slow");
    Value *slow = B.CreateAnd(primarySlow, secondarySlow,
                              "morok.negative.timing.slow");
    incrementDiff(B, diff, slow, "morok.negative.timing.slow");
    emitRetDiff(B, diff);
    return fn;
}

GlobalVariable *trapOracleState(Module &M, ir::IRRandom &rng) {
    if (auto *existing =
            M.getGlobalVariable("morok.trap.state", /*AllowInternal=*/true))
        return existing;
    auto *i64 = Type::getInt64Ty(M.getContext());
    auto *gv = new GlobalVariable(
        M, i64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(i64, rng.next()), "morok.trap.state");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

GlobalVariable *trapHitCounter(Module &M) {
    if (auto *existing =
            M.getGlobalVariable("morok.trap.hits", /*AllowInternal=*/true))
        return existing;
    auto *i32 = Type::getInt32Ty(M.getContext());
    auto *gv = new GlobalVariable(M, i32, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage,
                                  ConstantInt::get(i32, 0), "morok.trap.hits");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

bool useLinuxX86SiginfoTrapHandler(const Triple &TT) {
    return TT.isOSLinux() && TT.getArch() == Triple::x86_64;
}

Function *trapSignalHandler(Module &M, GlobalVariable *Counter,
                            GlobalVariable *State, const Triple &TT) {
    if (Function *existing = M.getFunction("morok.trap.handler"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);
    SmallVector<Type *, 3> args{i32, ptr, ptr};
    auto *fn = Function::Create(
        FunctionType::get(Type::getVoidTy(ctx), args, false),
        GlobalValue::PrivateLinkage, "morok.trap.handler", &M);
    fn->setDSOLocal(true);
    Argument *sig = fn->getArg(0);
    sig->setName("sig");
    Argument *info = fn->getArg(1);
    info->setName("info");
    Argument *uctx = fn->getArg(2);
    uctx->setName("uctx");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    IRBuilder<> B(entry);
    auto *old = B.CreateLoad(i32, Counter, "morok.trap.hits.old");
    old->setVolatile(true);
    Value *next =
        B.CreateAdd(old, ConstantInt::get(i32, 1), "morok.trap.hits.next");
    auto *store = B.CreateStore(next, Counter);
    store->setVolatile(true);
    foldState(B, State, sig, 0xC286B9F2B77D6A41ULL, "morok.trap.signal");
    foldState(B, State, next, 0x4F3C2D1E9876A5B1ULL, "morok.trap.count");

    if (useLinuxX86SiginfoTrapHandler(TT)) {
        auto *ip = intPtrTy(M);
        auto *i8 = Type::getInt8Ty(ctx);
        auto *checkCtx = BasicBlock::Create(ctx, "morok.trap.ill.ctx", fn);
        auto *checkByte = BasicBlock::Create(ctx, "morok.trap.ill.byte", fn);
        auto *advance = BasicBlock::Create(ctx, "morok.trap.ill.advance", fn);
        auto *done = BasicBlock::Create(ctx, "done", fn);

        Value *isIll =
            B.CreateICmpEQ(sig, ConstantInt::get(i32, 4), "morok.trap.ill");
        B.CreateCondBr(isIll, checkCtx, done);

        IRBuilder<> CB(checkCtx);
        CB.CreateCondBr(CB.CreateICmpNE(uctx, ConstantPointerNull::get(ptr)),
                        checkByte, done);

        IRBuilder<> BB(checkByte);
        // Linux x86_64 ucontext_t: uc_mcontext.gregs[REG_RIP] at byte 168.
        // Orb reports ICEBP (0xf1) as SIGILL at the same PC, so advance only
        // when the trapped byte is exactly the ICEBP stimulus.
        Value *ripSlot = gepI8(BB, M, uctx, constIp(M, 168),
                               "morok.trap.rip.slot");
        Value *rip = BB.CreateLoad(ip, ripSlot, "morok.trap.rip");
        Value *pc = BB.CreateIntToPtr(rip, ptr, "morok.trap.pc");
        Value *byte = BB.CreateLoad(i8, pc, "morok.trap.icebp.byte");
        BB.CreateCondBr(
            BB.CreateICmpEQ(byte, ConstantInt::get(i8, 0xF1),
                            "morok.trap.icebp"),
            advance, done);

        IRBuilder<> AB(advance);
        AB.CreateStore(AB.CreateAdd(rip, ConstantInt::get(ip, 1)), ripSlot);
        AB.CreateBr(done);

        B.SetInsertPoint(done);
    }

    B.CreateRetVoid();
    return fn;
}

FunctionCallee sigactionDecl(Module &M) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);
    return M.getOrInsertFunction(
        "sigaction", FunctionType::get(i32, {i32, ptr, ptr}, false));
}

FunctionCallee raiseDecl(Module &M) {
    auto *i32 = Type::getInt32Ty(M.getContext());
    return M.getOrInsertFunction("raise", FunctionType::get(i32, {i32}, false));
}

void zeroActionBytes(IRBuilder<> &B, Module &M, AllocaInst *Action,
                     std::uint64_t Bytes) {
    auto *i8 = Type::getInt8Ty(M.getContext());
    for (std::uint64_t i = 0; i < Bytes; ++i)
        B.CreateStore(ConstantInt::get(i8, 0),
                      gepI8(B, M, Action, constIp(M, i)));
}

struct TrapSigactionLayout {
    std::uint64_t sigactionSize = 0;
    std::uint64_t flagsOffset = 0;
    std::uint32_t saSiginfo = 0;
};

bool trapSigactionLayout(const Triple &TT, TrapSigactionLayout &L) {
    if (TT.isOSLinux() &&
        (TT.getArch() == Triple::x86_64 || TT.getArch() == Triple::aarch64 ||
         TT.getArch() == Triple::aarch64_be)) {
        L.sigactionSize = 152;
        L.flagsOffset = 136;
        L.saSiginfo = 4;
        return true;
    }
    if (TT.isOSDarwin() &&
        (TT.getArch() == Triple::x86_64 || TT.getArch() == Triple::aarch64)) {
        L.sigactionSize = 16;
        L.flagsOffset = 12;
        L.saSiginfo = 0x40;
        return true;
    }
    return false;
}

void storeTrapSiginfoAction(IRBuilder<> &B, Module &M, AllocaInst *Action,
                            Function *Handler,
                            const TrapSigactionLayout &Layout) {
    auto *i32 = Type::getInt32Ty(M.getContext());
    zeroActionBytes(B, M, Action, Layout.sigactionSize);
    B.CreateStore(Handler, gepI8(B, M, Action, constIp(M, 0),
                                 "morok.trap.sa.handler"));
    B.CreateStore(ConstantInt::get(i32, Layout.saSiginfo),
                  gepI8(B, M, Action, constIp(M, Layout.flagsOffset),
                        "morok.trap.sa.flags"));
}

void emitTrapInlineAsm(IRBuilder<> &B, StringRef Asm, StringRef Constraints) {
    auto *asmTy = FunctionType::get(Type::getVoidTy(B.getContext()), false);
    InlineAsm *IA =
        InlineAsm::get(asmTy, Asm, Constraints, /*hasSideEffects=*/true);
    B.CreateCall(asmTy, IA);
}

unsigned emitTrapStimuli(IRBuilder<> &B, Module &M, const Triple &TT) {
    auto *i32 = Type::getInt32Ty(M.getContext());
    constexpr int kSigTrap = 5;
    if (useLinuxX86SiginfoTrapHandler(TT)) {
        emitTrapInlineAsm(B, "int3", "~{dirflag},~{fpsr},~{flags}");
        emitTrapInlineAsm(B, ".byte 0xf1", "~{dirflag},~{fpsr},~{flags}");
        emitTrapInlineAsm(B,
                          "pushfq\npopq %rax\norq $$256, %rax\npushq "
                          "%rax\npopfq\nnop\npushfq\npopq %rax\nandq "
                          "$$-257, %rax\npushq %rax\npopfq",
                          "~{rax},~{dirflag},~{fpsr},~{flags}");
        return 3;
    }

    FunctionCallee raiseFn = raiseDecl(M);
    for (unsigned i = 0; i < 3; ++i)
        B.CreateCall(raiseFn, {ConstantInt::get(i32, kSigTrap)});
    return 3;
}

struct SchroFaultLayout {
    std::uint64_t sigactionSize = 0;
    std::uint64_t flagsOffset = 0;
    std::uint64_t siginfoAddrOffset = 0;
    std::uint64_t linuxPcSlotOffset = 0;
    std::uint64_t darwinMcontextOffset = 0;
    std::uint64_t darwinPcOffset = 0;
    std::uint32_t saSiginfo = 0;
    std::int32_t sigSegv = 11;
    std::int32_t sigBus = 7;
    bool darwinMcontext = false;
};

bool schroFaultLayout(const Triple &TT, SchroFaultLayout &L) {
    if (TT.isOSLinux() && TT.getArch() == Triple::x86_64) {
        L.sigactionSize = 152;
        L.flagsOffset = 136;
        L.siginfoAddrOffset = 16;
        L.linuxPcSlotOffset = 168;
        L.saSiginfo = 4;
        L.sigSegv = 11;
        L.sigBus = 7;
        return true;
    }
    if (TT.isOSDarwin() &&
        (TT.getArch() == Triple::x86_64 || TT.getArch() == Triple::aarch64 ||
         TT.getArch() == Triple::aarch64_32)) {
        L.sigactionSize = 16;
        L.flagsOffset = 12;
        L.siginfoAddrOffset = 24;
        L.darwinMcontextOffset = 48;
        L.darwinPcOffset = TT.getArch() == Triple::x86_64 ? 160 : 288;
        L.saSiginfo = 0x40;
        L.sigSegv = 11;
        L.sigBus = 10;
        L.darwinMcontext = true;
        return true;
    }
    return false;
}

GlobalVariable *schroPageGlobal(Module &M) {
    if (auto *existing = M.getGlobalVariable("morok.antihook.schro.page",
                                             /*AllowInternal=*/true))
        return existing;
    auto *ip = intPtrTy(M);
    auto *gv = new GlobalVariable(
        M, ip, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(ip, 0), "morok.antihook.schro.page");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

GlobalVariable *schroSizeGlobal(Module &M) {
    if (auto *existing = M.getGlobalVariable("morok.antihook.schro.size",
                                             /*AllowInternal=*/true))
        return existing;
    auto *ip = intPtrTy(M);
    auto *gv = new GlobalVariable(
        M, ip, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(ip, 0), "morok.antihook.schro.size");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

GlobalVariable *schroArmedGlobal(Module &M) {
    if (auto *existing = M.getGlobalVariable("morok.antihook.schro.armed",
                                             /*AllowInternal=*/true))
        return existing;
    auto *i32 = Type::getInt32Ty(M.getContext());
    auto *gv = new GlobalVariable(
        M, i32, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(i32, 0), "morok.antihook.schro.armed");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

GlobalVariable *schroOldActionGlobal(Module &M, StringRef Name,
                                     std::uint64_t Bytes) {
    if (auto *existing = M.getGlobalVariable(Name, /*AllowInternal=*/true))
        return existing;
    auto *i8 = Type::getInt8Ty(M.getContext());
    auto *ty = ArrayType::get(i8, Bytes);
    auto *gv = new GlobalVariable(M, ty, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage,
                                  ConstantAggregateZero::get(ty), Name);
    gv->setAlignment(Align(8));
    return gv;
}

void storeNamedSiginfoAction(IRBuilder<> &B, Module &M, AllocaInst *Action,
                             Function *Handler,
                             const SchroFaultLayout &Layout,
                             const Twine &Prefix) {
    auto *i32 = Type::getInt32Ty(M.getContext());
    zeroActionBytes(B, M, Action, Layout.sigactionSize);
    B.CreateStore(Handler,
                  gepI8(B, M, Action, constIp(M, 0), Prefix + ".handler"));
    B.CreateStore(ConstantInt::get(i32, Layout.saSiginfo),
                  gepI8(B, M, Action, constIp(M, Layout.flagsOffset),
                        Prefix + ".flags"));
}

void storeTargetSiginfoAction(IRBuilder<> &B, Module &M, AllocaInst *Action,
                              Function *Handler,
                              const SchroFaultLayout &Layout) {
    storeNamedSiginfoAction(B, M, Action, Handler, Layout,
                            "morok.antihook.schro.sa");
}

void storeCodeByte(IRBuilder<> &B, Module &M, Value *Page,
                   std::uint64_t Offset, std::uint8_t Byte) {
    auto *i8 = Type::getInt8Ty(M.getContext());
    auto *st = B.CreateStore(ConstantInt::get(i8, Byte),
                             gepI8(B, M, B.CreateIntToPtr(
                                             Page, PointerType::getUnqual(
                                                       M.getContext())),
                                   constIp(M, Offset),
                                   "morok.antihook.schro.code.ptr"));
    st->setVolatile(true);
    st->setAlignment(Align(1));
}

std::uint8_t emitSchroCodeIsland(IRBuilder<> &B, Module &M, const Triple &TT,
                                 Value *Page, ir::IRRandom &rng) {
    if (isX86Target(TT)) {
        const std::uint32_t imm =
            static_cast<std::uint32_t>(rng.next() ^ 0x51D07E3Fu);
        const std::array<std::uint8_t, 8> bytes = {
            0xB8,
            static_cast<std::uint8_t>(imm & 0xffu),
            static_cast<std::uint8_t>((imm >> 8) & 0xffu),
            static_cast<std::uint8_t>((imm >> 16) & 0xffu),
            static_cast<std::uint8_t>((imm >> 24) & 0xffu),
            0xC3,
            0x0F,
            0x0B,
        };
        for (std::uint64_t i = 0; i < bytes.size(); ++i)
            storeCodeByte(B, M, Page, i, bytes[i]);
        return bytes[0];
    }

    const std::uint32_t imm =
        static_cast<std::uint32_t>((rng.next() ^ 0x46A9u) & 0xffffu);
    const std::uint32_t movz = 0x52800000u | (imm << 5);
    const std::uint32_t ret = 0xD65F03C0u;
    const std::array<std::uint8_t, 8> bytes = {
        static_cast<std::uint8_t>(movz & 0xffu),
        static_cast<std::uint8_t>((movz >> 8) & 0xffu),
        static_cast<std::uint8_t>((movz >> 16) & 0xffu),
        static_cast<std::uint8_t>((movz >> 24) & 0xffu),
        static_cast<std::uint8_t>(ret & 0xffu),
        static_cast<std::uint8_t>((ret >> 8) & 0xffu),
        static_cast<std::uint8_t>((ret >> 16) & 0xffu),
        static_cast<std::uint8_t>((ret >> 24) & 0xffu),
    };
    for (std::uint64_t i = 0; i < bytes.size(); ++i)
        storeCodeByte(B, M, Page, i, bytes[i]);
    return bytes[0];
}

Function *schroSignalHandler(Module &M, GlobalVariable *State,
                             Function *Probe, const Triple &TT,
                             const SchroFaultLayout &Layout) {
    if (Function *existing = M.getFunction("morok.antihook.schro.handler"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(
        FunctionType::get(Type::getVoidTy(ctx), {i32, ptr, ptr}, false),
        GlobalValue::PrivateLinkage, "morok.antihook.schro.handler", &M);
    fn->setDSOLocal(true);
    Argument *sig = fn->getArg(0);
    sig->setName("sig");
    Argument *info = fn->getArg(1);
    info->setName("info");
    Argument *uctx = fn->getArg(2);
    uctx->setName("uctx");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *loadFaultBB = BasicBlock::Create(ctx, "fault.addr", fn);
    auto *checkCtxBB = BasicBlock::Create(ctx, "ctx.check", fn);
    auto *loadPcBB = BasicBlock::Create(ctx, "pc.load", fn);
    auto *loadDarwinPcBB = BasicBlock::Create(ctx, "pc.darwin", fn);
    auto *classifyBB = BasicBlock::Create(ctx, "classify", fn);
    auto *oursBB = BasicBlock::Create(ctx, "ours", fn);
    auto *restoreBB = BasicBlock::Create(ctx, "restore", fn);
    auto *legitBB = BasicBlock::Create(ctx, "legit", fn);
    auto *readerBB = BasicBlock::Create(ctx, "reader", fn);
    auto *doneBB = BasicBlock::Create(ctx, "done", fn);

    IRBuilder<> B(entry);
    AllocaInst *pcSlot = B.CreateAlloca(ip, nullptr, "morok.antihook.schro.pc.slot");
    AllocaInst *faultSlot =
        B.CreateAlloca(ip, nullptr, "morok.antihook.schro.fault.slot");
    B.CreateStore(ConstantInt::get(ip, 0), pcSlot)->setVolatile(true);
    B.CreateStore(ConstantInt::get(ip, 0), faultSlot)->setVolatile(true);
    B.CreateCondBr(B.CreateICmpNE(info, ConstantPointerNull::get(ptr)),
                   loadFaultBB, checkCtxBB);

    IRBuilder<> FB(loadFaultBB);
    Value *faultAddr = loadAt(FB, M, ip, info, Layout.siginfoAddrOffset,
                              "morok.antihook.schro.fault");
    FB.CreateStore(faultAddr, faultSlot)->setVolatile(true);
    FB.CreateBr(checkCtxBB);

    IRBuilder<> CB(checkCtxBB);
    CB.CreateCondBr(CB.CreateICmpNE(uctx, ConstantPointerNull::get(ptr)),
                    loadPcBB, classifyBB);

    IRBuilder<> PB(loadPcBB);
    if (Layout.darwinMcontext) {
        Value *mctx = loadAt(PB, M, ptr, uctx, Layout.darwinMcontextOffset,
                             "morok.antihook.schro.mcontext");
        PB.CreateCondBr(PB.CreateICmpNE(mctx, ConstantPointerNull::get(ptr)),
                        loadDarwinPcBB, classifyBB);

        IRBuilder<> DPB(loadDarwinPcBB);
        Value *pc = loadAt(DPB, M, ip, mctx, Layout.darwinPcOffset,
                           "morok.antihook.schro.pc");
        DPB.CreateStore(pc, pcSlot)->setVolatile(true);
        DPB.CreateBr(classifyBB);
    } else {
        Value *pc = loadAt(PB, M, ip, uctx, Layout.linuxPcSlotOffset,
                           "morok.antihook.schro.pc");
        PB.CreateStore(pc, pcSlot)->setVolatile(true);
        PB.CreateBr(classifyBB);
        IRBuilder<> DPB(loadDarwinPcBB);
        DPB.CreateUnreachable();
    }

    IRBuilder<> KB(classifyBB);
    Value *page = KB.CreateLoad(ip, schroPageGlobal(M),
                                "morok.antihook.schro.page.v");
    page->setName("morok.antihook.schro.page.v");
    cast<LoadInst>(page)->setVolatile(true);
    Value *size = KB.CreateLoad(ip, schroSizeGlobal(M),
                                "morok.antihook.schro.size.v");
    cast<LoadInst>(size)->setVolatile(true);
    Value *pc = KB.CreateLoad(ip, pcSlot, "morok.antihook.schro.pc.v");
    cast<LoadInst>(pc)->setVolatile(true);
    Value *fault = KB.CreateLoad(ip, faultSlot, "morok.antihook.schro.fault.v");
    cast<LoadInst>(fault)->setVolatile(true);
    Value *armed = KB.CreateLoad(i32, schroArmedGlobal(M),
                                 "morok.antihook.schro.armed.v");
    cast<LoadInst>(armed)->setVolatile(true);
    Value *end = KB.CreateAdd(page, size, "morok.antihook.schro.page.end");
    Value *inPage = KB.CreateAnd(
        KB.CreateICmpNE(page, ConstantInt::get(ip, 0)),
        KB.CreateAnd(KB.CreateICmpUGE(fault, page),
                     KB.CreateICmpULT(fault, end)),
        "morok.antihook.schro.fault.in.page");
    Value *probeStart =
        KB.CreatePtrToInt(Probe, ip, "morok.antihook.schro.probe.start");
    Value *probeEnd = KB.CreateAdd(probeStart, ConstantInt::get(ip, 8192),
                                   "morok.antihook.schro.probe.end");
    Value *ripOk = KB.CreateAnd(KB.CreateICmpUGE(pc, probeStart),
                                KB.CreateICmpULT(pc, probeEnd),
                                "morok.antihook.schro.rip.allowed");
    Value *armedOk =
        KB.CreateICmpEQ(armed, ConstantInt::get(i32, 1),
                        "morok.antihook.schro.armed.allowed");
    Value *legit = KB.CreateAnd(KB.CreateAnd(inPage, ripOk), armedOk,
                                "morok.antihook.schro.legit");
    KB.CreateCondBr(inPage, oursBB, restoreBB);

    IRBuilder<> OB(oursBB);
    Value *rc = emitPosixMprotect(OB, M, TT, page, size,
                                  ConstantInt::get(ip, 5));
    rc->setName("morok.antihook.schro.mprotect.rx");
    foldState(OB, State, fault, 0x3B9F71A8C4D205E6ULL,
              "morok.antihook.schro.fault.mix");
    foldState(OB, State, pc, 0xA64D07C2E9315B8FULL,
              "morok.antihook.schro.rip.mix");
    Value *reader = OB.CreateNot(legit, "morok.antihook.schro.reader");
    foldFlag(OB, State, reader, 0x6C42B871D9E503AFULL,
             "morok.antihook.schro.reader");
    OB.CreateCondBr(legit, legitBB, readerBB);

    IRBuilder<> LB(legitBB);
    LB.CreateStore(ConstantInt::get(i32, 2), schroArmedGlobal(M))
        ->setVolatile(true);
    LB.CreateBr(doneBB);

    IRBuilder<> RB(readerBB);
    RB.CreateStore(ConstantInt::get(i32, 3), schroArmedGlobal(M))
        ->setVolatile(true);
    RB.CreateBr(doneBB);

    IRBuilder<> XB(restoreBB);
    Value *isBus =
        XB.CreateICmpEQ(sig, ConstantInt::getSigned(i32, Layout.sigBus),
                        "morok.antihook.schro.sigbus");
    GlobalVariable *oldSegv = schroOldActionGlobal(
        M, "morok.antihook.schro.old.segv", Layout.sigactionSize);
    GlobalVariable *oldBus = schroOldActionGlobal(
        M, "morok.antihook.schro.old.bus", Layout.sigactionSize);
    Value *oldAction =
        XB.CreateSelect(isBus, static_cast<Value *>(oldBus),
                        static_cast<Value *>(oldSegv),
                        "morok.antihook.schro.old.action");
    XB.CreateCall(sigactionDecl(M),
                  {sig, oldAction, ConstantPointerNull::get(ptr)},
                  "morok.antihook.schro.restore");
    XB.CreateBr(doneBB);

    IRBuilder<> DB(doneBB);
    DB.CreateRetVoid();
    return fn;
}

Function *schrodingerPageProbe(Module &M, GlobalVariable *State,
                               ir::IRRandom &rng, const Triple &TT) {
    SchroFaultLayout layout;
    if (intPtrTy(M)->getBitWidth() != 64 || !schroFaultLayout(TT, layout))
        return nullptr;
    if (Function *existing = M.getFunction("morok.antihook.schro"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(i64, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antihook.schro", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *setupBB = BasicBlock::Create(ctx, "setup", fn);
    auto *afterRxBB = BasicBlock::Create(ctx, "after.rx", fn);
    auto *afterSigBB = BasicBlock::Create(ctx, "after.sig", fn);
    auto *faultBB = BasicBlock::Create(ctx, "fault", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    AllocaInst *diff = B.CreateAlloca(i64, nullptr, "morok.antihook.schro.diff");
    B.CreateStore(ConstantInt::get(i64, 0), diff)->setVolatile(true);
    Value *pageSize = nullptr;
    if (TT.isOSDarwin()) {
        FunctionCallee getpagesize =
            M.getOrInsertFunction("getpagesize", FunctionType::get(i32, false));
        pageSize = B.CreateZExt(
            B.CreateCall(getpagesize, {}, "morok.antihook.schro.pagesz"), ip);
    } else {
        pageSize = ConstantInt::get(ip, 4096);
    }
    const std::uint32_t mapAnon = TT.isOSDarwin() ? 0x1000u : 0x20u;
    Value *mapped = emitPosixAnonMmapAddr(
        B, M, TT, pageSize, ConstantInt::get(ip, 3),
        ConstantInt::get(ip, 2u | mapAnon), "morok.antihook.schro.mmap");
    mapped->setName("morok.antihook.schro.mmap");
    Value *mappedOk = B.CreateAnd(
        B.CreateICmpUGT(mapped, ConstantInt::get(ip, 4096)),
        B.CreateICmpULT(mapped, ConstantInt::getSigned(ip, -4095)),
        "morok.antihook.schro.mapped");
    B.CreateCondBr(mappedOk, setupBB, retBB);

    IRBuilder<> SB(setupBB);
    SB.CreateStore(mapped, schroPageGlobal(M))->setVolatile(true);
    SB.CreateStore(pageSize, schroSizeGlobal(M))->setVolatile(true);
    const std::uint8_t firstByte =
        emitSchroCodeIsland(SB, M, TT, mapped, rng);
    Value *rxTest = emitPosixMprotect(SB, M, TT, mapped, pageSize,
                                      ConstantInt::get(ip, 5));
    rxTest->setName("morok.antihook.schro.mprotect.rx.test");
    Value *rxFail =
        SB.CreateICmpSLT(rxTest, ConstantInt::getSigned(i32, 0),
                         "morok.antihook.schro.rx.fail");
    incrementDiff(SB, diff, rxFail, "morok.antihook.schro.rx.fail");
    SB.CreateCondBr(rxFail, retBB, afterRxBB);

    IRBuilder<> AB(afterRxBB);
    Function *handler = schroSignalHandler(M, State, fn, TT, layout);
    auto *actionTy = ArrayType::get(i8, layout.sigactionSize);
    AllocaInst *action =
        AB.CreateAlloca(actionTy, nullptr, "morok.antihook.schro.sa");
    storeTargetSiginfoAction(AB, M, action, handler, layout);
    FunctionCallee sigactionFn = sigactionDecl(M);
    GlobalVariable *oldSegv = schroOldActionGlobal(
        M, "morok.antihook.schro.old.segv", layout.sigactionSize);
    GlobalVariable *oldBus = schroOldActionGlobal(
        M, "morok.antihook.schro.old.bus", layout.sigactionSize);
    Value *segvRc =
        AB.CreateCall(sigactionFn,
                      {ConstantInt::getSigned(i32, layout.sigSegv), action,
                       oldSegv},
                      "morok.antihook.schro.sigaction.segv");
    Value *busRc =
        AB.CreateCall(sigactionFn,
                      {ConstantInt::getSigned(i32, layout.sigBus), action,
                       oldBus},
                      "morok.antihook.schro.sigaction.bus");
    Value *sigFail = AB.CreateOr(
        AB.CreateICmpNE(segvRc, ConstantInt::get(i32, 0)),
        AB.CreateICmpNE(busRc, ConstantInt::get(i32, 0)),
        "morok.antihook.schro.sigaction.fail");
    incrementDiff(AB, diff, sigFail, "morok.antihook.schro.sigaction.fail");
    AB.CreateCondBr(sigFail, retBB, afterSigBB);

    IRBuilder<> NB(afterSigBB);
    Value *noneRc = emitPosixMprotect(NB, M, TT, mapped, pageSize,
                                      ConstantInt::get(ip, 0));
    noneRc->setName("morok.antihook.schro.mprotect.none");
    Value *noneFail =
        NB.CreateICmpSLT(noneRc, ConstantInt::getSigned(i32, 0),
                         "morok.antihook.schro.none.fail");
    incrementDiff(NB, diff, noneFail, "morok.antihook.schro.none.fail");
    NB.CreateCondBr(noneFail, retBB, faultBB);

    IRBuilder<> FB(faultBB);
    FB.CreateStore(ConstantInt::get(i32, 1), schroArmedGlobal(M))
        ->setVolatile(true);
    Value *pagePtr = FB.CreateIntToPtr(mapped, ptr, "morok.antihook.schro.ptr");
    auto *faultByte = FB.CreateLoad(i8, pagePtr,
                                    "morok.antihook.schro.fault.byte");
    faultByte->setVolatile(true);
    faultByte->setAlignment(Align(1));
    auto *armedAfter =
        FB.CreateLoad(i32, schroArmedGlobal(M),
                      "morok.antihook.schro.armed.after");
    armedAfter->setVolatile(true);
    Value *handlerOk =
        FB.CreateICmpEQ(armedAfter, ConstantInt::get(i32, 2),
                        "morok.antihook.schro.handler.ok");
    Value *byteOk =
        FB.CreateICmpEQ(faultByte, ConstantInt::get(i8, firstByte),
                        "morok.antihook.schro.byte.ok");
    incrementDiff(FB, diff, FB.CreateNot(FB.CreateAnd(handlerOk, byteOk),
                                         "morok.antihook.schro.trip"),
                  "morok.antihook.schro.trip");
    FB.CreateStore(ConstantInt::get(i32, 0), schroArmedGlobal(M))
        ->setVolatile(true);
    Value *rearmRc = emitPosixMprotect(FB, M, TT, mapped, pageSize,
                                       ConstantInt::get(ip, 0));
    rearmRc->setName("morok.antihook.schro.mprotect.rearm");
    incrementDiff(FB, diff,
                  FB.CreateICmpSLT(rearmRc, ConstantInt::getSigned(i32, 0),
                                   "morok.antihook.schro.rearm.fail"),
                  "morok.antihook.schro.rearm.fail");
    FB.CreateBr(retBB);

    IRBuilder<> RB(retBB);
    emitRetDiff(RB, diff);
    return fn;
}

GlobalVariable *pageFaultTlbState(Module &M, ir::IRRandom &rng) {
    if (auto *existing =
            M.getGlobalVariable("morok.pftlb.state", /*AllowInternal=*/true))
        return existing;
    auto *i64 = Type::getInt64Ty(M.getContext());
    auto *gv = new GlobalVariable(
        M, i64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(i64, rng.next()), "morok.pftlb.state");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

GlobalVariable *pageFaultTlbBaseGlobal(Module &M) {
    if (auto *existing =
            M.getGlobalVariable("morok.pftlb.base", /*AllowInternal=*/true))
        return existing;
    auto *ip = intPtrTy(M);
    auto *gv = new GlobalVariable(
        M, ip, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(ip, 0), "morok.pftlb.base");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

GlobalVariable *pageFaultTlbSizeGlobal(Module &M) {
    if (auto *existing =
            M.getGlobalVariable("morok.pftlb.size", /*AllowInternal=*/true))
        return existing;
    auto *ip = intPtrTy(M);
    auto *gv = new GlobalVariable(
        M, ip, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(ip, 0), "morok.pftlb.size");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

GlobalVariable *pageFaultTlbPageSizeGlobal(Module &M) {
    if (auto *existing = M.getGlobalVariable("morok.pftlb.page.size",
                                             /*AllowInternal=*/true))
        return existing;
    auto *ip = intPtrTy(M);
    auto *gv = new GlobalVariable(
        M, ip, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(ip, 0), "morok.pftlb.page.size");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

GlobalVariable *pageFaultTlbArmedGlobal(Module &M) {
    if (auto *existing =
            M.getGlobalVariable("morok.pftlb.armed", /*AllowInternal=*/true))
        return existing;
    auto *i32 = Type::getInt32Ty(M.getContext());
    auto *gv = new GlobalVariable(M, i32, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage,
                                  ConstantInt::get(i32, 0),
                                  "morok.pftlb.armed");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

GlobalVariable *pageFaultTlbHitsGlobal(Module &M) {
    if (auto *existing =
            M.getGlobalVariable("morok.pftlb.hits", /*AllowInternal=*/true))
        return existing;
    auto *i32 = Type::getInt32Ty(M.getContext());
    auto *gv = new GlobalVariable(M, i32, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage,
                                  ConstantInt::get(i32, 0),
                                  "morok.pftlb.hits");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

void emitPageFaultTlbMunmap(IRBuilder<> &B, Module &M, const Triple &TT,
                            Value *Mapped, Value *Size) {
    if (TT.isOSLinux()) {
        emitLinuxMunmap(B, M, TT, Mapped, Size);
        return;
    }
    if (TT.isOSDarwin()) {
        emitDarwinMunmap(
            B, M, TT,
            B.CreateIntToPtr(Mapped, PointerType::getUnqual(M.getContext())),
            Size);
    }
}

Function *pageFaultTlbSignalHandler(Module &M, GlobalVariable *State,
                                    Function *Probe, const Triple &TT,
                                    const SchroFaultLayout &Layout) {
    if (Function *existing = M.getFunction("morok.pftlb.handler"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(
        FunctionType::get(Type::getVoidTy(ctx), {i32, ptr, ptr}, false),
        GlobalValue::PrivateLinkage, "morok.pftlb.handler", &M);
    fn->setDSOLocal(true);
    Argument *sig = fn->getArg(0);
    sig->setName("sig");
    Argument *info = fn->getArg(1);
    info->setName("info");
    Argument *uctx = fn->getArg(2);
    uctx->setName("uctx");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *loadFaultBB = BasicBlock::Create(ctx, "fault.addr", fn);
    auto *checkCtxBB = BasicBlock::Create(ctx, "ctx.check", fn);
    auto *loadPcBB = BasicBlock::Create(ctx, "pc.load", fn);
    auto *loadDarwinPcBB = BasicBlock::Create(ctx, "pc.darwin", fn);
    auto *classifyBB = BasicBlock::Create(ctx, "classify", fn);
    auto *oursBB = BasicBlock::Create(ctx, "ours", fn);
    auto *restoreBB = BasicBlock::Create(ctx, "restore", fn);
    auto *doneBB = BasicBlock::Create(ctx, "done", fn);

    IRBuilder<> B(entry);
    AllocaInst *pcSlot = B.CreateAlloca(ip, nullptr, "morok.pftlb.pc.slot");
    AllocaInst *faultSlot =
        B.CreateAlloca(ip, nullptr, "morok.pftlb.fault.slot");
    B.CreateStore(ConstantInt::get(ip, 0), pcSlot)->setVolatile(true);
    B.CreateStore(ConstantInt::get(ip, 0), faultSlot)->setVolatile(true);
    B.CreateCondBr(B.CreateICmpNE(info, ConstantPointerNull::get(ptr)),
                   loadFaultBB, checkCtxBB);

    IRBuilder<> FB(loadFaultBB);
    Value *faultAddr =
        loadAt(FB, M, ip, info, Layout.siginfoAddrOffset, "morok.pftlb.fault");
    FB.CreateStore(faultAddr, faultSlot)->setVolatile(true);
    FB.CreateBr(checkCtxBB);

    IRBuilder<> CB(checkCtxBB);
    CB.CreateCondBr(CB.CreateICmpNE(uctx, ConstantPointerNull::get(ptr)),
                    loadPcBB, classifyBB);

    IRBuilder<> PB(loadPcBB);
    if (Layout.darwinMcontext) {
        Value *mctx =
            loadAt(PB, M, ptr, uctx, Layout.darwinMcontextOffset,
                   "morok.pftlb.mcontext");
        PB.CreateCondBr(PB.CreateICmpNE(mctx, ConstantPointerNull::get(ptr)),
                        loadDarwinPcBB, classifyBB);

        IRBuilder<> DPB(loadDarwinPcBB);
        Value *pc =
            loadAt(DPB, M, ip, mctx, Layout.darwinPcOffset, "morok.pftlb.pc");
        DPB.CreateStore(pc, pcSlot)->setVolatile(true);
        DPB.CreateBr(classifyBB);
    } else {
        Value *pc =
            loadAt(PB, M, ip, uctx, Layout.linuxPcSlotOffset, "morok.pftlb.pc");
        PB.CreateStore(pc, pcSlot)->setVolatile(true);
        PB.CreateBr(classifyBB);
        IRBuilder<> DPB(loadDarwinPcBB);
        DPB.CreateUnreachable();
    }

    IRBuilder<> KB(classifyBB);
    Value *base =
        KB.CreateLoad(ip, pageFaultTlbBaseGlobal(M), "morok.pftlb.base.v");
    cast<LoadInst>(base)->setVolatile(true);
    Value *size =
        KB.CreateLoad(ip, pageFaultTlbSizeGlobal(M), "morok.pftlb.size.v");
    cast<LoadInst>(size)->setVolatile(true);
    Value *pageSize = KB.CreateLoad(ip, pageFaultTlbPageSizeGlobal(M),
                                    "morok.pftlb.page.size.v");
    cast<LoadInst>(pageSize)->setVolatile(true);
    Value *fault = KB.CreateLoad(ip, faultSlot, "morok.pftlb.fault.v");
    cast<LoadInst>(fault)->setVolatile(true);
    Value *end = KB.CreateAdd(base, size, "morok.pftlb.end");
    Value *baseReady =
        KB.CreateAnd(KB.CreateICmpNE(base, ConstantInt::get(ip, 0)),
                     KB.CreateICmpNE(pageSize, ConstantInt::get(ip, 0)),
                     "morok.pftlb.ready");
    Value *inRange =
        KB.CreateAnd(baseReady,
                     KB.CreateAnd(KB.CreateICmpUGE(fault, base),
                                  KB.CreateICmpULT(fault, end)),
                     "morok.pftlb.fault.in.range");
    KB.CreateCondBr(inRange, oursBB, restoreBB);

    IRBuilder<> OB(oursBB);
    Value *pc = OB.CreateLoad(ip, pcSlot, "morok.pftlb.pc.v");
    cast<LoadInst>(pc)->setVolatile(true);
    Value *offset = OB.CreateSub(fault, base, "morok.pftlb.fault.offset");
    Value *pageIndex = OB.CreateUDiv(offset, pageSize, "morok.pftlb.page.idx");
    Value *faultPage =
        OB.CreateAdd(base, OB.CreateMul(pageIndex, pageSize),
                     "morok.pftlb.fault.page");
    Value *rc = emitPosixMprotect(OB, M, TT, faultPage, pageSize,
                                  ConstantInt::get(ip, 3));
    rc->setName("morok.pftlb.mprotect.page");
    auto *oldHits =
        OB.CreateLoad(i32, pageFaultTlbHitsGlobal(M), "morok.pftlb.hits.old");
    oldHits->setVolatile(true);
    Value *nextHits =
        OB.CreateAdd(oldHits, ConstantInt::get(i32, 1), "morok.pftlb.hits.next");
    OB.CreateStore(nextHits, pageFaultTlbHitsGlobal(M))->setVolatile(true);
    Value *armed =
        OB.CreateLoad(i32, pageFaultTlbArmedGlobal(M), "morok.pftlb.armed.v");
    cast<LoadInst>(armed)->setVolatile(true);
    Value *probeStart = OB.CreatePtrToInt(Probe, ip, "morok.pftlb.probe.start");
    Value *probeEnd =
        OB.CreateAdd(probeStart, ConstantInt::get(ip, 16384),
                     "morok.pftlb.probe.end");
    Value *ripOk = OB.CreateAnd(OB.CreateICmpUGE(pc, probeStart),
                                OB.CreateICmpULT(pc, probeEnd),
                                "morok.pftlb.rip.allowed");
    Value *armedOk = OB.CreateICmpEQ(armed, ConstantInt::get(i32, 1),
                                     "morok.pftlb.armed.allowed");
    Value *unexpected =
        OB.CreateNot(OB.CreateAnd(ripOk, armedOk), "morok.pftlb.unexpected");
    foldState(OB, State, fault, 0xD28F4A3C91E7B605ULL, "morok.pftlb.fault.mix");
    foldState(OB, State, pc, 0x8A39C7514D20E6B3ULL, "morok.pftlb.pc.mix");
    foldState(OB, State, nextHits, 0x41E6BD90A3C8572FULL,
              "morok.pftlb.hits.mix");
    foldFlag(OB, State, unexpected, 0xE5074B2D6C91A83FULL,
             "morok.pftlb.unexpected.fault");
    OB.CreateBr(doneBB);

    IRBuilder<> XB(restoreBB);
    Value *isBus = XB.CreateICmpEQ(sig, ConstantInt::getSigned(i32, Layout.sigBus),
                                   "morok.pftlb.sigbus");
    GlobalVariable *oldSegv =
        schroOldActionGlobal(M, "morok.pftlb.old.segv", Layout.sigactionSize);
    GlobalVariable *oldBus =
        schroOldActionGlobal(M, "morok.pftlb.old.bus", Layout.sigactionSize);
    Value *oldAction = XB.CreateSelect(isBus, static_cast<Value *>(oldBus),
                                       static_cast<Value *>(oldSegv),
                                       "morok.pftlb.old.action");
    XB.CreateCall(sigactionDecl(M),
                  {sig, oldAction, ConstantPointerNull::get(ptr)},
                  "morok.pftlb.restore.foreign");
    XB.CreateBr(doneBB);

    IRBuilder<> DB(doneBB);
    DB.CreateRetVoid();
    return fn;
}

Function *pageFaultTlbProbe(Module &M, GlobalVariable *State,
                            ir::IRRandom &rng, const Triple &TT) {
    SchroFaultLayout layout;
    if (intPtrTy(M)->getBitWidth() != 64 || !schroFaultLayout(TT, layout))
        return nullptr;
    if (Function *existing = M.getFunction("morok.pftlb.oracle"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(Type::getVoidTy(ctx), false),
                                GlobalValue::PrivateLinkage,
                                "morok.pftlb.oracle", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    constexpr std::uint32_t kPageCount = 5;
    const std::uint32_t mapAnon = TT.isOSDarwin() ? 0x1000u : 0x20u;

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *installBusBB = BasicBlock::Create(ctx, "install.bus", fn);
    auto *restoreSegvBB = BasicBlock::Create(ctx, "restore.segv", fn);
    auto *protectBB = BasicBlock::Create(ctx, "protect", fn);
    auto *touchBB = BasicBlock::Create(ctx, "touch", fn);
    auto *analyzeBB = BasicBlock::Create(ctx, "analyze", fn);
    auto *restoreAllBB = BasicBlock::Create(ctx, "restore.all", fn);
    auto *unmapBB = BasicBlock::Create(ctx, "unmap", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    Value *pageSize = nullptr;
    if (TT.isOSDarwin()) {
        FunctionCallee getpagesize =
            M.getOrInsertFunction("getpagesize", FunctionType::get(i32, false));
        pageSize =
            B.CreateZExt(B.CreateCall(getpagesize, {}, "morok.pftlb.pagesz"),
                         ip);
    } else {
        pageSize = ConstantInt::get(ip, 4096);
    }
    Value *regionSize =
        B.CreateMul(pageSize, ConstantInt::get(ip, kPageCount),
                    "morok.pftlb.region.size");
    Value *mapped = emitPosixAnonMmapAddr(
        B, M, TT, regionSize, ConstantInt::get(ip, 3),
        ConstantInt::get(ip, 2u | mapAnon), "morok.pftlb.mmap");
    mapped->setName("morok.pftlb.mmap");
    // Reject the WHOLE kernel error range, not just -1: the direct x86_64-Linux
    // syscall path returns raw negative errno values (e.g. -ENOMEM = -12), which
    // are large unsigned values that pass a plain != ~0 test.  A syscall result
    // in [-4095, -1] (i.e. >= (unsigned)-4095) is an error; treating one as a
    // valid page base would write code bytes to a bogus high address before the
    // SIGSEGV/SIGBUS handler is installed — a clean no-op turned into a DoS.
    Value *mappedOk = B.CreateAnd(
        B.CreateICmpUGT(mapped, ConstantInt::get(ip, 4096)),
        B.CreateICmpULT(mapped, ConstantInt::getSigned(ip, -4095)),
        "morok.pftlb.mapped");
    B.CreateCondBr(mappedOk, installBusBB, retBB);

    IRBuilder<> IB(installBusBB);
    IB.CreateStore(mapped, pageFaultTlbBaseGlobal(M))->setVolatile(true);
    IB.CreateStore(regionSize, pageFaultTlbSizeGlobal(M))->setVolatile(true);
    IB.CreateStore(pageSize, pageFaultTlbPageSizeGlobal(M))->setVolatile(true);
    IB.CreateStore(ConstantInt::get(i32, 0), pageFaultTlbArmedGlobal(M))
        ->setVolatile(true);
    IB.CreateStore(ConstantInt::get(i32, 0), pageFaultTlbHitsGlobal(M))
        ->setVolatile(true);
    for (std::uint32_t i = 0; i < kPageCount; ++i) {
        Value *page =
            IB.CreateAdd(mapped, IB.CreateMul(pageSize, ConstantInt::get(ip, i)),
                         "morok.pftlb.page");
        emitSchroCodeIsland(IB, M, TT, page, rng);
    }

    Function *handler = pageFaultTlbSignalHandler(M, State, fn, TT, layout);
    auto *actionTy = ArrayType::get(i8, layout.sigactionSize);
    AllocaInst *action = IB.CreateAlloca(actionTy, nullptr, "morok.pftlb.sa");
    storeNamedSiginfoAction(IB, M, action, handler, layout, "morok.pftlb.sa");
    FunctionCallee sigactionFn = sigactionDecl(M);
    GlobalVariable *oldSegv =
        schroOldActionGlobal(M, "morok.pftlb.old.segv", layout.sigactionSize);
    GlobalVariable *oldBus =
        schroOldActionGlobal(M, "morok.pftlb.old.bus", layout.sigactionSize);
    Value *segvRc =
        IB.CreateCall(sigactionFn,
                      {ConstantInt::getSigned(i32, layout.sigSegv), action,
                       oldSegv},
                      "morok.pftlb.sigaction.segv");
    IB.CreateCondBr(IB.CreateICmpEQ(segvRc, ConstantInt::get(i32, 0)),
                    protectBB, unmapBB);

    IRBuilder<> PB(protectBB);
    Value *busRc =
        PB.CreateCall(sigactionFn,
                      {ConstantInt::getSigned(i32, layout.sigBus), action,
                       oldBus},
                      "morok.pftlb.sigaction.bus");
    PB.CreateCondBr(PB.CreateICmpEQ(busRc, ConstantInt::get(i32, 0)), touchBB,
                    restoreSegvBB);

    IRBuilder<> RSB(restoreSegvBB);
    RSB.CreateCall(sigactionFn,
                   {ConstantInt::getSigned(i32, layout.sigSegv), oldSegv,
                    ConstantPointerNull::get(ptr)},
                   "morok.pftlb.restore.segv");
    RSB.CreateBr(unmapBB);

    IRBuilder<> TB(touchBB);
    Value *noneRc = emitPosixMprotect(TB, M, TT, mapped, regionSize,
                                      ConstantInt::get(ip, 0));
    noneRc->setName("morok.pftlb.mprotect.none");
    TB.CreateCondBr(
        TB.CreateICmpEQ(noneRc, ConstantInt::get(i32, 0),
                        "morok.pftlb.none.ok"),
        analyzeBB, restoreAllBB);

    IRBuilder<> AB(analyzeBB);
    AB.CreateStore(ConstantInt::get(i32, 1), pageFaultTlbArmedGlobal(M))
        ->setVolatile(true);
    auto *mixSlot = AB.CreateAlloca(i64, nullptr, "morok.pftlb.touch.mix.slot");
    AB.CreateStore(ConstantInt::get(i64, rng.next()), mixSlot)
        ->setVolatile(true);
    Value *primaryStart =
        emitTimingPrimaryClock(AB, M, TT, "morok.pftlb.primary.start");
    Value *secondaryStart =
        emitTimingSecondaryClock(AB, M, TT, "morok.pftlb.secondary.start");

    for (std::uint32_t i = 0; i < kPageCount; ++i) {
        Value *offset =
            AB.CreateAdd(AB.CreateMul(pageSize, ConstantInt::get(ip, i)),
                         ConstantInt::get(ip, (i * 13u) & 63u),
                         "morok.pftlb.touch.offset");
        Value *addr = AB.CreateAdd(mapped, offset, "morok.pftlb.touch.addr");
        Value *bytePtr = AB.CreateIntToPtr(addr, ptr, "morok.pftlb.touch.ptr");
        auto *byte = AB.CreateLoad(i8, bytePtr, "morok.pftlb.fault.byte");
        byte->setVolatile(true);
        byte->setAlignment(Align(1));
        auto *oldMix =
            AB.CreateLoad(i64, mixSlot, "morok.pftlb.touch.mix.old");
        oldMix->setVolatile(true);
        Value *mixed = AB.CreateXor(
            AB.CreateMul(oldMix, ConstantInt::get(i64, rng.next() | 1ULL)),
            AB.CreateZExt(byte, i64), "morok.pftlb.touch.mix");
        AB.CreateStore(mixed, mixSlot)->setVolatile(true);
    }

    Value *primaryEnd =
        emitTimingPrimaryClock(AB, M, TT, "morok.pftlb.primary.end");
    Value *secondaryEnd =
        emitTimingSecondaryClock(AB, M, TT, "morok.pftlb.secondary.end");
    AB.CreateStore(ConstantInt::get(i32, 0), pageFaultTlbArmedGlobal(M))
        ->setVolatile(true);
    auto *hits =
        AB.CreateLoad(i32, pageFaultTlbHitsGlobal(M), "morok.pftlb.hits.final");
    hits->setVolatile(true);
    auto *mix = AB.CreateLoad(i64, mixSlot, "morok.pftlb.touch.mix.final");
    mix->setVolatile(true);
    Value *primaryDelta =
        AB.CreateSub(primaryEnd, primaryStart, "morok.pftlb.primary.delta");
    Value *secondaryDelta =
        AB.CreateSub(secondaryEnd, secondaryStart, "morok.pftlb.secondary.delta");
    const bool hasCycleClock = isX86Target(TT);
    const std::uint64_t primaryThreshold =
        hasCycleClock ? 75000000ULL : 35000000ULL;
    constexpr std::uint64_t secondaryThreshold = 35000000ULL;
    Value *missing =
        AB.CreateICmpULT(hits, ConstantInt::get(i32, kPageCount),
                         "morok.pftlb.faults.missing");
    Value *extra = AB.CreateICmpUGT(hits, ConstantInt::get(i32, kPageCount + 1),
                                    "morok.pftlb.faults.extra");
    Value *primarySlow =
        AB.CreateICmpUGT(primaryDelta, ConstantInt::get(i64, primaryThreshold),
                         "morok.pftlb.primary.slow");
    Value *secondarySlow = AB.CreateICmpUGT(
        secondaryDelta, ConstantInt::get(i64, secondaryThreshold),
        "morok.pftlb.secondary.slow");
    Value *slow =
        AB.CreateOr(primarySlow, secondarySlow, "morok.pftlb.sample.slow");
    Value *diverged =
        AB.CreateXor(primarySlow, secondarySlow, "morok.pftlb.sample.diverged");
    foldState(AB, State, mix, 0xB39A6D51C8027E4FULL, "morok.pftlb.touch.mix");
    foldState(AB, State, hits, 0x7C0E49D2A58B6311ULL, "morok.pftlb.hits");
    foldState(AB, State, primaryDelta, 0x2A61E50F9D4C837BULL,
              "morok.pftlb.primary.delta");
    foldState(AB, State, secondaryDelta, 0xC4D81729E63B5A90ULL,
              "morok.pftlb.secondary.delta");
    foldEnforcedFlag(AB, State, missing, 0x916B03D5E24A7F8CULL,
                     "morok.pftlb.pattern.missing");
    foldFlag(AB, State, extra, 0x4E7A92C80D5B31F6ULL,
             "morok.pftlb.pattern.extra");
    foldFlag(AB, State, slow, 0xA71D38E52F94C60BULL,
             "morok.pftlb.pattern.slow");
    foldFlag(AB, State, diverged, 0x6C52E9B1478D0A3FULL,
             "morok.pftlb.pattern.diverged");
    AB.CreateBr(restoreAllBB);

    IRBuilder<> RAB(restoreAllBB);
    RAB.CreateCall(sigactionFn,
                   {ConstantInt::getSigned(i32, layout.sigSegv), oldSegv,
                    ConstantPointerNull::get(ptr)},
                   "morok.pftlb.restore.all.segv");
    RAB.CreateCall(sigactionFn,
                   {ConstantInt::getSigned(i32, layout.sigBus), oldBus,
                    ConstantPointerNull::get(ptr)},
                   "morok.pftlb.restore.all.bus");
    RAB.CreateBr(unmapBB);

    IRBuilder<> UB(unmapBB);
    emitPosixMprotect(UB, M, TT, mapped, regionSize, ConstantInt::get(ip, 3))
        ->setName("morok.pftlb.mprotect.rw.cleanup");
    emitPageFaultTlbMunmap(UB, M, TT, mapped, regionSize);
    UB.CreateStore(ConstantInt::get(ip, 0), pageFaultTlbBaseGlobal(M))
        ->setVolatile(true);
    UB.CreateStore(ConstantInt::get(ip, 0), pageFaultTlbSizeGlobal(M))
        ->setVolatile(true);
    UB.CreateStore(ConstantInt::get(ip, 0), pageFaultTlbPageSizeGlobal(M))
        ->setVolatile(true);
    UB.CreateStore(ConstantInt::get(i32, 0), pageFaultTlbArmedGlobal(M))
        ->setVolatile(true);
    UB.CreateBr(retBB);

    IRBuilder<> RB(retBB);
    RB.CreateRetVoid();
    return fn;
}

GlobalVariable *cacheTimingState(Module &M, ir::IRRandom &rng) {
    if (auto *existing =
            M.getGlobalVariable("morok.cachetime.state", /*AllowInternal=*/true))
        return existing;
    auto *i64 = Type::getInt64Ty(M.getContext());
    auto *gv = new GlobalVariable(
        M, i64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(i64, rng.next()), "morok.cachetime.state");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

Value *selectCacheTimingTarget(IRBuilder<> &B, Module &M,
                               const std::vector<Function *> &Targets,
                               Value *Index, const Twine &Name) {
    auto *ip = intPtrTy(M);
    Value *selected =
        B.CreatePtrToInt(Targets.front(), ip, Name + ".target0");
    for (std::size_t i = 1; i < Targets.size(); ++i) {
        Value *candidate = B.CreatePtrToInt(Targets[i], ip, Name + ".target");
        selected = B.CreateSelect(
            B.CreateICmpEQ(Index, ConstantInt::get(Index->getType(), i),
                           Name + ".is.target"),
            candidate, selected, Name + ".selected");
    }
    return selected;
}

LoadInst *loadDynamicCodeByte(IRBuilder<> &B, Module &M, Value *Addr,
                              const Twine &Name) {
    auto *LI = B.CreateLoad(Type::getInt8Ty(M.getContext()),
                            B.CreateIntToPtr(
                                Addr, PointerType::getUnqual(M.getContext()),
                                Name + ".ptr"),
                            Name);
    LI->setVolatile(true);
    LI->setAlignment(Align(1));
    return LI;
}

Value *emitCacheTimingChase(IRBuilder<> &B, Module &M,
                            const std::vector<Function *> &Targets,
                            Value *Seed, ir::IRRandom &rng) {
    auto *i64 = Type::getInt64Ty(M.getContext());
    auto *ip = intPtrTy(M);
    Value *state = B.CreateXor(Seed, ConstantInt::get(i64, rng.next()),
                               "morok.cachetime.seed");
    Value *mix = ConstantInt::get(i64, rng.next());
    constexpr unsigned kSteps = 32;
    for (unsigned step = 0; step < kSteps; ++step) {
        Value *scrambled = B.CreateXor(
            state,
            B.CreateLShr(state, ConstantInt::get(i64, (step % 19) + 1)),
            "morok.cachetime.idx.scramble");
        Value *idx64 =
            B.CreateURem(scrambled, ConstantInt::get(i64, Targets.size()),
                         "morok.cachetime.target.idx");
        Value *basePtr =
            selectCacheTimingTarget(B, M, Targets, idx64, "morok.cachetime");
        Value *base64 =
            B.CreateZExtOrTrunc(basePtr, i64, "morok.cachetime.base.wide");
        Value *base = B.CreateZExtOrTrunc(basePtr, ip, "morok.cachetime.base");
        Value *offset = B.CreateAnd(
            B.CreateLShr(state, ConstantInt::get(i64, (step % 13) + 3)),
            ConstantInt::get(i64, 63), "morok.cachetime.offset");
        Value *addr = B.CreateAdd(base, B.CreateZExtOrTrunc(offset, ip),
                                  "morok.cachetime.addr");
        LoadInst *byte = loadDynamicCodeByte(B, M, addr, "morok.cachetime.byte");
        Value *wideByte = B.CreateZExt(byte, i64, "morok.cachetime.byte.wide");
        state = B.CreateXor(
            B.CreateMul(B.CreateAdd(state, wideByte),
                        ConstantInt::get(i64, rng.next() | 1ULL)),
            B.CreateAdd(base64, ConstantInt::get(i64, step + 1)),
            "morok.cachetime.next");
        mix = B.CreateXor(
            B.CreateAdd(mix,
                        B.CreateMul(wideByte,
                                    ConstantInt::get(i64, rng.next() | 1ULL))),
            B.CreateShl(state, ConstantInt::get(i64, step % 7)),
            "morok.cachetime.mix");
    }
    return B.CreateXor(mix, state, "morok.cachetime.chase.mix");
}

Function *cacheTimingProbe(Module &M, GlobalVariable *State,
                           ir::IRRandom &rng, const Triple &TT,
                           const std::vector<Function *> &Targets) {
    if (Targets.empty())
        return nullptr;
    if (Function *existing = M.getFunction("morok.cachetime.oracle"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *fn = Function::Create(FunctionType::get(Type::getVoidTy(ctx), false),
                                GlobalValue::PrivateLinkage,
                                "morok.cachetime.oracle", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    IRBuilder<> B(entry);
    Value *badSamples = ConstantInt::get(i32, 0);
    Value *divergentSamples = ConstantInt::get(i32, 0);
    Value *mix = ConstantInt::get(i64, rng.next());
    const bool hasCycleClock = isX86Target(TT);
    const std::uint64_t primaryThreshold =
        hasCycleClock ? 30000000ULL : 20000000ULL;
    constexpr std::uint64_t secondaryThreshold = 20000000ULL;

    for (unsigned sample = 0; sample < 4; ++sample) {
        Value *primaryStart =
            emitTimingPrimaryClock(B, M, TT, "morok.cachetime.primary.start");
        Value *secondaryStart =
            emitTimingSecondaryClock(B, M, TT,
                                     "morok.cachetime.secondary.start");
        Value *seed = B.CreateXor(
            B.CreateAdd(primaryStart,
                        ConstantInt::get(i64, rng.next() ^ sample)),
            secondaryStart, "morok.cachetime.sample.seed");
        Value *chase = emitCacheTimingChase(B, M, Targets, seed, rng);
        Value *primaryEnd =
            emitTimingPrimaryClock(B, M, TT, "morok.cachetime.primary.end");
        Value *secondaryEnd =
            emitTimingSecondaryClock(B, M, TT, "morok.cachetime.secondary.end");

        Value *primaryDelta =
            B.CreateSub(primaryEnd, primaryStart,
                        "morok.cachetime.primary.delta");
        Value *secondaryDelta =
            B.CreateSub(secondaryEnd, secondaryStart,
                        "morok.cachetime.secondary.delta");
        Value *primarySlow =
            B.CreateICmpUGT(primaryDelta, ConstantInt::get(i64, primaryThreshold),
                            "morok.cachetime.primary.slow");
        Value *secondarySlow = B.CreateICmpUGT(
            secondaryDelta, ConstantInt::get(i64, secondaryThreshold),
            "morok.cachetime.secondary.slow");
        Value *sampleSlow = B.CreateOr(primarySlow, secondarySlow,
                                       "morok.cachetime.sample.slow");
        Value *sampleDiverged =
            B.CreateXor(primarySlow, secondarySlow,
                        "morok.cachetime.sample.diverged");
        badSamples =
            B.CreateAdd(badSamples, B.CreateZExt(sampleSlow, i32),
                        "morok.cachetime.bad.n");
        divergentSamples =
            B.CreateAdd(divergentSamples, B.CreateZExt(sampleDiverged, i32),
                        "morok.cachetime.divergent.n");
        mix = B.CreateXor(
            B.CreateAdd(mix,
                        B.CreateMul(primaryDelta,
                                    ConstantInt::get(i64, rng.next() | 1ULL))),
            B.CreateXor(chase,
                        B.CreateMul(secondaryDelta,
                                    ConstantInt::get(i64, rng.next() | 1ULL))),
            "morok.cachetime.total.mix");
    }

    foldState(B, State, mix, 0xD7C3A91E5B4062F8ULL, "morok.cachetime.mix");
    foldState(B, State, badSamples, 0x82F16D4C0A9B753EULL,
              "morok.cachetime.bad.samples");
    foldState(B, State, divergentSamples, 0x3E49C807D2A6519BULL,
              "morok.cachetime.divergent.samples");
    Value *badDistribution = B.CreateICmpUGE(
        badSamples, ConstantInt::get(i32, 2),
        "morok.cachetime.bad.distribution");
    Value *divergentDistribution = B.CreateICmpUGE(
        divergentSamples, ConstantInt::get(i32, 2),
        "morok.cachetime.divergent.distribution");
    foldFlag(B, State, badDistribution, 0xB6417D0ECA52893FULL,
             "morok.cachetime.bad.distribution");
    foldFlag(B, State, divergentDistribution, 0x59A3E7D14C2068BFULL,
             "morok.cachetime.divergent.distribution");
    B.CreateRetVoid();
    return fn;
}

GlobalVariable *microCanaryState(Module &M, ir::IRRandom &rng) {
    if (auto *existing = M.getGlobalVariable("morok.microcanary.state",
                                             /*AllowInternal=*/true))
        return existing;
    auto *i64 = Type::getInt64Ty(M.getContext());
    auto *gv = new GlobalVariable(
        M, i64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(i64, rng.next()), "morok.microcanary.state");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

GlobalVariable *microCanaryLine(Module &M) {
    if (auto *existing = M.getGlobalVariable("morok.microcanary.line",
                                             /*AllowInternal=*/true))
        return existing;
    auto *i8 = Type::getInt8Ty(M.getContext());
    auto *ty = ArrayType::get(i8, 128);
    auto *gv = new GlobalVariable(M, ty, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage,
                                  ConstantAggregateZero::get(ty),
                                  "morok.microcanary.line");
    gv->setAlignment(Align(64));
    return gv;
}

GlobalVariable *microCanaryEviction(Module &M) {
    if (auto *existing = M.getGlobalVariable("morok.microcanary.evict",
                                             /*AllowInternal=*/true))
        return existing;
    auto *i8 = Type::getInt8Ty(M.getContext());
    auto *ty = ArrayType::get(i8, 32768);
    auto *gv = new GlobalVariable(M, ty, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage,
                                  ConstantAggregateZero::get(ty),
                                  "morok.microcanary.evict");
    gv->setAlignment(Align(64));
    return gv;
}

Value *microCanaryPtr(IRBuilderBase &B, Module &M, GlobalVariable *GV,
                      std::uint64_t Offset, const Twine &Name) {
    return gepI8(B, M, GV, constIp(M, Offset), Name);
}

LoadInst *loadMicroCanaryByte(IRBuilderBase &B, Module &M, Value *Ptr,
                              const Twine &Name) {
    auto *LI = B.CreateLoad(Type::getInt8Ty(M.getContext()), Ptr, Name);
    LI->setVolatile(true);
    LI->setAlignment(Align(1));
    return LI;
}

void emitMicroCanaryEviction(IRBuilder<> &B, Module &M, GlobalVariable *Evict,
                             std::uint64_t Salt) {
    constexpr std::uint64_t kEvictBytes = 32768;
    for (unsigned i = 0; i < 64; ++i) {
        std::uint64_t off = (Salt + 521ULL * i + 4099ULL * (i % 7)) %
                            kEvictBytes;
        loadMicroCanaryByte(
            B, M, microCanaryPtr(B, M, Evict, off, "morok.microcanary.evict.ptr"),
            "morok.microcanary.evict.byte");
    }
}

struct MicroCanarySample {
    Value *primaryDelta = nullptr;
    Value *secondaryDelta = nullptr;
    Value *measuredByte = nullptr;
};

MicroCanarySample emitMicroCanarySample(IRBuilder<> &B, Module &M,
                                        Function *Fn, GlobalVariable *Line,
                                        GlobalVariable *Evict,
                                        const Triple &TT, ir::IRRandom &rng,
                                        unsigned Sample) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    BasicBlock *preheader = B.GetInsertBlock();
    auto *loopBB = BasicBlock::Create(ctx, "morok.microcanary.train", Fn);
    auto *touchBB = BasicBlock::Create(ctx, "morok.microcanary.predicted", Fn);
    auto *doneBB = BasicBlock::Create(ctx, "morok.microcanary.measure", Fn);

    const std::uint64_t lineOff = (Sample * 17u) & 63u;
    Value *linePtr = microCanaryPtr(B, M, Line, lineOff,
                                    "morok.microcanary.line.ptr");
    B.CreateBr(loopBB);

    IRBuilder<> LB(loopBB);
    auto *idx = LB.CreatePHI(i32, 2, "morok.microcanary.train.idx");
    idx->addIncoming(ConstantInt::get(i32, 0), preheader);
    emitMicroCanaryEviction(LB, M, Evict, rng.next() ^ Sample);
    Value *train = LB.CreateICmpULT(idx, ConstantInt::get(i32, 24),
                                    "morok.microcanary.train.taken");
    LB.CreateCondBr(train, touchBB, doneBB);

    IRBuilder<> TB(touchBB);
    LoadInst *specByte =
        loadMicroCanaryByte(TB, M, linePtr, "morok.microcanary.spec.byte");
    (void)specByte;
    Value *next =
        TB.CreateAdd(idx, ConstantInt::get(i32, 1),
                     "morok.microcanary.train.next");
    TB.CreateBr(loopBB);
    idx->addIncoming(next, touchBB);

    IRBuilder<> DB(doneBB);
    Value *primaryStart =
        emitTimingPrimaryClock(DB, M, TT, "morok.microcanary.primary.start");
    Value *secondaryStart =
        emitTimingSecondaryClock(DB, M, TT,
                                 "morok.microcanary.secondary.start");
    LoadInst *measured =
        loadMicroCanaryByte(DB, M, linePtr, "morok.microcanary.measure.byte");
    Value *primaryEnd =
        emitTimingPrimaryClock(DB, M, TT, "morok.microcanary.primary.end");
    Value *secondaryEnd =
        emitTimingSecondaryClock(DB, M, TT, "morok.microcanary.secondary.end");

    MicroCanarySample out;
    out.primaryDelta =
        DB.CreateSub(primaryEnd, primaryStart,
                     "morok.microcanary.primary.delta");
    out.secondaryDelta =
        DB.CreateSub(secondaryEnd, secondaryStart,
                     "morok.microcanary.secondary.delta");
    out.measuredByte = DB.CreateZExt(measured, Type::getInt64Ty(ctx),
                                     "morok.microcanary.byte.wide");
    B.SetInsertPoint(doneBB);
    return out;
}

Function *microarchitecturalCanaryProbe(Module &M, GlobalVariable *State,
                                        ir::IRRandom &rng, const Triple &TT) {
    if (Function *existing = M.getFunction("morok.microcanary.oracle"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *fn = Function::Create(FunctionType::get(Type::getVoidTy(ctx), false),
                                GlobalValue::PrivateLinkage,
                                "morok.microcanary.oracle", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    GlobalVariable *line = microCanaryLine(M);
    GlobalVariable *evict = microCanaryEviction(M);
    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    IRBuilder<> B(entry);
    Value *badSamples = ConstantInt::get(i32, 0);
    Value *divergentSamples = ConstantInt::get(i32, 0);
    Value *mix = ConstantInt::get(i64, rng.next());
    const bool hasCycleClock = isX86Target(TT);
    const std::uint64_t primaryThreshold =
        hasCycleClock ? 10000ULL : 5000000ULL;
    constexpr std::uint64_t secondaryThreshold = 1000000ULL;

    for (unsigned sample = 0; sample < 4; ++sample) {
        MicroCanarySample s =
            emitMicroCanarySample(B, M, fn, line, evict, TT, rng, sample);
        Value *primarySlow =
            B.CreateICmpUGT(s.primaryDelta,
                            ConstantInt::get(i64, primaryThreshold),
                            "morok.microcanary.primary.slow");
        Value *secondarySlow =
            B.CreateICmpUGT(s.secondaryDelta,
                            ConstantInt::get(i64, secondaryThreshold),
                            "morok.microcanary.secondary.slow");
        Value *sampleSlow = B.CreateOr(primarySlow, secondarySlow,
                                       "morok.microcanary.sample.slow");
        Value *sampleDiverged =
            B.CreateXor(primarySlow, secondarySlow,
                        "morok.microcanary.sample.diverged");
        badSamples =
            B.CreateAdd(badSamples, B.CreateZExt(sampleSlow, i32),
                        "morok.microcanary.bad.n");
        divergentSamples =
            B.CreateAdd(divergentSamples, B.CreateZExt(sampleDiverged, i32),
                        "morok.microcanary.divergent.n");
        mix = B.CreateXor(
            B.CreateAdd(mix,
                        B.CreateMul(s.primaryDelta,
                                    ConstantInt::get(i64, rng.next() | 1ULL))),
            B.CreateXor(
                s.measuredByte,
                B.CreateMul(s.secondaryDelta,
                            ConstantInt::get(i64, rng.next() | 1ULL))),
            "morok.microcanary.mix");
    }

    foldState(B, State, mix, 0xC9E1A47D328B506FULL,
              "morok.microcanary.mix");
    foldState(B, State, badSamples, 0x716D3C89E502A4BFULL,
              "morok.microcanary.bad.samples");
    foldState(B, State, divergentSamples, 0x4F2B95A71C0E6D38ULL,
              "morok.microcanary.divergent.samples");
    Value *badDistribution = B.CreateICmpUGE(
        badSamples, ConstantInt::get(i32, 2),
        "morok.microcanary.bad.distribution");
    Value *divergentDistribution = B.CreateICmpUGE(
        divergentSamples, ConstantInt::get(i32, 2),
        "morok.microcanary.divergent.distribution");
    foldFlag(B, State, badDistribution, 0xA5B0E176D83429CFULL,
             "morok.microcanary.bad.distribution");
    foldFlag(B, State, divergentDistribution, 0x2D78C4B50FA691E3ULL,
             "morok.microcanary.divergent.distribution");
    B.CreateRetVoid();
    return fn;
}

std::uint64_t fnv1aName(StringRef Name) {
    constexpr std::uint64_t kOffset = 1469598103934665603ULL;
    constexpr std::uint64_t kPrime = 1099511628211ULL;
    std::uint64_t h = kOffset;
    for (unsigned char c : Name.bytes()) {
        h ^= c;
        h *= kPrime;
    }
    return h;
}

std::uint64_t fnv1aLowerAsciiName(StringRef Name) {
    constexpr std::uint64_t kOffset = 1469598103934665603ULL;
    constexpr std::uint64_t kPrime = 1099511628211ULL;
    std::uint64_t h = kOffset;
    for (unsigned char c : Name.bytes()) {
        if (c >= 'A' && c <= 'Z')
            c = static_cast<unsigned char>(c + ('a' - 'A'));
        h ^= c;
        h *= kPrime;
    }
    return h;
}

GlobalVariable *windowsPeState(Module &M, ir::IRRandom &rng) {
    if (auto *existing =
            M.getGlobalVariable("morok.win.state", /*AllowInternal=*/true))
        return existing;
    auto *i64 = Type::getInt64Ty(M.getContext());
    auto *gv = new GlobalVariable(
        M, i64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(i64, rng.next()), "morok.win.state");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

GlobalVariable *windowsVehHandle(Module &M) {
    if (auto *existing =
            M.getGlobalVariable("morok.win.veh.handle", /*AllowInternal=*/true))
        return existing;
    auto *ptr = PointerType::getUnqual(M.getContext());
    auto *gv = new GlobalVariable(M, ptr, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage,
                                  ConstantPointerNull::get(ptr),
                                  "morok.win.veh.handle");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return gv;
}

Value *emitWindowsGsRead(IRBuilder<> &B, Module &M, std::uint32_t Offset,
                         const Twine &Name) {
    auto *ip = intPtrTy(M);
    auto *asmTy = FunctionType::get(ip, false);
    const char *slot = Offset == 0x30 ? "0x30" : "0x60";
    std::string asmText = std::string("movq %gs:") + slot + ", $0";
    InlineAsm *IA =
        InlineAsm::get(asmTy, asmText, "=r,~{dirflag},~{fpsr},~{flags}",
                       /*hasSideEffects=*/true);
    return B.CreateCall(asmTy, IA, {}, Name);
}

Function *windowsTebReader(Module &M) {
    if (Function *existing = M.getFunction("morok.win.teb"))
        return existing;
    const Triple TT(M.getTargetTriple());
    if (!TT.isOSWindows() || TT.getArch() != Triple::x86_64)
        return nullptr;

    LLVMContext &ctx = M.getContext();
    auto *ip = intPtrTy(M);
    auto *fn = Function::Create(FunctionType::get(ip, false),
                                GlobalValue::PrivateLinkage, "morok.win.teb",
                                &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    IRBuilder<> B(entry);
    B.CreateRet(emitWindowsGsRead(B, M, 0x30, "morok.win.teb.gs"));
    return fn;
}

Function *windowsPebReader(Module &M) {
    if (Function *existing = M.getFunction("morok.win.peb"))
        return existing;
    const Triple TT(M.getTargetTriple());
    if (!TT.isOSWindows() || TT.getArch() != Triple::x86_64)
        return nullptr;

    LLVMContext &ctx = M.getContext();
    auto *ip = intPtrTy(M);
    auto *fn = Function::Create(FunctionType::get(ip, false),
                                GlobalValue::PrivateLinkage, "morok.win.peb",
                                &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    IRBuilder<> B(entry);
    B.CreateRet(emitWindowsGsRead(B, M, 0x60, "morok.win.peb.gs"));
    return fn;
}

Function *windowsPeHashName(Module &M) {
    if (Function *existing = M.getFunction("morok.win.pe.hash"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(i64, {ptr}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.win.pe.hash", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    Argument *name = fn->getArg(0);
    name->setName("name");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *loopBB = BasicBlock::Create(ctx, "loop", fn);
    auto *bodyBB = BasicBlock::Create(ctx, "body", fn);
    auto *nextBB = BasicBlock::Create(ctx, "next", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    B.CreateBr(loopBB);

    IRBuilder<> LB(loopBB);
    auto *idx = LB.CreatePHI(ip, 2, "morok.win.pe.hash.idx");
    auto *acc = LB.CreatePHI(i64, 2, "morok.win.pe.hash.acc");
    idx->addIncoming(ConstantInt::get(ip, 0), entry);
    acc->addIncoming(ConstantInt::get(i64, 1469598103934665603ULL), entry);
    LB.CreateCondBr(LB.CreateICmpULT(idx, ConstantInt::get(ip, 256)), bodyBB,
                    retBB);

    IRBuilder<> BB(bodyBB);
    auto *ch = BB.CreateLoad(i8, gepI8(BB, M, name, idx,
                                       "morok.win.pe.hash.char.ptr"),
                             "morok.win.pe.hash.char");
    BB.CreateCondBr(BB.CreateICmpNE(ch, ConstantInt::get(i8, 0)), nextBB,
                    retBB);

    IRBuilder<> NB(nextBB);
    Value *wide = NB.CreateZExt(ch, i64, "morok.win.pe.hash.wide");
    Value *nextAcc =
        NB.CreateMul(NB.CreateXor(acc, wide, "morok.win.pe.hash.xor"),
                     ConstantInt::get(i64, 1099511628211ULL),
                     "morok.win.pe.hash.next");
    Value *nextIdx =
        NB.CreateAdd(idx, ConstantInt::get(ip, 1), "morok.win.pe.hash.idx.next");
    NB.CreateBr(loopBB);
    idx->addIncoming(nextIdx, nextBB);
    acc->addIncoming(nextAcc, nextBB);

    IRBuilder<> RB(retBB);
    RB.CreateRet(acc);
    return fn;
}

Function *windowsWideNameHash(Module &M) {
    if (Function *existing = M.getFunction("morok.win.wide.hash"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i16 = Type::getInt16Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(i64, {ptr, i16}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.win.wide.hash", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    Argument *name = fn->getArg(0);
    name->setName("name");
    Argument *bytes = fn->getArg(1);
    bytes->setName("bytes");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *loopBB = BasicBlock::Create(ctx, "loop", fn);
    auto *bodyBB = BasicBlock::Create(ctx, "body", fn);
    auto *nextBB = BasicBlock::Create(ctx, "next", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    Value *byteCount = B.CreateZExt(bytes, i32, "morok.win.wide.bytes");
    Value *charCount =
        B.CreateLShr(byteCount, ConstantInt::get(i32, 1),
                     "morok.win.wide.chars");
    Value *limit = B.CreateSelect(
        B.CreateICmpULT(charCount, ConstantInt::get(i32, 260)), charCount,
        ConstantInt::get(i32, 260), "morok.win.wide.limit");
    Value *hasName =
        B.CreateAnd(B.CreateICmpNE(name, ConstantPointerNull::get(ptr)),
                    B.CreateICmpNE(limit, ConstantInt::get(i32, 0)),
                    "morok.win.wide.present");
    B.CreateCondBr(hasName, loopBB, retBB);

    IRBuilder<> LB(loopBB);
    auto *idx = LB.CreatePHI(i32, 2, "morok.win.wide.idx");
    auto *acc = LB.CreatePHI(i64, 2, "morok.win.wide.acc");
    idx->addIncoming(ConstantInt::get(i32, 0), entry);
    acc->addIncoming(ConstantInt::get(i64, 1469598103934665603ULL), entry);
    LB.CreateCondBr(LB.CreateICmpULT(idx, limit), bodyBB, retBB);

    IRBuilder<> BB(bodyBB);
    Value *idxIp = BB.CreateZExt(idx, ip, "morok.win.wide.idx.ip");
    Value *off = BB.CreateMul(idxIp, ConstantInt::get(ip, 2),
                              "morok.win.wide.byte.off");
    Value *wideChar = loadAt(BB, M, i16, name, off, "morok.win.wide.char");
    Value *low =
        BB.CreateAnd(BB.CreateZExt(wideChar, i32), ConstantInt::get(i32, 0xff),
                     "morok.win.wide.low");
    Value *geA = BB.CreateICmpUGE(low, ConstantInt::get(i32, 'A'),
                                  "morok.win.wide.ge.a");
    Value *leZ = BB.CreateICmpULE(low, ConstantInt::get(i32, 'Z'),
                                  "morok.win.wide.le.z");
    Value *isUpper = BB.CreateAnd(geA, leZ, "morok.win.wide.upper");
    Value *lower = BB.CreateSelect(
        isUpper, BB.CreateAdd(low, ConstantInt::get(i32, 'a' - 'A')), low,
        "morok.win.wide.lower");
    BB.CreateCondBr(BB.CreateICmpNE(wideChar, ConstantInt::get(i16, 0)),
                    nextBB, retBB);

    IRBuilder<> NB(nextBB);
    Value *byte = NB.CreateTrunc(lower, i8, "morok.win.wide.byte");
    Value *wide = NB.CreateZExt(byte, i64, "morok.win.wide.byte.wide");
    Value *nextAcc =
        NB.CreateMul(NB.CreateXor(acc, wide, "morok.win.wide.xor"),
                     ConstantInt::get(i64, 1099511628211ULL),
                     "morok.win.wide.next");
    Value *nextIdx =
        NB.CreateAdd(idx, ConstantInt::get(i32, 1), "morok.win.wide.idx.next");
    NB.CreateBr(loopBB);
    idx->addIncoming(nextIdx, nextBB);
    acc->addIncoming(nextAcc, nextBB);

    IRBuilder<> RB(retBB);
    auto *retAcc = RB.CreatePHI(i64, 3, "morok.win.wide.ret");
    retAcc->addIncoming(ConstantInt::get(i64, 1469598103934665603ULL), entry);
    retAcc->addIncoming(acc, loopBB);
    retAcc->addIncoming(acc, bodyBB);
    RB.CreateRet(retAcc);
    return fn;
}

Function *windowsLdrModuleByHash(Module &M) {
    if (Function *existing = M.getFunction("morok.win.ldr.module"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i16 = Type::getInt16Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(ip, {ip, i64}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.win.ldr.module", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    Argument *peb = fn->getArg(0);
    peb->setName("peb");
    Argument *wanted = fn->getArg(1);
    wanted->setName("wanted");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *loopBB = BasicBlock::Create(ctx, "loop", fn);
    auto *bodyBB = BasicBlock::Create(ctx, "body", fn);
    auto *nextBB = BasicBlock::Create(ctx, "next", fn);
    auto *ret0BB = BasicBlock::Create(ctx, "ret0", fn);

    IRBuilder<> B(entry);
    Value *pebPtr = B.CreateIntToPtr(peb, ptr, "morok.win.ldr.peb.ptr");
    Value *ldr = loadAt(B, M, ip, pebPtr, 0x18, "morok.win.ldr.peb.ldr");
    Value *hasLdr = B.CreateICmpNE(ldr, ConstantInt::get(ip, 0),
                                   "morok.win.ldr.present");
    Value *head = B.CreateAdd(ldr, ConstantInt::get(ip, 0x20),
                              "morok.win.ldr.mem.head");
    Value *headPtr = B.CreateIntToPtr(head, ptr, "morok.win.ldr.head.ptr");
    Value *first = loadAt(B, M, ip, headPtr, 0ULL, "morok.win.ldr.first");
    Value *hasFirst = B.CreateAnd(
        hasLdr,
        B.CreateAnd(B.CreateICmpNE(first, ConstantInt::get(ip, 0)),
                    B.CreateICmpNE(first, head),
                    "morok.win.ldr.first.valid"),
        "morok.win.ldr.can.walk");
    B.CreateCondBr(hasFirst, loopBB, ret0BB);

    IRBuilder<> LB(loopBB);
    auto *cursor = LB.CreatePHI(ip, 2, "morok.win.ldr.cursor");
    auto *idx = LB.CreatePHI(i32, 2, "morok.win.ldr.idx");
    cursor->addIncoming(first, entry);
    idx->addIncoming(ConstantInt::get(i32, 0), entry);
    Value *withinLimit =
        LB.CreateICmpULT(idx, ConstantInt::get(i32, 32),
                         "morok.win.ldr.limit");
    Value *notHead =
        LB.CreateICmpNE(cursor, head, "morok.win.ldr.not.head");
    LB.CreateCondBr(LB.CreateAnd(withinLimit, notHead,
                                 "morok.win.ldr.keep.walking"),
                    bodyBB, ret0BB);

    IRBuilder<> BB(bodyBB);
    Value *entryBase =
        BB.CreateSub(cursor, ConstantInt::get(ip, 0x10),
                     "morok.win.ldr.entry.base");
    Value *entryPtr =
        BB.CreateIntToPtr(entryBase, ptr, "morok.win.ldr.entry.ptr");
    Value *dllBase = loadAt(BB, M, ip, entryPtr, 0x30,
                            "morok.win.ldr.dll.base");
    Value *nameBytes =
        loadAt(BB, M, i16, entryPtr, 0x58, "morok.win.ldr.name.bytes");
    Value *nameBuffer =
        loadAt(BB, M, ip, entryPtr, 0x60, "morok.win.ldr.name.buffer");
    Function *hashFn = windowsWideNameHash(M);
    Value *nameHash = BB.CreateCall(
        hashFn, {BB.CreateIntToPtr(nameBuffer, ptr, "morok.win.ldr.name.ptr"),
                 nameBytes},
        "morok.win.ldr.name.hash");
    BB.CreateCondBr(
        BB.CreateICmpEQ(nameHash, wanted, "morok.win.ldr.name.match"),
        ret0BB, nextBB);

    IRBuilder<> NB(nextBB);
    Value *cursorPtr =
        NB.CreateIntToPtr(cursor, ptr, "morok.win.ldr.cursor.ptr");
    Value *nextCursor =
        loadAt(NB, M, ip, cursorPtr, 0ULL, "morok.win.ldr.next.cursor");
    Value *nextIdx =
        NB.CreateAdd(idx, ConstantInt::get(i32, 1), "morok.win.ldr.next.idx");
    NB.CreateBr(loopBB);
    cursor->addIncoming(nextCursor, nextBB);
    idx->addIncoming(nextIdx, nextBB);

    IRBuilder<> RB(ret0BB);
    auto *result = RB.CreatePHI(ip, 3, "morok.win.ldr.result");
    result->addIncoming(ConstantInt::get(ip, 0), entry);
    result->addIncoming(dllBase, bodyBB);
    result->addIncoming(ConstantInt::get(ip, 0), loopBB);
    RB.CreateRet(result);
    return fn;
}

Function *windowsPeExportResolver(Module &M) {
    if (Function *existing = M.getFunction("morok.win.pe.resolve"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i16 = Type::getInt16Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(ip, {ip, i64}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.win.pe.resolve", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    Argument *base = fn->getArg(0);
    base->setName("base");
    Argument *wanted = fn->getArg(1);
    wanted->setName("wanted");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *mzBB = BasicBlock::Create(ctx, "mz", fn);
    auto *headersBB = BasicBlock::Create(ctx, "headers", fn);
    auto *loopBB = BasicBlock::Create(ctx, "loop", fn);
    auto *bodyBB = BasicBlock::Create(ctx, "body", fn);
    auto *matchBB = BasicBlock::Create(ctx, "match", fn);
    auto *nextBB = BasicBlock::Create(ctx, "next", fn);
    auto *ret0BB = BasicBlock::Create(ctx, "ret0", fn);

    // Guard the module base before dereferencing it. windowsLdrModuleByHash
    // returns 0 when the requested module is not in the loader list (e.g.
    // kernelbase.dll on NT 6.0 / Windows Vista, or user32.dll in a process that
    // never loaded it). Reading the MZ signature from a null base would fault in
    // a startup constructor, so reject base == 0 up front.
    IRBuilder<> B(entry);
    B.CreateCondBr(B.CreateICmpNE(base, ConstantInt::get(ip, 0),
                                  "morok.win.pe.base.present"),
                   mzBB, ret0BB);

    IRBuilder<> MZB(mzBB);
    Value *basePtr = MZB.CreateIntToPtr(base, ptr, "morok.win.pe.base.ptr");
    Value *mz = loadAt(MZB, M, i16, basePtr, 0ULL, "morok.win.pe.mz");
    MZB.CreateCondBr(MZB.CreateICmpEQ(mz, ConstantInt::get(i16, 0x5A4D)),
                     headersBB, ret0BB);

    IRBuilder<> HB(headersBB);
    Value *lfanew32 = loadAt(HB, M, i32, basePtr, 0x3c,
                             "morok.win.pe.lfanew");
    Value *lfanew = HB.CreateZExt(lfanew32, ip, "morok.win.pe.lfanew.wide");
    Value *ntPtr = gepI8(HB, M, basePtr, lfanew, "morok.win.pe.nt");
    Value *sig = loadAt(HB, M, i32, ntPtr, 0ULL, "morok.win.pe.sig");
    Value *magic = loadAt(HB, M, i16, ntPtr, 24, "morok.win.pe.magic");
    Value *isPe32 = HB.CreateICmpEQ(magic, ConstantInt::get(i16, 0x10B),
                                    "morok.win.pe.pe32");
    Value *isPe64 = HB.CreateICmpEQ(magic, ConstantInt::get(i16, 0x20B),
                                    "morok.win.pe.pe64");
    Value *dataDirOff = HB.CreateSelect(isPe32, ConstantInt::get(ip, 120),
                                        ConstantInt::get(ip, 136),
                                        "morok.win.pe.datadir.off");
    Value *exportRva = loadAt(HB, M, i32, ntPtr, dataDirOff,
                              "morok.win.pe.export.rva");
    Value *exportSizeOff =
        HB.CreateAdd(dataDirOff, ConstantInt::get(ip, 4),
                     "morok.win.pe.export.size.off");
    Value *exportSize =
        loadAt(HB, M, i32, ntPtr, exportSizeOff, "morok.win.pe.export.size");
    Value *headersOk = HB.CreateAnd(
        HB.CreateICmpEQ(sig, ConstantInt::get(i32, 0x4550)),
        HB.CreateAnd(HB.CreateOr(isPe32, isPe64),
                     HB.CreateAnd(
                         HB.CreateICmpNE(exportRva, ConstantInt::get(i32, 0)),
                         HB.CreateICmpNE(exportSize, ConstantInt::get(i32, 0)),
                         "morok.win.pe.export.nonempty")),
        "morok.win.pe.headers.ok");
    HB.CreateCondBr(headersOk, loopBB, ret0BB);

    IRBuilder<> LB(loopBB);
    auto *idx = LB.CreatePHI(i32, 2, "morok.win.pe.name.idx");
    idx->addIncoming(ConstantInt::get(i32, 0), headersBB);
    Value *exportDir = gepI8(
        LB, M, basePtr, LB.CreateZExt(exportRva, ip, "morok.win.pe.export.off"),
        "morok.win.pe.export.dir");
    Value *numberNames =
        loadAt(LB, M, i32, exportDir, 24, "morok.win.pe.number.names");
    Value *limit = LB.CreateSelect(
        LB.CreateICmpULT(numberNames, ConstantInt::get(i32, 4096)),
        numberNames, ConstantInt::get(i32, 4096), "morok.win.pe.name.limit");
    LB.CreateCondBr(LB.CreateICmpULT(idx, limit), bodyBB, ret0BB);

    IRBuilder<> BB(bodyBB);
    Value *funcs = gepI8(
        BB, M, basePtr,
        BB.CreateZExt(loadAt(BB, M, i32, exportDir, 28,
                             "morok.win.pe.functions.rva"),
                      ip),
        "morok.win.pe.functions");
    Value *names = gepI8(
        BB, M, basePtr,
        BB.CreateZExt(loadAt(BB, M, i32, exportDir, 32,
                             "morok.win.pe.names.rva"),
                      ip),
        "morok.win.pe.names");
    Value *ords = gepI8(
        BB, M, basePtr,
        BB.CreateZExt(loadAt(BB, M, i32, exportDir, 36,
                             "morok.win.pe.ordinals.rva"),
                      ip),
        "morok.win.pe.ordinals");
    Value *idxIp = BB.CreateZExt(idx, ip, "morok.win.pe.name.idx.ip");
    Value *nameRva = loadAt(
        BB, M, i32, names,
        BB.CreateMul(idxIp, ConstantInt::get(ip, 4), "morok.win.pe.name.slot"),
        "morok.win.pe.name.rva");
    Value *namePtr =
        gepI8(BB, M, basePtr, BB.CreateZExt(nameRva, ip), "morok.win.pe.name");
    Function *hashFn = windowsPeHashName(M);
    Value *hash = BB.CreateCall(hashFn, {namePtr}, "morok.win.pe.name.hash");
    BB.CreateCondBr(BB.CreateICmpEQ(hash, wanted, "morok.win.pe.hash.match"),
                    matchBB, nextBB);

    IRBuilder<> MB(matchBB);
    Value *ord = loadAt(
        MB, M, i16, ords,
        MB.CreateMul(idxIp, ConstantInt::get(ip, 2), "morok.win.pe.ord.slot"),
        "morok.win.pe.ordinal");
    Value *funcRva = loadAt(
        MB, M, i32, funcs,
        MB.CreateMul(MB.CreateZExt(ord, ip), ConstantInt::get(ip, 4),
                     "morok.win.pe.func.slot"),
        "morok.win.pe.func.rva");
    Value *forwarderOff =
        MB.CreateSub(funcRva, exportRva, "morok.win.pe.forwarder.off");
    Value *isForwarder =
        MB.CreateICmpULT(forwarderOff, exportSize, "morok.win.pe.forwarder");
    Value *funcAddr = MB.CreateAdd(base, MB.CreateZExt(funcRva, ip),
                                   "morok.win.pe.func.addr");
    MB.CreateRet(MB.CreateSelect(isForwarder, ConstantInt::get(ip, 0),
                                 funcAddr, "morok.win.pe.func.safe"));

    IRBuilder<> NB(nextBB);
    Value *nextIdx =
        NB.CreateAdd(idx, ConstantInt::get(i32, 1), "morok.win.pe.name.next");
    NB.CreateBr(loopBB);
    idx->addIncoming(nextIdx, nextBB);

    IRBuilder<> RB(ret0BB);
    RB.CreateRet(ConstantInt::get(ip, 0));
    return fn;
}

Function *windowsPeTextSection(Module &M) {
    if (Function *existing = M.getFunction("morok.win.pe.text"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i16 = Type::getInt16Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(i64, {ip}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.win.pe.text", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    Argument *base = fn->getArg(0);
    base->setName("base");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *headersBB = BasicBlock::Create(ctx, "headers", fn);
    auto *loopBB = BasicBlock::Create(ctx, "loop", fn);
    auto *bodyBB = BasicBlock::Create(ctx, "body", fn);
    auto *foundBB = BasicBlock::Create(ctx, "found", fn);
    auto *nextBB = BasicBlock::Create(ctx, "next", fn);
    auto *ret0BB = BasicBlock::Create(ctx, "ret0", fn);

    IRBuilder<> B(entry);
    Value *basePtr = B.CreateIntToPtr(base, ptr, "morok.win.pe.text.base.ptr");
    Value *mz = loadAt(B, M, i16, basePtr, 0ULL, "morok.win.pe.text.mz");
    B.CreateCondBr(B.CreateICmpEQ(mz, ConstantInt::get(i16, 0x5A4D)),
                   headersBB, ret0BB);

    IRBuilder<> HB(headersBB);
    Value *lfanew32 = loadAt(HB, M, i32, basePtr, 0x3c,
                             "morok.win.pe.text.lfanew");
    Value *lfanew = HB.CreateZExt(lfanew32, ip, "morok.win.pe.text.lfanew.ip");
    Value *ntPtr = gepI8(HB, M, basePtr, lfanew, "morok.win.pe.text.nt");
    Value *sig = loadAt(HB, M, i32, ntPtr, 0ULL, "morok.win.pe.text.sig");
    Value *sections =
        loadAt(HB, M, i16, ntPtr, 6, "morok.win.pe.text.sections");
    Value *optSize =
        loadAt(HB, M, i16, ntPtr, 20, "morok.win.pe.text.opt.size");
    Value *sectionBase = gepI8(
        HB, M, ntPtr,
        HB.CreateAdd(ConstantInt::get(ip, 24),
                     HB.CreateZExt(optSize, ip, "morok.win.pe.text.opt.ip"),
                     "morok.win.pe.text.section.off"),
        "morok.win.pe.text.section.base");
    Value *sectionCount = HB.CreateZExt(sections, i32,
                                        "morok.win.pe.text.section.count");
    Value *limit = HB.CreateSelect(
        HB.CreateICmpULT(sectionCount, ConstantInt::get(i32, 96)),
        sectionCount, ConstantInt::get(i32, 96),
        "morok.win.pe.text.section.limit");
    Value *headersOk = HB.CreateAnd(
        HB.CreateICmpEQ(sig, ConstantInt::get(i32, 0x4550)),
        HB.CreateICmpNE(limit, ConstantInt::get(i32, 0)),
        "morok.win.pe.text.headers.ok");
    HB.CreateCondBr(headersOk, loopBB, ret0BB);

    IRBuilder<> LB(loopBB);
    auto *idx = LB.CreatePHI(i32, 2, "morok.win.pe.text.idx");
    idx->addIncoming(ConstantInt::get(i32, 0), headersBB);
    LB.CreateCondBr(LB.CreateICmpULT(idx, limit,
                                     "morok.win.pe.text.idx.in.range"),
                    bodyBB, ret0BB);

    IRBuilder<> SB(bodyBB);
    Value *idxIp = SB.CreateZExt(idx, ip, "morok.win.pe.text.idx.ip");
    Value *sectionPtr =
        gepI8(SB, M, sectionBase,
              SB.CreateMul(idxIp, ConstantInt::get(ip, 40),
                           "morok.win.pe.text.section.stride"),
              "morok.win.pe.text.section.ptr");
    Value *name0 =
        loadAt(SB, M, i32, sectionPtr, 0ULL, "morok.win.pe.text.name0");
    Value *virtualSize =
        loadAt(SB, M, i32, sectionPtr, 8, "morok.win.pe.text.virtual.size");
    Value *virtualRva =
        loadAt(SB, M, i32, sectionPtr, 12, "morok.win.pe.text.rva");
    Value *rawSize =
        loadAt(SB, M, i32, sectionPtr, 16, "morok.win.pe.text.raw.size");
    Value *chars =
        loadAt(SB, M, i32, sectionPtr, 36, "morok.win.pe.text.characteristics");
    Value *nameHit =
        SB.CreateICmpEQ(name0, ConstantInt::get(i32, 0x7865742e),
                        "morok.win.pe.text.name.match");
    Value *isCode =
        SB.CreateICmpNE(SB.CreateAnd(chars, ConstantInt::get(i32, 0x20)),
                        ConstantInt::get(i32, 0),
                        "morok.win.pe.text.code.flag");
    Value *isExecute = SB.CreateICmpNE(
        SB.CreateAnd(chars, ConstantInt::get(i32, 0x20000000)),
        ConstantInt::get(i32, 0), "morok.win.pe.text.execute.flag");
    Value *size = SB.CreateSelect(
        SB.CreateICmpNE(virtualSize, ConstantInt::get(i32, 0)),
        virtualSize, rawSize, "morok.win.pe.text.size");
    Value *sectionOk = SB.CreateAnd(
        SB.CreateOr(nameHit, SB.CreateAnd(isCode, isExecute,
                                          "morok.win.pe.text.code.exec"),
                    "morok.win.pe.text.kind"),
        SB.CreateAnd(SB.CreateICmpNE(size, ConstantInt::get(i32, 0)),
                     SB.CreateICmpNE(virtualRva, ConstantInt::get(i32, 0)),
                     "morok.win.pe.text.bounds"),
        "morok.win.pe.text.match");
    SB.CreateCondBr(sectionOk, foundBB, nextBB);

    IRBuilder<> FB(foundBB);
    Value *packed = FB.CreateOr(
        FB.CreateZExt(virtualRva, i64),
        FB.CreateShl(FB.CreateZExt(size, i64), ConstantInt::get(i64, 32)),
        "morok.win.pe.text.pack");
    FB.CreateRet(packed);

    IRBuilder<> NB(nextBB);
    Value *nextIdx =
        NB.CreateAdd(idx, ConstantInt::get(i32, 1),
                     "morok.win.pe.text.next");
    NB.CreateBr(loopBB);
    idx->addIncoming(nextIdx, nextBB);

    IRBuilder<> RB(ret0BB);
    RB.CreateRet(ConstantInt::get(i64, 0));
    return fn;
}

Value *storeWindowsWideLiteral(IRBuilderBase &B, Module &M,
                               std::initializer_list<char> Chars,
                               const Twine &Name) {
    LLVMContext &ctx = M.getContext();
    auto *i16 = Type::getInt16Ty(ctx);
    auto *arrTy = ArrayType::get(i16, Chars.size() + 1);
    AllocaInst *buf = B.CreateAlloca(arrTy, nullptr, Name + ".buf");
    unsigned idx = 0;
    for (char ch : Chars) {
        storeAt(B, M, buf, static_cast<unsigned long long>(idx) * 2ULL,
                ConstantInt::get(i16, static_cast<unsigned char>(ch)),
                Name + ".char");
        ++idx;
    }
    storeAt(B, M, buf, static_cast<unsigned long long>(idx) * 2ULL,
            ConstantInt::get(i16, 0), Name + ".nul");
    return buf;
}

Function *windowsKnownDllUnhookHelper(Module &M) {
    if (Function *existing = M.getFunction("morok.win.unhook.known"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i16 = Type::getInt16Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(
        FunctionType::get(i32, {ip, ptr, i16, ip, ip, ip, ip, ip}, false),
        GlobalValue::PrivateLinkage, "morok.win.unhook.known", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    Argument *liveBase = fn->getArg(0);
    liveBase->setName("live_base");
    Argument *wideName = fn->getArg(1);
    wideName->setName("wide_name");
    Argument *nameBytes = fn->getArg(2);
    nameBytes->setName("name_bytes");
    Argument *openSection = fn->getArg(3);
    openSection->setName("open_section");
    Argument *mapView = fn->getArg(4);
    mapView->setName("map_view");
    Argument *unmapView = fn->getArg(5);
    unmapView->setName("unmap_view");
    Argument *protect = fn->getArg(6);
    protect->setName("protect");
    Argument *close = fn->getArg(7);
    close->setName("close");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *openBB = BasicBlock::Create(ctx, "open", fn);
    auto *mapBB = BasicBlock::Create(ctx, "map", fn);
    auto *textBB = BasicBlock::Create(ctx, "text", fn);
    auto *protectBB = BasicBlock::Create(ctx, "protect", fn);
    auto *qLoopBB = BasicBlock::Create(ctx, "copy.q.loop", fn);
    auto *qBodyBB = BasicBlock::Create(ctx, "copy.q.body", fn);
    auto *byteLoopBB = BasicBlock::Create(ctx, "copy.byte.loop", fn);
    auto *byteBodyBB = BasicBlock::Create(ctx, "copy.byte.body", fn);
    auto *restoreBB = BasicBlock::Create(ctx, "restore", fn);
    auto *cleanupBB = BasicBlock::Create(ctx, "cleanup", fn);
    auto *unmapBB = BasicBlock::Create(ctx, "unmap", fn);
    auto *closeGateBB = BasicBlock::Create(ctx, "close.gate", fn);
    auto *closeBB = BasicBlock::Create(ctx, "close", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    auto *unicodeTy = ArrayType::get(i8, 16);
    auto *objectAttrTy = ArrayType::get(i8, 48);
    AllocaInst *unicode =
        B.CreateAlloca(unicodeTy, nullptr, "morok.win.unhook.unicode");
    AllocaInst *objectAttrs =
        B.CreateAlloca(objectAttrTy, nullptr, "morok.win.unhook.oa");
    AllocaInst *sectionHandle =
        B.CreateAlloca(ip, nullptr, "morok.win.unhook.section");
    AllocaInst *viewBase =
        B.CreateAlloca(ip, nullptr, "morok.win.unhook.view.base");
    AllocaInst *viewSize =
        B.CreateAlloca(ip, nullptr, "morok.win.unhook.view.size");
    AllocaInst *baseSlot =
        B.CreateAlloca(ip, nullptr, "morok.win.unhook.protect.base");
    AllocaInst *sizeSlot =
        B.CreateAlloca(ip, nullptr, "morok.win.unhook.protect.size");
    AllocaInst *oldProt =
        B.CreateAlloca(i32, nullptr, "morok.win.unhook.oldprot");
    AllocaInst *result =
        B.CreateAlloca(i32, nullptr, "morok.win.unhook.result");
    B.CreateStore(ConstantInt::get(ip, 0), sectionHandle)->setVolatile(true);
    B.CreateStore(ConstantInt::get(ip, 0), viewBase)->setVolatile(true);
    B.CreateStore(ConstantInt::get(ip, 0), viewSize)->setVolatile(true);
    B.CreateStore(ConstantInt::get(ip, 0), baseSlot)->setVolatile(true);
    B.CreateStore(ConstantInt::get(ip, 0), sizeSlot)->setVolatile(true);
    B.CreateStore(ConstantInt::get(i32, 0), oldProt)->setVolatile(true);
    B.CreateStore(ConstantInt::getSigned(i32, -1), result)->setVolatile(true);
    storeAt(B, M, unicode, 0, nameBytes, "morok.win.unhook.us.length");
    storeAt(B, M, unicode, 2,
            B.CreateAdd(nameBytes, ConstantInt::get(i16, 2),
                        "morok.win.unhook.us.max"),
            "morok.win.unhook.us.max.store");
    storeAt(B, M, unicode, 8, wideName, "morok.win.unhook.us.buffer");
    storeAt(B, M, objectAttrs, 0, ConstantInt::get(i32, 48),
            "morok.win.unhook.oa.length");
    storeAt(B, M, objectAttrs, 8, ConstantPointerNull::get(ptr),
            "morok.win.unhook.oa.root");
    storeAt(B, M, objectAttrs, 16, unicode, "morok.win.unhook.oa.name");
    storeAt(B, M, objectAttrs, 24, ConstantInt::get(i32, 0x40),
            "morok.win.unhook.oa.attrs");
    storeAt(B, M, objectAttrs, 32, ConstantPointerNull::get(ptr),
            "morok.win.unhook.oa.sd");
    storeAt(B, M, objectAttrs, 40, ConstantPointerNull::get(ptr),
            "morok.win.unhook.oa.sqos");
    Value *ready = B.CreateAnd(
        B.CreateAnd(B.CreateICmpNE(liveBase, ConstantInt::get(ip, 0)),
                    B.CreateICmpNE(wideName, ConstantPointerNull::get(ptr)),
                    "morok.win.unhook.image.ready"),
        B.CreateAnd(
            B.CreateAnd(B.CreateICmpNE(openSection, ConstantInt::get(ip, 0)),
                        B.CreateICmpNE(mapView, ConstantInt::get(ip, 0)),
                        "morok.win.unhook.map.ready"),
            B.CreateAnd(B.CreateICmpNE(unmapView, ConstantInt::get(ip, 0)),
                        B.CreateAnd(
                            B.CreateICmpNE(protect, ConstantInt::get(ip, 0)),
                            B.CreateICmpNE(close, ConstantInt::get(ip, 0)),
                            "morok.win.unhook.close.ready"),
                        "morok.win.unhook.cleanup.ready"),
            "morok.win.unhook.nt.ready"),
        "morok.win.unhook.ready");
    B.CreateCondBr(ready, openBB, retBB);

    IRBuilder<> OB(openBB);
    auto *openTy = FunctionType::get(i32, {ptr, i32, ptr}, false);
    Value *openStatus = OB.CreateCall(
        openTy, OB.CreateIntToPtr(openSection, ptr,
                                  "morok.win.unhook.ntopensection.ptr"),
        {sectionHandle, ConstantInt::get(i32, 0x0004), objectAttrs},
        "morok.win.unhook.ntopensection.status");
    OB.CreateStore(openStatus, result)->setVolatile(true);
    OB.CreateCondBr(OB.CreateICmpSGE(openStatus, ConstantInt::get(i32, 0),
                                     "morok.win.unhook.ntopensection.ok"),
                    mapBB, cleanupBB);

    IRBuilder<> MB(mapBB);
    auto *mapTy = FunctionType::get(
        i32, {ptr, ptr, ptr, ip, ip, ptr, ptr, i32, i32, i32}, false);
    Value *sectionValue =
        MB.CreateLoad(ip, sectionHandle, "morok.win.unhook.section.handle");
    cast<LoadInst>(sectionValue)->setVolatile(true);
    Value *mapStatus = MB.CreateCall(
        mapTy,
        MB.CreateIntToPtr(mapView, ptr, "morok.win.unhook.ntmapview.ptr"),
        {MB.CreateIntToPtr(sectionValue, ptr, "morok.win.unhook.section.ptr"),
         MB.CreateIntToPtr(ConstantInt::getSigned(ip, -1), ptr,
                           "morok.win.unhook.current.process"),
         viewBase, ConstantInt::get(ip, 0), ConstantInt::get(ip, 0),
         ConstantPointerNull::get(ptr), viewSize, ConstantInt::get(i32, 1),
         ConstantInt::get(i32, 0), ConstantInt::get(i32, 0x02)},
        "morok.win.unhook.ntmapview.status");
    MB.CreateStore(mapStatus, result)->setVolatile(true);
    MB.CreateCondBr(MB.CreateICmpSGE(mapStatus, ConstantInt::get(i32, 0),
                                     "morok.win.unhook.ntmapview.ok"),
                    textBB, cleanupBB);

    IRBuilder<> TB(textBB);
    Function *textFinder = windowsPeTextSection(M);
    Value *mappedBase =
        TB.CreateLoad(ip, viewBase, "morok.win.unhook.mapped.base");
    cast<LoadInst>(mappedBase)->setVolatile(true);
    Value *liveText =
        TB.CreateCall(textFinder, {liveBase}, "morok.win.unhook.live.text");
    Value *mappedText =
        TB.CreateCall(textFinder, {mappedBase}, "morok.win.unhook.mapped.text");
    Value *liveRva32 = TB.CreateTrunc(liveText, i32,
                                      "morok.win.unhook.live.rva32");
    Value *mappedRva32 = TB.CreateTrunc(mappedText, i32,
                                        "morok.win.unhook.mapped.rva32");
    Value *liveSize32 =
        TB.CreateTrunc(TB.CreateLShr(liveText, ConstantInt::get(i64, 32)),
                       i32, "morok.win.unhook.live.size32");
    Value *mappedSize32 =
        TB.CreateTrunc(TB.CreateLShr(mappedText, ConstantInt::get(i64, 32)),
                       i32, "morok.win.unhook.mapped.size32");
    Value *minSize32 = TB.CreateSelect(
        TB.CreateICmpULT(liveSize32, mappedSize32,
                         "morok.win.unhook.size.live.smaller"),
        liveSize32, mappedSize32, "morok.win.unhook.min.size32");
    Value *copySize = TB.CreateZExt(
        TB.CreateSelect(
            TB.CreateICmpULT(minSize32, ConstantInt::get(i32, 0x01000000)),
            minSize32, ConstantInt::get(i32, 0x01000000),
            "morok.win.unhook.copy.size32"),
        ip, "morok.win.unhook.copy.size");
    Value *liveRva = TB.CreateZExt(liveRva32, ip,
                                   "morok.win.unhook.live.rva");
    Value *mappedRva = TB.CreateZExt(mappedRva32, ip,
                                     "morok.win.unhook.mapped.rva");
    Value *targetBase =
        TB.CreateAdd(liveBase, liveRva, "morok.win.unhook.live.text.base");
    Value *sourceBase =
        TB.CreateAdd(mappedBase, mappedRva, "morok.win.unhook.clean.text.base");
    Value *textReady = TB.CreateAnd(
        TB.CreateAnd(TB.CreateICmpNE(liveText, ConstantInt::get(i64, 0)),
                     TB.CreateICmpNE(mappedText, ConstantInt::get(i64, 0)),
                     "morok.win.unhook.text.present"),
        TB.CreateICmpNE(copySize, ConstantInt::get(ip, 0),
                        "morok.win.unhook.copy.nonzero"),
        "morok.win.unhook.text.ready");
    TB.CreateStore(TB.CreateSelect(textReady, ConstantInt::get(i32, 0),
                                   ConstantInt::getSigned(i32, -4),
                                   "morok.win.unhook.text.result"),
                   result)
        ->setVolatile(true);
    TB.CreateCondBr(textReady, protectBB, cleanupBB);

    IRBuilder<> PB(protectBB);
    PB.CreateStore(targetBase, baseSlot)->setVolatile(true);
    PB.CreateStore(copySize, sizeSlot)->setVolatile(true);
    auto *protectTy = FunctionType::get(i32, {ptr, ptr, ptr, i32, ptr}, false);
    Value *protectPtr =
        PB.CreateIntToPtr(protect, ptr, "morok.win.unhook.ntprotect.ptr");
    Value *protectStatus = PB.CreateCall(
        protectTy, protectPtr,
        {PB.CreateIntToPtr(ConstantInt::getSigned(ip, -1), ptr),
         baseSlot, sizeSlot, ConstantInt::get(i32, 0x40), oldProt},
        "morok.win.unhook.ntprotect.status");
    PB.CreateStore(protectStatus, result)->setVolatile(true);
    Value *qLimit =
        PB.CreateAnd(copySize, ConstantInt::get(ip, ~7ULL),
                     "morok.win.unhook.copy.q.limit");
    PB.CreateCondBr(PB.CreateICmpSGE(protectStatus, ConstantInt::get(i32, 0),
                                     "morok.win.unhook.ntprotect.ok"),
                    qLoopBB, cleanupBB);

    IRBuilder<> QL(qLoopBB);
    auto *qIdx = QL.CreatePHI(ip, 2, "morok.win.unhook.copy.q.idx");
    qIdx->addIncoming(ConstantInt::get(ip, 0), protectBB);
    QL.CreateCondBr(QL.CreateICmpULT(qIdx, qLimit,
                                     "morok.win.unhook.copy.q.more"),
                    qBodyBB, byteLoopBB);

    IRBuilder<> QB(qBodyBB);
    Value *qSrc = gepI8(QB, M, QB.CreateIntToPtr(sourceBase, ptr),
                        qIdx, "morok.win.unhook.copy.q.src");
    Value *qDst = gepI8(QB, M, QB.CreateIntToPtr(targetBase, ptr),
                        qIdx, "morok.win.unhook.copy.q.dst");
    auto *qWord = QB.CreateLoad(i64, qSrc, "morok.win.unhook.copy.qword");
    qWord->setVolatile(true);
    qWord->setAlignment(Align(1));
    auto *qStore = QB.CreateStore(qWord, qDst);
    qStore->setVolatile(true);
    qStore->setAlignment(Align(1));
    Value *qNext =
        QB.CreateAdd(qIdx, ConstantInt::get(ip, 8),
                     "morok.win.unhook.copy.q.next");
    QB.CreateBr(qLoopBB);
    qIdx->addIncoming(qNext, qBodyBB);

    IRBuilder<> BL(byteLoopBB);
    auto *bIdx = BL.CreatePHI(ip, 2, "morok.win.unhook.copy.byte.idx");
    bIdx->addIncoming(qLimit, qLoopBB);
    BL.CreateCondBr(BL.CreateICmpULT(bIdx, copySize,
                                     "morok.win.unhook.copy.byte.more"),
                    byteBodyBB, restoreBB);

    IRBuilder<> BB(byteBodyBB);
    Value *bSrc = gepI8(BB, M, BB.CreateIntToPtr(sourceBase, ptr),
                        bIdx, "morok.win.unhook.copy.byte.src");
    Value *bDst = gepI8(BB, M, BB.CreateIntToPtr(targetBase, ptr),
                        bIdx, "morok.win.unhook.copy.byte.dst");
    auto *byte = BB.CreateLoad(i8, bSrc, "morok.win.unhook.copy.byte");
    byte->setVolatile(true);
    byte->setAlignment(Align(1));
    auto *byteStore = BB.CreateStore(byte, bDst);
    byteStore->setVolatile(true);
    byteStore->setAlignment(Align(1));
    Value *bNext =
        BB.CreateAdd(bIdx, ConstantInt::get(ip, 1),
                     "morok.win.unhook.copy.byte.next");
    BB.CreateBr(byteLoopBB);
    bIdx->addIncoming(bNext, byteBodyBB);

    IRBuilder<> RB(restoreBB);
    Value *oldProtValue =
        RB.CreateLoad(i32, oldProt, "morok.win.unhook.oldprot.value");
    cast<LoadInst>(oldProtValue)->setVolatile(true);
    RB.CreateStore(targetBase, baseSlot)->setVolatile(true);
    RB.CreateStore(copySize, sizeSlot)->setVolatile(true);
    Value *restoreStatus = RB.CreateCall(
        protectTy, protectPtr,
        {RB.CreateIntToPtr(ConstantInt::getSigned(ip, -1), ptr),
         baseSlot, sizeSlot, oldProtValue, oldProt},
        "morok.win.unhook.ntprotect.restore");
    RB.CreateStore(restoreStatus, result)->setVolatile(true);
    RB.CreateBr(cleanupBB);

    IRBuilder<> CB(cleanupBB);
    Value *mappedForCleanup =
        CB.CreateLoad(ip, viewBase, "morok.win.unhook.cleanup.mapped");
    cast<LoadInst>(mappedForCleanup)->setVolatile(true);
    CB.CreateCondBr(CB.CreateICmpNE(mappedForCleanup, ConstantInt::get(ip, 0),
                                    "morok.win.unhook.cleanup.has.mapping"),
                    unmapBB, closeGateBB);

    IRBuilder<> UB(unmapBB);
    auto *unmapTy = FunctionType::get(i32, {ptr, ptr}, false);
    Value *unmapStatus = UB.CreateCall(
        unmapTy,
        UB.CreateIntToPtr(unmapView, ptr, "morok.win.unhook.ntunmap.ptr"),
        {UB.CreateIntToPtr(ConstantInt::getSigned(ip, -1), ptr),
         UB.CreateIntToPtr(mappedForCleanup, ptr,
                           "morok.win.unhook.cleanup.mapped.ptr")},
        "morok.win.unhook.ntunmap.status");
    UB.CreateStore(ConstantInt::get(ip, 0), viewBase)->setVolatile(true);
    UB.CreateBr(closeGateBB);

    IRBuilder<> CGB(closeGateBB);
    Value *handleForCleanup =
        CGB.CreateLoad(ip, sectionHandle, "morok.win.unhook.cleanup.section");
    cast<LoadInst>(handleForCleanup)->setVolatile(true);
    CGB.CreateCondBr(CGB.CreateICmpNE(handleForCleanup, ConstantInt::get(ip, 0),
                                      "morok.win.unhook.cleanup.has.section"),
                     closeBB, retBB);

    IRBuilder<> CLB(closeBB);
    auto *closeTy = FunctionType::get(i32, {ptr}, false);
    Value *closeStatus = CLB.CreateCall(
        closeTy, CLB.CreateIntToPtr(close, ptr,
                                    "morok.win.unhook.ntclose.ptr"),
        {CLB.CreateIntToPtr(handleForCleanup, ptr,
                            "morok.win.unhook.cleanup.section.ptr")},
        "morok.win.unhook.ntclose.status");
    (void)unmapStatus;
    (void)closeStatus;
    CLB.CreateStore(ConstantInt::get(ip, 0), sectionHandle)->setVolatile(true);
    CLB.CreateBr(retBB);

    IRBuilder<> RetB(retBB);
    Value *out = RetB.CreateLoad(i32, result, "morok.win.unhook.status");
    cast<LoadInst>(out)->setVolatile(true);
    RetB.CreateRet(out);
    return fn;
}

Function *windowsPeImageSize(Module &M) {
    if (Function *existing = M.getFunction("morok.win.pe.image.size"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i16 = Type::getInt16Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(ip, {ip}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.win.pe.image.size", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    Argument *base = fn->getArg(0);
    base->setName("base");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *headersBB = BasicBlock::Create(ctx, "headers", fn);
    auto *ret0BB = BasicBlock::Create(ctx, "ret0", fn);

    IRBuilder<> B(entry);
    Value *basePtr = B.CreateIntToPtr(base, ptr, "morok.win.pe.size.base.ptr");
    Value *mz = loadAt(B, M, i16, basePtr, 0ULL, "morok.win.pe.size.mz");
    B.CreateCondBr(B.CreateICmpEQ(mz, ConstantInt::get(i16, 0x5A4D)),
                   headersBB, ret0BB);

    IRBuilder<> HB(headersBB);
    Value *lfanew32 =
        loadAt(HB, M, i32, basePtr, 0x3c, "morok.win.pe.size.lfanew");
    Value *ntPtr =
        gepI8(HB, M, basePtr,
              HB.CreateZExt(lfanew32, ip, "morok.win.pe.size.lfanew.ip"),
              "morok.win.pe.size.nt");
    Value *sig = loadAt(HB, M, i32, ntPtr, 0ULL, "morok.win.pe.size.sig");
    Value *imageSize =
        loadAt(HB, M, i32, ntPtr, 80, "morok.win.pe.size.image");
    Value *ok = HB.CreateAnd(
        HB.CreateICmpEQ(sig, ConstantInt::get(i32, 0x4550)),
        HB.CreateICmpNE(imageSize, ConstantInt::get(i32, 0)),
        "morok.win.pe.size.headers.ok");
    HB.CreateRet(HB.CreateSelect(ok, HB.CreateZExt(imageSize, ip),
                                 ConstantInt::get(ip, 0),
                                 "morok.win.pe.size.result"));

    IRBuilder<> RB(ret0BB);
    RB.CreateRet(ConstantInt::get(ip, 0));
    return fn;
}

Function *windowsAddressInLdrModule(Module &M) {
    if (Function *existing = M.getFunction("morok.win.ldr.contains"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(i32, {ip, ip}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.win.ldr.contains", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    Argument *peb = fn->getArg(0);
    peb->setName("peb");
    Argument *address = fn->getArg(1);
    address->setName("address");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *loopBB = BasicBlock::Create(ctx, "loop", fn);
    auto *bodyBB = BasicBlock::Create(ctx, "body", fn);
    auto *matchBB = BasicBlock::Create(ctx, "match", fn);
    auto *nextBB = BasicBlock::Create(ctx, "next", fn);
    auto *ret0BB = BasicBlock::Create(ctx, "ret0", fn);

    IRBuilder<> B(entry);
    Value *pebPtr = B.CreateIntToPtr(peb, ptr, "morok.win.ldr.contains.peb.ptr");
    Value *ldr = loadAt(B, M, ip, pebPtr, 0x18,
                        "morok.win.ldr.contains.ldr");
    Value *head = B.CreateAdd(ldr, ConstantInt::get(ip, 0x20),
                              "morok.win.ldr.contains.head");
    Value *headPtr =
        B.CreateIntToPtr(head, ptr, "morok.win.ldr.contains.head.ptr");
    Value *first =
        loadAt(B, M, ip, headPtr, 0ULL, "morok.win.ldr.contains.first");
    Value *ready = B.CreateAnd(
        B.CreateAnd(B.CreateICmpNE(peb, ConstantInt::get(ip, 0)),
                    B.CreateICmpNE(address, ConstantInt::get(ip, 0)),
                    "morok.win.ldr.contains.args"),
        B.CreateAnd(B.CreateICmpNE(ldr, ConstantInt::get(ip, 0)),
                    B.CreateAnd(B.CreateICmpNE(first, ConstantInt::get(ip, 0)),
                                B.CreateICmpNE(first, head),
                                "morok.win.ldr.contains.first.valid"),
                    "morok.win.ldr.contains.list"),
        "morok.win.ldr.contains.ready");
    B.CreateCondBr(ready, loopBB, ret0BB);

    IRBuilder<> LB(loopBB);
    auto *cursor = LB.CreatePHI(ip, 2, "morok.win.ldr.contains.cursor");
    auto *idx = LB.CreatePHI(i32, 2, "morok.win.ldr.contains.idx");
    cursor->addIncoming(first, entry);
    idx->addIncoming(ConstantInt::get(i32, 0), entry);
    LB.CreateCondBr(
        LB.CreateAnd(LB.CreateICmpULT(idx, ConstantInt::get(i32, 256),
                                      "morok.win.ldr.contains.limit"),
                     LB.CreateICmpNE(cursor, head),
                     "morok.win.ldr.contains.keep.walking"),
        bodyBB, ret0BB);

    IRBuilder<> BB(bodyBB);
    Value *entryBase =
        BB.CreateSub(cursor, ConstantInt::get(ip, 0x10),
                     "morok.win.ldr.contains.entry.base");
    Value *entryPtr =
        BB.CreateIntToPtr(entryBase, ptr, "morok.win.ldr.contains.entry.ptr");
    Value *dllBase =
        loadAt(BB, M, ip, entryPtr, 0x30, "morok.win.ldr.contains.dll.base");
    Value *imageSize32 =
        loadAt(BB, M, i32, entryPtr, 0x40, "morok.win.ldr.contains.image.size");
    Value *imageSize =
        BB.CreateZExt(imageSize32, ip, "morok.win.ldr.contains.image.size.ip");
    Value *imageEnd =
        BB.CreateAdd(dllBase, imageSize, "morok.win.ldr.contains.image.end");
    Value *inside = BB.CreateAnd(
        BB.CreateAnd(BB.CreateICmpNE(dllBase, ConstantInt::get(ip, 0)),
                     BB.CreateICmpNE(imageSize, ConstantInt::get(ip, 0)),
                     "morok.win.ldr.contains.image.valid"),
        BB.CreateAnd(BB.CreateICmpUGE(address, dllBase),
                     BB.CreateICmpULT(address, imageEnd),
                     "morok.win.ldr.contains.range"),
        "morok.win.ldr.contains.match");
    BB.CreateCondBr(inside, matchBB, nextBB);

    IRBuilder<> MB(matchBB);
    MB.CreateRet(ConstantInt::get(i32, 1));

    IRBuilder<> NB(nextBB);
    Value *cursorPtr =
        NB.CreateIntToPtr(cursor, ptr, "morok.win.ldr.contains.cursor.ptr");
    Value *nextCursor =
        loadAt(NB, M, ip, cursorPtr, 0ULL,
               "morok.win.ldr.contains.next.cursor");
    Value *nextIdx =
        NB.CreateAdd(idx, ConstantInt::get(i32, 1),
                     "morok.win.ldr.contains.next.idx");
    NB.CreateBr(loopBB);
    cursor->addIncoming(nextCursor, nextBB);
    idx->addIncoming(nextIdx, nextBB);

    IRBuilder<> RB(ret0BB);
    RB.CreateRet(ConstantInt::get(i32, 0));
    return fn;
}

Function *windowsReadableAddressHelper(Module &M) {
    if (Function *existing = M.getFunction("morok.win.veh.readable"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(i32, {ip, ip}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.win.veh.readable", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    Argument *address = fn->getArg(0);
    address->setName("address");
    Argument *queryVm = fn->getArg(1);
    queryVm->setName("query_vm");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *queryBB = BasicBlock::Create(ctx, "query", fn);
    auto *ret0BB = BasicBlock::Create(ctx, "ret0", fn);

    IRBuilder<> B(entry);
    auto *mbiTy = ArrayType::get(i8, 48);
    AllocaInst *mbi = B.CreateAlloca(mbiTy, nullptr, "morok.win.veh.mbi");
    AllocaInst *retLen =
        B.CreateAlloca(ip, nullptr, "morok.win.veh.mbi.retlen");
    B.CreateStore(ConstantInt::get(ip, 0), retLen)->setVolatile(true);
    B.CreateCondBr(B.CreateAnd(B.CreateICmpNE(address, ConstantInt::get(ip, 0)),
                               B.CreateICmpNE(queryVm, ConstantInt::get(ip, 0)),
                               "morok.win.veh.readable.ready"),
                   queryBB, ret0BB);

    IRBuilder<> QB(queryBB);
    auto *queryTy = FunctionType::get(i32, {ptr, ptr, i32, ptr, ip, ptr}, false);
    Value *status = QB.CreateCall(
        queryTy,
        QB.CreateIntToPtr(queryVm, ptr, "morok.win.veh.ntqueryvm.ptr"),
        {QB.CreateIntToPtr(ConstantInt::getSigned(ip, -1), ptr),
         QB.CreateIntToPtr(address, ptr, "morok.win.veh.query.address"),
         ConstantInt::get(i32, 0), mbi, ConstantInt::get(ip, 48), retLen},
        "morok.win.veh.ntqueryvm.status");
    Value *state = loadAt(QB, M, i32, mbi, 32, "morok.win.veh.mbi.state");
    Value *protect = loadAt(QB, M, i32, mbi, 36, "morok.win.veh.mbi.protect");
    Value *okStatus =
        QB.CreateICmpSGE(status, ConstantInt::get(i32, 0),
                         "morok.win.veh.ntqueryvm.ok");
    Value *committed =
        QB.CreateICmpEQ(state, ConstantInt::get(i32, 0x1000),
                        "morok.win.veh.mbi.committed");
    Value *blocked = QB.CreateICmpNE(
        QB.CreateAnd(protect, ConstantInt::get(i32, 0x101)),
        ConstantInt::get(i32, 0), "morok.win.veh.mbi.blocked");
    Value *readable =
        QB.CreateAnd(QB.CreateAnd(okStatus, committed,
                                  "morok.win.veh.mbi.valid"),
                     QB.CreateNot(blocked), "morok.win.veh.readable.result");
    QB.CreateRet(QB.CreateZExt(readable, i32));

    IRBuilder<> RB(ret0BB);
    RB.CreateRet(ConstantInt::get(i32, 0));
    return fn;
}

Function *windowsExecutableAddressHelper(Module &M) {
    if (Function *existing = M.getFunction("morok.win.veh.executable"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(i32, {ip, ip}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.win.veh.executable", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    Argument *address = fn->getArg(0);
    address->setName("address");
    Argument *queryVm = fn->getArg(1);
    queryVm->setName("query_vm");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *queryBB = BasicBlock::Create(ctx, "query", fn);
    auto *ret0BB = BasicBlock::Create(ctx, "ret0", fn);

    IRBuilder<> B(entry);
    auto *mbiTy = ArrayType::get(i8, 48);
    AllocaInst *mbi = B.CreateAlloca(mbiTy, nullptr, "morok.win.veh.exec.mbi");
    AllocaInst *retLen =
        B.CreateAlloca(ip, nullptr, "morok.win.veh.exec.mbi.retlen");
    B.CreateStore(ConstantInt::get(ip, 0), retLen)->setVolatile(true);
    B.CreateCondBr(B.CreateAnd(B.CreateICmpNE(address, ConstantInt::get(ip, 0)),
                               B.CreateICmpNE(queryVm, ConstantInt::get(ip, 0)),
                               "morok.win.veh.executable.ready"),
                   queryBB, ret0BB);

    IRBuilder<> QB(queryBB);
    auto *queryTy = FunctionType::get(i32, {ptr, ptr, i32, ptr, ip, ptr}, false);
    Value *status = QB.CreateCall(
        queryTy,
        QB.CreateIntToPtr(queryVm, ptr, "morok.win.veh.exec.ntqueryvm.ptr"),
        {QB.CreateIntToPtr(ConstantInt::getSigned(ip, -1), ptr),
         QB.CreateIntToPtr(address, ptr, "morok.win.veh.exec.query.address"),
         ConstantInt::get(i32, 0), mbi, ConstantInt::get(ip, 48), retLen},
        "morok.win.veh.exec.ntqueryvm.status");
    Value *state = loadAt(QB, M, i32, mbi, 32, "morok.win.veh.exec.mbi.state");
    Value *protect =
        loadAt(QB, M, i32, mbi, 36, "morok.win.veh.exec.mbi.protect");
    Value *type = loadAt(QB, M, i32, mbi, 40, "morok.win.veh.exec.mbi.type");
    Value *okStatus =
        QB.CreateICmpSGE(status, ConstantInt::get(i32, 0),
                         "morok.win.veh.exec.ntqueryvm.ok");
    Value *committed =
        QB.CreateICmpEQ(state, ConstantInt::get(i32, 0x1000),
                        "morok.win.veh.exec.mbi.committed");
    Value *image =
        QB.CreateICmpEQ(type, ConstantInt::get(i32, 0x1000000),
                        "morok.win.veh.exec.mbi.image");
    Value *blocked = QB.CreateICmpNE(
        QB.CreateAnd(protect, ConstantInt::get(i32, 0x101)),
        ConstantInt::get(i32, 0), "morok.win.veh.exec.mbi.blocked");
    Value *executable = QB.CreateICmpNE(
        QB.CreateAnd(protect, ConstantInt::get(i32, 0xF0)),
        ConstantInt::get(i32, 0), "morok.win.veh.exec.mbi.executable");
    Value *writableExecutable = QB.CreateICmpNE(
        QB.CreateAnd(protect, ConstantInt::get(i32, 0xC0)),
        ConstantInt::get(i32, 0), "morok.win.veh.exec.mbi.writable");
    Value *validRegion =
        QB.CreateAnd(QB.CreateAnd(okStatus, committed,
                                  "morok.win.veh.exec.mbi.committed.valid"),
                     image, "morok.win.veh.exec.mbi.valid");
    Value *safeProtect = QB.CreateAnd(
        QB.CreateNot(blocked), QB.CreateNot(writableExecutable),
        "morok.win.veh.exec.mbi.protect.safe");
    Value *allowedProtect = QB.CreateAnd(
        executable, safeProtect, "morok.win.veh.exec.mbi.allowed");
    Value *trusted =
        QB.CreateAnd(validRegion, allowedProtect,
                     "morok.win.veh.executable.result");
    QB.CreateRet(QB.CreateZExt(trusted, i32));

    IRBuilder<> RB(ret0BB);
    RB.CreateRet(ConstantInt::get(i32, 0));
    return fn;
}

Function *windowsVehListReferenceScanner(Module &M) {
    if (Function *existing = M.getFunction("morok.win.veh.scan.list"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(ip, {ip, ip, ip}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.win.veh.scan.list", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    Argument *imageBase = fn->getArg(0);
    imageBase->setName("image_base");
    Argument *imageSize = fn->getArg(1);
    imageSize->setName("image_size");
    Argument *functionPtr = fn->getArg(2);
    functionPtr->setName("function_ptr");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *loopBB = BasicBlock::Create(ctx, "loop", fn);
    auto *bodyBB = BasicBlock::Create(ctx, "body", fn);
    auto *foundBB = BasicBlock::Create(ctx, "found", fn);
    auto *nextBB = BasicBlock::Create(ctx, "next", fn);
    auto *ret0BB = BasicBlock::Create(ctx, "ret0", fn);

    IRBuilder<> B(entry);
    Value *ready = B.CreateAnd(
        B.CreateAnd(B.CreateICmpNE(imageBase, ConstantInt::get(ip, 0)),
                    B.CreateICmpNE(imageSize, ConstantInt::get(ip, 0)),
                    "morok.win.veh.scan.image.ready"),
        B.CreateICmpNE(functionPtr, ConstantInt::get(ip, 0),
                       "morok.win.veh.scan.fn.ready"),
        "morok.win.veh.scan.ready");
    B.CreateCondBr(ready, loopBB, ret0BB);

    IRBuilder<> LB(loopBB);
    auto *idx = LB.CreatePHI(i32, 2, "morok.win.veh.scan.idx");
    idx->addIncoming(ConstantInt::get(i32, 0), entry);
    LB.CreateCondBr(LB.CreateICmpULT(idx, ConstantInt::get(i32, 512),
                                     "morok.win.veh.scan.more"),
                    bodyBB, ret0BB);

    IRBuilder<> SB(bodyBB);
    Value *idxIp = SB.CreateZExt(idx, ip, "morok.win.veh.scan.idx.ip");
    Value *fnBytes =
        SB.CreateIntToPtr(functionPtr, ptr, "morok.win.veh.scan.fn.ptr");
    Value *b0 = loadAt(SB, M, i8, fnBytes, idxIp, "morok.win.veh.scan.b0");
    Value *b1 = loadAt(SB, M, i8, fnBytes,
                       SB.CreateAdd(idxIp, ConstantInt::get(ip, 1)),
                       "morok.win.veh.scan.b1");
    Value *b2 = loadAt(SB, M, i8, fnBytes,
                       SB.CreateAdd(idxIp, ConstantInt::get(ip, 2)),
                       "morok.win.veh.scan.b2");
    Value *rex = SB.CreateOr(SB.CreateICmpEQ(b0, ConstantInt::get(i8, 0x48)),
                             SB.CreateICmpEQ(b0, ConstantInt::get(i8, 0x4c)),
                             "morok.win.veh.scan.rex");
    Value *lea = SB.CreateICmpEQ(b1, ConstantInt::get(i8, 0x8d),
                                 "morok.win.veh.scan.lea");
    Value *ripRel = SB.CreateICmpEQ(
        SB.CreateAnd(b2, ConstantInt::get(i8, 0xc7)),
        ConstantInt::get(i8, 0x05), "morok.win.veh.scan.riprel");
    Value *disp32 = loadAt(
        SB, M, i32, fnBytes,
        SB.CreateAdd(idxIp, ConstantInt::get(ip, 3),
                     "morok.win.veh.scan.disp.off"),
        "morok.win.veh.scan.disp");
    Value *candidate = SB.CreateAdd(
        SB.CreateAdd(functionPtr,
                     SB.CreateAdd(idxIp, ConstantInt::get(ip, 7),
                                  "morok.win.veh.scan.instr.end.off"),
                     "morok.win.veh.scan.instr.end"),
        SB.CreateSExt(disp32, ip, "morok.win.veh.scan.disp.ip"),
        "morok.win.veh.scan.candidate");
    Value *imageEnd =
        SB.CreateAdd(imageBase, imageSize, "morok.win.veh.scan.image.end");
    Value *candidateInImage = SB.CreateAnd(
        SB.CreateICmpUGE(candidate, imageBase),
        SB.CreateICmpULT(candidate, imageEnd),
        "morok.win.veh.scan.candidate.in.image");
    Value *candidateAligned = SB.CreateICmpEQ(
        SB.CreateAnd(candidate, ConstantInt::get(ip, 7)),
        ConstantInt::get(ip, 0), "morok.win.veh.scan.candidate.aligned");
    Value *hit = SB.CreateAnd(
        SB.CreateAnd(SB.CreateAnd(rex, lea, "morok.win.veh.scan.rex.lea"),
                     ripRel, "morok.win.veh.scan.pattern"),
        SB.CreateAnd(candidateInImage, candidateAligned,
                     "morok.win.veh.scan.candidate.ok"),
        "morok.win.veh.scan.hit");
    SB.CreateCondBr(hit, foundBB, nextBB);

    IRBuilder<> FB(foundBB);
    FB.CreateRet(candidate);

    IRBuilder<> NB(nextBB);
    Value *nextIdx =
        NB.CreateAdd(idx, ConstantInt::get(i32, 1),
                     "morok.win.veh.scan.next");
    NB.CreateBr(loopBB);
    idx->addIncoming(nextIdx, nextBB);

    IRBuilder<> RB(ret0BB);
    RB.CreateRet(ConstantInt::get(ip, 0));
    return fn;
}

Function *windowsVehAuditListHelper(Module &M) {
    if (Function *existing = M.getFunction("morok.win.veh.audit.list"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(
        FunctionType::get(i64, {ip, ip, ip, ip}, false),
        GlobalValue::PrivateLinkage, "morok.win.veh.audit.list", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    Argument *peb = fn->getArg(0);
    peb->setName("peb");
    Argument *head = fn->getArg(1);
    head->setName("head");
    Argument *decode = fn->getArg(2);
    decode->setName("decode");
    Argument *queryVm = fn->getArg(3);
    queryVm->setName("query_vm");

    Function *contains = windowsAddressInLdrModule(M);
    Function *readable = windowsReadableAddressHelper(M);
    Function *executable = windowsExecutableAddressHelper(M);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *headBB = BasicBlock::Create(ctx, "head", fn);
    auto *startBB = BasicBlock::Create(ctx, "start", fn);
    auto *loopBB = BasicBlock::Create(ctx, "loop", fn);
    auto *readCursorBB = BasicBlock::Create(ctx, "read.cursor", fn);
    auto *bodyBB = BasicBlock::Create(ctx, "body", fn);
    auto *evalBB = BasicBlock::Create(ctx, "eval", fn);
    auto *nextBB = BasicBlock::Create(ctx, "next", fn);
    auto *doneBB = BasicBlock::Create(ctx, "done", fn);

    IRBuilder<> B(entry);
    AllocaInst *seen = B.CreateAlloca(i32, nullptr, "morok.win.veh.seen");
    AllocaInst *bad = B.CreateAlloca(i32, nullptr, "morok.win.veh.bad");
    B.CreateStore(ConstantInt::get(i32, 0), seen)->setVolatile(true);
    B.CreateStore(ConstantInt::get(i32, 0), bad)->setVolatile(true);
    Value *ready = B.CreateAnd(
        B.CreateAnd(B.CreateICmpNE(peb, ConstantInt::get(ip, 0)),
                    B.CreateICmpNE(head, ConstantInt::get(ip, 0)),
                    "morok.win.veh.audit.args"),
        B.CreateAnd(B.CreateICmpNE(decode, ConstantInt::get(ip, 0)),
                    B.CreateICmpNE(queryVm, ConstantInt::get(ip, 0)),
                    "morok.win.veh.audit.apis"),
        "morok.win.veh.audit.ready");
    B.CreateCondBr(ready, headBB, doneBB);

    IRBuilder<> HB(headBB);
    Value *headReadable = HB.CreateCall(readable, {head, queryVm},
                                        "morok.win.veh.head.readable");
    HB.CreateCondBr(HB.CreateICmpNE(headReadable, ConstantInt::get(i32, 0),
                                    "morok.win.veh.head.ok"),
                    startBB, doneBB);

    IRBuilder<> SB(startBB);
    Value *first = loadAt(SB, M, ip, SB.CreateIntToPtr(head, ptr),
                          0ULL, "morok.win.veh.first");
    SB.CreateBr(loopBB);

    IRBuilder<> LB(loopBB);
    auto *cursor = LB.CreatePHI(ip, 2, "morok.win.veh.cursor");
    auto *prev = LB.CreatePHI(ip, 2, "morok.win.veh.prev");
    auto *idx = LB.CreatePHI(i32, 2, "morok.win.veh.idx");
    cursor->addIncoming(first, startBB);
    prev->addIncoming(head, startBB);
    idx->addIncoming(ConstantInt::get(i32, 0), startBB);
    Value *keepWalking = LB.CreateAnd(
        LB.CreateAnd(LB.CreateICmpULT(idx, ConstantInt::get(i32, 32)),
                     LB.CreateICmpNE(cursor, ConstantInt::get(ip, 0)),
                     "morok.win.veh.limit"),
        LB.CreateICmpNE(cursor, head, "morok.win.veh.not.head"),
        "morok.win.veh.keep.walking");
    LB.CreateCondBr(keepWalking, readCursorBB, doneBB);

    IRBuilder<> RCB(readCursorBB);
    Value *cursorReadable = RCB.CreateCall(readable, {cursor, queryVm},
                                           "morok.win.veh.cursor.readable");
    RCB.CreateCondBr(RCB.CreateICmpNE(cursorReadable, ConstantInt::get(i32, 0),
                                      "morok.win.veh.cursor.ok"),
                     bodyBB, doneBB);

    IRBuilder<> BB(bodyBB);
    Value *cursorPtr =
        BB.CreateIntToPtr(cursor, ptr, "morok.win.veh.cursor.ptr");
    Value *next = loadAt(BB, M, ip, cursorPtr, 0ULL, "morok.win.veh.next");
    Value *back = loadAt(BB, M, ip, cursorPtr, 8, "morok.win.veh.back");
    BB.CreateCondBr(BB.CreateICmpEQ(back, prev, "morok.win.veh.link.ok"),
                    evalBB, doneBB);

    IRBuilder<> EB(evalBB);
    Value *oldSeen = EB.CreateLoad(i32, seen, "morok.win.veh.seen.old");
    cast<LoadInst>(oldSeen)->setVolatile(true);
    EB.CreateStore(EB.CreateAdd(oldSeen, ConstantInt::get(i32, 1),
                                "morok.win.veh.seen.next"),
                   seen)
        ->setVolatile(true);
    Value *encoded20 =
        loadAt(EB, M, ip, cursorPtr, 0x20, "morok.win.veh.encoded.20");
    Value *encoded18 =
        loadAt(EB, M, ip, cursorPtr, 0x18, "morok.win.veh.encoded.18");
    auto *decodeTy = FunctionType::get(ptr, {ptr}, false);
    Value *decodePtr =
        EB.CreateIntToPtr(decode, ptr, "morok.win.veh.decode.ptr");
    Value *decoded20Ptr = EB.CreateCall(
        decodeTy, decodePtr,
        {EB.CreateIntToPtr(encoded20, ptr, "morok.win.veh.encoded.20.ptr")},
        "morok.win.veh.decoded.20.ptr");
    Value *decoded18Ptr = EB.CreateCall(
        decodeTy, decodePtr,
        {EB.CreateIntToPtr(encoded18, ptr, "morok.win.veh.encoded.18.ptr")},
        "morok.win.veh.decoded.18.ptr");
    Value *decoded20 =
        EB.CreatePtrToInt(decoded20Ptr, ip, "morok.win.veh.decoded.20");
    Value *decoded18 =
        EB.CreatePtrToInt(decoded18Ptr, ip, "morok.win.veh.decoded.18");
    Value *inside20 = EB.CreateCall(contains, {peb, decoded20},
                                    "morok.win.veh.handler.20.inside");
    Value *inside18 = EB.CreateCall(contains, {peb, decoded18},
                                    "morok.win.veh.handler.18.inside");
    Value *exec20 = EB.CreateCall(executable, {decoded20, queryVm},
                                  "morok.win.veh.handler.20.executable");
    Value *exec18 = EB.CreateCall(executable, {decoded18, queryVm},
                                  "morok.win.veh.handler.18.executable");
    Value *present = EB.CreateOr(
        EB.CreateICmpNE(encoded20, ConstantInt::get(ip, 0)),
        EB.CreateICmpNE(encoded18, ConstantInt::get(ip, 0)),
        "morok.win.veh.handler.present");
    Value *trusted20 = EB.CreateOr(
        EB.CreateICmpNE(inside20, ConstantInt::get(i32, 0)),
        EB.CreateICmpNE(exec20, ConstantInt::get(i32, 0)),
        "morok.win.veh.handler.20.trusted");
    Value *trusted18 = EB.CreateOr(
        EB.CreateICmpNE(inside18, ConstantInt::get(i32, 0)),
        EB.CreateICmpNE(exec18, ConstantInt::get(i32, 0)),
        "morok.win.veh.handler.18.trusted");
    Value *trustedAny = EB.CreateOr(trusted20, trusted18,
                                    "morok.win.veh.handler.trusted.any");
    Value *foreign =
        EB.CreateAnd(present, EB.CreateNot(trustedAny),
                     "morok.win.veh.handler.foreign");
    Value *oldBad = EB.CreateLoad(i32, bad, "morok.win.veh.bad.old");
    cast<LoadInst>(oldBad)->setVolatile(true);
    EB.CreateStore(EB.CreateAdd(oldBad, EB.CreateZExt(foreign, i32),
                                "morok.win.veh.bad.next"),
                   bad)
        ->setVolatile(true);
    EB.CreateBr(nextBB);

    IRBuilder<> NB(nextBB);
    Value *nextIdx =
        NB.CreateAdd(idx, ConstantInt::get(i32, 1),
                     "morok.win.veh.next.idx");
    NB.CreateBr(loopBB);
    cursor->addIncoming(next, nextBB);
    prev->addIncoming(cursor, nextBB);
    idx->addIncoming(nextIdx, nextBB);

    IRBuilder<> DB(doneBB);
    Value *seenFinal = DB.CreateLoad(i32, seen, "morok.win.veh.seen.final");
    cast<LoadInst>(seenFinal)->setVolatile(true);
    Value *badFinal = DB.CreateLoad(i32, bad, "morok.win.veh.bad.final");
    cast<LoadInst>(badFinal)->setVolatile(true);
    DB.CreateRet(DB.CreateOr(
        DB.CreateZExt(seenFinal, i64),
        DB.CreateShl(DB.CreateZExt(badFinal, i64), ConstantInt::get(i64, 32)),
        "morok.win.veh.audit.result"));
    return fn;
}

Function *windowsSyscallStubScanner(Module &M) {
    if (Function *existing = M.getFunction("morok.win.sys.scan"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *i1 = Type::getInt1Ty(ctx);
    auto *fn = Function::Create(FunctionType::get(ip, {ptr, i1}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.win.sys.scan", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    Argument *stub = fn->getArg(0);
    stub->setName("stub");
    Argument *allowNeighbors = fn->getArg(1);
    allowNeighbors->setName("allow_neighbors");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *loopBB = BasicBlock::Create(ctx, "loop", fn);
    auto *bodyBB = BasicBlock::Create(ctx, "body", fn);
    auto *nextBB = BasicBlock::Create(ctx, "next", fn);
    auto *neighborGateBB = BasicBlock::Create(ctx, "neighbor.gate", fn);
    auto *neighborLoopBB = BasicBlock::Create(ctx, "neighbor.loop", fn);
    auto *neighborBodyBB = BasicBlock::Create(ctx, "neighbor.body", fn);
    auto *neighborNextBB = BasicBlock::Create(ctx, "neighbor.next", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    AllocaInst *ssnSlot = B.CreateAlloca(i32, nullptr, "morok.win.sys.ssn.slot");
    AllocaInst *gadgetSlot =
        B.CreateAlloca(i32, nullptr, "morok.win.sys.gadget.slot");
    AllocaInst *foundSlot =
        B.CreateAlloca(i8, nullptr, "morok.win.sys.found.slot");
    AllocaInst *gadgetFoundSlot =
        B.CreateAlloca(i8, nullptr, "morok.win.sys.gadget.found.slot");
    B.CreateStore(ConstantInt::get(i32, 0), ssnSlot)->setVolatile(true);
    B.CreateStore(ConstantInt::get(i32, 0), gadgetSlot)->setVolatile(true);
    B.CreateStore(ConstantInt::get(i8, 0), foundSlot)->setVolatile(true);
    B.CreateStore(ConstantInt::get(i8, 0), gadgetFoundSlot)->setVolatile(true);
    B.CreateCondBr(B.CreateICmpNE(stub, ConstantPointerNull::get(ptr),
                                  "morok.win.sys.scan.stub.present"),
                   loopBB, retBB);

    IRBuilder<> LB(loopBB);
    auto *idx = LB.CreatePHI(i32, 2, "morok.win.sys.scan.idx");
    idx->addIncoming(ConstantInt::get(i32, 0), entry);
    LB.CreateCondBr(
        LB.CreateICmpULT(idx, ConstantInt::get(i32, 30),
                         "morok.win.sys.scan.current.limit"),
        bodyBB, neighborGateBB);

    IRBuilder<> SB(bodyBB);
    Value *idxIp = SB.CreateZExt(idx, ip, "morok.win.sys.scan.idx.ip");
    Value *b0 = loadAt(SB, M, i8, stub, idxIp, "morok.win.sys.scan.b0");
    Value *b1 = loadAt(SB, M, i8, stub,
                       SB.CreateAdd(idxIp, ConstantInt::get(ip, 1)),
                       "morok.win.sys.scan.b1");
    Value *b2 = loadAt(SB, M, i8, stub,
                       SB.CreateAdd(idxIp, ConstantInt::get(ip, 2)),
                       "morok.win.sys.scan.b2");
    Value *p0 = loadAt(SB, M, i8, stub, 0ULL, "morok.win.sys.scan.p0");
    Value *p1 = loadAt(SB, M, i8, stub, 1, "morok.win.sys.scan.p1");
    Value *p2 = loadAt(SB, M, i8, stub, 2, "morok.win.sys.scan.p2");
    Value *prologue = SB.CreateAnd(
        SB.CreateAnd(SB.CreateICmpEQ(p0, ConstantInt::get(i8, 0x4C)),
                     SB.CreateICmpEQ(p1, ConstantInt::get(i8, 0x8B))),
        SB.CreateAnd(SB.CreateICmpEQ(p2, ConstantInt::get(i8, 0xD1)),
                     SB.CreateICmpEQ(b0, ConstantInt::get(i8, 0xB8))),
        "morok.win.sys.scan.prologue");
    Value *movEax = SB.CreateAnd(
        SB.CreateICmpEQ(idx, ConstantInt::get(i32, 3),
                        "morok.win.sys.scan.mov.offset"),
        prologue, "morok.win.sys.scan.mov.eax");
    Value *syscallRet = SB.CreateAnd(
        SB.CreateAnd(SB.CreateICmpEQ(b0, ConstantInt::get(i8, 0x0F)),
                     SB.CreateICmpEQ(b1, ConstantInt::get(i8, 0x05))),
        SB.CreateICmpEQ(b2, ConstantInt::get(i8, 0xC3)),
        "morok.win.sys.scan.syscall.ret");
    Value *oldFound =
        SB.CreateLoad(i8, foundSlot, "morok.win.sys.scan.found.old");
    cast<LoadInst>(oldFound)->setVolatile(true);
    Value *ssnAccept = SB.CreateAnd(
        movEax, SB.CreateICmpEQ(oldFound, ConstantInt::get(i8, 0)),
        "morok.win.sys.scan.ssn.accept");
    Value *ssn = loadAt(SB, M, i32, stub, 4ULL,
                        "morok.win.sys.scan.ssn");
    Value *oldSsn =
        SB.CreateLoad(i32, ssnSlot, "morok.win.sys.scan.ssn.old");
    cast<LoadInst>(oldSsn)->setVolatile(true);
    auto *ssnStore = SB.CreateStore(
        SB.CreateSelect(ssnAccept, ssn, oldSsn,
                        "morok.win.sys.scan.ssn.sel"),
        ssnSlot);
    ssnStore->setVolatile(true);
    Value *newFound = SB.CreateSelect(ssnAccept, ConstantInt::get(i8, 1),
                                      oldFound,
                                      "morok.win.sys.scan.found.sel");
    auto *foundStore = SB.CreateStore(newFound, foundSlot);
    foundStore->setVolatile(true);
    Value *oldGadgetFound = SB.CreateLoad(
        i8, gadgetFoundSlot, "morok.win.sys.scan.gadget.found.old");
    cast<LoadInst>(oldGadgetFound)->setVolatile(true);
    Value *gadgetAccept = SB.CreateAnd(
        syscallRet, SB.CreateICmpEQ(oldGadgetFound, ConstantInt::get(i8, 0)),
        "morok.win.sys.scan.gadget.accept");
    Value *oldGadget =
        SB.CreateLoad(i32, gadgetSlot, "morok.win.sys.scan.gadget.old");
    cast<LoadInst>(oldGadget)->setVolatile(true);
    auto *gadgetStore = SB.CreateStore(
        SB.CreateSelect(gadgetAccept, idx, oldGadget,
                        "morok.win.sys.scan.gadget.sel"),
        gadgetSlot);
    gadgetStore->setVolatile(true);
    Value *newGadgetFound =
        SB.CreateSelect(gadgetAccept, ConstantInt::get(i8, 1),
                        oldGadgetFound,
                        "morok.win.sys.scan.gadget.found.sel");
    SB.CreateStore(newGadgetFound, gadgetFoundSlot)->setVolatile(true);
    Value *complete = SB.CreateAnd(
        SB.CreateICmpNE(newFound, ConstantInt::get(i8, 0)),
        SB.CreateICmpNE(newGadgetFound, ConstantInt::get(i8, 0)),
        "morok.win.sys.scan.complete");
    SB.CreateCondBr(complete, retBB, nextBB);

    IRBuilder<> NB(nextBB);
    Value *nextIdx =
        NB.CreateAdd(idx, ConstantInt::get(i32, 1), "morok.win.sys.scan.next");
    NB.CreateBr(loopBB);
    idx->addIncoming(nextIdx, nextBB);

    IRBuilder<> GB(neighborGateBB);
    Value *found =
        GB.CreateLoad(i8, foundSlot, "morok.win.sys.scan.found.final");
    cast<LoadInst>(found)->setVolatile(true);
    Value *hellsReady =
        GB.CreateICmpNE(found, ConstantInt::get(i8, 0),
                        "morok.win.sys.scan.hells.ready");
    Value *neighborAllowed = GB.CreateAnd(
        GB.CreateNot(hellsReady), allowNeighbors,
        "morok.win.sys.scan.neighbor.enabled");
    GB.CreateCondBr(neighborAllowed, neighborLoopBB, retBB);

    IRBuilder<> NLB(neighborLoopBB);
    auto *neighborIdx =
        NLB.CreatePHI(i32, 2, "morok.win.sys.scan.neighbor.idx");
    neighborIdx->addIncoming(ConstantInt::get(i32, 1), neighborGateBB);
    NLB.CreateCondBr(
        NLB.CreateICmpULE(neighborIdx, ConstantInt::get(i32, 8),
                          "morok.win.sys.scan.neighbor.limit"),
        neighborBodyBB, retBB);

    IRBuilder<> HB(neighborBodyBB);
    Value *neighborSpan =
        HB.CreateMul(neighborIdx, ConstantInt::get(i32, 32),
                     "morok.win.sys.scan.neighbor.span");
    Value *posOff =
        HB.CreateZExt(neighborSpan, ip, "morok.win.sys.scan.halo.off");
    Value *negSpan =
        HB.CreateSub(ConstantInt::get(i32, 0), neighborSpan,
                     "morok.win.sys.scan.tartarus.span");
    Value *negOff =
        HB.CreateSExt(negSpan, ip, "morok.win.sys.scan.tartarus.off");
    Value *posPtr = gepI8(HB, M, stub, posOff, "morok.win.sys.scan.halo.ptr");
    Value *negPtr =
        gepI8(HB, M, stub, negOff, "morok.win.sys.scan.tartarus.ptr");

    Value *posP0 =
        loadAt(HB, M, i8, posPtr, 0ULL, "morok.win.sys.scan.halo.p0");
    Value *posP1 =
        loadAt(HB, M, i8, posPtr, 1, "morok.win.sys.scan.halo.p1");
    Value *posP2 =
        loadAt(HB, M, i8, posPtr, 2, "morok.win.sys.scan.halo.p2");
    Value *posP3 =
        loadAt(HB, M, i8, posPtr, 3, "morok.win.sys.scan.halo.p3");
    Value *negP0 =
        loadAt(HB, M, i8, negPtr, 0ULL, "morok.win.sys.scan.tartarus.p0");
    Value *negP1 =
        loadAt(HB, M, i8, negPtr, 1, "morok.win.sys.scan.tartarus.p1");
    Value *negP2 =
        loadAt(HB, M, i8, negPtr, 2, "morok.win.sys.scan.tartarus.p2");
    Value *negP3 =
        loadAt(HB, M, i8, negPtr, 3, "morok.win.sys.scan.tartarus.p3");
    Value *posPrologue = HB.CreateAnd(
        HB.CreateAnd(HB.CreateICmpEQ(posP0, ConstantInt::get(i8, 0x4C)),
                     HB.CreateICmpEQ(posP1, ConstantInt::get(i8, 0x8B))),
        HB.CreateAnd(HB.CreateICmpEQ(posP2, ConstantInt::get(i8, 0xD1)),
                     HB.CreateICmpEQ(posP3, ConstantInt::get(i8, 0xB8))),
        "morok.win.sys.scan.halo");
    Value *negPrologue = HB.CreateAnd(
        HB.CreateAnd(HB.CreateICmpEQ(negP0, ConstantInt::get(i8, 0x4C)),
                     HB.CreateICmpEQ(negP1, ConstantInt::get(i8, 0x8B))),
        HB.CreateAnd(HB.CreateICmpEQ(negP2, ConstantInt::get(i8, 0xD1)),
                     HB.CreateICmpEQ(negP3, ConstantInt::get(i8, 0xB8))),
        "morok.win.sys.scan.tartarus");
    Value *posSsn =
        loadAt(HB, M, i32, posPtr, 4, "morok.win.sys.scan.halo.ssn");
    Value *negSsn =
        loadAt(HB, M, i32, negPtr, 4, "morok.win.sys.scan.tartarus.ssn");
    Value *posCandidate =
        HB.CreateSub(posSsn, neighborIdx, "morok.win.sys.scan.halo.ssn.derive");
    Value *negCandidate = HB.CreateAdd(
        negSsn, neighborIdx, "morok.win.sys.scan.tartarus.ssn.derive");
    Value *anyNeighbor = HB.CreateOr(posPrologue, negPrologue,
                                     "morok.win.sys.scan.neighbor.hit");
    Value *neighborSsn =
        HB.CreateSelect(posPrologue, posCandidate, negCandidate,
                        "morok.win.sys.scan.neighbor.ssn");
    Value *neighborOldSsn =
        HB.CreateLoad(i32, ssnSlot, "morok.win.sys.scan.neighbor.ssn.old");
    cast<LoadInst>(neighborOldSsn)->setVolatile(true);
    HB.CreateStore(HB.CreateSelect(anyNeighbor, neighborSsn, neighborOldSsn,
                                   "morok.win.sys.scan.neighbor.ssn.sel"),
                   ssnSlot)
        ->setVolatile(true);

    Value *posG0 =
        loadAt(HB, M, i8, posPtr, 18, "morok.win.sys.scan.halo.g0");
    Value *posG1 =
        loadAt(HB, M, i8, posPtr, 19, "morok.win.sys.scan.halo.g1");
    Value *posG2 =
        loadAt(HB, M, i8, posPtr, 20, "morok.win.sys.scan.halo.g2");
    Value *negG0 =
        loadAt(HB, M, i8, negPtr, 18, "morok.win.sys.scan.tartarus.g0");
    Value *negG1 =
        loadAt(HB, M, i8, negPtr, 19, "morok.win.sys.scan.tartarus.g1");
    Value *negG2 =
        loadAt(HB, M, i8, negPtr, 20, "morok.win.sys.scan.tartarus.g2");
    Value *posGadget = HB.CreateAnd(
        posPrologue,
        HB.CreateAnd(HB.CreateAnd(HB.CreateICmpEQ(posG0, ConstantInt::get(i8, 0x0F)),
                                  HB.CreateICmpEQ(posG1, ConstantInt::get(i8, 0x05))),
                     HB.CreateICmpEQ(posG2, ConstantInt::get(i8, 0xC3))),
        "morok.win.sys.scan.halo.gadget");
    Value *negGadget = HB.CreateAnd(
        negPrologue,
        HB.CreateAnd(HB.CreateAnd(HB.CreateICmpEQ(negG0, ConstantInt::get(i8, 0x0F)),
                                  HB.CreateICmpEQ(negG1, ConstantInt::get(i8, 0x05))),
                     HB.CreateICmpEQ(negG2, ConstantInt::get(i8, 0xC3))),
        "morok.win.sys.scan.tartarus.gadget");
    Value *posGadgetOff = HB.CreateAdd(
        neighborSpan, ConstantInt::get(i32, 18),
        "morok.win.sys.scan.halo.gadget.off");
    Value *negGadgetOff = HB.CreateSub(
        ConstantInt::get(i32, 18), neighborSpan,
        "morok.win.sys.scan.tartarus.gadget.off");
    Value *anyGadget = HB.CreateOr(posGadget, negGadget,
                                   "morok.win.sys.scan.neighbor.gadget.hit");
    Value *neighborGadget =
        HB.CreateSelect(posGadget, posGadgetOff, negGadgetOff,
                        "morok.win.sys.scan.neighbor.gadget");
    Value *neighborOldGadget = HB.CreateLoad(
        i32, gadgetSlot, "morok.win.sys.scan.neighbor.gadget.old");
    cast<LoadInst>(neighborOldGadget)->setVolatile(true);
    HB.CreateStore(HB.CreateSelect(anyGadget, neighborGadget, neighborOldGadget,
                                   "morok.win.sys.scan.neighbor.gadget.sel"),
                   gadgetSlot)
        ->setVolatile(true);
    Value *neighborOldFound =
        HB.CreateLoad(i8, foundSlot, "morok.win.sys.scan.neighbor.found.old");
    cast<LoadInst>(neighborOldFound)->setVolatile(true);
    HB.CreateStore(HB.CreateSelect(anyNeighbor, ConstantInt::get(i8, 1),
                                   neighborOldFound,
                                   "morok.win.sys.scan.neighbor.found.sel"),
                   foundSlot)
        ->setVolatile(true);
    HB.CreateCondBr(anyNeighbor, retBB, neighborNextBB);

    IRBuilder<> NNB(neighborNextBB);
    Value *nextNeighbor = NNB.CreateAdd(
        neighborIdx, ConstantInt::get(i32, 1),
        "morok.win.sys.scan.neighbor.next");
    NNB.CreateBr(neighborLoopBB);
    neighborIdx->addIncoming(nextNeighbor, neighborNextBB);

    IRBuilder<> RB(retBB);
    Value *ssnOut = RB.CreateLoad(i32, ssnSlot, "morok.win.sys.ssn");
    cast<LoadInst>(ssnOut)->setVolatile(true);
    Value *gadgetOut = RB.CreateLoad(i32, gadgetSlot, "morok.win.sys.gadget");
    cast<LoadInst>(gadgetOut)->setVolatile(true);
    RB.CreateRet(RB.CreateOr(
        RB.CreateZExt(ssnOut, ip),
        RB.CreateShl(RB.CreateZExt(gadgetOut, ip), ConstantInt::get(ip, 32)),
        "morok.win.sys.scan.result"));
    return fn;
}

Function *windowsDirectSyscallThunk(Module &M) {
    if (Function *existing = M.getFunction("morok.win.sys.direct"))
        return existing;
    const Triple TT(M.getTargetTriple());
    if (!TT.isOSWindows() || TT.getArch() != Triple::x86_64)
        return nullptr;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *fn = Function::Create(
        FunctionType::get(ip, {i32, ip, ip, ip, ip}, false),
        GlobalValue::PrivateLinkage, "morok.win.sys.direct", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    IRBuilder<> B(entry);
    auto *asmTy = FunctionType::get(ip, {i32, ip, ip, ip, ip}, false);
    InlineAsm *IA = InlineAsm::get(
        asmTy, "movq %rcx, %r10\nsyscall",
        "={rax},{eax},{rcx},{rdx},{r8},{r9},~{r10},~{r11},~{memory},"
        "~{dirflag},~{fpsr},~{flags}",
        /*hasSideEffects=*/true);
    SmallVector<Value *, 5> args;
    for (Argument &A : fn->args())
        args.push_back(&A);
    B.CreateRet(B.CreateCall(asmTy, IA, args, "morok.win.sys.direct.ret"));
    return fn;
}

Function *windowsIndirectSyscallThunk(Module &M) {
    if (Function *existing = M.getFunction("morok.win.sys.indirect"))
        return existing;
    const Triple TT(M.getTargetTriple());
    if (!TT.isOSWindows() || TT.getArch() != Triple::x86_64)
        return nullptr;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *fn = Function::Create(
        FunctionType::get(ip, {i32, ip, ip, ip, ip, ip}, false),
        GlobalValue::PrivateLinkage, "morok.win.sys.indirect", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    IRBuilder<> B(entry);
    auto *asmTy = FunctionType::get(ip, {i32, ip, ip, ip, ip, ip}, false);
    InlineAsm *IA = InlineAsm::get(
        asmTy, "movq %rcx, %r10\ncallq *$6",
        "={rax},{eax},{rcx},{rdx},{r8},{r9},r,~{r10},~{r11},~{memory},"
        "~{dirflag},~{fpsr},~{flags}",
        /*hasSideEffects=*/true);
    SmallVector<Value *, 6> args;
    args.push_back(fn->getArg(0)); // SSN -> eax
    args.push_back(fn->getArg(2)); // syscall arg1 -> rcx
    args.push_back(fn->getArg(3)); // syscall arg2 -> rdx
    args.push_back(fn->getArg(4)); // syscall arg3 -> r8
    args.push_back(fn->getArg(5)); // syscall arg4 -> r9
    args.push_back(fn->getArg(1)); // recycled ntdll syscall;ret gadget
    B.CreateRet(B.CreateCall(asmTy, IA, args, "morok.win.sys.indirect.ret"));
    return fn;
}

Function *windowsVehHandler(Module &M, GlobalVariable *State) {
    if (Function *existing = M.getFunction("morok.win.veh.handler"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(i32, {ptr}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.win.veh.handler", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    Argument *exceptionPointers = fn->getArg(0);
    exceptionPointers->setName("exception_pointers");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *foldBB = BasicBlock::Create(ctx, "fold", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);
    IRBuilder<> B(entry);
    Value *record = loadAt(B, M, ptr, exceptionPointers, 0ULL,
                           "morok.win.veh.record");
    B.CreateCondBr(B.CreateICmpNE(record, ConstantPointerNull::get(ptr)),
                   foldBB, retBB);

    IRBuilder<> FB(foldBB);
    Value *code = loadAt(FB, M, i32, record, 0ULL, "morok.win.veh.code");
    Value *address = loadAt(FB, M, ip, record, 16, "morok.win.veh.address");
    foldState(FB, State, code, 0xA6D19C4E527B083FULL,
              "morok.win.veh.code.mix");
    foldState(FB, State, address, 0x53E7B20A49C1D68FULL,
              "morok.win.veh.address.mix");
    FB.CreateBr(retBB);

    IRBuilder<> RB(retBB);
    RB.CreateRet(ConstantInt::get(i32, 0)); // EXCEPTION_CONTINUE_SEARCH
    return fn;
}

Function *windowsPeFoundationProbe(Module &M, GlobalVariable *State,
                                   ir::IRRandom &rng, const Triple &TT) {
    if (!TT.isOSWindows() || TT.getArch() != Triple::x86_64 ||
        intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.win.foundation.probe"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i16 = Type::getInt16Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(Type::getVoidTy(ctx), false),
                                GlobalValue::PrivateLinkage,
                                "morok.win.foundation.probe", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    Function *tebReader = windowsTebReader(M);
    Function *pebReader = windowsPebReader(M);
    Function *resolver = windowsPeExportResolver(M);
    Function *scanner = windowsSyscallStubScanner(M);
    windowsDirectSyscallThunk(M);
    windowsIndirectSyscallThunk(M);
    Function *vehHandler = windowsVehHandler(M, State);

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    IRBuilder<> B(entry);
    Value *teb = B.CreateCall(tebReader, {}, "morok.win.foundation.teb");
    Value *peb = B.CreateCall(pebReader, {}, "morok.win.foundation.peb");
    Value *tebPtr = B.CreateIntToPtr(teb, ptr, "morok.win.foundation.teb.ptr");
    Value *pebFromTeb =
        loadAt(B, M, ip, tebPtr, 0x60, "morok.win.foundation.teb.peb");
    foldEnforcedFlag(B, State, B.CreateICmpNE(peb, pebFromTeb),
                     0xD92E0F61B47A35C8ULL,
                     "morok.win.foundation.peb.mismatch");
    Value *pebPtr = B.CreateIntToPtr(peb, ptr, "morok.win.foundation.peb.ptr");
    Value *imageBase =
        loadAt(B, M, ip, pebPtr, 0x10, "morok.win.foundation.image.base");
    Value *ldr = loadAt(B, M, ip, pebPtr, 0x18, "morok.win.foundation.ldr");
    foldState(B, State, imageBase, rng.next(), "morok.win.foundation.image");
    foldState(B, State, ldr, rng.next(), "morok.win.foundation.ldr");

    Value *imagePtr =
        B.CreateIntToPtr(imageBase, ptr, "morok.win.foundation.image.ptr");
    Value *mz = loadAt(B, M, i16, imagePtr, 0ULL, "morok.win.foundation.mz");
    Value *lfanew32 =
        loadAt(B, M, i32, imagePtr, 0x3c, "morok.win.foundation.lfanew");
    Value *nt = gepI8(B, M, imagePtr, B.CreateZExt(lfanew32, ip),
                      "morok.win.foundation.nt");
    Value *sig = loadAt(B, M, i32, nt, 0ULL, "morok.win.foundation.pe.sig");
    Value *headersOk = B.CreateAnd(
        B.CreateICmpEQ(mz, ConstantInt::get(i16, 0x5A4D)),
        B.CreateICmpEQ(sig, ConstantInt::get(i32, 0x4550)),
        "morok.win.foundation.headers.ok");
    foldEnforcedFlag(B, State, B.CreateNot(headersOk),
                     0x81F36C2D9A4075BEULL,
                     "morok.win.foundation.headers.bad");

    Value *probeExport = B.CreateCall(
        resolver,
        {imageBase,
         ConstantInt::get(i64, fnv1aName("MorokAbsentExportCanary"))},
        "morok.win.foundation.export.probe");
    foldState(B, State, probeExport, rng.next(), "morok.win.foundation.export");
    Value *stubScan = B.CreateCall(scanner, {imagePtr, ConstantInt::getFalse(ctx)},
                                   "morok.win.foundation.sys.scan");
    foldState(B, State, stubScan, rng.next(), "morok.win.foundation.sys");

    FunctionCallee addVeh = M.getOrInsertFunction(
        "AddVectoredExceptionHandler",
        FunctionType::get(ptr, {i32, ptr}, false));
    Value *veh = B.CreateCall(
        addVeh, {ConstantInt::get(i32, 1), vehHandler},
        "morok.win.foundation.veh.handle");
    B.CreateStore(veh, windowsVehHandle(M))->setVolatile(true);
    foldEnforcedFlag(B, State,
                     B.CreateICmpEQ(veh, ConstantPointerNull::get(ptr)),
                     0x4C62E5B190AD378FULL,
                     "morok.win.foundation.veh.missing");
    B.CreateRetVoid();
    return fn;
}

Function *windowsPebHeapDebugProbe(Module &M, GlobalVariable *State,
                                   ir::IRRandom &rng, const Triple &TT) {
    if (!TT.isOSWindows() || TT.getArch() != Triple::x86_64 ||
        intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.win.pebheap.probe"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(Type::getVoidTy(ctx), false),
                                GlobalValue::PrivateLinkage,
                                "morok.win.pebheap.probe", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    Function *pebReader = windowsPebReader(M);
    if (!pebReader)
        return nullptr;

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *readPebBB = BasicBlock::Create(ctx, "read.peb", fn);
    auto *readHeapBB = BasicBlock::Create(ctx, "read.heap", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    Value *peb = B.CreateCall(pebReader, {}, "morok.win.pebheap.peb");
    foldState(B, State, peb, rng.next(), "morok.win.pebheap.peb.mix");
    B.CreateCondBr(B.CreateICmpNE(peb, ConstantInt::get(ip, 0),
                                  "morok.win.pebheap.peb.present"),
                   readPebBB, retBB);

    IRBuilder<> PB(readPebBB);
    Value *pebPtr = PB.CreateIntToPtr(peb, ptr, "morok.win.pebheap.peb.ptr");
    Value *beingDebugged =
        loadAt(PB, M, i8, pebPtr, 0x02, "morok.win.pebheap.being.debugged");
    Value *ntGlobalFlag =
        loadAt(PB, M, i32, pebPtr, 0xBC, "morok.win.pebheap.nt.global.flag");
    Value *processHeap =
        loadAt(PB, M, ip, pebPtr, 0x30, "morok.win.pebheap.process.heap");
    foldState(PB, State, beingDebugged, rng.next(),
              "morok.win.pebheap.being.debugged.mix");
    foldState(PB, State, ntGlobalFlag, rng.next(),
              "morok.win.pebheap.nt.global.flag.mix");
    foldState(PB, State, processHeap, rng.next(),
              "morok.win.pebheap.process.heap.mix");
    foldEnforcedFlag(PB, State,
                     PB.CreateICmpNE(
                         beingDebugged, ConstantInt::get(i8, 0),
                         "morok.win.pebheap.being.debugged.hit"),
                     0xBAE7D1C05A16E903ULL,
                     "morok.win.pebheap.being.debugged");
    Value *ntDebugBits =
        PB.CreateAnd(ntGlobalFlag, ConstantInt::get(i32, 0x70),
                     "morok.win.pebheap.nt.global.flag.bits");
    foldEnforcedFlag(PB, State,
                     PB.CreateICmpNE(
                         ntDebugBits, ConstantInt::get(i32, 0),
                         "morok.win.pebheap.nt.global.flag.hit"),
                     0xE43BC91F672A580DULL,
                     "morok.win.pebheap.nt.global.flag");
    PB.CreateCondBr(PB.CreateICmpNE(processHeap, ConstantInt::get(ip, 0),
                                    "morok.win.pebheap.heap.present"),
                    readHeapBB, retBB);

    IRBuilder<> HB(readHeapBB);
    Value *heapPtr =
        HB.CreateIntToPtr(processHeap, ptr, "morok.win.pebheap.heap.ptr");
    Value *heapFlags =
        loadAt(HB, M, i32, heapPtr, 0x70, "morok.win.pebheap.heap.flags");
    Value *heapForceFlags = loadAt(HB, M, i32, heapPtr, 0x74,
                                   "morok.win.pebheap.heap.force.flags");
    foldState(HB, State, heapFlags, rng.next(),
              "morok.win.pebheap.heap.flags.mix");
    foldState(HB, State, heapForceFlags, rng.next(),
              "morok.win.pebheap.heap.force.flags.mix");
    Value *heapDebugBits =
        HB.CreateAnd(heapFlags, ConstantInt::get(i32, 0x40000060),
                     "morok.win.pebheap.heap.flags.debug.bits");
    foldEnforcedFlag(HB, State,
                     HB.CreateICmpNE(
                         heapDebugBits, ConstantInt::get(i32, 0),
                         "morok.win.pebheap.heap.flags.hit"),
                     0x6A278C0D4E95B1F3ULL,
                     "morok.win.pebheap.heap.flags");
    foldEnforcedFlag(HB, State,
                     HB.CreateICmpNE(
                         heapForceFlags, ConstantInt::get(i32, 0),
                         "morok.win.pebheap.heap.force.flags.hit"),
                     0x91D630A24CFB5875ULL,
                     "morok.win.pebheap.heap.force.flags");
    Value *heapVsPeb =
        HB.CreateOr(HB.CreateZExt(heapDebugBits, ip),
                    HB.CreateShl(HB.CreateZExt(heapForceFlags, ip),
                                 ConstantInt::get(ip, 32)),
                    "morok.win.pebheap.heap.composite");
    foldState(HB, State, heapVsPeb, rng.next(),
              "morok.win.pebheap.heap.composite.mix");
    HB.CreateBr(retBB);

    IRBuilder<> RB(retBB);
    RB.CreateRetVoid();
    return fn;
}

Function *windowsDebugObjectProbe(Module &M, GlobalVariable *State,
                                  ir::IRRandom &rng, const Triple &TT) {
    if (!TT.isOSWindows() || TT.getArch() != Triple::x86_64 ||
        intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.win.dbgobj.probe"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i16 = Type::getInt16Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    constexpr std::uint64_t kObjectTypesBufferBytes = 16384;
    constexpr std::uint64_t kObjectTypesHeaderBytes = 8;
    constexpr std::uint64_t kObjectTypeInfoFixedBytes = 0x68;
    constexpr std::uint32_t kObjectTypeWalkLimit = 64;
    auto *fn = Function::Create(FunctionType::get(Type::getVoidTy(ctx), false),
                                GlobalValue::PrivateLinkage,
                                "morok.win.dbgobj.probe", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    Function *pebReader = windowsPebReader(M);
    Function *moduleByHash = windowsLdrModuleByHash(M);
    Function *resolver = windowsPeExportResolver(M);
    Function *wideHash = windowsWideNameHash(M);
    if (!pebReader || !moduleByHash || !resolver || !wideHash)
        return nullptr;

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *resolveBB = BasicBlock::Create(ctx, "resolve", fn);
    auto *queryProcessBB = BasicBlock::Create(ctx, "query.process", fn);
    auto *objectGateBB = BasicBlock::Create(ctx, "object.gate", fn);
    auto *queryObjectBB = BasicBlock::Create(ctx, "query.object", fn);
    auto *objectLoopBB = BasicBlock::Create(ctx, "object.loop", fn);
    auto *objectBodyBB = BasicBlock::Create(ctx, "object.body", fn);
    auto *objectNextBB = BasicBlock::Create(ctx, "object.next", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    AllocaInst *retLen = B.CreateAlloca(i32, nullptr, "morok.win.dbgobj.retlen");
    AllocaInst *debugPort =
        B.CreateAlloca(ip, nullptr, "morok.win.dbgobj.debug.port.slot");
    AllocaInst *debugObject =
        B.CreateAlloca(ip, nullptr, "morok.win.dbgobj.debug.object.slot");
    AllocaInst *debugFlags =
        B.CreateAlloca(i32, nullptr, "morok.win.dbgobj.debug.flags.slot");
    AllocaInst *debugObjectCount =
        B.CreateAlloca(i32, nullptr, "morok.win.dbgobj.object.count.slot");
    auto *typesBufTy = ArrayType::get(i8, kObjectTypesBufferBytes);
    AllocaInst *typesBuf =
        B.CreateAlloca(typesBufTy, nullptr, "morok.win.dbgobj.types.buf");
    B.CreateStore(ConstantInt::get(i32, 0), retLen)->setVolatile(true);
    B.CreateStore(ConstantInt::get(ip, 0), debugPort)->setVolatile(true);
    B.CreateStore(ConstantInt::get(ip, 0), debugObject)->setVolatile(true);
    B.CreateStore(ConstantInt::get(i32, 1), debugFlags)->setVolatile(true);
    B.CreateStore(ConstantInt::get(i32, 0), debugObjectCount)
        ->setVolatile(true);

    Value *peb = B.CreateCall(pebReader, {}, "morok.win.dbgobj.peb");
    foldState(B, State, peb, rng.next(), "morok.win.dbgobj.peb.mix");
    B.CreateCondBr(B.CreateICmpNE(peb, ConstantInt::get(ip, 0),
                                  "morok.win.dbgobj.peb.present"),
                   resolveBB, retBB);

    IRBuilder<> RB(resolveBB);
    Value *ntdll = RB.CreateCall(
        moduleByHash,
        {peb, ConstantInt::get(i64, fnv1aLowerAsciiName("ntdll.dll"))},
        "morok.win.dbgobj.ntdll");
    foldState(RB, State, ntdll, rng.next(), "morok.win.dbgobj.ntdll.mix");
    Value *qip = RB.CreateCall(
        resolver,
        {ntdll, ConstantInt::get(i64, fnv1aName("NtQueryInformationProcess"))},
        "morok.win.dbgobj.ntqip");
    Value *qo = RB.CreateCall(
        resolver,
        {ntdll, ConstantInt::get(i64, fnv1aName("NtQueryObject"))},
        "morok.win.dbgobj.ntqo");
    foldState(RB, State, qip, rng.next(), "morok.win.dbgobj.ntqip.mix");
    foldState(RB, State, qo, rng.next(), "morok.win.dbgobj.ntqo.mix");
    RB.CreateCondBr(RB.CreateAnd(RB.CreateICmpNE(ntdll, ConstantInt::get(ip, 0)),
                                 RB.CreateICmpNE(qip, ConstantInt::get(ip, 0)),
                                 "morok.win.dbgobj.ntqip.ready"),
                    queryProcessBB, objectGateBB);

    IRBuilder<> QB(queryProcessBB);
    auto *qipTy = FunctionType::get(i32, {ptr, i32, ptr, i32, ptr}, false);
    Value *qipPtr = QB.CreateIntToPtr(qip, ptr, "morok.win.dbgobj.ntqip.ptr");
    Value *currentProcess = QB.CreateIntToPtr(
        ConstantInt::getSigned(ip, -1), ptr, "morok.win.dbgobj.current");
    Value *debugPortStatus = QB.CreateCall(
        qipTy, qipPtr,
        {currentProcess, ConstantInt::get(i32, 7), debugPort,
         ConstantInt::get(i32, 8), retLen},
        "morok.win.dbgobj.debug.port.status");
    Value *debugPortValue =
        QB.CreateLoad(ip, debugPort, "morok.win.dbgobj.debug.port");
    cast<LoadInst>(debugPortValue)->setVolatile(true);
    Value *debugPortOk =
        QB.CreateICmpSGE(debugPortStatus, ConstantInt::get(i32, 0),
                         "morok.win.dbgobj.debug.port.ok");
    Value *debugPortHit = QB.CreateAnd(
        debugPortOk,
        QB.CreateICmpNE(debugPortValue, ConstantInt::get(ip, 0),
                        "morok.win.dbgobj.debug.port.nonzero"),
        "morok.win.dbgobj.debug.port.hit");
    foldState(QB, State, debugPortStatus, rng.next(),
              "morok.win.dbgobj.debug.port.status.mix");
    foldState(QB, State, debugPortValue, rng.next(),
              "morok.win.dbgobj.debug.port.mix");
    foldEnforcedFlag(QB, State, debugPortHit, 0xA1B0E76C39D4825FULL,
                     "morok.win.dbgobj.debug.port");

    Value *debugObjectStatus = QB.CreateCall(
        qipTy, qipPtr,
        {currentProcess, ConstantInt::get(i32, 0x1E), debugObject,
         ConstantInt::get(i32, 8), retLen},
        "morok.win.dbgobj.debug.object.status");
    Value *debugObjectValue =
        QB.CreateLoad(ip, debugObject, "morok.win.dbgobj.debug.object.handle");
    cast<LoadInst>(debugObjectValue)->setVolatile(true);
    Value *debugObjectOk =
        QB.CreateICmpSGE(debugObjectStatus, ConstantInt::get(i32, 0),
                         "morok.win.dbgobj.debug.object.ok");
    Value *debugObjectHit = QB.CreateAnd(
        debugObjectOk,
        QB.CreateICmpNE(debugObjectValue, ConstantInt::get(ip, 0),
                        "morok.win.dbgobj.debug.object.nonzero"),
        "morok.win.dbgobj.debug.object.handle.hit");
    foldState(QB, State, debugObjectStatus, rng.next(),
              "morok.win.dbgobj.debug.object.status.mix");
    foldState(QB, State, debugObjectValue, rng.next(),
              "morok.win.dbgobj.debug.object.mix");
    foldEnforcedFlag(QB, State, debugObjectHit, 0xD971A24B6E830C5FULL,
                     "morok.win.dbgobj.debug.object");

    Value *debugFlagsStatus = QB.CreateCall(
        qipTy, qipPtr,
        {currentProcess, ConstantInt::get(i32, 0x1F), debugFlags,
         ConstantInt::get(i32, 4), retLen},
        "morok.win.dbgobj.debug.flags.status");
    Value *debugFlagsValue =
        QB.CreateLoad(i32, debugFlags, "morok.win.dbgobj.debug.flags");
    cast<LoadInst>(debugFlagsValue)->setVolatile(true);
    Value *debugFlagsOk =
        QB.CreateICmpSGE(debugFlagsStatus, ConstantInt::get(i32, 0),
                         "morok.win.dbgobj.debug.flags.ok");
    Value *debugFlagsHit = QB.CreateAnd(
        debugFlagsOk,
        QB.CreateICmpEQ(debugFlagsValue, ConstantInt::get(i32, 0),
                        "morok.win.dbgobj.debug.flags.zero"),
        "morok.win.dbgobj.debug.flags.hit");
    foldState(QB, State, debugFlagsStatus, rng.next(),
              "morok.win.dbgobj.debug.flags.status.mix");
    foldState(QB, State, debugFlagsValue, rng.next(),
              "morok.win.dbgobj.debug.flags.mix");
    foldEnforcedFlag(QB, State, debugFlagsHit, 0x58C6E3B19A2D704FULL,
                     "morok.win.dbgobj.debug.flags");
    QB.CreateBr(objectGateBB);

    IRBuilder<> GB(objectGateBB);
    GB.CreateCondBr(GB.CreateAnd(GB.CreateICmpNE(qo, ConstantInt::get(ip, 0)),
                                 GB.CreateICmpNE(ntdll, ConstantInt::get(ip, 0)),
                                 "morok.win.dbgobj.ntqo.ready"),
                    queryObjectBB, retBB);

    IRBuilder<> OB(queryObjectBB);
    auto *qoTy = FunctionType::get(i32, {ptr, i32, ptr, i32, ptr}, false);
    Value *qoPtr = OB.CreateIntToPtr(qo, ptr, "morok.win.dbgobj.ntqo.ptr");
    Value *objectStatus = OB.CreateCall(
        qoTy, qoPtr,
        {ConstantPointerNull::get(ptr), ConstantInt::get(i32, 3), typesBuf,
         ConstantInt::get(i32, kObjectTypesBufferBytes), retLen},
        "morok.win.dbgobj.object.types.status");
    Value *objectOk = OB.CreateICmpSGE(objectStatus, ConstantInt::get(i32, 0),
                                       "morok.win.dbgobj.object.types.ok");
    Value *returnedLen =
        OB.CreateLoad(i32, retLen, "morok.win.dbgobj.object.types.retlen");
    cast<LoadInst>(returnedLen)->setVolatile(true);
    foldState(OB, State, objectStatus, rng.next(),
              "morok.win.dbgobj.object.types.status.mix");
    foldState(OB, State, returnedLen, rng.next(),
              "morok.win.dbgobj.object.types.retlen.mix");
    OB.CreateCondBr(objectOk, objectLoopBB, retBB);

    IRBuilder<> LB(objectLoopBB);
    auto *objIdx = LB.CreatePHI(i32, 2, "morok.win.dbgobj.object.idx");
    auto *objOff = LB.CreatePHI(ip, 2, "morok.win.dbgobj.object.off");
    objIdx->addIncoming(ConstantInt::get(i32, 0), queryObjectBB);
    objOff->addIncoming(ConstantInt::get(ip, kObjectTypesHeaderBytes),
                        queryObjectBB);
    Value *typeCount =
        loadAt(LB, M, i32, typesBuf, 0ULL, "morok.win.dbgobj.object.types.count");
    Value *typeLimit = LB.CreateSelect(
        LB.CreateICmpULT(typeCount, ConstantInt::get(i32, kObjectTypeWalkLimit)),
        typeCount, ConstantInt::get(i32, kObjectTypeWalkLimit),
        "morok.win.dbgobj.object.types.limit");
    Value *idxOk =
        LB.CreateICmpULT(objIdx, typeLimit, "morok.win.dbgobj.object.idx.ok");
    Value *returnedLenIp =
        LB.CreateZExt(returnedLen, ip, "morok.win.dbgobj.object.retlen.ip");
    Value *walkLimit = LB.CreateSelect(
        LB.CreateICmpULT(returnedLenIp,
                         ConstantInt::get(ip, kObjectTypesBufferBytes)),
        returnedLenIp, ConstantInt::get(ip, kObjectTypesBufferBytes),
        "morok.win.dbgobj.object.walk.limit");
    Value *entryEnd =
        LB.CreateAdd(objOff, ConstantInt::get(ip, kObjectTypeInfoFixedBytes),
                     "morok.win.dbgobj.object.entry.end");
    Value *offOk = LB.CreateICmpULE(entryEnd, walkLimit,
                                    "morok.win.dbgobj.object.off.ok");
    LB.CreateCondBr(LB.CreateAnd(idxOk, offOk,
                                 "morok.win.dbgobj.object.keep.walking"),
                    objectBodyBB, retBB);

    IRBuilder<> TB(objectBodyBB);
    Value *entryPtr =
        gepI8(TB, M, typesBuf, objOff, "morok.win.dbgobj.object.entry");
    Value *nameLen =
        loadAt(TB, M, i16, entryPtr, 0ULL, "morok.win.dbgobj.object.name.len");
    Value *nameMax =
        loadAt(TB, M, i16, entryPtr, 2, "morok.win.dbgobj.object.name.max");
    Value *nameBuffer =
        loadAt(TB, M, ip, entryPtr, 8, "morok.win.dbgobj.object.name.buffer");
    Value *totalObjects =
        loadAt(TB, M, i32, entryPtr, 16,
               "morok.win.dbgobj.object.total.objects");
    Value *nameReturnedLenIp =
        TB.CreateZExt(returnedLen, ip, "morok.win.dbgobj.object.name.retlen.ip");
    Value *nameWalkLimit = TB.CreateSelect(
        TB.CreateICmpULT(nameReturnedLenIp,
                         ConstantInt::get(ip, kObjectTypesBufferBytes)),
        nameReturnedLenIp, ConstantInt::get(ip, kObjectTypesBufferBytes),
        "morok.win.dbgobj.object.name.limit");
    Value *typesBase =
        TB.CreatePtrToInt(typesBuf, ip, "morok.win.dbgobj.object.types.base");
    Value *typesEnd = TB.CreateAdd(typesBase, nameWalkLimit,
                                   "morok.win.dbgobj.object.types.end");
    Value *nameMaxIp =
        TB.CreateZExt(nameMax, ip, "morok.win.dbgobj.object.name.max.ip");
    Value *nameEnd =
        TB.CreateAdd(nameBuffer, nameMaxIp, "morok.win.dbgobj.object.name.end");
    Value *nameNoWrap = TB.CreateICmpUGE(
        nameEnd, nameBuffer, "morok.win.dbgobj.object.name.no.wrap");
    Value *nameStartOk = TB.CreateICmpUGE(
        nameBuffer, typesBase, "morok.win.dbgobj.object.name.start.ok");
    Value *nameEndOk = TB.CreateICmpULE(
        nameEnd, typesEnd, "morok.win.dbgobj.object.name.end.ok");
    Value *nameLenOk = TB.CreateICmpULE(
        nameLen, nameMax, "morok.win.dbgobj.object.name.len.ok");
    Value *nameRangeOk =
        TB.CreateAnd(nameStartOk, nameEndOk,
                     "morok.win.dbgobj.object.name.range.ok");
    Value *nameSizeOk =
        TB.CreateAnd(nameNoWrap, nameLenOk,
                     "morok.win.dbgobj.object.name.size.ok");
    Value *nameValid =
        TB.CreateAnd(nameRangeOk, nameSizeOk,
                     "morok.win.dbgobj.object.name.valid");
    Value *safeNameBuffer =
        TB.CreateSelect(nameValid, nameBuffer, ConstantInt::get(ip, 0),
                        "morok.win.dbgobj.object.name.safe");
    Value *safeNameLen =
        TB.CreateSelect(nameValid, nameLen, ConstantInt::get(i16, 0),
                        "morok.win.dbgobj.object.name.len.safe");
    Value *typeHash = TB.CreateCall(
        wideHash,
        {TB.CreateIntToPtr(safeNameBuffer, ptr,
                           "morok.win.dbgobj.object.name.ptr"),
         safeNameLen},
        "morok.win.dbgobj.object.type.hash");
    Value *isDebugObject = TB.CreateICmpEQ(
        typeHash, ConstantInt::get(i64, fnv1aLowerAsciiName("DebugObject")),
        "morok.win.dbgobj.object.debug.match");
    Value *hasObjects = TB.CreateICmpNE(totalObjects, ConstantInt::get(i32, 0),
                                        "morok.win.dbgobj.object.total.nonzero");
    Value *debugObjectTypeHit =
        TB.CreateAnd(isDebugObject, hasObjects,
                     "morok.win.dbgobj.object.debug.hit");
    Value *oldCount =
        TB.CreateLoad(i32, debugObjectCount,
                      "morok.win.dbgobj.object.debug.count.old");
    cast<LoadInst>(oldCount)->setVolatile(true);
    Value *nextCount =
        TB.CreateSelect(isDebugObject,
                        TB.CreateAdd(oldCount, totalObjects,
                                     "morok.win.dbgobj.object.debug.count.add"),
                        oldCount, "morok.win.dbgobj.object.debug.count.next");
    TB.CreateStore(nextCount, debugObjectCount)->setVolatile(true);
    foldState(TB, State, typeHash, rng.next(),
              "morok.win.dbgobj.object.type.hash.mix");
    foldEnforcedFlag(TB, State, debugObjectTypeHit, 0xCC7E31A04B962D85ULL,
                     "morok.win.dbgobj.object.debug");
    TB.CreateBr(objectNextBB);

    IRBuilder<> NB(objectNextBB);
    Value *nameSpan =
        NB.CreateAnd(NB.CreateAdd(NB.CreateZExt(nameMax, ip),
                                  ConstantInt::get(ip, 7),
                                  "morok.win.dbgobj.object.name.max.pad"),
                     ConstantInt::get(ip, ~7ULL),
                     "morok.win.dbgobj.object.name.max.align");
    Value *fixedNext =
        NB.CreateAdd(objOff, ConstantInt::get(ip, kObjectTypeInfoFixedBytes),
                     "morok.win.dbgobj.object.fixed.next");
    Value *nextOff =
        NB.CreateAdd(fixedNext, nameSpan, "morok.win.dbgobj.object.next.off");
    Value *nextIdx =
        NB.CreateAdd(objIdx, ConstantInt::get(i32, 1),
                     "morok.win.dbgobj.object.next.idx");
    NB.CreateBr(objectLoopBB);
    objIdx->addIncoming(nextIdx, objectNextBB);
    objOff->addIncoming(nextOff, objectNextBB);

    IRBuilder<> RetB(retBB);
    Value *finalCount =
        RetB.CreateLoad(i32, debugObjectCount,
                        "morok.win.dbgobj.object.debug.count.final");
    cast<LoadInst>(finalCount)->setVolatile(true);
    foldState(RetB, State, finalCount, rng.next(),
              "morok.win.dbgobj.object.debug.count.mix");
    foldEnforcedFlag(
        RetB, State,
        RetB.CreateICmpNE(finalCount, ConstantInt::get(i32, 0),
                          "morok.win.dbgobj.object.debug.count.hit"),
        0xE019A8C35F7B62D4ULL, "morok.win.dbgobj.object.debug.count");
    RetB.CreateRetVoid();
    return fn;
}

Function *windowsThreadHideProbe(Module &M, GlobalVariable *State,
                                 ir::IRRandom &rng, const Triple &TT) {
    if (!TT.isOSWindows() || TT.getArch() != Triple::x86_64 ||
        intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.win.thide.probe"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(Type::getVoidTy(ctx), false),
                                GlobalValue::PrivateLinkage,
                                "morok.win.thide.probe", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    Function *pebReader = windowsPebReader(M);
    Function *moduleByHash = windowsLdrModuleByHash(M);
    Function *resolver = windowsPeExportResolver(M);
    if (!pebReader || !moduleByHash || !resolver)
        return nullptr;

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *resolveBB = BasicBlock::Create(ctx, "resolve", fn);
    auto *loopBB = BasicBlock::Create(ctx, "loop", fn);
    auto *closePrevBB = BasicBlock::Create(ctx, "close.prev", fn);
    auto *closePrevCallBB = BasicBlock::Create(ctx, "close.prev.call", fn);
    auto *probeBB = BasicBlock::Create(ctx, "probe", fn);
    auto *nextBB = BasicBlock::Create(ctx, "next", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);
    auto *retCloseBB = BasicBlock::Create(ctx, "ret.close", fn);
    auto *doneBB = BasicBlock::Create(ctx, "done", fn);

    IRBuilder<> B(entry);
    AllocaInst *retLen = B.CreateAlloca(i32, nullptr, "morok.win.thide.retlen");
    AllocaInst *nextThread =
        B.CreateAlloca(ip, nullptr, "morok.win.thide.next.slot");
    AllocaInst *hidden =
        B.CreateAlloca(i8, nullptr, "morok.win.thide.hidden.slot");
    AllocaInst *threadsSeen =
        B.CreateAlloca(i32, nullptr, "morok.win.thide.seen.slot");
    AllocaInst *failures =
        B.CreateAlloca(i32, nullptr, "morok.win.thide.fail.slot");
    AllocaInst *closeSlot =
        B.CreateAlloca(ip, nullptr, "morok.win.thide.close.slot");
    B.CreateStore(ConstantInt::get(i32, 0), retLen)->setVolatile(true);
    B.CreateStore(ConstantInt::get(ip, 0), nextThread)->setVolatile(true);
    B.CreateStore(ConstantInt::get(i8, 0), hidden)->setVolatile(true);
    B.CreateStore(ConstantInt::get(i32, 0), threadsSeen)->setVolatile(true);
    B.CreateStore(ConstantInt::get(i32, 0), failures)->setVolatile(true);
    B.CreateStore(ConstantInt::get(ip, 0), closeSlot)->setVolatile(true);

    Value *peb = B.CreateCall(pebReader, {}, "morok.win.thide.peb");
    foldState(B, State, peb, rng.next(), "morok.win.thide.peb.mix");
    B.CreateCondBr(B.CreateICmpNE(peb, ConstantInt::get(ip, 0),
                                  "morok.win.thide.peb.present"),
                   resolveBB, retBB);

    IRBuilder<> RB(resolveBB);
    Value *ntdll = RB.CreateCall(
        moduleByHash,
        {peb, ConstantInt::get(i64, fnv1aLowerAsciiName("ntdll.dll"))},
        "morok.win.thide.ntdll");
    Function *peResolve = resolver;
    Value *getNext = RB.CreateCall(
        peResolve,
        {ntdll, ConstantInt::get(i64, fnv1aName("NtGetNextThread"))},
        "morok.win.thide.ntgetnextthread");
    Value *setInfo = RB.CreateCall(
        peResolve,
        {ntdll, ConstantInt::get(i64, fnv1aName("NtSetInformationThread"))},
        "morok.win.thide.ntsetinformationthread");
    Value *queryInfo = RB.CreateCall(
        peResolve,
        {ntdll, ConstantInt::get(i64, fnv1aName("NtQueryInformationThread"))},
        "morok.win.thide.ntqueryinformationthread");
    Value *closeFn = RB.CreateCall(
        peResolve, {ntdll, ConstantInt::get(i64, fnv1aName("NtClose"))},
        "morok.win.thide.ntclose");
    RB.CreateStore(closeFn, closeSlot)->setVolatile(true);
    foldState(RB, State, ntdll, rng.next(), "morok.win.thide.ntdll.mix");
    foldState(RB, State, getNext, rng.next(),
              "morok.win.thide.ntgetnextthread.mix");
    foldState(RB, State, setInfo, rng.next(),
              "morok.win.thide.ntsetinformationthread.mix");
    foldState(RB, State, queryInfo, rng.next(),
              "morok.win.thide.ntqueryinformationthread.mix");
    Value *ready = RB.CreateAnd(
        RB.CreateAnd(RB.CreateICmpNE(getNext, ConstantInt::get(ip, 0)),
                     RB.CreateICmpNE(closeFn, ConstantInt::get(ip, 0),
                                     "morok.win.thide.ntclose.ready"),
                     "morok.win.thide.close.ready"),
        RB.CreateAnd(RB.CreateICmpNE(setInfo, ConstantInt::get(ip, 0)),
                     RB.CreateICmpNE(queryInfo, ConstantInt::get(ip, 0)),
                     "morok.win.thide.info.ready"),
        "morok.win.thide.ready");
    RB.CreateCondBr(ready, loopBB, retBB);

    IRBuilder<> LB(loopBB);
    auto *current = LB.CreatePHI(ip, 2, "morok.win.thide.current");
    auto *idx = LB.CreatePHI(i32, 2, "morok.win.thide.idx");
    current->addIncoming(ConstantInt::get(ip, 0), resolveBB);
    idx->addIncoming(ConstantInt::get(i32, 0), resolveBB);
    LB.CreateStore(ConstantInt::get(ip, 0), nextThread)->setVolatile(true);
    auto *getNextTy =
        FunctionType::get(i32, {ptr, ptr, i32, i32, i32, ptr}, false);
    Value *getNextPtr =
        LB.CreateIntToPtr(getNext, ptr, "morok.win.thide.getnext.ptr");
    Value *currentProcess = LB.CreateIntToPtr(
        ConstantInt::getSigned(ip, -1), ptr, "morok.win.thide.current.process");
    Value *currentHandle =
        LB.CreateIntToPtr(current, ptr, "morok.win.thide.current.handle");
    Value *getStatus = LB.CreateCall(
        getNextTy, getNextPtr,
        {currentProcess, currentHandle, ConstantInt::get(i32, 0x60),
         ConstantInt::get(i32, 0), ConstantInt::get(i32, 0), nextThread},
        "morok.win.thide.getnext.status");
    Value *nextHandle =
        LB.CreateLoad(ip, nextThread, "morok.win.thide.next.handle");
    cast<LoadInst>(nextHandle)->setVolatile(true);
    foldState(LB, State, getStatus, rng.next(),
              "morok.win.thide.getnext.status.mix");
    Value *gotThread = LB.CreateAnd(
        LB.CreateICmpSGE(getStatus, ConstantInt::get(i32, 0)),
        LB.CreateAnd(LB.CreateICmpNE(nextHandle, ConstantInt::get(ip, 0)),
                     LB.CreateICmpULT(idx, ConstantInt::get(i32, 64)),
                     "morok.win.thide.next.valid"),
        "morok.win.thide.got.thread");
    LB.CreateCondBr(gotThread, closePrevBB, retBB);

    IRBuilder<> CP(closePrevBB);
    Value *closePrevFn =
        CP.CreateLoad(ip, closeSlot, "morok.win.thide.close.prev.fn");
    cast<LoadInst>(closePrevFn)->setVolatile(true);
    Value *canClosePrevious = CP.CreateAnd(
        CP.CreateICmpNE(current, ConstantInt::get(ip, 0),
                        "morok.win.thide.has.previous"),
        CP.CreateICmpNE(closePrevFn, ConstantInt::get(ip, 0),
                        "morok.win.thide.close.prev.available"),
        "morok.win.thide.close.prev.needed");
    CP.CreateCondBr(canClosePrevious, closePrevCallBB, probeBB);

    IRBuilder<> CCB(closePrevCallBB);
    auto *closeTy = FunctionType::get(i32, {ptr}, false);
    Value *closePtr =
        CCB.CreateIntToPtr(closePrevFn, ptr, "morok.win.thide.close.prev.ptr");
    Value *closePrevStatus = CCB.CreateCall(
        closeTy, closePtr,
        {CCB.CreateIntToPtr(current, ptr, "morok.win.thide.close.prev.handle")},
        "morok.win.thide.close.prev.status");
    foldState(CCB, State, closePrevStatus, rng.next(),
              "morok.win.thide.close.prev.status.mix");
    CCB.CreateBr(probeBB);

    IRBuilder<> PB(probeBB);
    auto *setTy = FunctionType::get(i32, {ptr, i32, ptr, i32}, false);
    auto *queryTy = FunctionType::get(i32, {ptr, i32, ptr, i32, ptr}, false);
    Value *threadHandle =
        PB.CreateIntToPtr(nextHandle, ptr, "morok.win.thide.thread.handle");
    Value *setPtr =
        PB.CreateIntToPtr(setInfo, ptr, "morok.win.thide.set.ptr");
    Value *queryPtr =
        PB.CreateIntToPtr(queryInfo, ptr, "morok.win.thide.query.ptr");
    Value *seenOld =
        PB.CreateLoad(i32, threadsSeen, "morok.win.thide.seen.old");
    cast<LoadInst>(seenOld)->setVolatile(true);
    PB.CreateStore(PB.CreateAdd(seenOld, ConstantInt::get(i32, 1),
                                "morok.win.thide.seen.next"),
                   threadsSeen)
        ->setVolatile(true);
    Value *setStatus = PB.CreateCall(
        setTy, setPtr,
        {threadHandle, ConstantInt::get(i32, 0x11),
         ConstantPointerNull::get(ptr), ConstantInt::get(i32, 0)},
        "morok.win.thide.set.status");
    PB.CreateStore(ConstantInt::get(i8, 0), hidden)->setVolatile(true);
    Value *queryStatus = PB.CreateCall(
        queryTy, queryPtr,
        {threadHandle, ConstantInt::get(i32, 0x11), hidden,
         ConstantInt::get(i32, 1), retLen},
        "morok.win.thide.query.status");
    Value *hiddenValue = PB.CreateLoad(i8, hidden, "morok.win.thide.hidden");
    cast<LoadInst>(hiddenValue)->setVolatile(true);
    Value *setOk = PB.CreateICmpSGE(setStatus, ConstantInt::get(i32, 0),
                                    "morok.win.thide.set.ok");
    Value *queryOk = PB.CreateICmpSGE(queryStatus, ConstantInt::get(i32, 0),
                                      "morok.win.thide.query.ok");
    Value *hiddenOk = PB.CreateICmpNE(hiddenValue, ConstantInt::get(i8, 0),
                                      "morok.win.thide.hidden.ok");
    Value *stuck = PB.CreateAnd(PB.CreateAnd(setOk, queryOk,
                                             "morok.win.thide.status.ok"),
                                hiddenOk, "morok.win.thide.stuck");
    Value *failed = PB.CreateNot(stuck, "morok.win.thide.failed");
    Value *failOld =
        PB.CreateLoad(i32, failures, "morok.win.thide.fail.old");
    cast<LoadInst>(failOld)->setVolatile(true);
    PB.CreateStore(PB.CreateAdd(failOld, PB.CreateZExt(failed, i32),
                                "morok.win.thide.fail.next"),
                   failures)
        ->setVolatile(true);
    foldState(PB, State, setStatus, rng.next(),
              "morok.win.thide.set.status.mix");
    foldState(PB, State, queryStatus, rng.next(),
              "morok.win.thide.query.status.mix");
    foldState(PB, State, hiddenValue, rng.next(),
              "morok.win.thide.hidden.mix");
    foldEnforcedFlag(PB, State, failed, 0xB68F214CD03E975AULL,
                     "morok.win.thide.failed");
    PB.CreateBr(nextBB);

    IRBuilder<> NB(nextBB);
    Value *nextIdx =
        NB.CreateAdd(idx, ConstantInt::get(i32, 1),
                     "morok.win.thide.next.idx");
    NB.CreateBr(loopBB);
    current->addIncoming(nextHandle, nextBB);
    idx->addIncoming(nextIdx, nextBB);

    IRBuilder<> RetB(retBB);
    auto *lastHandle = RetB.CreatePHI(ip, 3, "morok.win.thide.last.handle");
    lastHandle->addIncoming(ConstantInt::get(ip, 0), entry);
    lastHandle->addIncoming(ConstantInt::get(ip, 0), resolveBB);
    lastHandle->addIncoming(current, loopBB);
    Value *closeFinal =
        RetB.CreateLoad(ip, closeSlot, "morok.win.thide.close.final");
    cast<LoadInst>(closeFinal)->setVolatile(true);
    Value *shouldClose = RetB.CreateAnd(
        RetB.CreateICmpNE(lastHandle, ConstantInt::get(ip, 0)),
        RetB.CreateICmpNE(closeFinal, ConstantInt::get(ip, 0)),
        "morok.win.thide.close.final.needed");
    RetB.CreateCondBr(shouldClose, retCloseBB, doneBB);

    IRBuilder<> RCB(retCloseBB);
    Value *closeFinalPtr =
        RCB.CreateIntToPtr(closeFinal, ptr, "morok.win.thide.close.final.ptr");
    Value *closeFinalStatus = RCB.CreateCall(
        closeTy, closeFinalPtr,
        {RCB.CreateIntToPtr(lastHandle, ptr,
                            "morok.win.thide.close.final.handle")},
        "morok.win.thide.close.final.status");
    foldState(RCB, State, closeFinalStatus, rng.next(),
              "morok.win.thide.close.final.status.mix");
    RCB.CreateBr(doneBB);

    IRBuilder<> DB(doneBB);
    Value *seenFinal =
        DB.CreateLoad(i32, threadsSeen, "morok.win.thide.seen.final");
    cast<LoadInst>(seenFinal)->setVolatile(true);
    Value *failFinal =
        DB.CreateLoad(i32, failures, "morok.win.thide.fail.final");
    cast<LoadInst>(failFinal)->setVolatile(true);
    foldState(DB, State, seenFinal, rng.next(),
              "morok.win.thide.seen.final.mix");
    foldState(DB, State, failFinal, rng.next(),
              "morok.win.thide.fail.final.mix");
    foldEnforcedFlag(DB, State,
                     DB.CreateICmpNE(failFinal, ConstantInt::get(i32, 0),
                                     "morok.win.thide.fail.any"),
                     0x2AC96D507B1E48F3ULL, "morok.win.thide.fail.any");
    DB.CreateRetVoid();
    return fn;
}

Function *windowsPatchRetHelper(Module &M) {
    if (Function *existing = M.getFunction("morok.win.attach.patch.ret"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(i32, {ip, ip}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.win.attach.patch.ret", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    Argument *target = fn->getArg(0);
    target->setName("target");
    Argument *protect = fn->getArg(1);
    protect->setName("protect");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *protectBB = BasicBlock::Create(ctx, "protect", fn);
    auto *writeBB = BasicBlock::Create(ctx, "write", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    AllocaInst *baseSlot = B.CreateAlloca(ip, nullptr, "morok.win.attach.base");
    AllocaInst *sizeSlot = B.CreateAlloca(ip, nullptr, "morok.win.attach.size");
    AllocaInst *oldProt =
        B.CreateAlloca(i32, nullptr, "morok.win.attach.oldprot");
    B.CreateCondBr(B.CreateAnd(B.CreateICmpNE(target, ConstantInt::get(ip, 0)),
                               B.CreateICmpNE(protect, ConstantInt::get(ip, 0)),
                               "morok.win.attach.patch.ret.ready"),
                   protectBB, retBB);

    IRBuilder<> PB(protectBB);
    PB.CreateStore(target, baseSlot)->setVolatile(true);
    PB.CreateStore(ConstantInt::get(ip, 1), sizeSlot)->setVolatile(true);
    auto *protectTy = FunctionType::get(i32, {ptr, ptr, ptr, i32, ptr}, false);
    Value *protectPtr =
        PB.CreateIntToPtr(protect, ptr, "morok.win.attach.protect.ptr");
    Value *status = PB.CreateCall(
        protectTy, protectPtr,
        {PB.CreateIntToPtr(ConstantInt::getSigned(ip, -1), ptr), baseSlot,
         sizeSlot, ConstantInt::get(i32, 0x40), oldProt},
        "morok.win.attach.patch.ret.protect");
    PB.CreateCondBr(PB.CreateICmpSGE(status, ConstantInt::get(i32, 0),
                                    "morok.win.attach.patch.ret.protect.ok"),
                    writeBB, retBB);

    IRBuilder<> WB(writeBB);
    Value *targetPtr =
        WB.CreateIntToPtr(target, ptr, "morok.win.attach.patch.ret.ptr");
    storeAt(WB, M, targetPtr, 0, ConstantInt::get(i8, 0xC3),
            "morok.win.attach.patch.ret.byte");
    Value *oldProtValue =
        WB.CreateLoad(i32, oldProt, "morok.win.attach.patch.ret.oldprot");
    cast<LoadInst>(oldProtValue)->setVolatile(true);
    WB.CreateStore(target, baseSlot)->setVolatile(true);
    WB.CreateStore(ConstantInt::get(ip, 1), sizeSlot)->setVolatile(true);
    Value *restore = WB.CreateCall(
        protectTy, protectPtr,
        {WB.CreateIntToPtr(ConstantInt::getSigned(ip, -1), ptr), baseSlot,
         sizeSlot, oldProtValue, oldProt},
        "morok.win.attach.patch.ret.restore");
    WB.CreateBr(retBB);

    IRBuilder<> RB(retBB);
    auto *result = RB.CreatePHI(i32, 3, "morok.win.attach.patch.ret.result");
    result->addIncoming(ConstantInt::getSigned(i32, -1), entry);
    result->addIncoming(status, protectBB);
    result->addIncoming(restore, writeBB);
    RB.CreateRet(result);
    return fn;
}

Function *windowsPatchRemoteBreakinHelper(Module &M) {
    if (Function *existing = M.getFunction("morok.win.attach.patch.remote"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(i32, {ip, ip, ip}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.win.attach.patch.remote", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    Argument *target = fn->getArg(0);
    target->setName("target");
    Argument *exitProcess = fn->getArg(1);
    exitProcess->setName("exit_process");
    Argument *protect = fn->getArg(2);
    protect->setName("protect");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *protectBB = BasicBlock::Create(ctx, "protect", fn);
    auto *writeBB = BasicBlock::Create(ctx, "write", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    AllocaInst *baseSlot = B.CreateAlloca(ip, nullptr, "morok.win.attach.base");
    AllocaInst *sizeSlot = B.CreateAlloca(ip, nullptr, "morok.win.attach.size");
    AllocaInst *oldProt =
        B.CreateAlloca(i32, nullptr, "morok.win.attach.oldprot");
    Value *ready = B.CreateAnd(
        B.CreateICmpNE(target, ConstantInt::get(ip, 0)),
        B.CreateAnd(B.CreateICmpNE(exitProcess, ConstantInt::get(ip, 0)),
                    B.CreateICmpNE(protect, ConstantInt::get(ip, 0)),
                    "morok.win.attach.patch.remote.funcs"),
        "morok.win.attach.patch.remote.ready");
    B.CreateCondBr(ready, protectBB, retBB);

    IRBuilder<> PB(protectBB);
    PB.CreateStore(target, baseSlot)->setVolatile(true);
    PB.CreateStore(ConstantInt::get(ip, 19), sizeSlot)->setVolatile(true);
    auto *protectTy = FunctionType::get(i32, {ptr, ptr, ptr, i32, ptr}, false);
    Value *protectPtr =
        PB.CreateIntToPtr(protect, ptr, "morok.win.attach.protect.ptr");
    Value *status = PB.CreateCall(
        protectTy, protectPtr,
        {PB.CreateIntToPtr(ConstantInt::getSigned(ip, -1), ptr), baseSlot,
         sizeSlot, ConstantInt::get(i32, 0x40), oldProt},
        "morok.win.attach.patch.remote.protect");
    PB.CreateCondBr(
        PB.CreateICmpSGE(status, ConstantInt::get(i32, 0),
                         "morok.win.attach.patch.remote.protect.ok"),
        writeBB, retBB);

    IRBuilder<> WB(writeBB);
    Value *targetPtr =
        WB.CreateIntToPtr(target, ptr, "morok.win.attach.patch.remote.ptr");
    storeAt(WB, M, targetPtr, 0, ConstantInt::get(i8, 0x48),
            "morok.win.attach.patch.remote.movrcx0");
    storeAt(WB, M, targetPtr, 1, ConstantInt::get(i8, 0xC7),
            "morok.win.attach.patch.remote.movrcx1");
    storeAt(WB, M, targetPtr, 2, ConstantInt::get(i8, 0xC1),
            "morok.win.attach.patch.remote.movrcx2");
    storeAt(WB, M, targetPtr, 3, ConstantInt::get(i8, 0x01),
            "morok.win.attach.patch.remote.exitcode");
    storeAt(WB, M, targetPtr, 4, ConstantInt::get(i8, 0x00),
            "morok.win.attach.patch.remote.exitcode.pad0");
    storeAt(WB, M, targetPtr, 5, ConstantInt::get(i8, 0x00),
            "morok.win.attach.patch.remote.exitcode.pad1");
    storeAt(WB, M, targetPtr, 6, ConstantInt::get(i8, 0x00),
            "morok.win.attach.patch.remote.exitcode.pad2");
    storeAt(WB, M, targetPtr, 7, ConstantInt::get(i8, 0x48),
            "morok.win.attach.patch.remote.movrax0");
    storeAt(WB, M, targetPtr, 8, ConstantInt::get(i8, 0xB8),
            "morok.win.attach.patch.remote.movrax1");
    storeAt(WB, M, targetPtr, 9, exitProcess,
            "morok.win.attach.patch.remote.exitprocess");
    storeAt(WB, M, targetPtr, 17, ConstantInt::get(i8, 0xFF),
            "morok.win.attach.patch.remote.jmp0");
    storeAt(WB, M, targetPtr, 18, ConstantInt::get(i8, 0xE0),
            "morok.win.attach.patch.remote.jmp1");
    Value *oldProtValue =
        WB.CreateLoad(i32, oldProt, "morok.win.attach.patch.remote.oldprot");
    cast<LoadInst>(oldProtValue)->setVolatile(true);
    WB.CreateStore(target, baseSlot)->setVolatile(true);
    WB.CreateStore(ConstantInt::get(ip, 19), sizeSlot)->setVolatile(true);
    Value *restore = WB.CreateCall(
        protectTy, protectPtr,
        {WB.CreateIntToPtr(ConstantInt::getSigned(ip, -1), ptr), baseSlot,
         sizeSlot, oldProtValue, oldProt},
        "morok.win.attach.patch.remote.restore");
    WB.CreateBr(retBB);

    IRBuilder<> RB(retBB);
    auto *result =
        RB.CreatePHI(i32, 3, "morok.win.attach.patch.remote.result");
    result->addIncoming(ConstantInt::getSigned(i32, -1), entry);
    result->addIncoming(status, protectBB);
    result->addIncoming(restore, writeBB);
    RB.CreateRet(result);
    return fn;
}

Function *windowsInvalidHandleProbeHelper(Module &M) {
    if (Function *existing = M.getFunction("morok.win.attach.invalid"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(i64, {ip, ip}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.win.attach.invalid", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);
    Argument *ntClose = fn->getArg(0);
    ntClose->setName("ntclose");
    Argument *closeHandle = fn->getArg(1);
    closeHandle->setName("closehandle");

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *ntBB = BasicBlock::Create(ctx, "ntclose", fn);
    auto *closeGateBB = BasicBlock::Create(ctx, "close.gate", fn);
    auto *closeBB = BasicBlock::Create(ctx, "closehandle", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    AllocaInst *mix = B.CreateAlloca(i64, nullptr, "morok.win.attach.mix");
    B.CreateStore(ConstantInt::get(i64, 0), mix)->setVolatile(true);
    B.CreateCondBr(B.CreateICmpNE(ntClose, ConstantInt::get(ip, 0),
                                  "morok.win.attach.ntclose.ready"),
                   ntBB, closeGateBB);

    IRBuilder<> NB(ntBB);
    auto *closeTy = FunctionType::get(i32, {ptr}, false);
    Value *ntStatus = NB.CreateCall(
        closeTy, NB.CreateIntToPtr(ntClose, ptr, "morok.win.attach.ntclose.ptr"),
        {NB.CreateIntToPtr(ConstantInt::get(ip, 0xDEADDEADULL), ptr)},
        "morok.win.attach.ntclose.invalid");
    NB.CreateStore(NB.CreateZExt(ntStatus, i64), mix)->setVolatile(true);
    NB.CreateBr(closeGateBB);

    IRBuilder<> GB(closeGateBB);
    GB.CreateCondBr(GB.CreateICmpNE(closeHandle, ConstantInt::get(ip, 0),
                                    "morok.win.attach.closehandle.ready"),
                    closeBB, retBB);

    IRBuilder<> CB(closeBB);
    Value *oldMix =
        CB.CreateLoad(i64, mix, "morok.win.attach.invalid.old");
    cast<LoadInst>(oldMix)->setVolatile(true);
    Value *closeResult = CB.CreateCall(
        closeTy,
        CB.CreateIntToPtr(closeHandle, ptr, "morok.win.attach.closehandle.ptr"),
        {CB.CreateIntToPtr(ConstantInt::get(ip, 0xDEADFEEDULL), ptr)},
        "morok.win.attach.closehandle.invalid");
    Value *nextMix = CB.CreateXor(
        oldMix, CB.CreateShl(CB.CreateZExt(closeResult, i64),
                             ConstantInt::get(i64, 32)),
        "morok.win.attach.invalid.next");
    CB.CreateStore(nextMix, mix)->setVolatile(true);
    CB.CreateBr(retBB);

    IRBuilder<> RB(retBB);
    Value *out = RB.CreateLoad(i64, mix, "morok.win.attach.invalid.result");
    cast<LoadInst>(out)->setVolatile(true);
    RB.CreateRet(out);
    return fn;
}

Function *windowsAntiAttachProbe(Module &M, GlobalVariable *State,
                                 ir::IRRandom &rng, const Triple &TT) {
    if (!TT.isOSWindows() || TT.getArch() != Triple::x86_64 ||
        intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.win.attach.probe"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *fn = Function::Create(FunctionType::get(Type::getVoidTy(ctx), false),
                                GlobalValue::PrivateLinkage,
                                "morok.win.attach.probe", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    Function *pebReader = windowsPebReader(M);
    Function *moduleByHash = windowsLdrModuleByHash(M);
    Function *resolver = windowsPeExportResolver(M);
    Function *patchRet = windowsPatchRetHelper(M);
    Function *patchRemote = windowsPatchRemoteBreakinHelper(M);
    Function *invalidProbe = windowsInvalidHandleProbeHelper(M);
    if (!pebReader || !moduleByHash || !resolver || !patchRet ||
        !patchRemote || !invalidProbe)
        return nullptr;

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *resolveBB = BasicBlock::Create(ctx, "resolve", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    Value *peb = B.CreateCall(pebReader, {}, "morok.win.attach.peb");
    foldState(B, State, peb, rng.next(), "morok.win.attach.peb.mix");
    B.CreateCondBr(B.CreateICmpNE(peb, ConstantInt::get(ip, 0),
                                  "morok.win.attach.peb.present"),
                   resolveBB, retBB);

    IRBuilder<> RB(resolveBB);
    Value *ntdll = RB.CreateCall(
        moduleByHash,
        {peb, ConstantInt::get(i64, fnv1aLowerAsciiName("ntdll.dll"))},
        "morok.win.attach.ntdll");
    Value *kernel32 = RB.CreateCall(
        moduleByHash,
        {peb, ConstantInt::get(i64, fnv1aLowerAsciiName("kernel32.dll"))},
        "morok.win.attach.kernel32");
    Value *kernelbase = RB.CreateCall(
        moduleByHash,
        {peb, ConstantInt::get(i64, fnv1aLowerAsciiName("kernelbase.dll"))},
        "morok.win.attach.kernelbase");
    Value *remoteBreakin = RB.CreateCall(
        resolver,
        {ntdll, ConstantInt::get(i64, fnv1aName("DbgUiRemoteBreakin"))},
        "morok.win.attach.remote.breakin");
    Value *dbgBreak = RB.CreateCall(
        resolver, {ntdll, ConstantInt::get(i64, fnv1aName("DbgBreakPoint"))},
        "morok.win.attach.dbg.breakpoint");
    Value *ntProtect = RB.CreateCall(
        resolver,
        {ntdll, ConstantInt::get(i64, fnv1aName("NtProtectVirtualMemory"))},
        "morok.win.attach.ntprotect");
    Value *ntClose = RB.CreateCall(
        resolver, {ntdll, ConstantInt::get(i64, fnv1aName("NtClose"))},
        "morok.win.attach.ntclose");
    Value *kernelbaseExitProcess = RB.CreateCall(
        resolver,
        {kernelbase, ConstantInt::get(i64, fnv1aName("ExitProcess"))},
        "morok.win.attach.kernelbase.exitprocess");
    Value *kernel32ExitProcess = RB.CreateCall(
        resolver, {kernel32, ConstantInt::get(i64, fnv1aName("ExitProcess"))},
        "morok.win.attach.kernel32.exitprocess");
    Value *exitProcess = RB.CreateSelect(
        RB.CreateICmpNE(kernelbaseExitProcess, ConstantInt::get(ip, 0),
                        "morok.win.attach.kernelbase.exitprocess.ready"),
        kernelbaseExitProcess, kernel32ExitProcess,
        "morok.win.attach.exitprocess");
    Value *kernelbaseCloseHandle = RB.CreateCall(
        resolver,
        {kernelbase, ConstantInt::get(i64, fnv1aName("CloseHandle"))},
        "morok.win.attach.kernelbase.closehandle");
    Value *kernel32CloseHandle = RB.CreateCall(
        resolver, {kernel32, ConstantInt::get(i64, fnv1aName("CloseHandle"))},
        "morok.win.attach.kernel32.closehandle");
    Value *closeHandle = RB.CreateSelect(
        RB.CreateICmpNE(kernelbaseCloseHandle, ConstantInt::get(ip, 0),
                        "morok.win.attach.kernelbase.closehandle.ready"),
        kernelbaseCloseHandle, kernel32CloseHandle,
        "morok.win.attach.closehandle");
    foldState(RB, State, remoteBreakin, rng.next(),
              "morok.win.attach.remote.breakin.mix");
    foldState(RB, State, dbgBreak, rng.next(),
              "morok.win.attach.dbg.breakpoint.mix");
    Value *remoteStatus = RB.CreateCall(
        patchRemote, {remoteBreakin, exitProcess, ntProtect},
        "morok.win.attach.patch.remote.status");
    Value *breakStatus = RB.CreateCall(
        patchRet, {dbgBreak, ntProtect}, "morok.win.attach.patch.ret.status");
    Value *invalid = RB.CreateCall(
        invalidProbe, {ntClose, closeHandle}, "morok.win.attach.invalid.mix");
    foldState(RB, State, remoteStatus, rng.next(),
              "morok.win.attach.patch.remote.status.mix");
    foldState(RB, State, breakStatus, rng.next(),
              "morok.win.attach.patch.ret.status.mix");
    foldState(RB, State, invalid, rng.next(),
              "morok.win.attach.invalid.mix.state");
    Value *patchFailed = RB.CreateOr(
        RB.CreateICmpSLT(remoteStatus, ConstantInt::get(i32, 0),
                         "morok.win.attach.patch.remote.failed"),
        RB.CreateICmpSLT(breakStatus, ConstantInt::get(i32, 0),
                         "morok.win.attach.patch.ret.failed"),
        "morok.win.attach.patch.failed");
    foldEnforcedFlag(RB, State, patchFailed, 0xE57B1490C6A32D8FULL,
                     "morok.win.attach.patch.failed");
    RB.CreateBr(retBB);

    IRBuilder<> RetB(retBB);
    RetB.CreateRetVoid();
    return fn;
}

Function *windowsKernelDebuggerProbe(Module &M, GlobalVariable *State,
                                     ir::IRRandom &rng, const Triple &TT) {
    if (!TT.isOSWindows() || TT.getArch() != Triple::x86_64 ||
        intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.win.kdbg.probe"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(Type::getVoidTy(ctx), false),
                                GlobalValue::PrivateLinkage,
                                "morok.win.kdbg.probe", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    Function *pebReader = windowsPebReader(M);
    Function *moduleByHash = windowsLdrModuleByHash(M);
    Function *resolver = windowsPeExportResolver(M);
    if (!pebReader || !moduleByHash || !resolver)
        return nullptr;

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *resolveBB = BasicBlock::Create(ctx, "resolve", fn);
    auto *qsiBB = BasicBlock::Create(ctx, "qsi", fn);
    auto *qipGateBB = BasicBlock::Create(ctx, "qip.gate", fn);
    auto *qipBB = BasicBlock::Create(ctx, "qip", fn);
    auto *windowGateBB = BasicBlock::Create(ctx, "window.gate", fn);
    auto *windowBB = BasicBlock::Create(ctx, "window", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    auto *kdPtr = B.CreateIntToPtr(ConstantInt::get(ip, 0x7FFE02D4ULL), ptr,
                                   "morok.win.kdbg.shared.ptr");
    Value *kdEnabled =
        loadAt(B, M, i8, kdPtr, 0ULL, "morok.win.kdbg.shared.enabled");
    Value *kdNotPresent =
        loadAt(B, M, i8, kdPtr, 1, "morok.win.kdbg.shared.not.present");
    Value *sharedHit = B.CreateOr(
        B.CreateICmpNE(kdEnabled, ConstantInt::get(i8, 0),
                       "morok.win.kdbg.shared.enabled.hit"),
        B.CreateICmpEQ(kdNotPresent, ConstantInt::get(i8, 0),
                       "morok.win.kdbg.shared.present.hit"),
        "morok.win.kdbg.shared.hit");
    foldState(B, State, kdEnabled, rng.next(),
              "morok.win.kdbg.shared.enabled.mix");
    foldState(B, State, kdNotPresent, rng.next(),
              "morok.win.kdbg.shared.not.present.mix");
    foldEnforcedFlag(B, State, sharedHit, 0xB1DE6A540C92F731ULL,
                     "morok.win.kdbg.shared");

    Value *peb = B.CreateCall(pebReader, {}, "morok.win.kdbg.peb");
    B.CreateCondBr(B.CreateICmpNE(peb, ConstantInt::get(ip, 0),
                                  "morok.win.kdbg.peb.present"),
                   resolveBB, retBB);

    IRBuilder<> RB(resolveBB);
    AllocaInst *retLen = RB.CreateAlloca(i32, nullptr, "morok.win.kdbg.retlen");
    auto *kdInfoTy = ArrayType::get(i8, 2);
    auto *pbiTy = ArrayType::get(i8, 48);
    auto *moduleTy = ArrayType::get(i8, 4096);
    AllocaInst *kdInfo =
        RB.CreateAlloca(kdInfoTy, nullptr, "morok.win.kdbg.info");
    AllocaInst *pbi = RB.CreateAlloca(pbiTy, nullptr, "morok.win.kdbg.pbi");
    AllocaInst *modules =
        RB.CreateAlloca(moduleTy, nullptr, "morok.win.kdbg.modules");
    Value *ntdll = RB.CreateCall(
        moduleByHash,
        {peb, ConstantInt::get(i64, fnv1aLowerAsciiName("ntdll.dll"))},
        "morok.win.kdbg.ntdll");
    Value *user32 = RB.CreateCall(
        moduleByHash,
        {peb, ConstantInt::get(i64, fnv1aLowerAsciiName("user32.dll"))},
        "morok.win.kdbg.user32");
    Value *qsi = RB.CreateCall(
        resolver,
        {ntdll, ConstantInt::get(i64, fnv1aName("NtQuerySystemInformation"))},
        "morok.win.kdbg.ntqsi");
    Value *qip = RB.CreateCall(
        resolver,
        {ntdll, ConstantInt::get(i64, fnv1aName("NtQueryInformationProcess"))},
        "morok.win.kdbg.ntqip");
    Value *findWindow = RB.CreateCall(
        resolver, {user32, ConstantInt::get(i64, fnv1aName("FindWindowA"))},
        "morok.win.kdbg.findwindow");
    foldState(RB, State, qsi, rng.next(), "morok.win.kdbg.ntqsi.mix");
    foldState(RB, State, qip, rng.next(), "morok.win.kdbg.ntqip.mix");
    RB.CreateCondBr(RB.CreateICmpNE(qsi, ConstantInt::get(ip, 0),
                                    "morok.win.kdbg.ntqsi.ready"),
                    qsiBB, qipGateBB);

    IRBuilder<> SB(qsiBB);
    auto *qsiTy = FunctionType::get(i32, {i32, ptr, i32, ptr}, false);
    Value *qsiPtr = SB.CreateIntToPtr(qsi, ptr, "morok.win.kdbg.ntqsi.ptr");
    Value *kdStatus = SB.CreateCall(
        qsiTy, qsiPtr,
        {ConstantInt::get(i32, 0x23), kdInfo, ConstantInt::get(i32, 2),
         retLen},
        "morok.win.kdbg.system.kd.status");
    Value *sysKdEnabled =
        loadAt(SB, M, i8, kdInfo, 0ULL, "morok.win.kdbg.system.kd.enabled");
    Value *sysKdNotPresent =
        loadAt(SB, M, i8, kdInfo, 1, "morok.win.kdbg.system.kd.not.present");
    Value *kdOk = SB.CreateICmpSGE(kdStatus, ConstantInt::get(i32, 0),
                                   "morok.win.kdbg.system.kd.ok");
    Value *sysKdHit = SB.CreateAnd(
        kdOk,
        SB.CreateOr(SB.CreateICmpNE(sysKdEnabled, ConstantInt::get(i8, 0)),
                    SB.CreateICmpEQ(sysKdNotPresent, ConstantInt::get(i8, 0)),
                    "morok.win.kdbg.system.kd.bits"),
        "morok.win.kdbg.system.kd.hit");
    foldState(SB, State, kdStatus, rng.next(),
              "morok.win.kdbg.system.kd.status.mix");
    foldEnforcedFlag(SB, State, sysKdHit, 0x794A0FE2D51B36C8ULL,
                     "morok.win.kdbg.system.kd");

    Value *moduleStatus = SB.CreateCall(
        qsiTy, qsiPtr,
        {ConstantInt::get(i32, 0x0B), modules, ConstantInt::get(i32, 4096),
         retLen},
        "morok.win.kdbg.system.modules.status");
    Value *moduleCount =
        loadAt(SB, M, i32, modules, 0ULL, "morok.win.kdbg.system.modules.count");
    foldState(SB, State, moduleStatus, rng.next(),
              "morok.win.kdbg.system.modules.status.mix");
    foldState(SB, State, moduleCount, rng.next(),
              "morok.win.kdbg.system.modules.count.mix");
    SB.CreateBr(qipGateBB);

    IRBuilder<> QG(qipGateBB);
    QG.CreateCondBr(QG.CreateICmpNE(qip, ConstantInt::get(ip, 0),
                                    "morok.win.kdbg.ntqip.ready"),
                    qipBB, windowGateBB);

    IRBuilder<> PB(qipBB);
    auto *qipTy = FunctionType::get(i32, {ptr, i32, ptr, i32, ptr}, false);
    Value *qipStatus = PB.CreateCall(
        qipTy, PB.CreateIntToPtr(qip, ptr, "morok.win.kdbg.ntqip.ptr"),
        {PB.CreateIntToPtr(ConstantInt::getSigned(ip, -1), ptr),
         ConstantInt::get(i32, 0), pbi, ConstantInt::get(i32, 48), retLen},
        "morok.win.kdbg.parent.status");
    Value *parentPid =
        loadAt(PB, M, ip, pbi, 40, "morok.win.kdbg.parent.pid");
    foldState(PB, State, qipStatus, rng.next(),
              "morok.win.kdbg.parent.status.mix");
    foldState(PB, State, parentPid, rng.next(),
              "morok.win.kdbg.parent.pid.mix");
    PB.CreateBr(windowGateBB);

    IRBuilder<> WG(windowGateBB);
    WG.CreateCondBr(WG.CreateICmpNE(findWindow, ConstantInt::get(ip, 0),
                                    "morok.win.kdbg.findwindow.ready"),
                    windowBB, retBB);

    IRBuilder<> WB(windowBB);
    auto *findTy = FunctionType::get(ptr, {ptr, ptr}, false);
    Value *findPtr =
        WB.CreateIntToPtr(findWindow, ptr, "morok.win.kdbg.findwindow.ptr");
    Value *windbg = ir::emitCloakedSymbol(WB, M, "WinDbgFrameClass", rng);
    Value *olly = ir::emitCloakedSymbol(WB, M, "OLLYDBG", rng);
    Value *qt = ir::emitCloakedSymbol(WB, M, "Qt5QWindowIcon", rng);
    Value *w0 = WB.CreateCall(findTy, findPtr,
                              {windbg, ConstantPointerNull::get(ptr)},
                              "morok.win.kdbg.window.windbg");
    Value *w1 = WB.CreateCall(findTy, findPtr,
                              {olly, ConstantPointerNull::get(ptr)},
                              "morok.win.kdbg.window.olly");
    Value *w2 = WB.CreateCall(findTy, findPtr,
                              {qt, ConstantPointerNull::get(ptr)},
                              "morok.win.kdbg.window.qt");
    Value *windowHit = WB.CreateOr(
        WB.CreateICmpNE(w0, ConstantPointerNull::get(ptr)),
        WB.CreateOr(WB.CreateICmpNE(w1, ConstantPointerNull::get(ptr)),
                    WB.CreateICmpNE(w2, ConstantPointerNull::get(ptr))),
        "morok.win.kdbg.window.hit");
    foldEnforcedFlag(WB, State, windowHit, 0xC52F6B9038D41EA7ULL,
                     "morok.win.kdbg.window");
    WB.CreateBr(retBB);

    IRBuilder<> RetB(retBB);
    RetB.CreateRetVoid();
    return fn;
}

Function *windowsSyscallsProbe(Module &M, GlobalVariable *State,
                               ir::IRRandom &rng, const Triple &TT) {
    if (!TT.isOSWindows() || TT.getArch() != Triple::x86_64 ||
        intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.win.syscalls.probe"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(Type::getVoidTy(ctx), false),
                                GlobalValue::PrivateLinkage,
                                "morok.win.syscalls.probe", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    Function *pebReader = windowsPebReader(M);
    Function *moduleByHash = windowsLdrModuleByHash(M);
    Function *resolver = windowsPeExportResolver(M);
    Function *scanner = windowsSyscallStubScanner(M);
    Function *direct = windowsDirectSyscallThunk(M);
    Function *indirect = windowsIndirectSyscallThunk(M);
    if (!pebReader || !moduleByHash || !resolver || !scanner || !direct ||
        !indirect)
        return nullptr;

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *resolveBB = BasicBlock::Create(ctx, "resolve", fn);
    auto *qsiDirectBB = BasicBlock::Create(ctx, "qsi.direct", fn);
    auto *qsiIndirectBB = BasicBlock::Create(ctx, "qsi.indirect", fn);
    auto *closeGateBB = BasicBlock::Create(ctx, "close.gate", fn);
    auto *closeDirectBB = BasicBlock::Create(ctx, "close.direct", fn);
    auto *closeIndirectBB = BasicBlock::Create(ctx, "close.indirect", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    AllocaInst *retLen =
        B.CreateAlloca(i32, nullptr, "morok.win.syscalls.retlen");
    auto *kdInfoTy = ArrayType::get(i8, 2);
    AllocaInst *kdInfo =
        B.CreateAlloca(kdInfoTy, nullptr, "morok.win.syscalls.kdinfo");
    B.CreateStore(ConstantInt::get(i32, 0), retLen)->setVolatile(true);
    storeAt(B, M, kdInfo, 0, ConstantInt::get(i8, 0),
            "morok.win.syscalls.kdinfo.init0");
    storeAt(B, M, kdInfo, 1, ConstantInt::get(i8, 0),
            "morok.win.syscalls.kdinfo.init1");
    Value *peb = B.CreateCall(pebReader, {}, "morok.win.syscalls.peb");
    foldState(B, State, peb, rng.next(), "morok.win.syscalls.peb.mix");
    B.CreateCondBr(B.CreateICmpNE(peb, ConstantInt::get(ip, 0),
                                  "morok.win.syscalls.peb.present"),
                   resolveBB, retBB);

    IRBuilder<> RB(resolveBB);
    Value *ntdll = RB.CreateCall(
        moduleByHash,
        {peb, ConstantInt::get(i64, fnv1aLowerAsciiName("ntdll.dll"))},
        "morok.win.syscalls.ntdll");
    Value *qsi = RB.CreateCall(
        resolver,
        {ntdll, ConstantInt::get(i64, fnv1aName("NtQuerySystemInformation"))},
        "morok.win.syscalls.ntqsi");
    Value *ntClose = RB.CreateCall(
        resolver, {ntdll, ConstantInt::get(i64, fnv1aName("NtClose"))},
        "morok.win.syscalls.ntclose");
    Value *qsiPack = RB.CreateCall(
        scanner,
        {RB.CreateIntToPtr(qsi, ptr, "morok.win.syscalls.ntqsi.ptr"),
         ConstantInt::getTrue(ctx)},
        "morok.win.syscalls.ntqsi.pack");
    Value *closePack = RB.CreateCall(
        scanner,
        {RB.CreateIntToPtr(ntClose, ptr, "morok.win.syscalls.ntclose.ptr"),
         ConstantInt::getTrue(ctx)},
        "morok.win.syscalls.ntclose.pack");
    Value *qsiSsn = RB.CreateTrunc(qsiPack, i32, "morok.win.syscalls.ntqsi.ssn");
    Value *qsiGadget32 =
        RB.CreateTrunc(RB.CreateLShr(qsiPack, ConstantInt::get(ip, 32)),
                       i32, "morok.win.syscalls.ntqsi.gadget32");
    Value *closeSsn =
        RB.CreateTrunc(closePack, i32, "morok.win.syscalls.ntclose.ssn");
    Value *closeGadget32 =
        RB.CreateTrunc(RB.CreateLShr(closePack, ConstantInt::get(ip, 32)),
                       i32, "morok.win.syscalls.ntclose.gadget32");
    foldState(RB, State, ntdll, rng.next(), "morok.win.syscalls.ntdll.mix");
    foldState(RB, State, qsiPack, rng.next(), "morok.win.syscalls.ntqsi.pack.mix");
    foldState(RB, State, closePack, rng.next(),
              "morok.win.syscalls.ntclose.pack.mix");
    Value *qsiReady = RB.CreateAnd(
        RB.CreateICmpNE(qsi, ConstantInt::get(ip, 0)),
        RB.CreateICmpNE(qsiSsn, ConstantInt::get(i32, 0)),
        "morok.win.syscalls.ntqsi.ready");
    RB.CreateCondBr(qsiReady, qsiDirectBB, closeGateBB);

    IRBuilder<> QB(qsiDirectBB);
    QB.CreateStore(ConstantInt::get(i32, 0), retLen)->setVolatile(true);
    storeAt(QB, M, kdInfo, 0, ConstantInt::get(i8, 0),
            "morok.win.syscalls.kdinfo.direct0");
    storeAt(QB, M, kdInfo, 1, ConstantInt::get(i8, 0),
            "morok.win.syscalls.kdinfo.direct1");
    Value *kdInfoIp =
        QB.CreatePtrToInt(kdInfo, ip, "morok.win.syscalls.kdinfo.ip");
    Value *retLenIp =
        QB.CreatePtrToInt(retLen, ip, "morok.win.syscalls.retlen.ip");
    auto *directTy = direct->getFunctionType();
    Value *qsiDirect = QB.CreateCall(
        directTy, direct,
        {qsiSsn, ConstantInt::get(ip, 0x23), kdInfoIp,
         ConstantInt::get(ip, 2), retLenIp},
        "morok.win.syscalls.ntqsi.direct");
    Value *qsiDirectStatus =
        QB.CreateTrunc(qsiDirect, i32, "morok.win.syscalls.ntqsi.direct.i32");
    Value *kdDirect0 =
        loadAt(QB, M, i8, kdInfo, 0ULL, "morok.win.syscalls.kd.direct0");
    Value *kdDirect1 =
        loadAt(QB, M, i8, kdInfo, 1, "morok.win.syscalls.kd.direct1");
    foldState(QB, State, qsiDirect, rng.next(),
              "morok.win.syscalls.ntqsi.direct.mix");
    foldState(QB, State, kdDirect0, rng.next(),
              "morok.win.syscalls.kd.direct0.mix");
    foldState(QB, State, kdDirect1, rng.next(),
              "morok.win.syscalls.kd.direct1.mix");
    QB.CreateCondBr(QB.CreateICmpNE(qsiGadget32, ConstantInt::get(i32, 0),
                                    "morok.win.syscalls.ntqsi.gadget.ready"),
                    qsiIndirectBB, closeGateBB);

    IRBuilder<> IB(qsiIndirectBB);
    IB.CreateStore(ConstantInt::get(i32, 0), retLen)->setVolatile(true);
    storeAt(IB, M, kdInfo, 0, ConstantInt::get(i8, 0),
            "morok.win.syscalls.kdinfo.indirect0");
    storeAt(IB, M, kdInfo, 1, ConstantInt::get(i8, 0),
            "morok.win.syscalls.kdinfo.indirect1");
    Value *qsiGadget = IB.CreateAdd(
        qsi,
        IB.CreateSExt(qsiGadget32, ip, "morok.win.syscalls.ntqsi.gadget.off"),
        "morok.win.syscalls.ntqsi.gadget");
    auto *indirectTy = indirect->getFunctionType();
    Value *qsiIndirect = IB.CreateCall(
        indirectTy, indirect,
        {qsiSsn, qsiGadget, ConstantInt::get(ip, 0x23), kdInfoIp,
         ConstantInt::get(ip, 2), retLenIp},
        "morok.win.syscalls.ntqsi.indirect");
    Value *qsiIndirectStatus =
        IB.CreateTrunc(qsiIndirect, i32, "morok.win.syscalls.ntqsi.indirect.i32");
    Value *kdIndirect0 =
        loadAt(IB, M, i8, kdInfo, 0ULL, "morok.win.syscalls.kd.indirect0");
    Value *kdIndirect1 =
        loadAt(IB, M, i8, kdInfo, 1, "morok.win.syscalls.kd.indirect1");
    Value *qsiStatusDiverged =
        IB.CreateICmpNE(qsiDirectStatus, qsiIndirectStatus,
                        "morok.win.syscalls.ntqsi.status.diverged");
    Value *qsiDataDiverged = IB.CreateOr(
        IB.CreateICmpNE(kdDirect0, kdIndirect0,
                        "morok.win.syscalls.kd.enabled.diverged"),
        IB.CreateICmpNE(kdDirect1, kdIndirect1,
                        "morok.win.syscalls.kd.present.diverged"),
        "morok.win.syscalls.kd.diverged");
    foldState(IB, State, qsiIndirect, rng.next(),
              "morok.win.syscalls.ntqsi.indirect.mix");
    foldEnforcedFlag(
        IB, State,
        IB.CreateOr(qsiStatusDiverged, qsiDataDiverged,
                    "morok.win.syscalls.ntqsi.diverged"),
        0x38B2E1F46D0A9C57ULL, "morok.win.syscalls.ntqsi.divergence");
    IB.CreateBr(closeGateBB);

    IRBuilder<> CGB(closeGateBB);
    Value *closeReady = CGB.CreateAnd(
        CGB.CreateICmpNE(ntClose, ConstantInt::get(ip, 0)),
        CGB.CreateICmpNE(closeSsn, ConstantInt::get(i32, 0)),
        "morok.win.syscalls.ntclose.ready");
    CGB.CreateCondBr(closeReady, closeDirectBB, retBB);

    IRBuilder<> CB(closeDirectBB);
    Value *invalidHandle = ConstantInt::get(ip, 0xDEADDEADULL);
    Value *closeDirect = CB.CreateCall(
        directTy, direct,
        {closeSsn, invalidHandle, ConstantInt::get(ip, 0),
         ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)},
        "morok.win.syscalls.ntclose.direct");
    Value *closeDirectStatus = CB.CreateTrunc(
        closeDirect, i32, "morok.win.syscalls.ntclose.direct.i32");
    foldState(CB, State, closeDirect, rng.next(),
              "morok.win.syscalls.ntclose.direct.mix");
    CB.CreateCondBr(CB.CreateICmpNE(closeGadget32, ConstantInt::get(i32, 0),
                                    "morok.win.syscalls.ntclose.gadget.ready"),
                    closeIndirectBB, retBB);

    IRBuilder<> CIB(closeIndirectBB);
    Value *closeGadget = CIB.CreateAdd(
        ntClose,
        CIB.CreateSExt(closeGadget32, ip,
                       "morok.win.syscalls.ntclose.gadget.off"),
        "morok.win.syscalls.ntclose.gadget");
    Value *closeIndirect = CIB.CreateCall(
        indirectTy, indirect,
        {closeSsn, closeGadget, invalidHandle, ConstantInt::get(ip, 0),
         ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)},
        "morok.win.syscalls.ntclose.indirect");
    Value *closeIndirectStatus = CIB.CreateTrunc(
        closeIndirect, i32, "morok.win.syscalls.ntclose.indirect.i32");
    foldState(CIB, State, closeIndirect, rng.next(),
              "morok.win.syscalls.ntclose.indirect.mix");
    foldEnforcedFlag(
        CIB, State,
        CIB.CreateICmpNE(closeDirectStatus, closeIndirectStatus,
                         "morok.win.syscalls.ntclose.diverged"),
        0xA65C04D3189BE72FULL, "morok.win.syscalls.ntclose.divergence");
    CIB.CreateBr(retBB);

    IRBuilder<> RetB(retBB);
    RetB.CreateRetVoid();
    return fn;
}

Function *windowsUnhookProbe(Module &M, GlobalVariable *State,
                             ir::IRRandom &rng, const Triple &TT) {
    if (!TT.isOSWindows() || TT.getArch() != Triple::x86_64 ||
        intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.win.unhook.probe"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i16 = Type::getInt16Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *fn = Function::Create(FunctionType::get(Type::getVoidTy(ctx), false),
                                GlobalValue::PrivateLinkage,
                                "morok.win.unhook.probe", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    Function *pebReader = windowsPebReader(M);
    Function *moduleByHash = windowsLdrModuleByHash(M);
    Function *resolver = windowsPeExportResolver(M);
    Function *knownUnhook = windowsKnownDllUnhookHelper(M);
    if (!pebReader || !moduleByHash || !resolver || !knownUnhook)
        return nullptr;

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *resolveBB = BasicBlock::Create(ctx, "resolve", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    Value *peb = B.CreateCall(pebReader, {}, "morok.win.unhook.peb");
    foldState(B, State, peb, rng.next(), "morok.win.unhook.peb.mix");
    B.CreateCondBr(B.CreateICmpNE(peb, ConstantInt::get(ip, 0),
                                  "morok.win.unhook.peb.present"),
                   resolveBB, retBB);

    IRBuilder<> RB(resolveBB);
    Value *ntdll = RB.CreateCall(
        moduleByHash,
        {peb, ConstantInt::get(i64, fnv1aLowerAsciiName("ntdll.dll"))},
        "morok.win.unhook.ntdll");
    Value *kernel32 = RB.CreateCall(
        moduleByHash,
        {peb, ConstantInt::get(i64, fnv1aLowerAsciiName("kernel32.dll"))},
        "morok.win.unhook.kernel32");
    Value *ntOpenSection = RB.CreateCall(
        resolver, {ntdll, ConstantInt::get(i64, fnv1aName("NtOpenSection"))},
        "morok.win.unhook.ntopensection");
    Value *ntMapView = RB.CreateCall(
        resolver, {ntdll, ConstantInt::get(i64, fnv1aName("NtMapViewOfSection"))},
        "morok.win.unhook.ntmapview");
    Value *ntUnmapView = RB.CreateCall(
        resolver,
        {ntdll, ConstantInt::get(i64, fnv1aName("NtUnmapViewOfSection"))},
        "morok.win.unhook.ntunmap");
    Value *ntProtect = RB.CreateCall(
        resolver,
        {ntdll, ConstantInt::get(i64, fnv1aName("NtProtectVirtualMemory"))},
        "morok.win.unhook.ntprotect");
    Value *ntClose = RB.CreateCall(
        resolver, {ntdll, ConstantInt::get(i64, fnv1aName("NtClose"))},
        "morok.win.unhook.ntclose");
    foldState(RB, State, ntdll, rng.next(), "morok.win.unhook.ntdll.mix");
    foldState(RB, State, kernel32, rng.next(),
              "morok.win.unhook.kernel32.mix");
    foldState(RB, State, ntOpenSection, rng.next(),
              "morok.win.unhook.ntopensection.mix");
    foldState(RB, State, ntMapView, rng.next(),
              "morok.win.unhook.ntmapview.mix");
    foldState(RB, State, ntProtect, rng.next(),
              "morok.win.unhook.ntprotect.mix");

    Value *ntdllKnown = storeWindowsWideLiteral(
        RB, M,
        {'\\', 'K', 'n', 'o', 'w', 'n', 'D', 'l', 'l', 's', '\\', 'n',
         't', 'd', 'l', 'l', '.', 'd', 'l', 'l'},
        "morok.win.unhook.known.nt");
    Value *kernelKnown = storeWindowsWideLiteral(
        RB, M,
        {'\\', 'K', 'n', 'o', 'w', 'n', 'D', 'l', 'l', 's', '\\', 'k',
         'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'},
        "morok.win.unhook.known.k32");
    auto *knownTy = knownUnhook->getFunctionType();
    Value *ntdllStatus = RB.CreateCall(
        knownTy, knownUnhook,
        {ntdll, ntdllKnown, ConstantInt::get(i16, 40), ntOpenSection,
         ntMapView, ntUnmapView, ntProtect, ntClose},
        "morok.win.unhook.ntdll.status");
    Value *kernelStatus = RB.CreateCall(
        knownTy, knownUnhook,
        {kernel32, kernelKnown, ConstantInt::get(i16, 46), ntOpenSection,
         ntMapView, ntUnmapView, ntProtect, ntClose},
        "morok.win.unhook.kernel32.status");
    foldState(RB, State, ntdllStatus, rng.next(),
              "morok.win.unhook.ntdll.status.mix");
    foldState(RB, State, kernelStatus, rng.next(),
              "morok.win.unhook.kernel32.status.mix");
    Value *failed = RB.CreateOr(
        RB.CreateICmpSLT(ntdllStatus, ConstantInt::get(i32, 0),
                         "morok.win.unhook.ntdll.failed"),
        RB.CreateICmpSLT(kernelStatus, ConstantInt::get(i32, 0),
                         "morok.win.unhook.kernel32.failed"),
        "morok.win.unhook.failed");
    foldEnforcedFlag(RB, State, failed, 0x43D2BE581F09A76CULL,
                     "morok.win.unhook.failure");
    RB.CreateBr(retBB);

    IRBuilder<> RetB(retBB);
    RetB.CreateRetVoid();
    return fn;
}

Function *windowsVehAuditProbe(Module &M, GlobalVariable *State,
                               ir::IRRandom &rng, const Triple &TT) {
    if (!TT.isOSWindows() || TT.getArch() != Triple::x86_64 ||
        intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.win.veh.probe"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *fn = Function::Create(FunctionType::get(Type::getVoidTy(ctx), false),
                                GlobalValue::PrivateLinkage,
                                "morok.win.veh.probe", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    Function *pebReader = windowsPebReader(M);
    Function *moduleByHash = windowsLdrModuleByHash(M);
    Function *resolver = windowsPeExportResolver(M);
    Function *imageSizeFn = windowsPeImageSize(M);
    Function *scanner = windowsVehListReferenceScanner(M);
    Function *auditList = windowsVehAuditListHelper(M);
    if (!pebReader || !moduleByHash || !resolver || !imageSizeFn || !scanner ||
        !auditList)
        return nullptr;

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *resolveBB = BasicBlock::Create(ctx, "resolve", fn);
    auto *auditBB = BasicBlock::Create(ctx, "audit", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    Value *peb = B.CreateCall(pebReader, {}, "morok.win.veh.peb");
    foldState(B, State, peb, rng.next(), "morok.win.veh.peb.mix");
    B.CreateCondBr(B.CreateICmpNE(peb, ConstantInt::get(ip, 0),
                                  "morok.win.veh.peb.present"),
                   resolveBB, retBB);

    IRBuilder<> RB(resolveBB);
    Value *ntdll = RB.CreateCall(
        moduleByHash,
        {peb, ConstantInt::get(i64, fnv1aLowerAsciiName("ntdll.dll"))},
        "morok.win.veh.ntdll");
    Value *rtlAdd = RB.CreateCall(
        resolver,
        {ntdll, ConstantInt::get(i64,
                                 fnv1aName("RtlAddVectoredExceptionHandler"))},
        "morok.win.veh.rtladd");
    Value *rtlRemove = RB.CreateCall(
        resolver,
        {ntdll,
         ConstantInt::get(i64,
                          fnv1aName("RtlRemoveVectoredExceptionHandler"))},
        "morok.win.veh.rtlremove");
    Value *rtlDecode = RB.CreateCall(
        resolver, {ntdll, ConstantInt::get(i64, fnv1aName("RtlDecodePointer"))},
        "morok.win.veh.rtldecode");
    Value *ntQueryVm = RB.CreateCall(
        resolver,
        {ntdll, ConstantInt::get(i64, fnv1aName("NtQueryVirtualMemory"))},
        "morok.win.veh.ntqueryvm");
    Value *imageSize =
        RB.CreateCall(imageSizeFn, {ntdll}, "morok.win.veh.ntdll.image.size");
    foldState(RB, State, ntdll, rng.next(), "morok.win.veh.ntdll.mix");
    foldState(RB, State, rtlAdd, rng.next(), "morok.win.veh.rtladd.mix");
    foldState(RB, State, rtlRemove, rng.next(),
              "morok.win.veh.rtlremove.mix");
    foldState(RB, State, rtlDecode, rng.next(),
              "morok.win.veh.rtldecode.mix");
    Value *ready = RB.CreateAnd(
        RB.CreateAnd(RB.CreateICmpNE(ntdll, ConstantInt::get(ip, 0)),
                     RB.CreateICmpNE(imageSize, ConstantInt::get(ip, 0)),
                     "morok.win.veh.image.ready"),
        RB.CreateAnd(RB.CreateICmpNE(rtlDecode, ConstantInt::get(ip, 0)),
                     RB.CreateICmpNE(ntQueryVm, ConstantInt::get(ip, 0)),
                     "morok.win.veh.audit.apis.ready"),
        "morok.win.veh.ready");
    RB.CreateCondBr(ready, auditBB, retBB);

    IRBuilder<> AB(auditBB);
    Value *addCandidate =
        AB.CreateCall(scanner, {ntdll, imageSize, rtlAdd},
                      "morok.win.veh.list.from.add");
    Value *removeCandidate =
        AB.CreateCall(scanner, {ntdll, imageSize, rtlRemove},
                      "morok.win.veh.list.from.remove");
    Value *listBase = AB.CreateSelect(
        AB.CreateICmpNE(addCandidate, ConstantInt::get(ip, 0),
                        "morok.win.veh.add.candidate.present"),
        addCandidate, removeCandidate, "morok.win.veh.list.base");
    Value *shiftedHead = AB.CreateSelect(
        AB.CreateICmpNE(listBase, ConstantInt::get(ip, 0),
                        "morok.win.veh.list.base.present"),
        AB.CreateAdd(listBase, ConstantInt::get(ip, 8),
                     "morok.win.veh.list.base.plus.lock"),
        ConstantInt::get(ip, 0), "morok.win.veh.list.shifted");
    auto *auditTy = auditList->getFunctionType();
    Value *audit0 = AB.CreateCall(
        auditTy, auditList, {peb, listBase, rtlDecode, ntQueryVm},
        "morok.win.veh.audit.primary");
    Value *audit1 = AB.CreateCall(
        auditTy, auditList, {peb, shiftedHead, rtlDecode, ntQueryVm},
        "morok.win.veh.audit.shifted");
    Value *bad0 =
        AB.CreateTrunc(AB.CreateLShr(audit0, ConstantInt::get(i64, 32)),
                       i32, "morok.win.veh.bad.primary");
    Value *bad1 =
        AB.CreateTrunc(AB.CreateLShr(audit1, ConstantInt::get(i64, 32)),
                       i32, "morok.win.veh.bad.shifted");
    Value *seen0 = AB.CreateTrunc(audit0, i32, "morok.win.veh.seen.primary");
    Value *seen1 = AB.CreateTrunc(audit1, i32, "morok.win.veh.seen.shifted");
    Value *badTotal =
        AB.CreateAdd(bad0, bad1, "morok.win.veh.bad.total");
    Value *seenTotal =
        AB.CreateAdd(seen0, seen1, "morok.win.veh.seen.total");
    foldState(AB, State, addCandidate, rng.next(),
              "morok.win.veh.list.from.add.mix");
    foldState(AB, State, removeCandidate, rng.next(),
              "morok.win.veh.list.from.remove.mix");
    foldState(AB, State, audit0, rng.next(),
              "morok.win.veh.audit.primary.mix");
    foldState(AB, State, audit1, rng.next(),
              "morok.win.veh.audit.shifted.mix");
    foldState(AB, State, seenTotal, rng.next(),
              "morok.win.veh.seen.total.mix");
    // Foreign VEH classification is not zero-on-clean: legitimate runtimes can
    // register non-image/JIT handlers, so keep it out of the enforced seal.
    foldFlag(AB, State,
             AB.CreateICmpNE(badTotal, ConstantInt::get(i32, 0),
                             "morok.win.veh.bad.any"),
             0xAE6D401E2B75893FULL, "morok.win.veh.foreign");
    AB.CreateBr(retBB);

    IRBuilder<> RetB(retBB);
    RetB.CreateRetVoid();
    return fn;
}

Function *windowsProcessMitigationsProbe(Module &M, GlobalVariable *State,
                                         ir::IRRandom &rng, const Triple &TT) {
    if (!TT.isOSWindows() || TT.getArch() != Triple::x86_64 ||
        intPtrTy(M)->getBitWidth() != 64)
        return nullptr;
    if (Function *existing = M.getFunction("morok.win.mitigate.probe"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *fn = Function::Create(FunctionType::get(Type::getVoidTy(ctx), false),
                                GlobalValue::PrivateLinkage,
                                "morok.win.mitigate.probe", &M);
    fn->addFnAttr(Attribute::NoInline);
    fn->setDSOLocal(true);

    Function *pebReader = windowsPebReader(M);
    Function *moduleByHash = windowsLdrModuleByHash(M);
    Function *resolver = windowsPeExportResolver(M);
    if (!pebReader || !moduleByHash || !resolver)
        return nullptr;

    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *resolveBB = BasicBlock::Create(ctx, "resolve", fn);
    auto *applyBB = BasicBlock::Create(ctx, "apply", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    Value *peb = B.CreateCall(pebReader, {}, "morok.win.mitigate.peb");
    foldState(B, State, peb, rng.next(), "morok.win.mitigate.peb.mix");
    B.CreateCondBr(B.CreateICmpNE(peb, ConstantInt::get(ip, 0),
                                  "morok.win.mitigate.peb.present"),
                   resolveBB, retBB);

    IRBuilder<> RB(resolveBB);
    AllocaInst *dynamicPolicy =
        RB.CreateAlloca(i32, nullptr, "morok.win.mitigate.dynamic.policy");
    AllocaInst *signaturePolicy =
        RB.CreateAlloca(i32, nullptr, "morok.win.mitigate.signature.policy");
    RB.CreateStore(ConstantInt::get(i32, 0x1), dynamicPolicy)
        ->setVolatile(true);
    RB.CreateStore(ConstantInt::get(i32, 0x1), signaturePolicy)
        ->setVolatile(true);
    Value *kernelbase = RB.CreateCall(
        moduleByHash,
        {peb, ConstantInt::get(i64, fnv1aLowerAsciiName("kernelbase.dll"))},
        "morok.win.mitigate.kernelbase");
    Value *kernel32 = RB.CreateCall(
        moduleByHash,
        {peb, ConstantInt::get(i64, fnv1aLowerAsciiName("kernel32.dll"))},
        "morok.win.mitigate.kernel32");
    Value *kernelbasePolicy = RB.CreateCall(
        resolver,
        {kernelbase,
         ConstantInt::get(i64, fnv1aName("SetProcessMitigationPolicy"))},
        "morok.win.mitigate.setpolicy.kernelbase");
    Value *kernel32Policy = RB.CreateCall(
        resolver,
        {kernel32,
         ConstantInt::get(i64, fnv1aName("SetProcessMitigationPolicy"))},
        "morok.win.mitigate.setpolicy.kernel32");
    Value *setPolicy = RB.CreateSelect(
        RB.CreateICmpNE(kernelbasePolicy, ConstantInt::get(ip, 0),
                        "morok.win.mitigate.kernelbase.policy.ready"),
        kernelbasePolicy, kernel32Policy, "morok.win.mitigate.setpolicy");
    foldState(RB, State, kernelbase, rng.next(),
              "morok.win.mitigate.kernelbase.mix");
    foldState(RB, State, kernel32, rng.next(),
              "morok.win.mitigate.kernel32.mix");
    foldState(RB, State, setPolicy, rng.next(),
              "morok.win.mitigate.setpolicy.mix");
    RB.CreateCondBr(RB.CreateICmpNE(setPolicy, ConstantInt::get(ip, 0),
                                    "morok.win.mitigate.setpolicy.ready"),
                    applyBB, retBB);

    IRBuilder<> AB(applyBB);
    auto *setPolicyTy = FunctionType::get(i32, {i32, ptr, ip}, false);
    Value *setPolicyPtr =
        AB.CreateIntToPtr(setPolicy, ptr, "morok.win.mitigate.setpolicy.ptr");
    Value *dynamicResult = AB.CreateCall(
        setPolicyTy, setPolicyPtr,
        {ConstantInt::get(i32, 2), dynamicPolicy, ConstantInt::get(ip, 4)},
        "morok.win.mitigate.dynamic.result");
    Value *signatureResult = AB.CreateCall(
        setPolicyTy, setPolicyPtr,
        {ConstantInt::get(i32, 8), signaturePolicy, ConstantInt::get(ip, 4)},
        "morok.win.mitigate.signature.result");
    foldState(AB, State, dynamicResult, rng.next(),
              "morok.win.mitigate.dynamic.result.mix");
    foldState(AB, State, signatureResult, rng.next(),
              "morok.win.mitigate.signature.result.mix");
    Value *failed = AB.CreateOr(
        AB.CreateICmpEQ(dynamicResult, ConstantInt::get(i32, 0),
                        "morok.win.mitigate.dynamic.failed"),
        AB.CreateICmpEQ(signatureResult, ConstantInt::get(i32, 0),
                        "morok.win.mitigate.signature.failed"),
        "morok.win.mitigate.failed");
    foldFlag(AB, State, failed, 0xC167A4E398520D2BULL,
             "morok.win.mitigate.failure");
    AB.CreateBr(retBB);

    IRBuilder<> RetB(retBB);
    RetB.CreateRetVoid();
    return fn;
}

} // namespace

bool antiDebuggingModule(Module &M, ir::IRRandom &rng, bool AllowSelfTrace) {
    const Triple tt(M.getTargetTriple());
    const bool startLiveWatchers = !moduleUsesForkOrSignalApis(M);

    if (tt.isOSLinux())
        emitLinuxMemfdReexecCtor(M, rng, tt);

    Function *ctor = makeCtorShell(M, "morok.antidbg");
    GlobalVariable *state = antiDebugState(M, rng);
    // Create the verdict-bound seal up front so it exists before the per-function
    // self-checksum pass references it; detectors fold into it via sealFold.
    antiDebugSeal(M, rng);
    if (tt.isOSLinux())
        emitLinuxAntiDebug(M, ctor, state, rng, tt, AllowSelfTrace,
                           startLiveWatchers);
    else if (tt.isOSDarwin())
        emitDarwinAntiDebug(M, ctor, state, rng, tt, startLiveWatchers);
    else
        IRBuilder<>(&ctor->getEntryBlock()).CreateRetVoid();
    Function *probe = antiDebugProbe(M, state, rng, tt);
    insertAntiDebugCallsiteProbes(M, probe, rng);
    appendToGlobalCtors(M, ctor, 0);
    if (startLiveWatchers)
        emitAntiDebugWatchdogStart(M, probe, state, rng, tt);
    return true;
}

bool antiDebuggingModule(Module &M) {
    auto engine = core::Xoshiro256pp::fromSeed(0xA17D3B9u);
    ir::IRRandom rng(engine);
    return antiDebuggingModule(M, rng);
}

bool timingOracleModule(Module &M, ir::IRRandom &rng) {
    const Triple tt(M.getTargetTriple());
    Function *ctor = makeCtorShell(M, "morok.timing");
    antiDebugSeal(M, rng);
    GlobalVariable *state = timingOracleState(M, rng);
    Function *oracle = timingOracleProbe(M, state, rng, tt);

    IRBuilder<> B(&ctor->getEntryBlock());
    B.CreateCall(oracle);
    B.CreateRetVoid();
    appendToGlobalCtors(M, ctor, 0);
    return true;
}

bool schedulerStepOracleModule(Module &M, ir::IRRandom &rng) {
    const Triple tt(M.getTargetTriple());
    if (intPtrTy(M)->getBitWidth() != 64 ||
        (!tt.isOSLinux() && !tt.isOSDarwin() && !tt.isOSWindows()))
        return false;
    antiDebugSeal(M, rng);
    GlobalVariable *state = schedulerStepOracleState(M, rng);
    Function *oracle = schedulerStepOracleProbe(M, state, rng, tt);
    if (!oracle)
        return false;

    Function *ctor = makeCtorShell(M, "morok.step");
    IRBuilder<> B(&ctor->getEntryBlock());
    B.CreateCall(oracle);
    B.CreateRetVoid();
    appendToGlobalCtors(M, ctor, 0);
    return true;
}

bool trapOracleModule(Module &M, ir::IRRandom &rng) {
    const Triple tt(M.getTargetTriple());
    TrapSigactionLayout layout;
    if (intPtrTy(M)->getBitWidth() != 64 || !trapSigactionLayout(tt, layout))
        return false;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);
    constexpr int kSigTrap = 5;

    Function *ctor = makeCtorShell(M, "morok.trap");
    antiDebugSeal(M, rng);
    GlobalVariable *state = trapOracleState(M, rng);
    GlobalVariable *counter = trapHitCounter(M);
    Function *handler = trapSignalHandler(M, counter, state, tt);

    IRBuilder<> B(&ctor->getEntryBlock());
    B.CreateStore(ConstantInt::get(i32, 0), counter)->setVolatile(true);

    auto *actionTy = ArrayType::get(i8, layout.sigactionSize);
    AllocaInst *newAction = B.CreateAlloca(actionTy, nullptr, "morok.trap.sa");
    AllocaInst *oldTrapAction =
        B.CreateAlloca(actionTy, nullptr, "morok.trap.old.trap");
    AllocaInst *oldIllAction = nullptr;
    storeTrapSiginfoAction(B, M, newAction, handler, layout);
    FunctionCallee sigactionFn = sigactionDecl(M);
    B.CreateCall(sigactionFn,
                 {ConstantInt::get(i32, kSigTrap), newAction, oldTrapAction},
                 "morok.trap.sigaction.trap");
    if (useLinuxX86SiginfoTrapHandler(tt)) {
        constexpr int kSigIll = 4;
        oldIllAction = B.CreateAlloca(actionTy, nullptr, "morok.trap.old.ill");
        B.CreateCall(sigactionFn,
                     {ConstantInt::get(i32, kSigIll), newAction, oldIllAction},
                     "morok.trap.sigaction.ill");
    }

    unsigned expected = emitTrapStimuli(B, M, tt);
    auto *hits = B.CreateLoad(i32, counter, "morok.trap.hits.final");
    hits->setVolatile(true);
    foldState(B, state, hits, 0x91D0F736B52C48EAULL, "morok.trap.final");
    Value *missing = B.CreateICmpULT(hits, ConstantInt::get(i32, expected),
                                     "morok.trap.missing");
    foldEnforcedFlag(B, state, missing, 0xE2AB41739D08C6F5ULL,
                     "morok.trap.missing");
    if (useLinuxX86SiginfoTrapHandler(tt)) {
        constexpr int kSigIll = 4;
        B.CreateCall(sigactionFn,
                     {ConstantInt::get(i32, kSigTrap), oldTrapAction,
                      ConstantPointerNull::get(ptr)});
        B.CreateCall(sigactionFn,
                     {ConstantInt::get(i32, kSigIll), oldIllAction,
                      ConstantPointerNull::get(ptr)});
    } else {
        B.CreateCall(sigactionFn,
                     {ConstantInt::get(i32, kSigTrap), oldTrapAction,
                      ConstantPointerNull::get(ptr)});
    }
    B.CreateRetVoid();
    appendToGlobalCtors(M, ctor, 0);
    return true;
}

bool pageFaultTlbOracleModule(Module &M, ir::IRRandom &rng) {
    const Triple tt(M.getTargetTriple());
    antiDebugSeal(M, rng);
    GlobalVariable *state = pageFaultTlbState(M, rng);
    Function *oracle = pageFaultTlbProbe(M, state, rng, tt);
    if (!oracle)
        return false;

    Function *ctor = makeCtorShell(M, "morok.pftlb");
    IRBuilder<> B(&ctor->getEntryBlock());
    B.CreateCall(oracle);
    B.CreateRetVoid();
    appendToGlobalCtors(M, ctor, 0);
    return true;
}

bool cacheTimingOracleModule(Module &M, ir::IRRandom &rng) {
    const Triple tt(M.getTargetTriple());
    if (intPtrTy(M)->getBitWidth() != 64)
        return false;
    antiDebugSeal(M, rng);
    constexpr std::uint32_t kMaxTargets = 16;
    std::vector<Function *> targets;
    targets.reserve(kMaxTargets);
    for (Function &F : M) {
        if (targets.size() >= kMaxTargets)
            break;
        if (isPrologueProbeCandidate(F))
            targets.push_back(&F);
    }
    if (targets.empty())
        return false;

    GlobalVariable *state = cacheTimingState(M, rng);
    Function *oracle = cacheTimingProbe(M, state, rng, tt, targets);
    if (!oracle)
        return false;

    Function *ctor = makeCtorShell(M, "morok.cachetime");
    IRBuilder<> B(&ctor->getEntryBlock());
    B.CreateCall(oracle);
    B.CreateRetVoid();
    appendToGlobalCtors(M, ctor, 0);
    return true;
}

bool microarchitecturalCanaryModule(Module &M, ir::IRRandom &rng) {
    const Triple tt(M.getTargetTriple());
    antiDebugSeal(M, rng);
    GlobalVariable *state = microCanaryState(M, rng);
    Function *oracle = microarchitecturalCanaryProbe(M, state, rng, tt);
    if (!oracle)
        return false;

    Function *ctor = makeCtorShell(M, "morok.microcanary");
    IRBuilder<> B(&ctor->getEntryBlock());
    B.CreateCall(oracle);
    B.CreateRetVoid();
    appendToGlobalCtors(M, ctor, 0);
    return true;
}

bool antiHookingModule(Module &M, ir::IRRandom &rng) {
    const Triple tt(M.getTargetTriple());
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);
    constexpr std::uint32_t kMaxPrologueTargets = 16;

    std::vector<Function *> prologueTargets;
    prologueTargets.reserve(kMaxPrologueTargets + 1);
    for (Function &F : M) {
        if (prologueTargets.size() >= kMaxPrologueTargets)
            break;
        if (isPrologueProbeCandidate(F))
            prologueTargets.push_back(&F);
    }
    functionMacTargetTable(M, prologueTargets);

    Function *ctor = makeCtorShell(M, "morok.antihook");
    antiDebugSeal(M, rng);
    GlobalVariable *state = antiHookState(M, rng);
    IRBuilder<> B(&ctor->getEntryBlock());
    AllocaInst *corroboration =
        B.CreateAlloca(B.getInt64Ty(), nullptr, "morok.corroborate.score");
    B.CreateStore(ConstantInt::get(B.getInt64Ty(), 0), corroboration)
        ->setVolatile(true);

    if (Function *clean = cleanCopyProbe(M, rng, tt)) {
        Value *diff = B.CreateCall(clean, {}, "morok.antihook.clean.diff");
        Value *changed =
            B.CreateICmpNE(diff, ConstantInt::get(B.getInt64Ty(), 0),
                           "morok.corroborate.clean.changed");
        incrementDiff(B, corroboration, changed, "morok.corroborate.clean");
        foldState(B, state, diff, 0xE0B9CA7F2D341985ULL,
                  "morok.antihook.clean");
        foldFlag(B, state, changed, 0x48C3F3A9127DE40BULL,
                 "morok.antihook.clean.changed");
        prologueTargets.push_back(clean);
    }
    Function *gotProbe = linuxGotPltProbe(M, tt);
    if (gotProbe) {
        Value *diff = B.CreateCall(gotProbe, {}, "morok.antihook.got.diff");
        Value *changed =
            B.CreateICmpNE(diff, ConstantInt::get(B.getInt64Ty(), 0),
                           "morok.corroborate.got.changed");
        incrementDiff(B, corroboration, changed, "morok.corroborate.got");
        foldState(B, state, diff, 0xF93A8B7C62D514E1ULL, "morok.antihook.got");
        foldEnforcedFlag(B, state, changed, 0xB17D4E23C9A5806FULL,
                         "morok.antihook.got.changed");
    }
    if (Function *fixups = darwinFixupProbe(M, tt)) {
        Value *diff = B.CreateCall(fixups, {}, "morok.antihook.fixup.diff");
        Value *changed =
            B.CreateICmpNE(diff, ConstantInt::get(B.getInt64Ty(), 0),
                           "morok.corroborate.fixup.changed");
        incrementDiff(B, corroboration, changed, "morok.corroborate.fixup");
        foldState(B, state, diff, 0x8D46E52CA7B9130FULL,
                  "morok.antihook.fixup");
        foldFlag(B, state, changed, 0xD1C9A03F76542BE8ULL,
                 "morok.antihook.fixup.changed");
    }
    // Census must observe the original protections before W^X remediation can
    // normalize suspicious RWX pages into clean-looking RX mappings.
    if (Function *census = addressSpaceCensusProbe(M, rng, tt)) {
        Value *diff = B.CreateCall(census, {}, "morok.antihook.census.diff");
        Value *changed =
            B.CreateICmpNE(diff, ConstantInt::get(B.getInt64Ty(), 0),
                           "morok.corroborate.census.changed");
        incrementDiff(B, corroboration, changed, "morok.corroborate.census");
        foldState(B, state, diff, 0x6B4E9D718C2A35F0ULL,
                  "morok.antihook.census");
        changed->setName("morok.negative.modules.extra");
        foldFlag(B, state, changed, 0xA7815E3C49D206BFULL,
                 "morok.antihook.census.changed");
        foldFlag(B, state, changed, 0xB2E746D9108CA53FULL,
                 "morok.negative.modules.extra");
    }
    if (Function *wx = wxEnforceProbe(M, tt)) {
        Value *diff = B.CreateCall(wx, {}, "morok.antihook.wxorx.diff");
        Value *changed =
            B.CreateICmpNE(diff, ConstantInt::get(B.getInt64Ty(), 0),
                           "morok.corroborate.wxorx.changed");
        incrementDiff(B, corroboration, changed, "morok.corroborate.wxorx");
        foldState(B, state, diff, 0x14E2B7C95A680D3FULL,
                  "morok.antihook.wxorx");
        foldEnforcedFlag(B, state, changed, 0xD8F31C6A4B927E50ULL,
                         "morok.antihook.wxorx.changed");
    }
    if (Function *diverge = methodDivergenceProbe(M, tt)) {
        Value *diff =
            B.CreateCall(diverge, {}, "morok.antihook.diverge.diff");
        Value *changed =
            B.CreateICmpNE(diff, ConstantInt::get(B.getInt64Ty(), 0),
                           "morok.corroborate.diverge.changed");
        incrementDiff(B, corroboration, changed, "morok.corroborate.diverge");
        foldState(B, state, diff, 0x2F8D6C1E9A7453B0ULL,
                  "morok.antihook.diverge");
        foldEnforcedFlag(B, state, changed, 0xC58E90A37B42D16FULL,
                         "morok.antihook.diverge.changed");
    }
    if (Function *emu = emulationDivergenceProbe(M, tt)) {
        Value *diff = B.CreateCall(emu, {}, "morok.antihook.emu.diff");
        Value *changed =
            B.CreateICmpNE(diff, ConstantInt::get(B.getInt64Ty(), 0),
                           "morok.corroborate.emu.changed");
        incrementDiff(B, corroboration, changed, "morok.corroborate.emu");
        foldState(B, state, diff, 0x7642CDB91E30A58FULL, "morok.antihook.emu");
        foldEnforcedFlag(B, state, changed, 0x1F0E3D2C4B5A6978ULL,
                         "morok.antihook.emu.changed");
    }
    if (Function *sandbox = sandboxHeuristicProbe(M, tt)) {
        Value *score =
            B.CreateCall(sandbox, {}, "morok.antihook.sandbox.score");
        Value *changed =
            B.CreateICmpUGE(score, ConstantInt::get(B.getInt64Ty(), 2),
                            "morok.corroborate.sandbox.changed");
        incrementDiff(B, corroboration, changed, "morok.corroborate.sandbox");
        foldState(B, state, score, 0x9A01C7E52D63B48FULL,
                  "morok.antihook.sandbox");
        // VM/cloud identity and sandbox-shape signals are useful telemetry, but
        // legitimate customers run under hypervisors.  Never let these
        // identity-only scores perturb the consumed anti_debug seal (#128).
        foldFlag(B, state, changed, 0x4E87A61D39C205B3ULL,
                 "morok.antihook.sandbox.changed");
    }
    if (Function *smc = dbiSmcTripwireProbe(M, tt)) {
        Value *diff = B.CreateCall(smc, {}, "morok.antihook.dbi.smc.diff");
        Value *changed =
            B.CreateICmpNE(diff, ConstantInt::get(B.getInt64Ty(), 0),
                           "morok.corroborate.dbi.smc.changed");
        incrementDiff(B, corroboration, changed, "morok.corroborate.dbi.smc");
        foldState(B, state, diff, 0xE62D41B98A3F570CULL,
                  "morok.antihook.dbi.smc");
        foldEnforcedFlag(B, state, changed, 0x73B5D02E6C49A18FULL,
                         "morok.antihook.dbi.smc.changed");
    }
    if (Function *schro = schrodingerPageProbe(M, state, rng, tt)) {
        Value *diff = B.CreateCall(schro, {}, "morok.antihook.schro.diff");
        Value *changed =
            B.CreateICmpNE(diff, ConstantInt::get(B.getInt64Ty(), 0),
                           "morok.corroborate.schro.changed");
        incrementDiff(B, corroboration, changed, "morok.corroborate.schro");
        foldState(B, state, diff, 0xC92D4F61A7E8053BULL,
                  "morok.antihook.schro");
        foldFlag(B, state, changed, 0x5F0A81C3D624B7E9ULL,
                 "morok.antihook.schro.changed");
    }
    if (Function *antiDump = antiDumpProbe(M, tt)) {
        Value *diff =
            B.CreateCall(antiDump, {}, "morok.antihook.antidump.diff");
        Value *changed =
            B.CreateICmpNE(diff, ConstantInt::get(B.getInt64Ty(), 0),
                           "morok.corroborate.antidump.changed");
        incrementDiff(B, corroboration, changed, "morok.corroborate.antidump");
        foldState(B, state, diff, 0xD48C71E9A5B2036FULL,
                  "morok.antihook.antidump");
        foldFlag(B, state, changed, 0x6E51B9C07D3A428FULL,
                 "morok.antihook.antidump.changed");
    }
    if (Function *dbi = linuxDbiSignatureProbe(M, rng, tt)) {
        Value *diff = B.CreateCall(dbi, {}, "morok.antihook.dbi.diff");
        Value *changed =
            B.CreateICmpNE(diff, ConstantInt::get(B.getInt64Ty(), 0),
                           "morok.corroborate.dbi.changed");
        incrementDiff(B, corroboration, changed, "morok.corroborate.dbi");
        foldState(B, state, diff, 0x1B89E4C76F20DA53ULL,
                  "morok.antihook.dbi");
        foldEnforcedFlag(B, state, changed, 0xF4A7812C39D60E5BULL,
                         "morok.antihook.dbi.changed");
    }
    if (Function *negativeTiming = negativeTimingProbe(M, rng, tt)) {
        Value *diff =
            B.CreateCall(negativeTiming, {}, "morok.negative.timing.diff");
        Value *changed =
            B.CreateICmpNE(diff, ConstantInt::get(B.getInt64Ty(), 0),
                           "morok.corroborate.negative.timing.changed");
        incrementDiff(B, corroboration, changed,
                      "morok.corroborate.negative.timing");
        foldState(B, state, diff, 0x4D91C2A8F76E350BULL,
                  "morok.negative.timing");
        foldEnforcedFlag(B, state, changed, 0x8A6357D1C49E20BFULL,
                         "morok.negative.timing.changed");
    }
    insertStackOriginChecks(M, stackOriginCheck(M), state, prologueTargets, rng);
    emitProloguePatternChecks(B, M, tt, state, prologueTargets, rng);
    if (gotProbe)
        insertAntiHookGotRecheckSites(M, linuxGotRecheckProbe(M, gotProbe, state),
                                      rng);

    if (tt.isOSDarwin()) {
        B.CreateRetVoid();
        appendToGlobalCtors(M, ctor, 0);
        return true;
    }
    if (!tt.isOSLinux()) {
        B.CreateRetVoid();
        appendToGlobalCtors(M, ctor, 0);
        return true;
    }

    // Detect a resident function-hooking framework: if its entry point
    // resolves, the process is being instrumented — bail out.  Darwin uses the
    // clean-copy checker here until the Mach-O export-by-hash resolver exists.
    FunctionCallee dlsym = M.getOrInsertFunction(
        "dlsym", FunctionType::get(ptr, {ptr, ptr}, false));
    FunctionCallee exitFn = M.getOrInsertFunction(
        "exit", FunctionType::get(Type::getVoidTy(ctx), {i32}, false));

    BasicBlock *guardBB = B.GetInsertBlock();
    auto *dlsymBB = BasicBlock::Create(ctx, "morok.antihook.dlsym", ctor);
    auto *afterDlsymBB =
        BasicBlock::Create(ctx, "morok.antihook.after.dlsym", ctor);
    B.CreateCondBr(emitElfDynamicPresent(B, M, tt), dlsymBB, afterDlsymBB);

    IRBuilder<> DB(dlsymBB);
    // The probed symbol is cloaked inline — never a readable "MSHookFunction".
    Value *sym = ir::emitCloakedSymbol(DB, M, "MSHookFunction", rng);
    // glibc RTLD_DEFAULT is (void *)0.  Darwin's (void *)-2 value never reaches
    // this Linux-only block.
    Value *rtldDefault = ConstantPointerNull::get(ptr);
    Value *found = DB.CreateCall(dlsym, {rtldDefault, sym});
    Value *dynHooked =
        DB.CreateICmpNE(found, ConstantPointerNull::get(ptr));
    DB.CreateBr(afterDlsymBB);

    B.SetInsertPoint(afterDlsymBB);
    auto *hooked = B.CreatePHI(Type::getInt1Ty(ctx), 2,
                               "morok.antihook.hooked");
    hooked->addIncoming(ConstantInt::getFalse(ctx), guardBB);
    hooked->addIncoming(dynHooked, dlsymBB);
    auto *score = B.CreateLoad(B.getInt64Ty(), corroboration,
                               "morok.corroborate.score.final");
    score->setVolatile(true);
    Value *confirmed =
        B.CreateICmpUGE(score, ConstantInt::get(B.getInt64Ty(), 2),
                        "morok.corroborate.confirmed");
    Value *aggressive = B.CreateAnd(hooked, confirmed,
                                    "morok.corroborate.aggressive");
    foldPoisonFlag(B, aggressive, 0xA4F6C2E91B537D8BULL,
                   "morok.antihook.corroborated");

    auto *bail = BasicBlock::Create(ctx, "bail", ctor);
    auto *cont = BasicBlock::Create(ctx, "cont", ctor);
    B.CreateCondBr(aggressive, bail, cont);

    IRBuilder<> BB(bail);
    BB.CreateCall(exitFn, {ConstantInt::get(i32, 1)});
    BB.CreateUnreachable();

    IRBuilder<> CB(cont);
    CB.CreateRetVoid();
    appendToGlobalCtors(M, ctor, 0);
    return true;
}

bool antiClassDumpModule(Module &M) {
    // Objective-C metadata lives in __objc_* sections / OBJC_* globals.  Only
    // act when such metadata exists; plain C/C++ modules have none, so this is
    // a safe no-op there.
    bool hasObjC = false;
    for (GlobalVariable &gv : M.globals()) {
        StringRef sec = gv.getSection();
        if (gv.getName().starts_with("OBJC_") || sec.contains("__objc")) {
            hasObjC = true;
            break;
        }
    }
    if (!hasObjC)
        return false;

    // Scramble the names of private Objective-C metadata globals so class-dump
    // style tools cannot recover symbol names from the metadata.
    bool changed = false;
    for (GlobalVariable &gv : M.globals()) {
        if (gv.hasLocalLinkage() && gv.getName().starts_with("OBJC_")) {
            gv.setName("morok.objc");
            changed = true;
        }
    }
    return changed;
}

bool windowsPeFoundationModule(Module &M, ir::IRRandom &rng) {
    const Triple tt(M.getTargetTriple());
    antiDebugSeal(M, rng);
    GlobalVariable *state = windowsPeState(M, rng);
    Function *probe = windowsPeFoundationProbe(M, state, rng, tt);
    if (!probe)
        return false;

    Function *ctor = makeCtorShell(M, "morok.win.foundation");
    IRBuilder<> B(&ctor->getEntryBlock());
    B.CreateCall(probe);
    B.CreateRetVoid();
    appendToGlobalCtors(M, ctor, 0);
    return true;
}

bool windowsPebHeapDebugModule(Module &M, ir::IRRandom &rng) {
    const Triple tt(M.getTargetTriple());
    antiDebugSeal(M, rng);
    GlobalVariable *state = windowsPeState(M, rng);
    Function *probe = windowsPebHeapDebugProbe(M, state, rng, tt);
    if (!probe)
        return false;

    Function *ctor = makeCtorShell(M, "morok.win.pebheap");
    IRBuilder<> B(&ctor->getEntryBlock());
    B.CreateCall(probe);
    B.CreateRetVoid();
    appendToGlobalCtors(M, ctor, 0);
    return true;
}

bool windowsDebugObjectModule(Module &M, ir::IRRandom &rng) {
    const Triple tt(M.getTargetTriple());
    antiDebugSeal(M, rng);
    GlobalVariable *state = windowsPeState(M, rng);
    Function *probe = windowsDebugObjectProbe(M, state, rng, tt);
    if (!probe)
        return false;

    Function *ctor = makeCtorShell(M, "morok.win.dbgobj");
    IRBuilder<> B(&ctor->getEntryBlock());
    B.CreateCall(probe);
    B.CreateRetVoid();
    appendToGlobalCtors(M, ctor, 0);
    return true;
}

bool windowsThreadHideModule(Module &M, ir::IRRandom &rng) {
    const Triple tt(M.getTargetTriple());
    antiDebugSeal(M, rng);
    GlobalVariable *state = windowsPeState(M, rng);
    Function *probe = windowsThreadHideProbe(M, state, rng, tt);
    if (!probe)
        return false;

    Function *ctor = makeCtorShell(M, "morok.win.thide");
    IRBuilder<> B(&ctor->getEntryBlock());
    B.CreateCall(probe);
    B.CreateRetVoid();
    appendToGlobalCtors(M, ctor, 0);
    return true;
}

bool windowsAntiAttachModule(Module &M, ir::IRRandom &rng) {
    const Triple tt(M.getTargetTriple());
    antiDebugSeal(M, rng);
    GlobalVariable *state = windowsPeState(M, rng);
    Function *probe = windowsAntiAttachProbe(M, state, rng, tt);
    if (!probe)
        return false;

    Function *ctor = makeCtorShell(M, "morok.win.attach");
    IRBuilder<> B(&ctor->getEntryBlock());
    B.CreateCall(probe);
    B.CreateRetVoid();
    appendToGlobalCtors(M, ctor, 0);
    return true;
}

bool windowsKernelDebuggerModule(Module &M, ir::IRRandom &rng) {
    const Triple tt(M.getTargetTriple());
    antiDebugSeal(M, rng);
    GlobalVariable *state = windowsPeState(M, rng);
    Function *probe = windowsKernelDebuggerProbe(M, state, rng, tt);
    if (!probe)
        return false;

    Function *ctor = makeCtorShell(M, "morok.win.kdbg");
    IRBuilder<> B(&ctor->getEntryBlock());
    B.CreateCall(probe);
    B.CreateRetVoid();
    appendToGlobalCtors(M, ctor, 0);
    return true;
}

bool windowsSyscallsModule(Module &M, ir::IRRandom &rng) {
    const Triple tt(M.getTargetTriple());
    antiDebugSeal(M, rng);
    GlobalVariable *state = windowsPeState(M, rng);
    Function *probe = windowsSyscallsProbe(M, state, rng, tt);
    if (!probe)
        return false;

    Function *ctor = makeCtorShell(M, "morok.win.syscalls");
    IRBuilder<> B(&ctor->getEntryBlock());
    B.CreateCall(probe);
    B.CreateRetVoid();
    appendToGlobalCtors(M, ctor, 0);
    return true;
}

bool windowsUnhookModule(Module &M, ir::IRRandom &rng) {
    const Triple tt(M.getTargetTriple());
    antiDebugSeal(M, rng);
    GlobalVariable *state = windowsPeState(M, rng);
    Function *probe = windowsUnhookProbe(M, state, rng, tt);
    if (!probe)
        return false;

    Function *ctor = makeCtorShell(M, "morok.win.unhook");
    IRBuilder<> B(&ctor->getEntryBlock());
    B.CreateCall(probe);
    B.CreateRetVoid();
    appendToGlobalCtors(M, ctor, 0);
    return true;
}

bool windowsVehAuditModule(Module &M, ir::IRRandom &rng) {
    const Triple tt(M.getTargetTriple());
    antiDebugSeal(M, rng);
    GlobalVariable *state = windowsPeState(M, rng);
    Function *probe = windowsVehAuditProbe(M, state, rng, tt);
    if (!probe)
        return false;

    Function *ctor = makeCtorShell(M, "morok.win.veh.audit");
    IRBuilder<> B(&ctor->getEntryBlock());
    B.CreateCall(probe);
    B.CreateRetVoid();
    appendToGlobalCtors(M, ctor, 0);
    return true;
}

bool windowsProcessMitigationsModule(Module &M, ir::IRRandom &rng) {
    const Triple tt(M.getTargetTriple());
    GlobalVariable *state = windowsPeState(M, rng);
    Function *probe = windowsProcessMitigationsProbe(M, state, rng, tt);
    if (!probe)
        return false;

    Function *ctor = makeCtorShell(M, "morok.win.mitigate");
    IRBuilder<> B(&ctor->getEntryBlock());
    B.CreateCall(probe);
    B.CreateRetVoid();
    appendToGlobalCtors(M, ctor, 0);
    return true;
}

PreservedAnalyses AntiDebuggingPass::run(Module &M, ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return antiDebuggingModule(M, rng) ? PreservedAnalyses::none()
                                       : PreservedAnalyses::all();
}
PreservedAnalyses AntiHookingPass::run(Module &M, ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return antiHookingModule(M, rng) ? PreservedAnalyses::none()
                                     : PreservedAnalyses::all();
}
PreservedAnalyses AntiClassDumpPass::run(Module &M, ModuleAnalysisManager &) {
    return antiClassDumpModule(M) ? PreservedAnalyses::none()
                                  : PreservedAnalyses::all();
}

PreservedAnalyses WindowsPEFoundationPass::run(Module &M,
                                               ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return windowsPeFoundationModule(M, rng) ? PreservedAnalyses::none()
                                             : PreservedAnalyses::all();
}

PreservedAnalyses WindowsPebHeapDebugPass::run(Module &M,
                                               ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return windowsPebHeapDebugModule(M, rng) ? PreservedAnalyses::none()
                                             : PreservedAnalyses::all();
}

PreservedAnalyses WindowsDebugObjectPass::run(Module &M,
                                              ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return windowsDebugObjectModule(M, rng) ? PreservedAnalyses::none()
                                            : PreservedAnalyses::all();
}

PreservedAnalyses WindowsThreadHidePass::run(Module &M,
                                             ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return windowsThreadHideModule(M, rng) ? PreservedAnalyses::none()
                                           : PreservedAnalyses::all();
}

PreservedAnalyses WindowsAntiAttachPass::run(Module &M,
                                             ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return windowsAntiAttachModule(M, rng) ? PreservedAnalyses::none()
                                           : PreservedAnalyses::all();
}

PreservedAnalyses WindowsKernelDebuggerPass::run(Module &M,
                                                 ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return windowsKernelDebuggerModule(M, rng) ? PreservedAnalyses::none()
                                               : PreservedAnalyses::all();
}

PreservedAnalyses WindowsSyscallsPass::run(Module &M,
                                           ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return windowsSyscallsModule(M, rng) ? PreservedAnalyses::none()
                                         : PreservedAnalyses::all();
}

PreservedAnalyses WindowsUnhookPass::run(Module &M,
                                         ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return windowsUnhookModule(M, rng) ? PreservedAnalyses::none()
                                       : PreservedAnalyses::all();
}

PreservedAnalyses WindowsVehAuditPass::run(Module &M,
                                           ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return windowsVehAuditModule(M, rng) ? PreservedAnalyses::none()
                                         : PreservedAnalyses::all();
}

PreservedAnalyses WindowsProcessMitigationsPass::run(
    Module &M, ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return windowsProcessMitigationsModule(M, rng) ? PreservedAnalyses::none()
                                                   : PreservedAnalyses::all();
}

PreservedAnalyses TimingOraclePass::run(Module &M, ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return timingOracleModule(M, rng) ? PreservedAnalyses::none()
                                      : PreservedAnalyses::all();
}

PreservedAnalyses SchedulerStepOraclePass::run(Module &M,
                                               ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return schedulerStepOracleModule(M, rng) ? PreservedAnalyses::none()
                                             : PreservedAnalyses::all();
}

PreservedAnalyses TrapOraclePass::run(Module &M, ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return trapOracleModule(M, rng) ? PreservedAnalyses::none()
                                    : PreservedAnalyses::all();
}

PreservedAnalyses PageFaultTlbOraclePass::run(Module &M,
                                              ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return pageFaultTlbOracleModule(M, rng) ? PreservedAnalyses::none()
                                            : PreservedAnalyses::all();
}

PreservedAnalyses CacheTimingOraclePass::run(Module &M,
                                             ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return cacheTimingOracleModule(M, rng) ? PreservedAnalyses::none()
                                           : PreservedAnalyses::all();
}

PreservedAnalyses MicroarchitecturalCanaryPass::run(
    Module &M, ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return microarchitecturalCanaryModule(M, rng) ? PreservedAnalyses::none()
                                                  : PreservedAnalyses::all();
}

} // namespace morok::passes
