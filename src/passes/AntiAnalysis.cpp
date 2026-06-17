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

#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Alignment.h"
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

FunctionCallee ptraceDecl(Module &M) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);
    return M.getOrInsertFunction(
        "ptrace", FunctionType::get(i32, {i32, i32, ptr, i32}, false));
}

Value *emitPtrace(IRBuilderBase &B, Module &M, int request) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);
    return B.CreateCall(ptraceDecl(M), {ConstantInt::getSigned(i32, request),
                                        ConstantInt::get(i32, 0),
                                        ConstantPointerNull::get(ptr),
                                        ConstantInt::get(i32, 0)});
}

bool useDirectLinuxSyscalls(const Triple &TT) {
    return TT.isOSLinux() && TT.getArch() == Triple::x86_64;
}

Value *toSyscallArg(IRBuilderBase &B, Value *V) {
    auto *ip = intPtrTy(*B.GetInsertBlock()->getModule());
    if (V->getType()->isPointerTy())
        return B.CreatePtrToInt(V, ip);
    if (V->getType()->isIntegerTy())
        return B.CreateSExtOrTrunc(V, ip);
    return ConstantInt::get(ip, 0);
}

FunctionCallee syscallDecl(Module &M) {
    auto *ip = intPtrTy(M);
    return M.getOrInsertFunction("syscall", FunctionType::get(ip, {ip}, true));
}

FunctionCallee getpidDecl(Module &M) {
    return M.getOrInsertFunction(
        "getpid", FunctionType::get(Type::getInt32Ty(M.getContext()), false));
}

FunctionCallee getppidDecl(Module &M) {
    return M.getOrInsertFunction(
        "getppid", FunctionType::get(Type::getInt32Ty(M.getContext()), false));
}

Value *emitLinuxSyscall(IRBuilder<> &B, Module &M, const Triple &TT,
                        std::uint32_t Number,
                        std::initializer_list<Value *> Args) {
    auto *ip = intPtrTy(M);
    std::array<Value *, 6> sysArgs = {
        ConstantInt::get(ip, 0), ConstantInt::get(ip, 0),
        ConstantInt::get(ip, 0), ConstantInt::get(ip, 0),
        ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)};
    std::size_t i = 0;
    for (Value *arg : Args) {
        if (i >= sysArgs.size())
            break;
        sysArgs[i++] = toSyscallArg(B, arg);
    }

    if (useDirectLinuxSyscalls(TT)) {
        std::vector<Type *> params(7, ip);
        auto *asmTy = FunctionType::get(ip, params, false);
        InlineAsm *syscall = InlineAsm::get(
            asmTy, "syscall",
            "={rax},{rax},{rdi},{rsi},{rdx},{r10},{r8},{r9},~{rcx},~{r11},"
            "~{memory},~{dirflag},~{fpsr},~{flags}",
            /*hasSideEffects=*/true);
        return B.CreateCall(asmTy, syscall,
                            {ConstantInt::get(ip, Number), sysArgs[0],
                             sysArgs[1], sysArgs[2], sysArgs[3], sysArgs[4],
                             sysArgs[5]},
                            "morok.linux.syscall");
    }

    return B.CreateCall(syscallDecl(M),
                        {ConstantInt::get(ip, Number), sysArgs[0], sysArgs[1],
                         sysArgs[2], sysArgs[3], sysArgs[4], sysArgs[5]},
                        "morok.linux.syscall.wrap");
}

bool linuxCoreSyscalls(const Triple &TT, std::uint32_t &Ptrace,
                       std::uint32_t &Prctl, std::uint32_t &OpenAt,
                       std::uint32_t &Read, std::uint32_t &Close) {
    switch (TT.getArch()) {
    case Triple::x86_64:
        Ptrace = 101;
        Prctl = 157;
        OpenAt = 257;
        Read = 0;
        Close = 3;
        return true;
    case Triple::aarch64:
        Ptrace = 117;
        Prctl = 167;
        OpenAt = 56;
        Read = 63;
        Close = 57;
        return true;
    default:
        return false;
    }
}

Value *emitLinuxPtrace(IRBuilder<> &B, Module &M, const Triple &TT,
                       int request) {
    std::uint32_t ptraceNr = 0;
    std::uint32_t prctlNr = 0;
    std::uint32_t openatNr = 0;
    std::uint32_t readNr = 0;
    std::uint32_t closeNr = 0;
    if (!linuxCoreSyscalls(TT, ptraceNr, prctlNr, openatNr, readNr, closeNr))
        return emitPtrace(B, M, request);
    auto *i32 = Type::getInt32Ty(M.getContext());
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(M.getContext());
    Value *rc = emitLinuxSyscall(
        B, M, TT, ptraceNr,
        {ConstantInt::getSigned(ip, request), ConstantInt::get(ip, 0),
         ConstantPointerNull::get(ptr), ConstantInt::get(ip, 0)});
    return B.CreateTruncOrBitCast(rc, i32);
}

Value *emitLinuxPrctl(IRBuilder<> &B, Module &M, const Triple &TT,
                      std::int64_t Option, std::int64_t A2 = 0,
                      std::int64_t A3 = 0, std::int64_t A4 = 0,
                      std::int64_t A5 = 0) {
    std::uint32_t ptraceNr = 0;
    std::uint32_t prctlNr = 0;
    std::uint32_t openatNr = 0;
    std::uint32_t readNr = 0;
    std::uint32_t closeNr = 0;
    if (!linuxCoreSyscalls(TT, ptraceNr, prctlNr, openatNr, readNr, closeNr)) {
        auto *i32 = Type::getInt32Ty(M.getContext());
        auto *ip = intPtrTy(M);
        FunctionCallee prctl = M.getOrInsertFunction(
            "prctl", FunctionType::get(i32, {i32, ip, ip, ip, ip}, false));
        auto arg = [&](std::int64_t v) {
            return ConstantInt::getSigned(ip, v);
        };
        return B.CreateCall(prctl, {ConstantInt::getSigned(i32, Option),
                                    arg(A2), arg(A3), arg(A4), arg(A5)});
    }

    auto *i32 = Type::getInt32Ty(M.getContext());
    auto *ip = intPtrTy(M);
    Value *rc = emitLinuxSyscall(
        B, M, TT, prctlNr,
        {ConstantInt::getSigned(ip, Option), ConstantInt::getSigned(ip, A2),
         ConstantInt::getSigned(ip, A3), ConstantInt::getSigned(ip, A4),
         ConstantInt::getSigned(ip, A5)});
    return B.CreateTruncOrBitCast(rc, i32);
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

bool useDirectDarwinSyscalls(const Triple &TT) {
    return TT.isOSDarwin() && TT.getArch() == Triple::x86_64;
}

Value *emitDarwinSyscall(IRBuilder<> &B, Module &M, const Triple &TT,
                         std::uint32_t Number,
                         std::initializer_list<Value *> Args) {
    auto *ip = intPtrTy(M);
    std::array<Value *, 6> sysArgs = {
        ConstantInt::get(ip, 0), ConstantInt::get(ip, 0),
        ConstantInt::get(ip, 0), ConstantInt::get(ip, 0),
        ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)};
    std::size_t i = 0;
    for (Value *arg : Args) {
        if (i >= sysArgs.size())
            break;
        sysArgs[i++] = toSyscallArg(B, arg);
    }

    if (useDirectDarwinSyscalls(TT)) {
        std::vector<Type *> params(7, ip);
        auto *asmTy = FunctionType::get(ip, params, false);
        InlineAsm *syscall = InlineAsm::get(
            asmTy, "syscall\nsbbq %r11, %r11\norq %r11, %rax",
            "={rax},{rax},{rdi},{rsi},{rdx},{r10},{r8},{r9},~{rcx},~{r11},"
            "~{memory},~{dirflag},~{fpsr},~{flags}",
            /*hasSideEffects=*/true);
        return B.CreateCall(asmTy, syscall,
                            {ConstantInt::get(ip, 0x02000000U | Number),
                             sysArgs[0], sysArgs[1], sysArgs[2], sysArgs[3],
                             sysArgs[4], sysArgs[5]},
                            "morok.darwin.syscall");
    }

    return B.CreateCall(syscallDecl(M),
                        {ConstantInt::get(ip, Number), sysArgs[0], sysArgs[1],
                         sysArgs[2], sysArgs[3], sysArgs[4], sysArgs[5]},
                        "morok.darwin.syscall.wrap");
}

Value *emitDarwinGetpid(IRBuilder<> &B, Module &M, const Triple &TT) {
    auto *i32 = Type::getInt32Ty(M.getContext());
    if (useDirectDarwinSyscalls(TT))
        return B.CreateTruncOrBitCast(emitDarwinSyscall(B, M, TT, 20, {}), i32);
    return B.CreateCall(getpidDecl(M));
}

Value *emitDarwinPtrace(IRBuilder<> &B, Module &M, const Triple &TT,
                        std::int32_t Request) {
    auto *i32 = Type::getInt32Ty(M.getContext());
    auto *ptr = PointerType::getUnqual(M.getContext());
    if (useDirectDarwinSyscalls(TT))
        return B.CreateTruncOrBitCast(
            emitDarwinSyscall(
                B, M, TT, 26,
                {ConstantInt::getSigned(i32, Request), ConstantInt::get(i32, 0),
                 ConstantPointerNull::get(ptr), ConstantInt::get(i32, 0)}),
            i32);
    return emitPtrace(B, M, Request);
}

Value *emitDarwinSysctl(IRBuilder<> &B, Module &M, const Triple &TT, Value *Mib,
                        Value *MibLen, Value *OldP, Value *OldLenP, Value *NewP,
                        Value *NewLen) {
    auto *i32 = Type::getInt32Ty(M.getContext());
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(M.getContext());
    if (useDirectDarwinSyscalls(TT))
        return B.CreateTruncOrBitCast(
            emitDarwinSyscall(B, M, TT, 202,
                              {Mib, MibLen, OldP, OldLenP, NewP, NewLen}),
            i32);
    FunctionCallee sysctl = M.getOrInsertFunction(
        "sysctl", FunctionType::get(i32, {ptr, i32, ptr, ptr, ptr, ip}, false));
    return B.CreateCall(sysctl,
                        {Mib, B.CreateTruncOrBitCast(MibLen, i32), OldP,
                         OldLenP, NewP, B.CreateZExtOrTrunc(NewLen, ip)});
}

Value *emitClockGettimeNanos(IRBuilder<> &B, Module &M, std::int32_t ClockId,
                             const Twine &Name);

Value *emitDarwinCsops(IRBuilder<> &B, Module &M, const Triple &TT, Value *Pid,
                       Value *Ops, Value *UserAddr, Value *UserSize) {
    auto *i32 = Type::getInt32Ty(M.getContext());
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(M.getContext());
    if (useDirectDarwinSyscalls(TT))
        return B.CreateTruncOrBitCast(
            emitDarwinSyscall(B, M, TT, 169, {Pid, Ops, UserAddr, UserSize}),
            i32);
    FunctionCallee csops = M.getOrInsertFunction(
        "csops", FunctionType::get(i32, {i32, i32, ptr, ip}, false));
    return B.CreateCall(csops, {B.CreateTruncOrBitCast(Pid, i32),
                                B.CreateTruncOrBitCast(Ops, i32), UserAddr,
                                B.CreateZExtOrTrunc(UserSize, ip)});
}

FunctionCallee openDecl(Module &M) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);
    return M.getOrInsertFunction("open",
                                 FunctionType::get(i32, {ptr, i32}, true));
}

FunctionCallee readDecl(Module &M) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *ip = intPtrTy(M);
    return M.getOrInsertFunction("read",
                                 FunctionType::get(ip, {i32, ptr, ip}, false));
}

FunctionCallee closeDecl(Module &M) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    return M.getOrInsertFunction("close", FunctionType::get(i32, {i32}, false));
}

FunctionCallee readlinkDecl(Module &M) {
    LLVMContext &ctx = M.getContext();
    auto *ptr = PointerType::getUnqual(ctx);
    auto *ip = intPtrTy(M);
    return M.getOrInsertFunction("readlink",
                                 FunctionType::get(ip, {ptr, ptr, ip}, false));
}

FunctionCallee lseekDecl(Module &M) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    return M.getOrInsertFunction("lseek",
                                 FunctionType::get(ip, {i32, ip, i32}, false));
}

FunctionCallee mmapDecl(Module &M) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *ip = intPtrTy(M);
    return M.getOrInsertFunction(
        "mmap", FunctionType::get(ptr, {ptr, ip, i32, i32, i32, ip}, false));
}

FunctionCallee munmapDecl(Module &M) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *ip = intPtrTy(M);
    return M.getOrInsertFunction("munmap",
                                 FunctionType::get(i32, {ptr, ip}, false));
}

FunctionCallee mprotectDecl(Module &M) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);
    auto *ip = intPtrTy(M);
    return M.getOrInsertFunction("mprotect",
                                 FunctionType::get(i32, {ptr, ip, i32}, false));
}

bool linuxCleanCopySyscalls(const Triple &TT, std::uint32_t &Readlink,
                            std::uint32_t &Lseek, std::uint32_t &Mmap,
                            std::uint32_t &Munmap) {
    switch (TT.getArch()) {
    case Triple::x86_64:
        Readlink = 89;
        Lseek = 8;
        Mmap = 9;
        Munmap = 11;
        return true;
    default:
        return false;
    }
}

Value *emitLinuxReadlink(IRBuilder<> &B, Module &M, const Triple &TT,
                         Value *Path, Value *Buf, Value *Size) {
    std::uint32_t readlinkNr = 0;
    std::uint32_t lseekNr = 0;
    std::uint32_t mmapNr = 0;
    std::uint32_t munmapNr = 0;
    if (useDirectLinuxSyscalls(TT) &&
        linuxCleanCopySyscalls(TT, readlinkNr, lseekNr, mmapNr, munmapNr))
        return emitLinuxSyscall(B, M, TT, readlinkNr, {Path, Buf, Size});
    return B.CreateCall(readlinkDecl(M), {Path, Buf, Size},
                        "morok.clean.readlink");
}

Value *emitLinuxLseek(IRBuilder<> &B, Module &M, const Triple &TT, Value *Fd,
                      std::int64_t Offset, std::int32_t Whence) {
    std::uint32_t readlinkNr = 0;
    std::uint32_t lseekNr = 0;
    std::uint32_t mmapNr = 0;
    std::uint32_t munmapNr = 0;
    if (useDirectLinuxSyscalls(TT) &&
        linuxCleanCopySyscalls(TT, readlinkNr, lseekNr, mmapNr, munmapNr))
        return emitLinuxSyscall(
            B, M, TT, lseekNr,
            {Fd, constSignedIp(M, Offset),
             ConstantInt::getSigned(Type::getInt32Ty(M.getContext()), Whence)});
    return B.CreateCall(
        lseekDecl(M),
        {B.CreateTruncOrBitCast(Fd, Type::getInt32Ty(M.getContext())),
         constSignedIp(M, Offset),
         ConstantInt::getSigned(Type::getInt32Ty(M.getContext()), Whence)},
        "morok.clean.lseek");
}

Value *emitLinuxMmapAddr(IRBuilder<> &B, Module &M, const Triple &TT,
                         Value *Size, Value *Fd) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    constexpr std::uint32_t kProtRead = 1;
    constexpr std::uint32_t kMapPrivate = 2;

    std::uint32_t readlinkNr = 0;
    std::uint32_t lseekNr = 0;
    std::uint32_t mmapNr = 0;
    std::uint32_t munmapNr = 0;
    if (useDirectLinuxSyscalls(TT) &&
        linuxCleanCopySyscalls(TT, readlinkNr, lseekNr, mmapNr, munmapNr))
        return emitLinuxSyscall(B, M, TT, mmapNr,
                                {ConstantPointerNull::get(ptr), Size,
                                 ConstantInt::get(i32, kProtRead),
                                 ConstantInt::get(i32, kMapPrivate), Fd,
                                 ConstantInt::get(ip, 0)});

    Value *mapped = B.CreateCall(
        mmapDecl(M),
        {ConstantPointerNull::get(ptr), Size, ConstantInt::get(i32, kProtRead),
         ConstantInt::get(i32, kMapPrivate), B.CreateTruncOrBitCast(Fd, i32),
         ConstantInt::get(ip, 0)},
        "morok.clean.mmap");
    return B.CreatePtrToInt(mapped, ip);
}

void emitLinuxMunmap(IRBuilder<> &B, Module &M, const Triple &TT, Value *Addr,
                     Value *Size) {
    std::uint32_t readlinkNr = 0;
    std::uint32_t lseekNr = 0;
    std::uint32_t mmapNr = 0;
    std::uint32_t munmapNr = 0;
    if (useDirectLinuxSyscalls(TT) &&
        linuxCleanCopySyscalls(TT, readlinkNr, lseekNr, mmapNr, munmapNr)) {
        emitLinuxSyscall(B, M, TT, munmapNr, {Addr, Size});
        return;
    }
    B.CreateCall(
        munmapDecl(M),
        {B.CreateIntToPtr(Addr, PointerType::getUnqual(M.getContext())), Size});
}

Value *emitLinuxMprotect(IRBuilder<> &B, Module &M, const Triple &TT,
                         Value *Addr, Value *Size, Value *Prot) {
    std::uint32_t mprotectNr = 0;
    if (TT.getArch() == Triple::x86_64)
        mprotectNr = 10;
    if (useDirectLinuxSyscalls(TT) && mprotectNr != 0)
        return B.CreateTruncOrBitCast(
            emitLinuxSyscall(B, M, TT, mprotectNr, {Addr, Size, Prot}),
            Type::getInt32Ty(M.getContext()));

    auto *i32 = Type::getInt32Ty(M.getContext());
    auto *ptr = PointerType::getUnqual(M.getContext());
    return B.CreateCall(mprotectDecl(M), {B.CreateIntToPtr(Addr, ptr), Size,
                                          B.CreateTruncOrBitCast(Prot, i32)});
}

Value *emitDarwinMprotect(IRBuilder<> &B, Module &M, const Triple &TT,
                          Value *Addr, Value *Size, Value *Prot) {
    auto *i32 = Type::getInt32Ty(M.getContext());
    if (useDirectDarwinSyscalls(TT))
        return B.CreateTruncOrBitCast(
            emitDarwinSyscall(B, M, TT, 74, {Addr, Size, Prot}), i32);

    auto *ptr = PointerType::getUnqual(M.getContext());
    return B.CreateCall(mprotectDecl(M), {B.CreateIntToPtr(Addr, ptr), Size,
                                          B.CreateTruncOrBitCast(Prot, i32)});
}

void emitLinuxClose(IRBuilder<> &B, Module &M, const Triple &TT, Value *Fd) {
    std::uint32_t ptraceNr = 0;
    std::uint32_t prctlNr = 0;
    std::uint32_t openatNr = 0;
    std::uint32_t readNr = 0;
    std::uint32_t closeNr = 0;
    if (linuxCoreSyscalls(TT, ptraceNr, prctlNr, openatNr, readNr, closeNr)) {
        emitLinuxSyscall(B, M, TT, closeNr, {Fd});
        return;
    }
    B.CreateCall(closeDecl(M), {B.CreateTruncOrBitCast(
                                   Fd, Type::getInt32Ty(M.getContext()))});
}

Value *emitDarwinOpen(IRBuilder<> &B, Module &M, const Triple &TT, Value *Path,
                      std::int32_t Flags, std::int32_t Mode) {
    auto *i32 = Type::getInt32Ty(M.getContext());
    if (useDirectDarwinSyscalls(TT))
        return B.CreateTruncOrBitCast(
            emitDarwinSyscall(B, M, TT, 5,
                              {Path, ConstantInt::getSigned(i32, Flags),
                               ConstantInt::getSigned(i32, Mode)}),
            i32);
    return B.CreateCall(openDecl(M),
                        {Path, ConstantInt::getSigned(i32, Flags),
                         ConstantInt::getSigned(i32, Mode)},
                        "morok.clean.open");
}

void emitDarwinClose(IRBuilder<> &B, Module &M, const Triple &TT, Value *Fd) {
    if (useDirectDarwinSyscalls(TT)) {
        emitDarwinSyscall(B, M, TT, 6, {Fd});
        return;
    }
    B.CreateCall(closeDecl(M), {B.CreateTruncOrBitCast(
                                   Fd, Type::getInt32Ty(M.getContext()))});
}

Value *emitDarwinLseek(IRBuilder<> &B, Module &M, const Triple &TT, Value *Fd,
                       std::int64_t Offset, std::int32_t Whence) {
    auto *i32 = Type::getInt32Ty(M.getContext());
    if (useDirectDarwinSyscalls(TT))
        return emitDarwinSyscall(B, M, TT, 199,
                                 {Fd, constSignedIp(M, Offset),
                                  ConstantInt::getSigned(i32, Whence)});
    return B.CreateCall(lseekDecl(M),
                        {B.CreateTruncOrBitCast(Fd, i32),
                         constSignedIp(M, Offset),
                         ConstantInt::getSigned(i32, Whence)},
                        "morok.clean.lseek");
}

Value *emitDarwinMmap(IRBuilder<> &B, Module &M, const Triple &TT, Value *Size,
                      Value *Fd) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);
    constexpr std::uint32_t kProtRead = 1;
    constexpr std::uint32_t kMapPrivate = 2;

    if (useDirectDarwinSyscalls(TT)) {
        Value *addr = emitDarwinSyscall(B, M, TT, 197,
                                        {ConstantPointerNull::get(ptr), Size,
                                         ConstantInt::get(i32, kProtRead),
                                         ConstantInt::get(i32, kMapPrivate), Fd,
                                         ConstantInt::get(ip, 0)});
        return B.CreateIntToPtr(addr, ptr, "morok.clean.mmap.ptr");
    }

    return B.CreateCall(
        mmapDecl(M),
        {ConstantPointerNull::get(ptr), Size, ConstantInt::get(i32, kProtRead),
         ConstantInt::get(i32, kMapPrivate), B.CreateTruncOrBitCast(Fd, i32),
         ConstantInt::get(ip, 0)},
        "morok.clean.mmap");
}

void emitDarwinMunmap(IRBuilder<> &B, Module &M, const Triple &TT,
                      Value *Mapped, Value *Size) {
    if (useDirectDarwinSyscalls(TT)) {
        emitDarwinSyscall(B, M, TT, 73, {Mapped, Size});
        return;
    }
    B.CreateCall(munmapDecl(M), {Mapped, Size});
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
    if (!useDirectLinuxSyscalls(TT) ||
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
    auto *scanInitBB = BasicBlock::Create(ctx, "scan.init", fn);
    auto *scanBB = BasicBlock::Create(ctx, "scan", fn);
    auto *scanBodyBB = BasicBlock::Create(ctx, "scan.body", fn);
    auto *scanNextBB = BasicBlock::Create(ctx, "scan.next", fn);
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
    B.CreateCondBr(pathOk, scanInitBB, retBB);

    IRBuilder<> SIB(scanInitBB);
    Value *scanEnough = SIB.CreateICmpUGE(
        pathLen, ConstantInt::get(ip, 6), "morok.antidbg.memfd.scan.enough");
    SIB.CreateCondBr(scanEnough, scanBB, openBB);

    IRBuilder<> SB(scanBB);
    auto *scanIdx = SB.CreatePHI(ip, 2, "morok.antidbg.memfd.scan.idx");
    scanIdx->addIncoming(ConstantInt::get(ip, 0), scanInitBB);
    Value *last = SB.CreateSub(pathLen, ConstantInt::get(ip, 6),
                               "morok.antidbg.memfd.scan.last");
    Value *scanRange =
        SB.CreateICmpULE(scanIdx, last, "morok.antidbg.memfd.scan.range");
    SB.CreateCondBr(scanRange, scanBodyBB, openBB);

    IRBuilder<> SBB(scanBodyBB);
    constexpr std::array<unsigned char, 6> marker = {'m', 'e', 'm',
                                                     'f', 'd', ':'};
    Value *match = ConstantInt::get(i1, true);
    for (std::uint32_t i = 0; i < marker.size(); ++i) {
        Value *off = SBB.CreateAdd(scanIdx, ConstantInt::get(ip, i));
        Value *ch = SBB.CreateLoad(i8, gepI8(SBB, M, pathBuf, off,
                                             "morok.antidbg.memfd.scan.ch"));
        Value *eq = SBB.CreateICmpEQ(ch, ConstantInt::get(i8, marker[i]));
        match = SBB.CreateAnd(match, eq);
    }
    SBB.CreateCondBr(match, retBB, scanNextBB);

    IRBuilder<> SNB(scanNextBB);
    Value *scanNext = SNB.CreateAdd(scanIdx, ConstantInt::get(ip, 1),
                                    "morok.antidbg.memfd.scan.next");
    SNB.CreateBr(scanBB);
    scanIdx->addIncoming(scanNext, scanNextBB);

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
                           const Triple &TT, bool AllowSelfTrace) {
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
    if (watchBuddy)
        LB.CreateBr(bodyBB);
    else
        LB.CreateCondBr(LB.CreateICmpULT(iter, ConstantInt::get(i32, 8)), bodyBB,
                        retBB);

    IRBuilder<> BB(bodyBB);
    FunctionCallee sleepFn =
        M.getOrInsertFunction("sleep", FunctionType::get(i32, {i32}, false));
    BB.CreateCall(sleepFn, {ConstantInt::get(i32, 1)});
    if (AllowSelfTrace)
        emitLinuxPtrace(BB, M, TT, 0);
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
        CB.CreateCondBr(CB.CreateICmpSGT(pid, ConstantInt::get(ip, 1)),
                        buddyLiveBB, nextBB);

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
        foldFlag(BuddyB, State, missing, 0xDF0E7318A649C2B5ULL,
                 "morok.antidbg.buddy.missing");
        foldState(BuddyB, State, waitRc, 0x5B47E91D2C806A3FULL,
                  "morok.antidbg.buddy.wait");
        BuddyB.CreateBr(nextBB);

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
    LB.CreateBr(bodyBB);

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
                              GlobalVariable *BuddyPid, ir::IRRandom &rng,
                              const Triple &TT) {
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
    if (!helper || !BuddyPid)
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
    ChildB.CreateCall(helper->getFunctionType(), helper, {});
    emitLinuxSyscall(ChildB, M, TT, exitNr, {ConstantInt::get(ip, 0)});
    ChildB.CreateUnreachable();

    IRBuilder<> ParentB(parentBB);
    auto *buddyStore = ParentB.CreateStore(pid, BuddyPid);
    buddyStore->setVolatile(true);
    ParentB.CreateCondBr(ParentB.CreateICmpSGT(pid, ConstantInt::get(ip, 0)),
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
    foldState(PB, State, prctlRc, 0x419C75EF62D3A80BULL,
              "morok.antidbg.dr.ptracer");
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

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i16 = Type::getInt16Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);

    constexpr std::uint16_t kBpfLdWAbs = 0x20;
    constexpr std::uint16_t kBpfJmpJeqK = 0x15;
    constexpr std::uint16_t kBpfRetK = 0x06;
    constexpr std::uint32_t kSeccompDataNr = 0;
    constexpr std::uint32_t kSeccompRetKillProcess = 0x80000000U;
    constexpr std::uint32_t kSeccompRetAllow = 0x7fff0000U;
    constexpr std::uint32_t kPrSetSeccomp = 22;
    constexpr std::uint32_t kSeccompModeFilter = 2;

    auto *filterTy = StructType::get(ctx, {i16, i8, i8, i32});
    auto *filtersTy = ArrayType::get(filterTy, 10);
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

    storeFilter(0, kBpfLdWAbs, 0, 0, kSeccompDataNr);
    if (AllowSelfTrace) {
        constexpr std::uint32_t kSeccompDataArg0 = 16;
        constexpr std::uint32_t kPtraceTraceme = 0;
        storeFilter(1, kBpfJmpJeqK, 0, 3, ptraceNr);
        storeFilter(2, kBpfLdWAbs, 0, 0, kSeccompDataArg0);
        storeFilter(3, kBpfJmpJeqK, 5, 0, kPtraceTraceme);
        storeFilter(4, kBpfRetK, 0, 0, kSeccompRetKillProcess);
        storeFilter(5, kBpfLdWAbs, 0, 0, kSeccompDataNr);
        storeFilter(6, kBpfJmpJeqK, 1, 0, readvNr);
        storeFilter(7, kBpfJmpJeqK, 0, 1, writevNr);
        storeFilter(8, kBpfRetK, 0, 0, kSeccompRetKillProcess);
    } else {
        storeFilter(1, kBpfJmpJeqK, 6, 0, ptraceNr);
        storeFilter(2, kBpfJmpJeqK, 5, 0, readvNr);
        storeFilter(3, kBpfJmpJeqK, 4, 0, writevNr);
        storeFilter(4, kBpfRetK, 0, 0, kSeccompRetAllow);
        storeFilter(5, kBpfRetK, 0, 0, kSeccompRetAllow);
        storeFilter(6, kBpfRetK, 0, 0, kSeccompRetAllow);
        storeFilter(7, kBpfRetK, 0, 0, kSeccompRetAllow);
        storeFilter(8, kBpfRetK, 0, 0, kSeccompRetKillProcess);
    }
    storeFilter(9, kBpfRetK, 0, 0, kSeccompRetAllow);

    Value *filterPtr = B.CreateInBoundsGEP(
        filtersTy, filters, {ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)});
    B.CreateStore(ConstantInt::get(i16, 10),
                  B.CreateStructGEP(progTy, prog, 0));
    B.CreateStore(filterPtr, B.CreateStructGEP(progTy, prog, 1));

    std::uint32_t corePtraceNr = 0;
    std::uint32_t prctlNr = 0;
    std::uint32_t openatNr = 0;
    std::uint32_t readNrCore = 0;
    std::uint32_t closeNrCore = 0;
    if (linuxCoreSyscalls(TT, corePtraceNr, prctlNr, openatNr, readNrCore,
                          closeNrCore)) {
        emitLinuxSyscall(B, M, TT, prctlNr,
                         {ConstantInt::get(ip, kPrSetSeccomp),
                          ConstantInt::get(ip, kSeccompModeFilter), prog,
                          ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)});
    } else {
        FunctionCallee prctl = M.getOrInsertFunction(
            "prctl", FunctionType::get(i32, {i32, ip, ip, ip, ip}, false));
        B.CreateCall(prctl, {ConstantInt::get(i32, kPrSetSeccomp),
                             ConstantInt::get(ip, kSeccompModeFilter),
                             B.CreatePtrToInt(prog, ip),
                             ConstantInt::get(ip, 0), ConstantInt::get(ip, 0)});
    }
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
    LB.CreateBr(bodyBB);

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
    Value *beat = BB.CreateXor(
        BB.CreateAdd(BB.CreateMul(oldBeat, ConstantInt::get(i64, beatMul)), tag),
        ConstantInt::get(i64, beatSalt), "morok.watchdog.heartbeat.beat");
    auto *beatStore = BB.CreateStore(beat, Heartbeat);
    beatStore->setVolatile(true);
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
    EB.CreateBr(loopBB);

    IRBuilder<> LB(loopBB);
    auto *iter = LB.CreatePHI(i32, 2, "morok.watchdog.heartbeat.iter");
    auto *last = LB.CreatePHI(i64, 2, "morok.watchdog.heartbeat.last");
    auto *staleCount = LB.CreatePHI(i32, 2, "morok.watchdog.heartbeat.stale");
    iter->addIncoming(ConstantInt::get(i32, 0), entry);
    last->addIncoming(ConstantInt::get(i64, 0), entry);
    staleCount->addIncoming(ConstantInt::get(i32, 0), entry);
    LB.CreateBr(bodyBB);

    IRBuilder<> BB(bodyBB);
    FunctionCallee sleepFn =
        M.getOrInsertFunction("sleep", FunctionType::get(i32, {i32}, false));
    Value *cadence = BB.CreateAdd(
        BB.CreateAnd(BB.CreateAdd(BB.CreateMul(iter, ConstantInt::get(i32, cadenceMul)),
                                  ConstantInt::get(i32, cadenceAdd)),
                     ConstantInt::get(i32, 3)),
        ConstantInt::get(i32, 2), "morok.watchdog.heartbeat.cadence");
    BB.CreateCall(sleepFn, {cadence});
    auto *cur = BB.CreateLoad(i64, Heartbeat, "morok.watchdog.heartbeat.cur");
    cur->setVolatile(true);
    Value *armed =
        BB.CreateICmpNE(last, ConstantInt::get(i64, 0), "morok.watchdog.armed");
    Value *stale = BB.CreateAnd(armed, BB.CreateICmpEQ(cur, last),
                                "morok.watchdog.heartbeat.same");
    Value *staleNext = BB.CreateSelect(
        stale, BB.CreateAdd(staleCount, ConstantInt::get(i32, 1)),
        ConstantInt::get(i32, 0), "morok.watchdog.heartbeat.stale.next");
    Value *missing = BB.CreateICmpUGE(staleNext, ConstantInt::get(i32, 2),
                                      "morok.watchdog.heartbeat.missing");
    foldState(BB, State, cur, 0x35A8F179C46D20B3ULL,
              "morok.watchdog.heartbeat.sample");
    foldFlag(BB, State, missing, 0xC7D2841AF09B53E6ULL,
             "morok.watchdog.heartbeat.missing");
    auto *cryptoOld =
        BB.CreateLoad(i64, Crypto, "morok.watchdog.crypto.old");
    cryptoOld->setVolatile(true);
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
                        bool AllowSelfTrace) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    IRBuilder<> B(&Ctor->getEntryBlock());

    GlobalVariable *buddyPid = antiDebugBuddyPid(M);
    bool drSentinel = emitLinuxDrSentinelStart(B, M, State, buddyPid, rng, TT);
    if (!drSentinel)
        buddyPid = nullptr;
    emitLinuxHardening(B, M, TT, drSentinel);
    if (AllowSelfTrace && !drSentinel) {
        Value *traceRc = emitLinuxPtrace(B, M, TT, 0);
        foldFlag(B, State,
                 B.CreateICmpSLT(traceRc, ConstantInt::getSigned(i32, 0)),
                 0x3D2D7F2BAE63D5C9ULL, "morok.antidbg.ptrace.init");
    }

    Function *statusFn = linuxStatusTracerCheck(M, rng, TT);
    Function *statFn = linuxStatField4Check(M, rng, TT);
    Value *status = B.CreateCall(statusFn);
    Value *stat4 = B.CreateCall(statFn);
    foldFlag(B, State, B.CreateICmpNE(status, ConstantInt::get(i32, 0)),
             0xA4756E49F2D31219ULL, "morok.antidbg.status");
    foldState(B, State, stat4, 0xDA942042E4DD58B5ULL, "morok.antidbg.stat4");
    emitLinuxLandlockSandbox(B, M, State, TT);
    emitLinuxSeccompFilter(B, M, TT, AllowSelfTrace && !drSentinel);

    Function *watch = linuxWatchThread(M, statusFn, statFn, State, buddyPid, TT,
                                       AllowSelfTrace && !drSentinel);
    emitLinuxWatcherStart(B, M, watch);
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
    foldFlag(B, State, B.CreateAnd(ok, traced), 0xBD6A33A5F07A4E31ULL,
             "morok.antidbg.sysctl");
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
    foldFlag(B, State, B.CreateAnd(ok, debugged), 0xF1D88C6C72195307ULL,
             "morok.antidbg.csops");
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
    }
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
                         ir::IRRandom &rng, const Triple &TT) {
    IRBuilder<> B(&Ctor->getEntryBlock());
    emitDarwinPtrace(B, M, TT, 31); // PT_DENY_ATTACH
    emitDarwinSysctlCheck(B, M, State, TT);
    emitDarwinCsopsCheck(B, M, State, TT);
    emitDarwinDyldCensus(B, M, State, rng);
    if (Function *drWatch = darwinDrWatchThread(M, TT))
        emitLinuxWatcherStart(B, M, drWatch);
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
    auto *i16 = Type::getInt16Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
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
    auto *mapInitBB = BasicBlock::Create(ctx, "map.init", fn);
    auto *mapFirstBB = BasicBlock::Create(ctx, "map.first", fn);
    auto *mapLoopBB = BasicBlock::Create(ctx, "map.loop", fn);
    auto *mapBodyBB = BasicBlock::Create(ctx, "map.body", fn);
    auto *mapHeaderBB = BasicBlock::Create(ctx, "map.header", fn);
    auto *mapPhInitBB = BasicBlock::Create(ctx, "map.ph.init", fn);
    auto *mapPhLoopBB = BasicBlock::Create(ctx, "map.ph.loop", fn);
    auto *mapPhBodyBB = BasicBlock::Create(ctx, "map.ph.body", fn);
    auto *mapPhNextBB = BasicBlock::Create(ctx, "map.ph.next", fn);
    auto *mapNextBB = BasicBlock::Create(ctx, "map.next", fn);
    auto *ret1BB = BasicBlock::Create(ctx, "ret1", fn);
    auto *ret0BB = BasicBlock::Create(ctx, "ret0", fn);

    IRBuilder<> EB(entry);
    Value *hasSelfPhdr =
        EB.CreateAnd(EB.CreateICmpNE(atPhdr, ConstantInt::get(ip, 0)),
                     EB.CreateICmpUGE(phEnt, ConstantInt::get(ip, 56)),
                     "morok.antihook.got.self.phdr");
    EB.CreateCondBr(hasSelfPhdr, selfLoopBB, mapInitBB);

    IRBuilder<> SLB(selfLoopBB);
    auto *selfIdx = SLB.CreatePHI(ip, 2, "morok.antihook.got.self.idx");
    selfIdx->addIncoming(ConstantInt::get(ip, 0), entry);
    Value *selfInRange =
        SLB.CreateAnd(SLB.CreateICmpULT(selfIdx, phNum),
                      SLB.CreateICmpULT(selfIdx, ConstantInt::get(ip, 128)));
    SLB.CreateCondBr(selfInRange, selfBodyBB, mapInitBB);

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

    IRBuilder<> MIB(mapInitBB);
    MIB.CreateCondBr(MIB.CreateICmpNE(debug, ConstantPointerNull::get(ptr)),
                     mapFirstBB, ret0BB);

    IRBuilder<> MFB(mapFirstBB);
    Value *initialMap =
        MFB.CreateLoad(ptr,
                       gepI8(MFB, M, debug, ConstantInt::get(ip, 8),
                             "morok.antihook.got.rdebug.map"),
                       "morok.antihook.got.map.first");
    MFB.CreateBr(mapLoopBB);

    IRBuilder<> MLB(mapLoopBB);
    auto *map = MLB.CreatePHI(ptr, 2, "morok.antihook.got.map");
    auto *mapCount = MLB.CreatePHI(ip, 2, "morok.antihook.got.map.count");
    map->addIncoming(initialMap, mapFirstBB);
    mapCount->addIncoming(ConstantInt::get(ip, 0), mapFirstBB);
    Value *mapActive =
        MLB.CreateAnd(MLB.CreateICmpNE(map, ConstantPointerNull::get(ptr)),
                      MLB.CreateICmpULT(mapCount, ConstantInt::get(ip, 64)),
                      "morok.antihook.got.map.active");
    MLB.CreateCondBr(mapActive, mapBodyBB, ret0BB);

    IRBuilder<> MBB(mapBodyBB);
    Value *mapBase =
        loadAt(MBB, M, ip, map, 0ULL, "morok.antihook.got.map.base");
    Value *nextMap = MBB.CreateLoad(ptr,
                                    gepI8(MBB, M, map, ConstantInt::get(ip, 24),
                                          "morok.antihook.got.map.next.ptr"),
                                    "morok.antihook.got.map.next");
    MBB.CreateCondBr(MBB.CreateICmpNE(mapBase, ConstantInt::get(ip, 0)),
                     mapHeaderBB, mapNextBB);

    IRBuilder<> MHB(mapHeaderBB);
    Value *mapHdr =
        MHB.CreateIntToPtr(mapBase, ptr, "morok.antihook.got.map.hdr");
    Value *magic =
        loadAt(MHB, M, i32, mapHdr, 0ULL, "morok.antihook.got.map.magic");
    MHB.CreateCondBr(MHB.CreateICmpEQ(magic, ConstantInt::get(i32, 0x464C457F)),
                     mapPhInitBB, mapNextBB);

    IRBuilder<> MPIB(mapPhInitBB);
    Value *mapPhOff =
        loadAt(MPIB, M, i64, mapHdr, 32, "morok.antihook.got.map.phoff");
    Value *mapPhEntRaw =
        loadAt(MPIB, M, i16, mapHdr, 54, "morok.antihook.got.map.phentsize");
    Value *mapPhNumRaw =
        loadAt(MPIB, M, i16, mapHdr, 56, "morok.antihook.got.map.phnum");
    Value *mapPhEnt =
        MPIB.CreateZExt(mapPhEntRaw, ip, "morok.antihook.got.map.phent");
    Value *mapPhNum =
        MPIB.CreateZExt(mapPhNumRaw, ip, "morok.antihook.got.map.phnum.w");
    Value *mapPhValid =
        MPIB.CreateAnd(MPIB.CreateICmpUGE(mapPhEnt, ConstantInt::get(ip, 56)),
                       MPIB.CreateICmpUGT(mapPhNum, ConstantInt::get(ip, 0)),
                       "morok.antihook.got.map.ph.valid");
    MPIB.CreateCondBr(mapPhValid, mapPhLoopBB, mapNextBB);

    IRBuilder<> MPLB(mapPhLoopBB);
    auto *mapPhIdx = MPLB.CreatePHI(ip, 2, "morok.antihook.got.map.ph.idx");
    mapPhIdx->addIncoming(ConstantInt::get(ip, 0), mapPhInitBB);
    Value *mapPhInRange =
        MPLB.CreateAnd(MPLB.CreateICmpULT(mapPhIdx, mapPhNum),
                       MPLB.CreateICmpULT(mapPhIdx, ConstantInt::get(ip, 128)));
    MPLB.CreateCondBr(mapPhInRange, mapPhBodyBB, mapNextBB);

    IRBuilder<> MPBB(mapPhBodyBB);
    Value *mapPhPtr = MPBB.CreateIntToPtr(
        MPBB.CreateAdd(
            mapBase,
            MPBB.CreateAdd(mapPhOff, MPBB.CreateMul(mapPhIdx, mapPhEnt))),
        ptr, "morok.antihook.got.map.ph");
    MPBB.CreateCondBr(emitElfExecSegmentHit(MPBB, M, target, mapBase, mapPhPtr,
                                            "morok.antihook.got.map.seg"),
                      ret1BB, mapPhNextBB);

    IRBuilder<> MPNB(mapPhNextBB);
    Value *mapPhNext = MPNB.CreateAdd(mapPhIdx, ConstantInt::get(ip, 1),
                                      "morok.antihook.got.map.ph.next");
    MPNB.CreateBr(mapPhLoopBB);
    mapPhIdx->addIncoming(mapPhNext, mapPhNextBB);

    IRBuilder<> MNB(mapNextBB);
    Value *nextMapCount = MNB.CreateAdd(mapCount, ConstantInt::get(ip, 1),
                                        "morok.antihook.got.map.count.next");
    MNB.CreateBr(mapLoopBB);
    map->addIncoming(nextMap, mapNextBB);
    mapCount->addIncoming(nextMapCount, mapNextBB);

    IRBuilder<> R1(ret1BB);
    R1.CreateRet(ConstantInt::get(i32, 1));

    IRBuilder<> R0(ret0BB);
    R0.CreateRet(ConstantInt::get(i32, 0));
    return fn;
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
          jmpRelSlot, pltRelSzSlot, pltRelSlot, debugSlot, bindNowSlot,
          flagsSlot, flags1Slot})
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
                      RPB.CreateOr(isRela, isRel)),
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
    incrementDiff(
        RBB, diff,
        RBB.CreateICmpEQ(rxOk, ConstantInt::get(Type::getInt32Ty(ctx), 0)),
        "morok.antihook.got.violation");

    Value *relroV =
        RBB.CreateLoad(ip, relroVaddrSlot, "morok.antihook.got.relro.v");
    Value *relroSize =
        RBB.CreateLoad(ip, relroMemszSlot, "morok.antihook.got.relro.sz");
    Value *relroStart =
        RBB.CreateAdd(base, relroV, "morok.antihook.got.relro.start");
    Value *relroEnd =
        RBB.CreateAdd(relroStart, relroSize, "morok.antihook.got.relro.end");
    Value *slotInRelro = RBB.CreateAnd(
        RBB.CreateAnd(hasNow,
                      RBB.CreateICmpNE(relroV, ConstantInt::get(ip, 0))),
        RBB.CreateAnd(RBB.CreateICmpUGE(slotAddr, relroStart),
                      RBB.CreateICmpULT(slotAddr, relroEnd)),
        "morok.antihook.got.protect");
    RBB.CreateCondBr(slotInRelro, protectBB, relNextBB);

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
    Value *validImage = IBB.CreateAnd(
        IBB.CreateICmpNE(hdr, ConstantPointerNull::get(ptr)),
        IBB.CreateICmpEQ(magic, ConstantInt::get(i32, 0xFEEDFACF)));
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
    Function *textCheck = darwinTextTargetInDyldImages(M);

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
    auto *entryNextBB = BasicBlock::Create(ctx, "entry.next", fn);
    auto *secNextBB = BasicBlock::Create(ctx, "section.next", fn);
    auto *cmdNextBB = BasicBlock::Create(ctx, "cmd.next", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    AllocaInst *diff =
        B.CreateAlloca(i64, nullptr, "morok.antihook.macho.fixup.diff");
    B.CreateStore(ConstantInt::get(i64, 0), diff)->setVolatile(true);
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
    Value *textOk =
        ECB.CreateCall(textCheck, {targetAddr}, "morok.antihook.fixup.text");
    incrementDiff(
        ECB, diff,
        ECB.CreateICmpEQ(textOk, ConstantInt::get(Type::getInt32Ty(ctx), 0)),
        "morok.antihook.fixup.violation");
    ECB.CreateBr(entryNextBB);

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
    auto *ptr = PointerType::getUnqual(ctx);

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
    auto *bufTy = ArrayType::get(i8, 8192);
    AllocaInst *buf = B.CreateAlloca(bufTy, nullptr, "morok.antihook.maps.buf");
    AllocaInst *diff =
        B.CreateAlloca(i64, nullptr, "morok.antihook.maps.diff");
    B.CreateStore(ConstantInt::get(i64, 0), diff)->setVolatile(true);
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
            {fdLong, bufPtr, ConstantInt::get(ip, 8192)});
    } else {
        nread = OB.CreateCall(readDecl(M),
                              {OB.CreateTruncOrBitCast(fdLong, i32), bufPtr,
                               ConstantInt::get(ip, 8192)});
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

    IRBuilder<> EB(envBB);
    FunctionCallee getenv =
        M.getOrInsertFunction("getenv", FunctionType::get(ptr, {ptr}, false));
    Value *ldPreload = ir::emitCloakedSymbol(EB, M, "LD_PRELOAD", rng);
    Value *ldAudit = ir::emitCloakedSymbol(EB, M, "LD_AUDIT", rng);
    Value *preload = EB.CreateICmpNE(EB.CreateCall(getenv, {ldPreload}),
                                     ConstantPointerNull::get(ptr));
    Value *audit = EB.CreateICmpNE(EB.CreateCall(getenv, {ldAudit}),
                                   ConstantPointerNull::get(ptr));
    incrementDiff(EB, diff, preload, "morok.antihook.maps.preload");
    incrementDiff(EB, diff, audit, "morok.antihook.maps.audit");
    EB.CreateBr(retBB);

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
    FunctionCallee returnAddress = M.getOrInsertFunction(
        "llvm.returnaddress.p0", FunctionType::get(ptr, {i32}, false));
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
        foldFlag(B, State, B.CreateICmpEQ(ok, ConstantInt::get(i32, 0)),
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
    const bool linux = useDirectLinuxSyscalls(TT);
    const bool darwin = useDirectDarwinSyscalls(TT);
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
    }

    auto *out = B.CreateLoad(i64, score, "morok.antihook.sandbox.score.ret");
    out->setVolatile(true);
    B.CreateRet(out);
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
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> B(entry);
    AllocaInst *diff = B.CreateAlloca(i64, nullptr, "morok.antihook.dbi.smc.diff");
    B.CreateStore(ConstantInt::get(i64, 0), diff)->setVolatile(true);
    auto *gate = B.CreateLoad(i8, dbiSmcGate(M), "morok.antihook.dbi.smc.load");
    gate->setVolatile(true);
    B.CreateCondBr(B.CreateICmpNE(gate, ConstantInt::get(i8, 0),
                                  "morok.antihook.dbi.smc.armed"),
                   hotBB, retBB);

    IRBuilder<> HB(hotBB);
    Value *targetAddr = HB.CreatePtrToInt(target, ip, "morok.antihook.dbi.smc.addr");
    Value *page = HB.CreateAnd(targetAddr, ConstantInt::get(ip, ~0xfffULL),
                               "morok.antihook.dbi.smc.page");
    Value *codePtr = HB.CreateIntToPtr(targetAddr, ptr, "morok.antihook.dbi.smc.ptr");
    if (TT.isOSLinux()) {
        Value *rc = emitLinuxMprotect(HB, M, TT, page, ConstantInt::get(ip, 4096),
                                      ConstantInt::get(i32, 7));
        rc->setName("morok.antihook.dbi.smc.mprotect.rwx");
    } else if (TT.isOSDarwin()) {
        Value *rc = emitDarwinMprotect(HB, M, TT, page, ConstantInt::get(ip, 4096),
                                       ConstantInt::get(i32, 7));
        rc->setName("morok.antihook.dbi.smc.mprotect.rwx");
    } else if (TT.isOSWindows()) {
        auto *oldProt = HB.CreateAlloca(i32, nullptr, "morok.antihook.dbi.smc.old");
        FunctionCallee virtualProtect = M.getOrInsertFunction(
            "VirtualProtect", FunctionType::get(i32, {ptr, ip, i32, ptr}, false));
        HB.CreateCall(virtualProtect,
                      {HB.CreateIntToPtr(page, ptr), ConstantInt::get(ip, 4096),
                       ConstantInt::get(i32, 0x40), oldProt},
                      "morok.antihook.dbi.smc.virtualprotect.rwx");
    }

    auto *oldByte = HB.CreateLoad(i8, codePtr, "morok.antihook.dbi.smc.byte");
    oldByte->setVolatile(true);
    auto *touch = HB.CreateStore(oldByte, codePtr);
    touch->setVolatile(true);
    if (TT.isOSLinux()) {
        Value *rc = emitLinuxMprotect(HB, M, TT, page, ConstantInt::get(ip, 4096),
                                      ConstantInt::get(i32, 5));
        rc->setName("morok.antihook.dbi.smc.mprotect.rx");
    } else if (TT.isOSDarwin()) {
        Value *rc = emitDarwinMprotect(HB, M, TT, page, ConstantInt::get(ip, 4096),
                                       ConstantInt::get(i32, 5));
        rc->setName("morok.antihook.dbi.smc.mprotect.rx");
    } else if (TT.isOSWindows()) {
        auto *oldProt2 =
            HB.CreateAlloca(i32, nullptr, "morok.antihook.dbi.smc.old2");
        FunctionCallee virtualProtect = M.getOrInsertFunction(
            "VirtualProtect", FunctionType::get(i32, {ptr, ip, i32, ptr}, false));
        HB.CreateCall(virtualProtect,
                      {HB.CreateIntToPtr(page, ptr), ConstantInt::get(ip, 4096),
                       ConstantInt::get(i32, 0x20), oldProt2},
                      "morok.antihook.dbi.smc.virtualprotect.rx");
    }
    Value *result = HB.CreateCall(target, {}, "morok.antihook.dbi.smc.result");
    incrementDiff(HB, diff,
                  HB.CreateICmpNE(result, ConstantInt::get(i32, 0x13579BDFu),
                                  "morok.antihook.dbi.smc.trip"),
                  "morok.antihook.dbi.smc.trip");
    HB.CreateBr(retBB);

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
        foldFlag(B, State, hit, rng.next() ^ (0x9E3779B97F4A7C15ULL * site++),
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
    } else {
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
        if (!rng.chance(kFunctionChance))
            continue;

        std::vector<Instruction *> candidates;
        candidates.reserve(8);
        for (BasicBlock &BB : F) {
            if (BB.isEHPad() || BB.isLandingPad())
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

bool isX86Target(const Triple &TT) {
    return TT.getArch() == Triple::x86 || TT.getArch() == Triple::x86_64;
}

Value *emitRdtscp(IRBuilder<> &B, Module &M) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *pairTy = StructType::get(ctx, {i32, i32});
    auto *asmTy = FunctionType::get(pairTy, false);
    InlineAsm *rdtscp =
        InlineAsm::get(asmTy, "lfence\nrdtscp\nlfence",
                       "={eax},={edx},~{ecx},~{dirflag},~{fpsr},~{flags}",
                       /*hasSideEffects=*/true);
    Value *pair = B.CreateCall(asmTy, rdtscp, {}, "morok.timing.rdtscp");
    Value *lo = B.CreateExtractValue(pair, {0}, "morok.timing.tsc.lo");
    Value *hi = B.CreateExtractValue(pair, {1}, "morok.timing.tsc.hi");
    return B.CreateOr(
        B.CreateZExt(lo, i64),
        B.CreateShl(B.CreateZExt(hi, i64), ConstantInt::get(i64, 32)),
        "morok.timing.tsc");
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
    foldFlag(B, State, B.CreateICmpUGE(badSamples, ConstantInt::get(i32, 3)),
             0xA331D8B47E1C5905ULL, "morok.timing.bad.distribution");
    foldFlag(B, State,
             B.CreateICmpUGE(divergentSamples, ConstantInt::get(i32, 2)),
             0x5E74B29D13C8A60BULL, "morok.timing.divergent.distribution");
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
    const bool siginfo = useLinuxX86SiginfoTrapHandler(TT);
    SmallVector<Type *, 3> args{i32};
    if (siginfo) {
        args.push_back(ptr);
        args.push_back(ptr);
    }
    auto *fn = Function::Create(
        FunctionType::get(Type::getVoidTy(ctx), args, false),
        GlobalValue::PrivateLinkage, "morok.trap.handler", &M);
    fn->setDSOLocal(true);
    Argument *sig = fn->getArg(0);
    sig->setName("sig");
    Argument *uctx = siginfo ? fn->getArg(2) : nullptr;
    if (uctx)
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

    if (siginfo) {
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

FunctionCallee signalDecl(Module &M) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);
    return M.getOrInsertFunction("signal",
                                 FunctionType::get(ptr, {i32, ptr}, false));
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

void storeSiginfoAction(IRBuilder<> &B, Module &M, AllocaInst *Action,
                        Function *Handler) {
    auto *i32 = Type::getInt32Ty(M.getContext());
    constexpr std::uint64_t kSigactionSize = 152;
    constexpr std::uint64_t kFlagsOffset = 136;
    constexpr std::uint32_t kSaSiginfo = 4;

    zeroActionBytes(B, M, Action, kSigactionSize);
    B.CreateStore(Handler, gepI8(B, M, Action, constIp(M, 0),
                                 "morok.trap.sa.handler"));
    B.CreateStore(ConstantInt::get(i32, kSaSiginfo),
                  gepI8(B, M, Action, constIp(M, kFlagsOffset),
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
    if (isX86Target(TT)) {
        emitTrapInlineAsm(B, "int3", "~{dirflag},~{fpsr},~{flags}");
        emitTrapInlineAsm(B, ".byte 0xf1", "~{dirflag},~{fpsr},~{flags}");
        if (TT.getArch() == Triple::x86_64) {
            emitTrapInlineAsm(B,
                              "pushfq\npopq %rax\norq $$256, %rax\npushq "
                              "%rax\npopfq\nnop\npushfq\npopq %rax\nandq "
                              "$$-257, %rax\npushq %rax\npopfq",
                              "~{rax},~{dirflag},~{fpsr},~{flags}");
        } else {
            emitTrapInlineAsm(B,
                              "pushfl\npopl %eax\norl $$256, %eax\npushl "
                              "%eax\npopfl\nnop\npushfl\npopl %eax\nandl "
                              "$$-257, %eax\npushl %eax\npopfl",
                              "~{eax},~{dirflag},~{fpsr},~{flags}");
        }
        return 3;
    }

    FunctionCallee raiseFn = raiseDecl(M);
    for (unsigned i = 0; i < 3; ++i)
        B.CreateCall(raiseFn, {ConstantInt::get(i32, kSigTrap)});
    return 3;
}

} // namespace

bool antiDebuggingModule(Module &M, ir::IRRandom &rng, bool AllowSelfTrace) {
    const Triple tt(M.getTargetTriple());

    if (tt.isOSLinux())
        emitLinuxMemfdReexecCtor(M, rng, tt);

    Function *ctor = makeCtorShell(M, "morok.antidbg");
    GlobalVariable *state = antiDebugState(M, rng);
    if (tt.isOSLinux())
        emitLinuxAntiDebug(M, ctor, state, rng, tt, AllowSelfTrace);
    else if (tt.isOSDarwin())
        emitDarwinAntiDebug(M, ctor, state, rng, tt);
    else {
        IRBuilder<> B(&ctor->getEntryBlock());
        emitPtrace(B, M, 0);
        B.CreateRetVoid();
    }
    Function *probe = antiDebugProbe(M, state, rng, tt);
    insertAntiDebugCallsiteProbes(M, probe, rng);
    appendToGlobalCtors(M, ctor, 0);
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
    GlobalVariable *state = timingOracleState(M, rng);
    Function *oracle = timingOracleProbe(M, state, rng, tt);

    IRBuilder<> B(&ctor->getEntryBlock());
    B.CreateCall(oracle);
    B.CreateRetVoid();
    appendToGlobalCtors(M, ctor, 0);
    return true;
}

bool trapOracleModule(Module &M, ir::IRRandom &rng) {
    const Triple tt(M.getTargetTriple());
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    constexpr int kSigTrap = 5;

    Function *ctor = makeCtorShell(M, "morok.trap");
    GlobalVariable *state = trapOracleState(M, rng);
    GlobalVariable *counter = trapHitCounter(M);
    Function *handler = trapSignalHandler(M, counter, state, tt);

    IRBuilder<> B(&ctor->getEntryBlock());
    B.CreateStore(ConstantInt::get(i32, 0), counter)->setVolatile(true);

    Value *oldHandler = nullptr;
    AllocaInst *oldTrapAction = nullptr;
    AllocaInst *oldIllAction = nullptr;
    if (useLinuxX86SiginfoTrapHandler(tt)) {
        constexpr int kSigIll = 4;
        auto *actionTy = ArrayType::get(Type::getInt8Ty(ctx), 152);
        AllocaInst *newAction =
            B.CreateAlloca(actionTy, nullptr, "morok.trap.sa");
        oldTrapAction = B.CreateAlloca(actionTy, nullptr, "morok.trap.old.trap");
        oldIllAction = B.CreateAlloca(actionTy, nullptr, "morok.trap.old.ill");
        storeSiginfoAction(B, M, newAction, handler);
        FunctionCallee sigactionFn = sigactionDecl(M);
        B.CreateCall(sigactionFn,
                     {ConstantInt::get(i32, kSigTrap), newAction,
                      oldTrapAction},
                     "morok.trap.sigaction.trap");
        B.CreateCall(sigactionFn,
                     {ConstantInt::get(i32, kSigIll), newAction, oldIllAction},
                     "morok.trap.sigaction.ill");
    } else {
        oldHandler = B.CreateCall(
            signalDecl(M), {ConstantInt::get(i32, kSigTrap), handler},
            "morok.trap.old.handler");
    }

    unsigned expected = emitTrapStimuli(B, M, tt);
    auto *hits = B.CreateLoad(i32, counter, "morok.trap.hits.final");
    hits->setVolatile(true);
    foldState(B, state, hits, 0x91D0F736B52C48EAULL, "morok.trap.final");
    foldFlag(B, state, B.CreateICmpULT(hits, ConstantInt::get(i32, expected)),
             0xE2AB41739D08C6F5ULL, "morok.trap.missing");
    if (useLinuxX86SiginfoTrapHandler(tt)) {
        constexpr int kSigIll = 4;
        FunctionCallee sigactionFn = sigactionDecl(M);
        B.CreateCall(sigactionFn,
                     {ConstantInt::get(i32, kSigTrap), oldTrapAction,
                      ConstantPointerNull::get(PointerType::getUnqual(ctx))});
        B.CreateCall(sigactionFn,
                     {ConstantInt::get(i32, kSigIll), oldIllAction,
                      ConstantPointerNull::get(PointerType::getUnqual(ctx))});
    } else {
        B.CreateCall(signalDecl(M),
                     {ConstantInt::get(i32, kSigTrap), oldHandler});
    }
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
    if (Function *got = linuxGotPltProbe(M, tt)) {
        Value *diff = B.CreateCall(got, {}, "morok.antihook.got.diff");
        Value *changed =
            B.CreateICmpNE(diff, ConstantInt::get(B.getInt64Ty(), 0),
                           "morok.corroborate.got.changed");
        incrementDiff(B, corroboration, changed, "morok.corroborate.got");
        foldState(B, state, diff, 0xF93A8B7C62D514E1ULL, "morok.antihook.got");
        foldFlag(B, state, changed, 0xB17D4E23C9A5806FULL,
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
    if (Function *wx = wxEnforceProbe(M, tt)) {
        Value *diff = B.CreateCall(wx, {}, "morok.antihook.wxorx.diff");
        Value *changed =
            B.CreateICmpNE(diff, ConstantInt::get(B.getInt64Ty(), 0),
                           "morok.corroborate.wxorx.changed");
        incrementDiff(B, corroboration, changed, "morok.corroborate.wxorx");
        foldState(B, state, diff, 0x14E2B7C95A680D3FULL,
                  "morok.antihook.wxorx");
        foldFlag(B, state, changed, 0xD8F31C6A4B927E50ULL,
                 "morok.antihook.wxorx.changed");
    }
    if (Function *census = addressSpaceCensusProbe(M, rng, tt)) {
        Value *diff = B.CreateCall(census, {}, "morok.antihook.census.diff");
        Value *changed =
            B.CreateICmpNE(diff, ConstantInt::get(B.getInt64Ty(), 0),
                           "morok.corroborate.census.changed");
        incrementDiff(B, corroboration, changed, "morok.corroborate.census");
        foldState(B, state, diff, 0x6B4E9D718C2A35F0ULL,
                  "morok.antihook.census");
        changed->setName("morok.negative.modules.extra");
        foldFlag(B, state, changed,
                 0xA7815E3C49D206BFULL, "morok.antihook.census.changed");
        foldFlag(B, state, changed, 0xB2E746D9108CA53FULL,
                 "morok.negative.modules.extra");
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
        foldFlag(B, state, changed, 0xC58E90A37B42D16FULL,
                 "morok.antihook.diverge.changed");
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
        foldFlag(B, state, changed, 0x73B5D02E6C49A18FULL,
                 "morok.antihook.dbi.smc.changed");
    }
    if (Function *dbi = linuxDbiSignatureProbe(M, rng, tt)) {
        Value *diff = B.CreateCall(dbi, {}, "morok.antihook.dbi.diff");
        Value *changed =
            B.CreateICmpNE(diff, ConstantInt::get(B.getInt64Ty(), 0),
                           "morok.corroborate.dbi.changed");
        incrementDiff(B, corroboration, changed, "morok.corroborate.dbi");
        foldState(B, state, diff, 0x1B89E4C76F20DA53ULL,
                  "morok.antihook.dbi");
        foldFlag(B, state, changed, 0xF4A7812C39D60E5BULL,
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
        foldFlag(B, state, changed, 0x8A6357D1C49E20BFULL,
                 "morok.negative.timing.changed");
    }
    insertStackOriginChecks(M, stackOriginCheck(M), state, prologueTargets, rng);
    emitProloguePatternChecks(B, M, tt, state, prologueTargets, rng);

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
    // RTLD_DEFAULT == (void*)-2; build it at pointer width so inttoptr does not
    // zero-extend a 32-bit value into the wrong handle.
    auto *i64 = Type::getInt64Ty(ctx);
    Value *rtldDefault =
        DB.CreateIntToPtr(ConstantInt::getSigned(i64, -2), ptr);
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

PreservedAnalyses TimingOraclePass::run(Module &M, ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return timingOracleModule(M, rng) ? PreservedAnalyses::none()
                                      : PreservedAnalyses::all();
}

PreservedAnalyses TrapOraclePass::run(Module &M, ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return trapOracleModule(M, rng) ? PreservedAnalyses::none()
                                    : PreservedAnalyses::all();
}

} // namespace morok::passes
