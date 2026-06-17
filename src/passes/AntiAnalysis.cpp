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

Function *linuxWatchThread(Module &M, Function *StatusFn, Function *StatFn,
                           GlobalVariable *State, const Triple &TT) {
    if (Function *existing = M.getFunction("morok.antidbg.linux.watch"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);

    auto *fn = Function::Create(FunctionType::get(ptr, {ptr}, false),
                                GlobalValue::PrivateLinkage,
                                "morok.antidbg.linux.watch", &M);
    auto *entry = BasicBlock::Create(ctx, "entry", fn);
    auto *loopBB = BasicBlock::Create(ctx, "loop", fn);
    auto *bodyBB = BasicBlock::Create(ctx, "body", fn);
    auto *retBB = BasicBlock::Create(ctx, "ret", fn);

    IRBuilder<> EB(entry);
    EB.CreateBr(loopBB);

    IRBuilder<> LB(loopBB);
    auto *iter = LB.CreatePHI(i32, 2, "morok.antidbg.iter");
    iter->addIncoming(ConstantInt::get(i32, 0), entry);
    LB.CreateCondBr(LB.CreateICmpULT(iter, ConstantInt::get(i32, 8)), bodyBB,
                    retBB);

    IRBuilder<> BB(bodyBB);
    FunctionCallee sleepFn =
        M.getOrInsertFunction("sleep", FunctionType::get(i32, {i32}, false));
    BB.CreateCall(sleepFn, {ConstantInt::get(i32, 1)});
    emitLinuxPtrace(BB, M, TT, 0);
    Value *status = BB.CreateCall(StatusFn);
    Value *stat4 = BB.CreateCall(StatFn);
    foldFlag(BB, State, BB.CreateICmpNE(status, ConstantInt::get(i32, 0)),
             0x64C2D0B6D8F44A2DULL, "morok.antidbg.watch.status");
    foldState(BB, State, stat4, 0x8CB92BA72F3D8DD7ULL,
              "morok.antidbg.watch.stat4");
    Value *next = BB.CreateAdd(iter, ConstantInt::get(i32, 1));
    BB.CreateBr(loopBB);
    iter->addIncoming(next, bodyBB);

    IRBuilder<> RB(retBB);
    RB.CreateRet(ConstantPointerNull::get(ptr));
    return fn;
}

void emitLinuxHardening(IRBuilder<> &B, Module &M, const Triple &TT) {
    emitLinuxPrctl(B, M, TT, 4, 0, 0, 0, 0);          // PR_SET_DUMPABLE
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

void emitLinuxSeccompFilter(IRBuilder<> &B, Module &M, const Triple &TT) {
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
    constexpr std::uint32_t kSeccompDataArg0 = 16;
    constexpr std::uint32_t kSeccompRetKillProcess = 0x80000000U;
    constexpr std::uint32_t kSeccompRetAllow = 0x7fff0000U;
    constexpr std::uint32_t kPtraceTraceme = 0;
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
    storeFilter(1, kBpfJmpJeqK, 0, 3, ptraceNr);
    storeFilter(2, kBpfLdWAbs, 0, 0, kSeccompDataArg0);
    storeFilter(3, kBpfJmpJeqK, 5, 0, kPtraceTraceme);
    storeFilter(4, kBpfRetK, 0, 0, kSeccompRetKillProcess);
    storeFilter(5, kBpfLdWAbs, 0, 0, kSeccompDataNr);
    storeFilter(6, kBpfJmpJeqK, 1, 0, readvNr);
    storeFilter(7, kBpfJmpJeqK, 0, 1, writevNr);
    storeFilter(8, kBpfRetK, 0, 0, kSeccompRetKillProcess);
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

Function *probeWatchThread(Module &M, Function *Probe) {
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

    IRBuilder<> EB(entry);
    EB.CreateBr(loopBB);

    IRBuilder<> LB(loopBB);
    auto *iter = LB.CreatePHI(i32, 2, "morok.antidbg.probe.iter");
    iter->addIncoming(ConstantInt::get(i32, 0), entry);
    LB.CreateCondBr(LB.CreateICmpULT(iter, ConstantInt::get(i32, 8)), bodyBB,
                    retBB);

    IRBuilder<> BB(bodyBB);
    FunctionCallee sleepFn =
        M.getOrInsertFunction("sleep", FunctionType::get(i32, {i32}, false));
    BB.CreateCall(sleepFn, {ConstantInt::get(i32, 1)});
    Value *tag = BB.CreateAdd(BB.CreateZExt(iter, i64),
                              ConstantInt::get(i64, 0xD14B2E3520B47A11ULL),
                              "morok.antidbg.probe.watch.tag");
    BB.CreateCall(Probe->getFunctionType(), Probe, {tag});
    Value *next = BB.CreateAdd(iter, ConstantInt::get(i32, 1));
    BB.CreateBr(loopBB);
    iter->addIncoming(next, bodyBB);

    IRBuilder<> RB(retBB);
    RB.CreateRet(ConstantPointerNull::get(ptr));
    return fn;
}

void emitLinuxAntiDebug(Module &M, Function *Ctor, GlobalVariable *State,
                        ir::IRRandom &rng, const Triple &TT) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    IRBuilder<> B(&Ctor->getEntryBlock());

    emitLinuxHardening(B, M, TT);
    Value *traceRc = emitLinuxPtrace(B, M, TT, 0);
    foldFlag(B, State, B.CreateICmpSLT(traceRc, ConstantInt::getSigned(i32, 0)),
             0x3D2D7F2BAE63D5C9ULL, "morok.antidbg.ptrace.init");

    Function *statusFn = linuxStatusTracerCheck(M, rng, TT);
    Function *statFn = linuxStatField4Check(M, rng, TT);
    Value *status = B.CreateCall(statusFn);
    Value *stat4 = B.CreateCall(statFn);
    foldFlag(B, State, B.CreateICmpNE(status, ConstantInt::get(i32, 0)),
             0xA4756E49F2D31219ULL, "morok.antidbg.status");
    foldState(B, State, stat4, 0xDA942042E4DD58B5ULL, "morok.antidbg.stat4");
    emitLinuxLandlockSandbox(B, M, State, TT);
    emitLinuxSeccompFilter(B, M, TT);

    Function *watch = linuxWatchThread(M, statusFn, statFn, State, TT);
    emitLinuxWatcherStart(B, M, watch);
    B.CreateRetVoid();
}

void emitDarwinSysctlCheck(IRBuilder<> &B, Module &M, GlobalVariable *State) {
    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);

    FunctionCallee getpid =
        M.getOrInsertFunction("getpid", FunctionType::get(i32, false));
    FunctionCallee sysctl = M.getOrInsertFunction(
        "sysctl", FunctionType::get(i32, {ptr, i32, ptr, ptr, ptr, ip}, false));

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
    storeMib(3, B.CreateCall(getpid));

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
    Value *rc = B.CreateCall(sysctl, {mibPtr, ConstantInt::get(i32, 4), bufPtr,
                                      len, ConstantPointerNull::get(ptr),
                                      ConstantInt::get(ip, 0)});
    Value *pflag = B.CreateLoad(i32, pflagPtr);
    Value *traced =
        B.CreateICmpNE(B.CreateAnd(pflag, ConstantInt::get(i32, 0x800)),
                       ConstantInt::get(i32, 0));
    Value *ok = B.CreateICmpEQ(rc, ConstantInt::get(i32, 0));
    foldFlag(B, State, B.CreateAnd(ok, traced), 0xBD6A33A5F07A4E31ULL,
             "morok.antidbg.sysctl");
}

void emitDarwinCsopsCheck(IRBuilder<> &B, Module &M, GlobalVariable *State) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ip = intPtrTy(M);
    auto *ptr = PointerType::getUnqual(ctx);

    FunctionCallee getpid =
        M.getOrInsertFunction("getpid", FunctionType::get(i32, false));
    FunctionCallee csops = M.getOrInsertFunction(
        "csops", FunctionType::get(i32, {i32, i32, ptr, ip}, false));

    auto *status = B.CreateAlloca(i32, nullptr, "morok.antidbg.cs");
    B.CreateStore(ConstantInt::get(i32, 0), status);
    Value *rc =
        B.CreateCall(csops, {B.CreateCall(getpid), ConstantInt::get(i32, 0),
                             status, ConstantInt::get(ip, 4)});
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

void emitDarwinAntiDebug(Module &M, Function *Ctor, GlobalVariable *State,
                         ir::IRRandom &rng) {
    IRBuilder<> B(&Ctor->getEntryBlock());
    emitPtrace(B, M, 31); // PT_DENY_ATTACH
    emitDarwinSysctlCheck(B, M, State);
    emitDarwinCsopsCheck(B, M, State);
    emitDarwinDyldCensus(B, M, State, rng);
    B.CreateRetVoid();
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
        emitDarwinSysctlCheck(B, M, State);
        emitDarwinCsopsCheck(B, M, State);
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

Value *emitTimingPrimaryClock(IRBuilder<> &B, Module &M, const Triple &TT,
                              const Twine &Name) {
    if (isX86Target(TT))
        return emitRdtscp(B, M);
    if (TT.isOSDarwin())
        return emitMachAbsoluteTime(B, M, Name + ".mach");
    return emitClockGettimeNanos(B, M, 1, Name + ".mono");
}

Value *emitTimingSecondaryClock(IRBuilder<> &B, Module &M, const Triple &TT,
                                const Twine &Name) {
    if (TT.isOSDarwin() && isX86Target(TT))
        return emitMachAbsoluteTime(B, M, Name + ".mach");
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

Function *trapSignalHandler(Module &M, GlobalVariable *Counter,
                            GlobalVariable *State) {
    if (Function *existing = M.getFunction("morok.trap.handler"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *fn =
        Function::Create(FunctionType::get(Type::getVoidTy(ctx), {i32}, false),
                         GlobalValue::PrivateLinkage, "morok.trap.handler", &M);
    fn->setDSOLocal(true);
    Argument *sig = fn->getArg(0);
    sig->setName("sig");

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

FunctionCallee raiseDecl(Module &M) {
    auto *i32 = Type::getInt32Ty(M.getContext());
    return M.getOrInsertFunction("raise", FunctionType::get(i32, {i32}, false));
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

bool antiDebuggingModule(Module &M, ir::IRRandom &rng) {
    const Triple tt(M.getTargetTriple());

    Function *ctor = makeCtorShell(M, "morok.antidbg");
    GlobalVariable *state = antiDebugState(M, rng);
    if (tt.isOSLinux())
        emitLinuxAntiDebug(M, ctor, state, rng, tt);
    else if (tt.isOSDarwin())
        emitDarwinAntiDebug(M, ctor, state, rng);
    else {
        IRBuilder<> B(&ctor->getEntryBlock());
        emitPtrace(B, M, 0);
        B.CreateRetVoid();
    }
    Function *probe = antiDebugProbe(M, state, rng, tt);
    if (tt.isOSDarwin()) {
        Instruction *term = ctor->getEntryBlock().getTerminator();
        term->eraseFromParent();
        IRBuilder<> B(&ctor->getEntryBlock());
        emitLinuxWatcherStart(B, M, probeWatchThread(M, probe));
        B.CreateRetVoid();
    }
    insertAntiDebugCallsiteProbes(M, probe, rng);
    appendToGlobalCtors(M, ctor, 0);
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
    Function *handler = trapSignalHandler(M, counter, state);

    IRBuilder<> B(&ctor->getEntryBlock());
    B.CreateStore(ConstantInt::get(i32, 0), counter)->setVolatile(true);
    Value *oldHandler =
        B.CreateCall(signalDecl(M), {ConstantInt::get(i32, kSigTrap), handler},
                     "morok.trap.old.handler");
    unsigned expected = emitTrapStimuli(B, M, tt);
    auto *hits = B.CreateLoad(i32, counter, "morok.trap.hits.final");
    hits->setVolatile(true);
    foldState(B, state, hits, 0x91D0F736B52C48EAULL, "morok.trap.final");
    foldFlag(B, state, B.CreateICmpULT(hits, ConstantInt::get(i32, expected)),
             0xE2AB41739D08C6F5ULL, "morok.trap.missing");
    B.CreateCall(signalDecl(M), {ConstantInt::get(i32, kSigTrap), oldHandler});
    B.CreateRetVoid();
    appendToGlobalCtors(M, ctor, 0);
    return true;
}

bool antiHookingModule(Module &M, ir::IRRandom &rng) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);

    // Detect a resident function-hooking framework: if its entry point
    // resolves, the process is being instrumented — bail out.
    FunctionCallee dlsym = M.getOrInsertFunction(
        "dlsym", FunctionType::get(ptr, {ptr, ptr}, false));
    FunctionCallee exitFn = M.getOrInsertFunction(
        "exit", FunctionType::get(Type::getVoidTy(ctx), {i32}, false));

    Function *ctor = makeCtorShell(M, "morok.antihook");
    IRBuilder<> B(&ctor->getEntryBlock());
    // The probed symbol is cloaked inline — never a readable "MSHookFunction".
    Value *sym = ir::emitCloakedSymbol(B, M, "MSHookFunction", rng);
    // RTLD_DEFAULT == (void*)-2; build it at pointer width so inttoptr does not
    // zero-extend a 32-bit value into the wrong handle.
    auto *i64 = Type::getInt64Ty(ctx);
    Value *rtldDefault = B.CreateIntToPtr(ConstantInt::getSigned(i64, -2), ptr);
    Value *found = B.CreateCall(dlsym, {rtldDefault, sym});
    Value *hooked = B.CreateICmpNE(found, ConstantPointerNull::get(ptr));

    auto *bail = BasicBlock::Create(ctx, "bail", ctor);
    auto *cont = BasicBlock::Create(ctx, "cont", ctor);
    B.CreateCondBr(hooked, bail, cont);

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
