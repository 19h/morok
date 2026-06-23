// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// Centralized platform primitive emission.  Passes call through this layer so
// syscall numbers, ABI constraints, direct/fallback policy, and import surface
// decisions are audited in one place.

#include "morok/runtime/PlatformRuntime.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"

#include <array>
#include <atomic>
#include <string>
#include <vector>

using namespace llvm;

namespace morok::runtime {

IntegerType *platformWordTy(Module &M) {
    unsigned Bits = M.getDataLayout().getPointerSizeInBits(0);
    if (Bits == 0) {
        Triple TT(M.getTargetTriple());
        Bits = TT.isArch32Bit() ? 32 : 64;
    }
    return IntegerType::get(M.getContext(), Bits);
}

Value *toSyscallArg(IRBuilderBase &B, Value *V) {
    auto *IP = platformWordTy(*B.GetInsertBlock()->getModule());
    if (V->getType()->isPointerTy())
        return B.CreatePtrToInt(V, IP);
    if (V->getType()->isIntegerTy())
        return B.CreateSExtOrTrunc(V, IP);
    return ConstantInt::get(IP, 0);
}

FunctionCallee ptraceDecl(Module &M) {
    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);
    return M.getOrInsertFunction(
        "ptrace", FunctionType::get(I32, {I32, I32, Ptr, I32}, false));
}

FunctionCallee syscallDecl(Module &M) {
    auto *IP = platformWordTy(M);
    return M.getOrInsertFunction("syscall", FunctionType::get(IP, {IP}, true));
}

FunctionCallee getpidDecl(Module &M) {
    return M.getOrInsertFunction(
        "getpid", FunctionType::get(Type::getInt32Ty(M.getContext()), false));
}

FunctionCallee getppidDecl(Module &M) {
    return M.getOrInsertFunction(
        "getppid", FunctionType::get(Type::getInt32Ty(M.getContext()), false));
}

FunctionCallee openDecl(Module &M) {
    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);
    return M.getOrInsertFunction("open",
                                 FunctionType::get(I32, {Ptr, I32}, true));
}

FunctionCallee readDecl(Module &M) {
    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);
    auto *IP = platformWordTy(M);
    return M.getOrInsertFunction("read",
                                 FunctionType::get(IP, {I32, Ptr, IP}, false));
}

FunctionCallee closeDecl(Module &M) {
    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    return M.getOrInsertFunction("close", FunctionType::get(I32, {I32}, false));
}

FunctionCallee readlinkDecl(Module &M) {
    LLVMContext &Ctx = M.getContext();
    auto *Ptr = PointerType::getUnqual(Ctx);
    auto *IP = platformWordTy(M);
    return M.getOrInsertFunction(
        "readlink", FunctionType::get(IP, {Ptr, Ptr, IP}, false));
}

FunctionCallee lseekDecl(Module &M) {
    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *IP = platformWordTy(M);
    return M.getOrInsertFunction("lseek",
                                 FunctionType::get(IP, {I32, IP, I32}, false));
}

FunctionCallee mmapDecl(Module &M) {
    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);
    auto *IP = platformWordTy(M);
    return M.getOrInsertFunction(
        "mmap", FunctionType::get(Ptr, {Ptr, IP, I32, I32, I32, IP}, false));
}

FunctionCallee munmapDecl(Module &M) {
    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);
    auto *IP = platformWordTy(M);
    return M.getOrInsertFunction("munmap",
                                 FunctionType::get(I32, {Ptr, IP}, false));
}

FunctionCallee mprotectDecl(Module &M) {
    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);
    auto *IP = platformWordTy(M);
    return M.getOrInsertFunction(
        "mprotect", FunctionType::get(I32, {Ptr, IP, I32}, false));
}

// Operator syscall-surface policy (#102), carried as a module flag set once by
// the pipeline from platform_runtime.direct_syscalls.  0 = auto, 1 = always,
// 2 = never.  The flag is IR-level metadata and is dropped before the final
// binary, so it never appears in shipped output.
constexpr StringLiteral kDirectSyscallFlag = "morok.platform.direct_syscalls";

unsigned directSyscallPolicy(const Module &M) {
    if (auto *MD = M.getModuleFlag(kDirectSyscallFlag))
        if (auto *CMD = dyn_cast<ConstantAsMetadata>(MD))
            if (auto *CI = dyn_cast<ConstantInt>(CMD->getValue()))
                return static_cast<unsigned>(CI->getZExtValue());
    return 0; // auto
}

// "never" forces the import path even where a direct-syscall ABI exists, so an
// operator who wants no inline syscalls actually gets none.  "always"/"auto"
// keep the architecture-gated direct path (a direct syscall cannot be forged
// where the ABI is unknown, so "always" is best-effort on those targets).
bool useDirectLinuxSyscalls(const Module &M, const Triple &TT) {
    if (directSyscallPolicy(M) == 2u)
        return false;
    if (!TT.isOSLinux())
        return false;
    return TT.getArch() == Triple::x86_64 ||
           TT.getArch() == Triple::aarch64 || TT.getArch() == Triple::arm;
}

static std::uint64_t mix64(std::uint64_t X) {
    X ^= X >> 30;
    X *= 0xbf58476d1ce4e5b9ULL;
    X ^= X >> 27;
    X *= 0x94d049bb133111ebULL;
    X ^= X >> 31;
    return X;
}

static std::uint64_t hashString(StringRef S) {
    std::uint64_t H = 0xcbf29ce484222325ULL;
    for (char C : S) {
        H ^= static_cast<unsigned char>(C);
        H *= 0x100000001b3ULL;
    }
    return H;
}

static std::uint64_t wordMask(IntegerType *IP) {
    unsigned Bits = IP->getBitWidth();
    return Bits >= 64 ? ~0ULL : ((1ULL << Bits) - 1ULL);
}

static ConstantInt *wordConstant(IntegerType *IP, std::uint64_t V) {
    return ConstantInt::get(IP, V & wordMask(IP));
}

static unsigned nextLinuxRawSyscallSite(Module &M) {
    static std::atomic_uint SiteCounter{0};
    (void)M;
    return SiteCounter.fetch_add(1, std::memory_order_relaxed);
}

static std::string rawSysName(unsigned Site, StringRef Role) {
    return (Twine("morok.linux.rawsys.") + Role + "." + Twine(Site)).str();
}

static AllocaInst *emitVolatileWordSlot(IRBuilder<> &B, IntegerType *IP,
                                        std::uint64_t V,
                                        const Twine &Name) {
    auto *Slot = B.CreateAlloca(IP, nullptr, Name);
    Slot->setMetadata(LLVMContext::MD_dbg, nullptr);
    auto *Store = B.CreateStore(wordConstant(IP, V), Slot);
    Store->setMetadata(LLVMContext::MD_dbg, nullptr);
    Store->setVolatile(true);
    return Slot;
}

static LoadInst *emitVolatileWordLoad(IRBuilder<> &B, IntegerType *IP,
                                      AllocaInst *Slot, const Twine &Name) {
    auto *Load = B.CreateLoad(IP, Slot, Name);
    Load->setMetadata(LLVMContext::MD_dbg, nullptr);
    Load->setVolatile(true);
    return Load;
}

template <typename InstT> static InstT *stripDbg(InstT *I) {
    if (I)
        I->setMetadata(LLVMContext::MD_dbg, nullptr);
    return I;
}

static Value *stripDbgValue(Value *V) {
    if (auto *I = dyn_cast<Instruction>(V))
        I->setMetadata(LLVMContext::MD_dbg, nullptr);
    return V;
}

static Function *createLinuxNrMaterializer(Module &M, IntegerType *IP,
                                           std::uint64_t Enc,
                                           std::uint64_t Key,
                                           std::uint64_t Guard,
                                           std::uint64_t Check,
                                           unsigned Site) {
    LLVMContext &Ctx = M.getContext();
    auto *Fn = Function::Create(FunctionType::get(IP, false),
                                GlobalValue::InternalLinkage,
                                rawSysName(Site, "nr.materialize"), &M);
    Fn->setDSOLocal(true);

    BasicBlock *Entry = BasicBlock::Create(Ctx, rawSysName(Site, "entry"), Fn);
    BasicBlock *Decode =
        BasicBlock::Create(Ctx, rawSysName(Site, "decode"), Fn);
    BasicBlock *Real = BasicBlock::Create(Ctx, rawSysName(Site, "real"), Fn);
    BasicBlock *Noise = BasicBlock::Create(Ctx, rawSysName(Site, "noise"), Fn);

    IRBuilder<> EB(Entry);
    EB.SetCurrentDebugLocation(DebugLoc());
    AllocaInst *EncSlot =
        emitVolatileWordSlot(EB, IP, Enc, rawSysName(Site, "nr.enc"));
    AllocaInst *KeySlot =
        emitVolatileWordSlot(EB, IP, Key, rawSysName(Site, "nr.key"));
    AllocaInst *GuardSlot =
        emitVolatileWordSlot(EB, IP, Guard, rawSysName(Site, "nr.guard"));
    stripDbg(EB.CreateBr(Decode));

    IRBuilder<> DB(Decode);
    DB.SetCurrentDebugLocation(DebugLoc());
    Value *EncV =
        emitVolatileWordLoad(DB, IP, EncSlot, rawSysName(Site, "enc"));
    Value *KeyV =
        emitVolatileWordLoad(DB, IP, KeySlot, rawSysName(Site, "key"));
    Value *GuardV =
        emitVolatileWordLoad(DB, IP, GuardSlot, rawSysName(Site, "guard"));
    Value *Nr =
        stripDbgValue(DB.CreateXor(EncV, KeyV, rawSysName(Site, "nr.dec")));
    Value *OpaqueNr = stripDbgValue(
        DB.CreateXor(EncV, KeyV, rawSysName(Site, "opaque.nr")));
    Value *Opaque = stripDbgValue(
        DB.CreateXor(OpaqueNr, GuardV, rawSysName(Site, "opaque.mix")));
    Value *Ok = stripDbgValue(DB.CreateICmpEQ(
        Opaque, wordConstant(IP, Check), rawSysName(Site, "opaque.ok")));
    stripDbg(DB.CreateCondBr(Ok, Real, Noise));

    IRBuilder<> RB(Real);
    RB.SetCurrentDebugLocation(DebugLoc());
    stripDbg(RB.CreateRet(Nr));

    IRBuilder<> NB(Noise);
    NB.SetCurrentDebugLocation(DebugLoc());
    Value *NoiseRc =
        stripDbgValue(NB.CreateXor(Nr, GuardV, rawSysName(Site, "noise.rc")));
    stripDbg(NB.CreateRet(NoiseRc));
    return Fn;
}

static Value *emitLinuxDirectSyscallAsm(IRBuilder<> &B, Module &M,
                                        const Triple &TT, Value *Nr,
                                        const std::array<Value *, 6> &A,
                                        unsigned Variant,
                                        const Twine &Name) {
    auto *IP = platformWordTy(M);
    std::vector<Type *> Params(7, IP);
    auto *AsmTy = FunctionType::get(IP, Params, false);
    InlineAsm *Syscall = nullptr;
    switch (TT.getArch()) {
    case Triple::x86_64: {
        StringRef Body = "syscall";
        if (Variant % 3 == 1)
            Body = "movq %r10, %r10\nsyscall";
        else if (Variant % 3 == 2)
            Body = "leaq 0(%r8), %r8\nsyscall";
        Syscall = InlineAsm::get(
            AsmTy, Body,
            "={rax},{rax},{rdi},{rsi},{rdx},{r10},{r8},{r9},~{rcx},~{r11},"
            "~{memory},~{dirflag},~{fpsr},~{flags}",
            /*hasSideEffects=*/true);
        break;
    }
    case Triple::aarch64: {
        StringRef Body = "svc #0";
        if (Variant % 3 == 1)
            Body = "mov x0, x0\nsvc #0";
        else if (Variant % 3 == 2)
            Body = "orr x1, x1, xzr\nsvc #0";
        Syscall = InlineAsm::get(
            AsmTy, Body,
            "={x0},{x8},0,{x1},{x2},{x3},{x4},{x5},~{memory},~{cc}",
            /*hasSideEffects=*/true);
        break;
    }
    case Triple::arm: {
        StringRef Body = "svc #0";
        if (Variant % 3 == 1)
            Body = "mov r0, r0\nsvc #0";
        else if (Variant % 3 == 2)
            Body = "nop\nsvc #0";
        Syscall = InlineAsm::get(
            AsmTy, Body,
            "={r0},{r7},0,{r1},{r2},{r3},{r4},{r5},~{memory},~{cc}",
            /*hasSideEffects=*/true);
        break;
    }
    default:
        return nullptr;
    }
    return stripDbgValue(B.CreateCall(
        AsmTy, Syscall, {Nr, A[0], A[1], A[2], A[3], A[4], A[5]}, Name));
}

static Value *emitHardenedLinuxSyscall(IRBuilder<> &B, Module &M,
                                       const Triple &TT, std::uint32_t Number,
                                       const std::array<Value *, 6> &SysArgs,
                                       const Twine &Name) {
    auto *IP = platformWordTy(M);
    DebugLoc SavedDL = B.getCurrentDebugLocation();
    B.SetCurrentDebugLocation(DebugLoc());
    unsigned Site = nextLinuxRawSyscallSite(M);
    std::string PublicName = Name.str();
    std::uint64_t Mask = wordMask(IP);
    std::uint64_t Plain = static_cast<std::uint64_t>(Number) & Mask;
    std::uint64_t Seed = mix64(static_cast<std::uint64_t>(Site) ^
                               (Plain << 17) ^
                               hashString(PublicName) ^
                               hashString(M.getModuleIdentifier()));
    std::uint64_t Key = mix64(Seed ^ 0xa0761d6478bd642fULL) & Mask;
    if (Key == 0 || Key == Plain)
        Key = (Key ^ 0x7f4a7c159e3779b9ULL) & Mask;
    if (Key == 0 || Key == Plain)
        Key = (Key + 0x9e3779b97f4a7c15ULL) & Mask;
    std::uint64_t Enc = (Plain ^ Key) & Mask;
    std::uint64_t Check = mix64(Seed ^ 0xe7037ed1a0b428dbULL) & Mask;
    if (Check == Plain)
        Check = (Check ^ 0xd1b54a32d192ed03ULL) & Mask;
    std::uint64_t Guard = (Enc ^ Key ^ Check) & Mask;

    Function *Materializer =
        createLinuxNrMaterializer(M, IP, Enc, Key, Guard, Check, Site);
    Value *Nr = stripDbgValue(B.CreateCall(Materializer->getFunctionType(),
                                           Materializer, {},
                                           rawSysName(Site, "nr.call")));
    Value *Result =
        emitLinuxDirectSyscallAsm(B, M, TT, Nr, SysArgs, Site, PublicName);
    B.SetCurrentDebugLocation(SavedDL);
    return Result;
}

bool lookupLinuxCoreSyscalls(const Triple &TT, LinuxCoreSyscalls &Out) {
    switch (TT.getArch()) {
    case Triple::x86_64:
        Out.ptrace = 101;
        Out.prctl = 157;
        Out.openat = 257;
        Out.read = 0;
        Out.close = 3;
        return true;
    case Triple::aarch64:
        Out.ptrace = 117;
        Out.prctl = 167;
        Out.openat = 56;
        Out.read = 63;
        Out.close = 57;
        return true;
    case Triple::arm:
        Out.ptrace = 26;
        Out.prctl = 172;
        Out.openat = 322;
        Out.read = 3;
        Out.close = 6;
        return true;
    case Triple::x86:
        // i386/i686 (32-bit) syscall numbers. Emission is handled by the
        // int $0x80 path in emitLinuxStaticRawSyscall. Without this case the
        // lookup returned false, emitLinuxPrctlDirect folded every prctl to a
        // constant -ENOSYS, and i386 binaries silently lost their
        // PR_SET_DUMPABLE / PR_SET_PTRACER / PR_SET_NO_NEW_PRIVS anti-debug
        // hardening (#262). i386 shares ptrace/prctl/read/close with the legacy
        // ARM numbers but uses openat=295.
        Out.ptrace = 26;
        Out.prctl = 172;
        Out.openat = 295;
        Out.read = 3;
        Out.close = 6;
        return true;
    default:
        return false;
    }
}

bool lookupLinuxCleanCopySyscalls(const Triple &TT,
                                  LinuxCleanCopySyscalls &Out) {
    switch (TT.getArch()) {
    case Triple::x86_64:
        Out.readlink = 89;
        Out.lseek = 8;
        Out.mmap = 9;
        Out.munmap = 11;
        return true;
    default:
        return false;
    }
}

Value *emitPtraceImport(IRBuilderBase &B, Module &M, int Request) {
    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);
    return B.CreateCall(ptraceDecl(M), {ConstantInt::getSigned(I32, Request),
                                        ConstantInt::get(I32, 0),
                                        ConstantPointerNull::get(Ptr),
                                        ConstantInt::get(I32, 0)});
}

Value *emitLinuxSyscall(IRBuilder<> &B, Module &M, const Triple &TT,
                        std::uint32_t Number,
                        std::initializer_list<Value *> Args,
                        const Twine &Name) {
    auto *IP = platformWordTy(M);
    std::array<Value *, 6> SysArgs = {
        ConstantInt::get(IP, 0), ConstantInt::get(IP, 0),
        ConstantInt::get(IP, 0), ConstantInt::get(IP, 0),
        ConstantInt::get(IP, 0), ConstantInt::get(IP, 0)};
    std::size_t I = 0;
    for (Value *Arg : Args) {
        if (I >= SysArgs.size())
            break;
        SysArgs[I++] = toSyscallArg(B, Arg);
    }

    if (useDirectLinuxSyscalls(M, TT))
        return emitHardenedLinuxSyscall(B, M, TT, Number, SysArgs, Name);

    return B.CreateCall(syscallDecl(M),
                        {ConstantInt::get(IP, Number), SysArgs[0], SysArgs[1],
                         SysArgs[2], SysArgs[3], SysArgs[4], SysArgs[5]},
                        Name + ".wrap");
}

Value *emitLinuxPtrace(IRBuilder<> &B, Module &M, const Triple &TT,
                       int Request) {
    LinuxCoreSyscalls Sys;
    if (!lookupLinuxCoreSyscalls(TT, Sys))
        return emitPtraceImport(B, M, Request);
    auto *I32 = Type::getInt32Ty(M.getContext());
    auto *IP = platformWordTy(M);
    auto *Ptr = PointerType::getUnqual(M.getContext());
    Value *Rc = emitLinuxSyscall(
        B, M, TT, Sys.ptrace,
        {ConstantInt::getSigned(IP, Request), ConstantInt::get(IP, 0),
         ConstantPointerNull::get(Ptr), ConstantInt::get(IP, 0)});
    return B.CreateTruncOrBitCast(Rc, I32);
}

Value *emitLinuxPrctl(IRBuilder<> &B, Module &M, const Triple &TT,
                      std::int64_t Option, std::int64_t A2, std::int64_t A3,
                      std::int64_t A4, std::int64_t A5) {
    LinuxCoreSyscalls Sys;
    if (!lookupLinuxCoreSyscalls(TT, Sys)) {
        auto *I32 = Type::getInt32Ty(M.getContext());
        auto *IP = platformWordTy(M);
        FunctionCallee Prctl = M.getOrInsertFunction(
            "prctl", FunctionType::get(I32, {I32, IP, IP, IP, IP}, false));
        auto Arg = [&](std::int64_t V) {
            return ConstantInt::getSigned(IP, V);
        };
        return B.CreateCall(Prctl, {ConstantInt::getSigned(I32, Option),
                                    Arg(A2), Arg(A3), Arg(A4), Arg(A5)});
    }

    auto *I32 = Type::getInt32Ty(M.getContext());
    auto *IP = platformWordTy(M);
    Value *Rc = emitLinuxSyscall(
        B, M, TT, Sys.prctl,
        {ConstantInt::getSigned(IP, Option), ConstantInt::getSigned(IP, A2),
         ConstantInt::getSigned(IP, A3), ConstantInt::getSigned(IP, A4),
         ConstantInt::getSigned(IP, A5)});
    return B.CreateTruncOrBitCast(Rc, I32);
}

bool useDirectDarwinSyscalls(const Module &M, const Triple &TT) {
    if (directSyscallPolicy(M) == 2u)
        return false;
    return TT.isOSDarwin() && TT.getArch() == Triple::x86_64;
}

void setDirectSyscallPolicy(Module &M, StringRef Policy) {
    std::uint32_t Value = 0; // auto
    if (Policy == "always")
        Value = 1;
    else if (Policy == "never")
        Value = 2;
    // Use setModuleFlag, NOT addModuleFlag (#102): addModuleFlag's Override
    // behavior only governs cross-module linking and does not replace a same-key
    // flag already present in THIS module, so a repeated Morok run or pre-flagged
    // input IR would accumulate duplicate llvm.module.flags entries — which are
    // verifier-invalid (a build DoS) and let a stale first value shadow the
    // operator policy.  setModuleFlag replaces any existing entry in place, so
    // exactly one flag for the key is ever present.
    M.setModuleFlag(Module::Override, kDirectSyscallFlag, Value);
}

static Value *emitArm64SvcInlineAsm(IRBuilder<> &B, Module &M, Value *Nr,
                                    const std::array<Value *, 6> &A,
                                    const Twine &Name) {
    auto *IP = platformWordTy(M);
    std::vector<Type *> Params(7, IP);
    auto *AsmTy = FunctionType::get(IP, Params, false);
    InlineAsm *Svc = InlineAsm::get(
        AsmTy, "svc #0x80",
        "={x0},{x16},0,{x1},{x2},{x3},{x4},{x5},~{memory},~{cc}",
        /*hasSideEffects=*/true);
    return B.CreateCall(AsmTy, Svc, {Nr, A[0], A[1], A[2], A[3], A[4], A[5]},
                        Name);
}

static Value *emitArm64Svc7InlineAsm(IRBuilder<> &B, Module &M, Value *Nr,
                                     const std::array<Value *, 7> &A,
                                     const Twine &Name) {
    auto *IP = platformWordTy(M);
    std::vector<Type *> Params(8, IP);
    auto *AsmTy = FunctionType::get(IP, Params, false);
    InlineAsm *Svc = InlineAsm::get(
        AsmTy, "svc #0x80",
        "={x0},{x16},0,{x1},{x2},{x3},{x4},{x5},{x6},~{memory},~{cc}",
        /*hasSideEffects=*/true);
    return B.CreateCall(
        AsmTy, Svc, {Nr, A[0], A[1], A[2], A[3], A[4], A[5], A[6]}, Name);
}

static Value *emitArm64Svc8InlineAsm(IRBuilder<> &B, Module &M, Value *Nr,
                                     const std::array<Value *, 8> &A,
                                     const Twine &Name) {
    auto *IP = platformWordTy(M);
    std::vector<Type *> Params(9, IP);
    auto *AsmTy = FunctionType::get(IP, Params, false);
    InlineAsm *Svc = InlineAsm::get(
        AsmTy, "svc #0x80",
        "={x0},{x16},0,{x1},{x2},{x3},{x4},{x5},{x6},{x7},~{memory},~{cc}",
        /*hasSideEffects=*/true);
    return B.CreateCall(AsmTy, Svc,
                        {Nr, A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7]},
                        Name);
}

static ConstantInt *darwinX86MachTrapNumber(IntegerType *IP,
                                            std::int32_t Trap) {
    std::uint32_t Ordinal =
        Trap < 0 ? static_cast<std::uint32_t>(-Trap)
                 : static_cast<std::uint32_t>(Trap);
    return ConstantInt::get(IP, 0x01000000U | Ordinal);
}

static Value *emitX86DarwinMachTrap0(IRBuilder<> &B, Module &M,
                                     std::int32_t Trap, const Twine &Name) {
    auto *IP = platformWordTy(M);
    auto *AsmTy = FunctionType::get(IP, {IP}, false);
    InlineAsm *TrapAsm = InlineAsm::get(
        AsmTy, "syscall\nsbbq %r11, %r11\norq %r11, %rax",
        "={rax},{rax},~{rcx},~{r11},~{memory},~{dirflag},~{fpsr},~{flags}",
        /*hasSideEffects=*/true);
    return B.CreateCall(AsmTy, TrapAsm, {darwinX86MachTrapNumber(IP, Trap)},
                        Name);
}

static Value *emitX86DarwinMachTrap2(IRBuilder<> &B, Module &M,
                                     std::int32_t Trap,
                                     const std::array<Value *, 2> &A,
                                     const Twine &Name) {
    auto *IP = platformWordTy(M);
    std::vector<Type *> Params(3, IP);
    auto *AsmTy = FunctionType::get(IP, Params, false);
    InlineAsm *TrapAsm = InlineAsm::get(
        AsmTy, "syscall\nsbbq %r11, %r11\norq %r11, %rax",
        "={rax},{rax},{rdi},{rsi},~{rcx},~{r11},~{memory},~{dirflag},~{fpsr},"
        "~{flags}",
        /*hasSideEffects=*/true);
    return B.CreateCall(AsmTy, TrapAsm,
                        {darwinX86MachTrapNumber(IP, Trap), A[0], A[1]},
                        Name);
}

static Value *emitX86DarwinMachTrap3(IRBuilder<> &B, Module &M,
                                     std::int32_t Trap,
                                     const std::array<Value *, 3> &A,
                                     const Twine &Name) {
    auto *IP = platformWordTy(M);
    std::vector<Type *> Params(4, IP);
    auto *AsmTy = FunctionType::get(IP, Params, false);
    InlineAsm *TrapAsm = InlineAsm::get(
        AsmTy, "syscall\nsbbq %r11, %r11\norq %r11, %rax",
        "={rax},{rax},{rdi},{rsi},{rdx},~{rcx},~{r11},~{memory},~{dirflag},"
        "~{fpsr},~{flags}",
        /*hasSideEffects=*/true);
    return B.CreateCall(AsmTy, TrapAsm,
                        {darwinX86MachTrapNumber(IP, Trap), A[0], A[1], A[2]},
                        Name);
}

static Value *emitX86DarwinMachTrap7(IRBuilder<> &B, Module &M,
                                     std::int32_t Trap,
                                     const std::array<Value *, 7> &A,
                                     const Twine &Name) {
    auto *IP = platformWordTy(M);
    std::vector<Type *> Params(8, IP);
    auto *AsmTy = FunctionType::get(IP, Params, false);
    InlineAsm *TrapAsm = InlineAsm::get(
        AsmTy,
        "subq $$8, %rsp\nmovq $8, (%rsp)\nsyscall\naddq $$8, %rsp\n"
        "sbbq %r11, %r11\norq %r11, %rax",
        "={rax},{rax},{rdi},{rsi},{rdx},{r10},{r8},{r9},r,~{rcx},~{r11},"
        "~{memory},~{dirflag},~{fpsr},~{flags}",
        /*hasSideEffects=*/true);
    return B.CreateCall(
        AsmTy, TrapAsm,
        {darwinX86MachTrapNumber(IP, Trap), A[0], A[1], A[2], A[3], A[4],
         A[5], A[6]},
        Name);
}

static bool useDirectDarwinMachTraps(const Module &M, const Triple &TT) {
    if (directSyscallPolicy(M) == 2u)
        return false;
    return TT.isOSDarwin() &&
           (TT.getArch() == Triple::x86_64 || TT.getArch() == Triple::aarch64);
}

static Value *emitDarwinMachTrap0(IRBuilder<> &B, Module &M, const Triple &TT,
                                  std::int32_t Trap, const Twine &Name) {
    if (useDirectDarwinSyscalls(M, TT))
        return emitX86DarwinMachTrap0(B, M, Trap, Name);
    if (TT.isOSDarwin() && TT.getArch() == Triple::aarch64 &&
        directSyscallPolicy(M) != 2u) {
        auto *IP = platformWordTy(M);
        std::array<Value *, 6> A = {
            ConstantInt::get(IP, 0), ConstantInt::get(IP, 0),
            ConstantInt::get(IP, 0), ConstantInt::get(IP, 0),
            ConstantInt::get(IP, 0), ConstantInt::get(IP, 0)};
        return emitArm64SvcInlineAsm(B, M, ConstantInt::getSigned(IP, Trap), A,
                                     Name);
    }
    return nullptr;
}

static Value *emitDarwinMachTrap2(IRBuilder<> &B, Module &M, const Triple &TT,
                                  std::int32_t Trap,
                                  const std::array<Value *, 2> &A,
                                  const Twine &Name) {
    if (useDirectDarwinSyscalls(M, TT))
        return emitX86DarwinMachTrap2(B, M, Trap, A, Name);
    if (TT.isOSDarwin() && TT.getArch() == Triple::aarch64 &&
        directSyscallPolicy(M) != 2u) {
        auto *IP = platformWordTy(M);
        std::array<Value *, 6> Args = {
            A[0], A[1], ConstantInt::get(IP, 0), ConstantInt::get(IP, 0),
            ConstantInt::get(IP, 0), ConstantInt::get(IP, 0)};
        return emitArm64SvcInlineAsm(B, M, ConstantInt::getSigned(IP, Trap),
                                     Args, Name);
    }
    return nullptr;
}

static Value *emitDarwinMachTrap3(IRBuilder<> &B, Module &M, const Triple &TT,
                                  std::int32_t Trap,
                                  const std::array<Value *, 3> &A,
                                  const Twine &Name) {
    if (useDirectDarwinSyscalls(M, TT))
        return emitX86DarwinMachTrap3(B, M, Trap, A, Name);
    if (TT.isOSDarwin() && TT.getArch() == Triple::aarch64 &&
        directSyscallPolicy(M) != 2u) {
        auto *IP = platformWordTy(M);
        std::array<Value *, 6> Args = {
            A[0], A[1], A[2], ConstantInt::get(IP, 0),
            ConstantInt::get(IP, 0), ConstantInt::get(IP, 0)};
        return emitArm64SvcInlineAsm(B, M, ConstantInt::getSigned(IP, Trap),
                                     Args, Name);
    }
    return nullptr;
}

static Value *emitDarwinMachTrap7(IRBuilder<> &B, Module &M, const Triple &TT,
                                  std::int32_t Trap,
                                  const std::array<Value *, 7> &A,
                                  const Twine &Name) {
    if (useDirectDarwinSyscalls(M, TT))
        return emitX86DarwinMachTrap7(B, M, Trap, A, Name);
    if (TT.isOSDarwin() && TT.getArch() == Triple::aarch64 &&
        directSyscallPolicy(M) != 2u)
        return emitArm64Svc7InlineAsm(
            B, M, ConstantInt::getSigned(platformWordTy(M), Trap), A, Name);
    return nullptr;
}

static Function *getOrCreateSvcFallback(Module &M) {
    if (auto *F = M.getFunction("morok.svc.fallback"))
        return F;
    LLVMContext &Ctx = M.getContext();
    auto *IP = platformWordTy(M);
    std::vector<Type *> Params(7, IP);
    auto *SysTy = FunctionType::get(IP, Params, false);
    Function *Fb = Function::Create(SysTy, GlobalValue::InternalLinkage,
                                    "morok.svc.fallback", &M);
    Fb->addFnAttr(Attribute::NoInline);
    BasicBlock *BB = BasicBlock::Create(Ctx, "entry", Fb);
    IRBuilder<> FB(BB);
    auto AI = Fb->arg_begin();
    Value *Nr = &*AI++;
    std::array<Value *, 6> A{};
    for (std::size_t K = 0; K < 6; ++K)
        A[K] = &*AI++;
    FB.CreateRet(emitArm64SvcInlineAsm(FB, M, Nr, A, "morok.darwin.svc"));
    return Fb;
}

Value *emitDarwinArm64Svc(IRBuilder<> &B, Module &M, std::uint32_t Number,
                          std::initializer_list<Value *> Args,
                          const Twine &Name) {
    auto *IP = platformWordTy(M);
    std::array<Value *, 6> A = {ConstantInt::get(IP, 0),
                                ConstantInt::get(IP, 0),
                                ConstantInt::get(IP, 0),
                                ConstantInt::get(IP, 0),
                                ConstantInt::get(IP, 0),
                                ConstantInt::get(IP, 0)};
    std::size_t I = 0;
    for (Value *Arg : Args)
        if (I < A.size())
            A[I++] = toSyscallArg(B, Arg);
    Function *Fallback = getOrCreateSvcFallback(M);
    return B.CreateCall(Fallback->getFunctionType(), Fallback,
                        {ConstantInt::get(IP, Number), A[0], A[1], A[2], A[3],
                         A[4], A[5]},
                        Name);
}

Value *emitDarwinSyscall(IRBuilder<> &B, Module &M, const Triple &TT,
                         std::uint32_t Number,
                         std::initializer_list<Value *> Args,
                         const Twine &Name) {
    auto *IP = platformWordTy(M);
    std::array<Value *, 6> SysArgs = {
        ConstantInt::get(IP, 0), ConstantInt::get(IP, 0),
        ConstantInt::get(IP, 0), ConstantInt::get(IP, 0),
        ConstantInt::get(IP, 0), ConstantInt::get(IP, 0)};
    std::size_t I = 0;
    for (Value *Arg : Args) {
        if (I >= SysArgs.size())
            break;
        SysArgs[I++] = toSyscallArg(B, Arg);
    }

    if (useDirectDarwinSyscalls(M, TT)) {
        std::vector<Type *> Params(7, IP);
        auto *AsmTy = FunctionType::get(IP, Params, false);
        InlineAsm *Syscall = InlineAsm::get(
            AsmTy, "syscall\nsbbq %r11, %r11\norq %r11, %rax",
            "={rax},{rax},{rdi},{rsi},{rdx},{r10},{r8},{r9},~{rcx},~{r11},"
            "~{memory},~{dirflag},~{fpsr},~{flags}",
            /*hasSideEffects=*/true);
        return B.CreateCall(AsmTy, Syscall,
                            {ConstantInt::get(IP, 0x02000000U | Number),
                             SysArgs[0], SysArgs[1], SysArgs[2], SysArgs[3],
                             SysArgs[4], SysArgs[5]},
                            Name);
    }

    return B.CreateCall(syscallDecl(M),
                        {ConstantInt::get(IP, Number), SysArgs[0], SysArgs[1],
                         SysArgs[2], SysArgs[3], SysArgs[4], SysArgs[5]},
                        Name + ".wrap");
}

Value *emitDarwinGetpid(IRBuilder<> &B, Module &M, const Triple &TT) {
    auto *I32 = Type::getInt32Ty(M.getContext());
    if (useDirectDarwinSyscalls(M, TT))
        return B.CreateTruncOrBitCast(emitDarwinSyscall(B, M, TT, 20, {}), I32);
    if (TT.getArch() == Triple::aarch64 && directSyscallPolicy(M) != 2u)
        return B.CreateTruncOrBitCast(emitDarwinArm64Svc(B, M, 20, {}), I32);
    return B.CreateCall(getpidDecl(M));
}

Value *emitDarwinPtrace(IRBuilder<> &B, Module &M, const Triple &TT,
                        std::int32_t Request) {
    auto *I32 = Type::getInt32Ty(M.getContext());
    auto *Ptr = PointerType::getUnqual(M.getContext());
    if (useDirectDarwinSyscalls(M, TT))
        return B.CreateTruncOrBitCast(
            emitDarwinSyscall(
                B, M, TT, 26,
                {ConstantInt::getSigned(I32, Request), ConstantInt::get(I32, 0),
                 ConstantPointerNull::get(Ptr), ConstantInt::get(I32, 0)}),
            I32);
    if (TT.getArch() == Triple::aarch64 && directSyscallPolicy(M) != 2u)
        return B.CreateTruncOrBitCast(
            emitDarwinArm64Svc(
                B, M, 26,
                {ConstantInt::getSigned(I32, Request), ConstantInt::get(I32, 0),
                 ConstantPointerNull::get(Ptr), ConstantInt::get(I32, 0)}),
            I32);
    return emitPtraceImport(B, M, Request);
}

Value *emitDarwinSysctl(IRBuilder<> &B, Module &M, const Triple &TT, Value *Mib,
                        Value *MibLen, Value *OldP, Value *OldLenP, Value *NewP,
                        Value *NewLen) {
    auto *I32 = Type::getInt32Ty(M.getContext());
    auto *IP = platformWordTy(M);
    auto *Ptr = PointerType::getUnqual(M.getContext());
    if (useDirectDarwinSyscalls(M, TT))
        return B.CreateTruncOrBitCast(
            emitDarwinSyscall(B, M, TT, 202,
                              {Mib, MibLen, OldP, OldLenP, NewP, NewLen}),
            I32);
    if (TT.getArch() == Triple::aarch64 && directSyscallPolicy(M) != 2u)
        return B.CreateTruncOrBitCast(
            emitDarwinArm64Svc(B, M, 202,
                               {Mib, MibLen, OldP, OldLenP, NewP, NewLen}),
            I32);
    FunctionCallee Sysctl = M.getOrInsertFunction(
        "sysctl", FunctionType::get(I32, {Ptr, I32, Ptr, Ptr, Ptr, IP}, false));
    return B.CreateCall(Sysctl,
                        {Mib, B.CreateTruncOrBitCast(MibLen, I32), OldP,
                         OldLenP, NewP, B.CreateZExtOrTrunc(NewLen, IP)});
}

Value *emitDarwinCsops(IRBuilder<> &B, Module &M, const Triple &TT, Value *Pid,
                       Value *Ops, Value *UserAddr, Value *UserSize) {
    auto *I32 = Type::getInt32Ty(M.getContext());
    auto *IP = platformWordTy(M);
    auto *Ptr = PointerType::getUnqual(M.getContext());
    if (useDirectDarwinSyscalls(M, TT))
        return B.CreateTruncOrBitCast(
            emitDarwinSyscall(B, M, TT, 169, {Pid, Ops, UserAddr, UserSize}),
            I32);
    if (TT.getArch() == Triple::aarch64 && directSyscallPolicy(M) != 2u)
        return B.CreateTruncOrBitCast(
            emitDarwinArm64Svc(B, M, 169, {Pid, Ops, UserAddr, UserSize}), I32);
    FunctionCallee Csops = M.getOrInsertFunction(
        "csops", FunctionType::get(I32, {I32, I32, Ptr, IP}, false));
    return B.CreateCall(Csops, {B.CreateTruncOrBitCast(Pid, I32),
                                B.CreateTruncOrBitCast(Ops, I32), UserAddr,
                                B.CreateZExtOrTrunc(UserSize, IP)});
}

Value *emitDarwinCsopsAuditToken(IRBuilder<> &B, Module &M, const Triple &TT,
                                 Value *Pid, Value *Ops, Value *UserAddr,
                                 Value *UserSize, Value *AuditToken) {
    auto *I32 = Type::getInt32Ty(M.getContext());
    if (useDirectDarwinSyscalls(M, TT))
        return B.CreateTruncOrBitCast(
            emitDarwinSyscall(B, M, TT, 170,
                              {Pid, Ops, UserAddr, UserSize, AuditToken},
                              "morok.darwin.csops.audit"),
            I32);
    if (TT.getArch() == Triple::aarch64 && directSyscallPolicy(M) != 2u)
        return B.CreateTruncOrBitCast(
            emitDarwinArm64Svc(B, M, 170,
                               {Pid, Ops, UserAddr, UserSize, AuditToken},
                               "morok.darwin.csops.audit.svc"),
            I32);
    return B.CreateTruncOrBitCast(
        emitDarwinSyscall(B, M, TT, 170,
                          {Pid, Ops, UserAddr, UserSize, AuditToken},
                          "morok.darwin.csops.audit"),
        I32);
}

Value *emitDarwinTaskInfoAuditToken(IRBuilder<> &B, Module &M, const Triple &TT,
                                    Value *Task, Value *AuditToken,
                                    const Twine &Name) {
    LLVMContext &Ctx = M.getContext();
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *IP = platformWordTy(M);
    auto *Ptr = PointerType::getUnqual(Ctx);
    constexpr std::uint32_t kTaskAuditTokenFlavor = 15;
    constexpr std::uint32_t kTaskAuditTokenCount = 8;

    if (useDirectDarwinMachTraps(M, TT)) {
        auto *HeaderTy =
            StructType::get(Ctx, {I32, I32, I32, I32, I32, I32});
        auto *NdrTy = ArrayType::get(I8, 8);
        auto *ReqTy = StructType::get(Ctx, {HeaderTy, NdrTy, I32, I32});
        auto *MsgTy = ArrayType::get(I8, 448);

        constexpr std::uint32_t kRequestSize = 40;
        constexpr std::uint32_t kMessageBufferSize = 448;
        constexpr std::uint32_t kReplyRetCodeOffset = 32;
        constexpr std::uint32_t kReplyCountOffset = 36;
        constexpr std::uint32_t kReplyInfoOffset = 40;
        constexpr std::uint32_t kTaskInfoId = 3405;
        constexpr std::uint32_t kTaskInfoReplyId = 3505;
        constexpr std::uint32_t kMachMsgBitsCopySendMakeSendOnce =
            19U | (21U << 8);
        constexpr std::int32_t kMigReplyMismatch = -301;

        AllocaInst *Msg =
            B.CreateAlloca(MsgTy, nullptr, Name + ".mig.message");
        B.CreateMemSet(Msg, ConstantInt::get(I8, 0),
                       ConstantInt::get(IP, kMessageBufferSize), MaybeAlign(4));
        auto gepI8Const = [&](IRBuilder<> &Builder, std::uint32_t Offset,
                              const Twine &GepName) -> Value * {
            return Builder.CreateInBoundsGEP(
                I8, Msg, ConstantInt::get(IP, Offset), GepName);
        };
        auto loadI32AtConst = [&](IRBuilder<> &Builder, std::uint32_t Offset,
                                  const Twine &LoadName) -> LoadInst * {
            Value *Slot = gepI8Const(Builder, Offset, LoadName + ".ptr");
            return Builder.CreateAlignedLoad(I32, Slot, Align(4), LoadName);
        };

        Value *ReplyPort =
            emitDarwinMachTrap0(B, M, TT, -26, Name + ".reply_port");
        Value *ReplyPort32 = B.CreateTruncOrBitCast(
            ReplyPort, I32, Name + ".reply_port.name");
        Value *Task32 = B.CreateTruncOrBitCast(Task, I32, Name + ".task.name");

        Value *ReqHeader = B.CreateStructGEP(ReqTy, Msg, 0);
        B.CreateStore(ConstantInt::get(I32, kMachMsgBitsCopySendMakeSendOnce),
                      B.CreateStructGEP(HeaderTy, ReqHeader, 0));
        B.CreateStore(ConstantInt::get(I32, kRequestSize),
                      B.CreateStructGEP(HeaderTy, ReqHeader, 1));
        B.CreateStore(Task32, B.CreateStructGEP(HeaderTy, ReqHeader, 2));
        B.CreateStore(ReplyPort32, B.CreateStructGEP(HeaderTy, ReqHeader, 3));
        B.CreateStore(ConstantInt::get(I32, 0),
                      B.CreateStructGEP(HeaderTy, ReqHeader, 4));
        B.CreateStore(ConstantInt::get(I32, kTaskInfoId),
                      B.CreateStructGEP(HeaderTy, ReqHeader, 5));

        Value *Ndr = B.CreateStructGEP(ReqTy, Msg, 1);
        constexpr std::array<std::uint8_t, 8> kNdrRecord = {0, 0, 0, 0,
                                                            1, 0, 0, 0};
        for (std::uint32_t I = 0; I < kNdrRecord.size(); ++I) {
            Value *Slot = B.CreateInBoundsGEP(
                NdrTy, Ndr, {ConstantInt::get(IP, 0), ConstantInt::get(IP, I)},
                Name + ".ndr");
            B.CreateStore(ConstantInt::get(I8, kNdrRecord[I]), Slot);
        }
        B.CreateStore(ConstantInt::get(I32, kTaskAuditTokenFlavor),
                      B.CreateStructGEP(ReqTy, Msg, 2));
        B.CreateStore(ConstantInt::get(I32, kTaskAuditTokenCount),
                      B.CreateStructGEP(ReqTy, Msg, 3));

        Value *ReplyPortIP =
            B.CreateZExtOrTrunc(ReplyPort32, IP, Name + ".reply_port.ip");
        Value *MsgRc = nullptr;
        if (TT.getArch() == Triple::aarch64) {
            Value *RemoteLocal = B.CreateOr(
                B.CreateShl(ReplyPortIP, ConstantInt::get(IP, 32),
                            Name + ".msg2.local"),
                B.CreateZExtOrTrunc(Task32, IP), Name + ".msg2.ports");
            Value *TimeoutReceive = B.CreateShl(
                ReplyPortIP, ConstantInt::get(IP, 32), Name + ".msg2.receive");
            std::array<Value *, 8> Args = {
                toSyscallArg(B, Msg),
                ConstantInt::get(IP, (std::uint64_t{0x2} << 32) |
                                         (0x00000001U | 0x00000002U)),
                ConstantInt::get(IP, (std::uint64_t{kRequestSize} << 32) |
                                         kMachMsgBitsCopySendMakeSendOnce),
                RemoteLocal,
                ConstantInt::get(IP, std::uint64_t{kTaskInfoId} << 32),
                TimeoutReceive,
                ConstantInt::get(IP, kMessageBufferSize),
                ConstantInt::get(IP, 0),
            };
            MsgRc = emitArm64Svc8InlineAsm(B, M, ConstantInt::getSigned(IP, -47),
                                           Args, Name + ".mach_msg");
        } else {
            std::array<Value *, 7> Args = {
                toSyscallArg(B, Msg),
                ConstantInt::get(IP, 0x00000001U | 0x00000002U),
                ConstantInt::get(IP, kRequestSize),
                ConstantInt::get(IP, kMessageBufferSize),
                ReplyPortIP,
                ConstantInt::get(IP, 0),
                ConstantInt::get(IP, 0),
            };
            MsgRc = emitDarwinMachTrap7(B, M, TT, -31, Args,
                                        Name + ".mach_msg");
        }
        Value *MsgRc32 = B.CreateTruncOrBitCast(MsgRc, I32, Name + ".rc");
        Value *ReplyId =
            B.CreateLoad(I32, B.CreateStructGEP(HeaderTy, Msg, 5),
                         Name + ".reply.id");
        Value *RetCode =
            loadI32AtConst(B, kReplyRetCodeOffset, Name + ".reply.ret");
        Value *ReplyCount =
            loadI32AtConst(B, kReplyCountOffset, Name + ".reply.count");

        Value *MsgOk =
            B.CreateICmpEQ(MsgRc32, ConstantInt::get(I32, 0), Name + ".msg.ok");
        Value *IdOk = B.CreateICmpEQ(
            ReplyId, ConstantInt::get(I32, kTaskInfoReplyId),
            Name + ".reply.id.ok");
        Value *RetOk =
            B.CreateICmpEQ(RetCode, ConstantInt::get(I32, 0), Name + ".ret.ok");
        Value *CountOk = B.CreateICmpUGE(
            ReplyCount, ConstantInt::get(I32, kTaskAuditTokenCount),
            Name + ".count.ok");
        Value *Ok = B.CreateAnd(MsgOk, IdOk, Name + ".ok.id");
        Ok = B.CreateAnd(Ok, RetOk, Name + ".ok.ret");
        Ok = B.CreateAnd(Ok, CountOk, Name + ".ok.count");

        Function *Fn = B.GetInsertBlock()->getParent();
        BasicBlock *StartBB = B.GetInsertBlock();
        BasicBlock *CopyBB =
            BasicBlock::Create(Ctx, (Name + ".copy").str(), Fn);
        BasicBlock *DoneBB =
            BasicBlock::Create(Ctx, (Name + ".done").str(), Fn);
        Value *ReplyFailure = B.CreateSelect(
            B.CreateICmpNE(RetCode, ConstantInt::get(I32, 0)),
            RetCode, ConstantInt::getSigned(I32, kMigReplyMismatch),
            Name + ".reply.failure");
        Value *FailureRc = B.CreateSelect(
            B.CreateICmpNE(MsgRc32, ConstantInt::get(I32, 0)),
            MsgRc32, ReplyFailure, Name + ".failure");
        B.CreateCondBr(Ok, CopyBB, DoneBB);

        IRBuilder<> CB(CopyBB);
        for (std::uint32_t I = 0; I < kTaskAuditTokenCount; ++I) {
            Value *Word = loadI32AtConst(
                CB, kReplyInfoOffset + I * 4, Name + ".copy.word");
            Value *Slot = CB.CreateInBoundsGEP(
                I32, AuditToken, ConstantInt::get(IP, I), Name + ".copy.out");
            CB.CreateStore(Word, Slot);
        }
        CB.CreateBr(DoneBB);

        B.SetInsertPoint(DoneBB);
        PHINode *Result = B.CreatePHI(I32, 2, Name + ".direct.rc");
        Result->addIncoming(ConstantInt::get(I32, 0), CopyBB);
        Result->addIncoming(FailureRc, StartBB);
        return Result;
    }

    AllocaInst *Count = B.CreateAlloca(I32, nullptr, Name + ".count");
    B.CreateStore(ConstantInt::get(I32, kTaskAuditTokenCount), Count);
    FunctionCallee TaskInfo = M.getOrInsertFunction(
        "task_info", FunctionType::get(I32, {I32, I32, Ptr, Ptr}, false));
    return B.CreateCall(TaskInfo,
                        {B.CreateTruncOrBitCast(Task, I32),
                         ConstantInt::get(I32, kTaskAuditTokenFlavor),
                         AuditToken, Count},
                        Name + ".import");
}

Value *emitDarwinTaskSelf(IRBuilder<> &B, Module &M, const Triple &TT,
                          const Twine &Name) {
    auto *I32 = Type::getInt32Ty(M.getContext());
    if (Value *Raw = emitDarwinMachTrap0(B, M, TT, -28, Name))
        return B.CreateTruncOrBitCast(Raw, I32, Name + ".name");
    auto *Self = cast<GlobalVariable>(M.getOrInsertGlobal("mach_task_self_", I32));
    return B.CreateLoad(I32, Self, Name + ".global");
}

Value *emitDarwinTaskForPid(IRBuilder<> &B, Module &M, const Triple &TT,
                            Value *TargetTask, Value *Pid, Value *OutTask,
                            const Twine &Name) {
    auto *I32 = Type::getInt32Ty(M.getContext());
    auto *Ptr = PointerType::getUnqual(M.getContext());
    if (Value *Raw = emitDarwinMachTrap3(
            B, M, TT, -45,
            {toSyscallArg(B, TargetTask), toSyscallArg(B, Pid),
             toSyscallArg(B, OutTask)},
            Name))
        return B.CreateTruncOrBitCast(Raw, I32, Name + ".rc");

    FunctionCallee TaskForPid = M.getOrInsertFunction(
        "task_for_pid", FunctionType::get(I32, {I32, I32, Ptr}, false));
    return B.CreateCall(TaskForPid,
                        {B.CreateTruncOrBitCast(TargetTask, I32),
                         B.CreateTruncOrBitCast(Pid, I32), OutTask},
                        Name + ".import");
}

Value *emitDarwinMachPortDeallocate(IRBuilder<> &B, Module &M,
                                    const Triple &TT, Value *Task,
                                    Value *PortName, const Twine &CallName) {
    auto *I32 = Type::getInt32Ty(M.getContext());
    if (Value *Raw = emitDarwinMachTrap2(
            B, M, TT, -18,
            {toSyscallArg(B, Task), toSyscallArg(B, PortName)}, CallName))
        return B.CreateTruncOrBitCast(Raw, I32, CallName + ".rc");

    FunctionCallee Deallocate = M.getOrInsertFunction(
        "mach_port_deallocate", FunctionType::get(I32, {I32, I32}, false));
    return B.CreateCall(Deallocate,
                        {B.CreateTruncOrBitCast(Task, I32),
                         B.CreateTruncOrBitCast(PortName, I32)},
                        CallName + ".import");
}

Value *emitDarwinTaskGetExceptionPorts(
    IRBuilder<> &B, Module &M, const Triple &TT, Value *Task,
    Value *ExceptionMask, Value *Masks, Value *MaskCount, Value *Handlers,
    Value *Behaviors, Value *Flavors, const Twine &Name) {
    if (useDirectDarwinMachTraps(M, TT)) {
        LLVMContext &Ctx = M.getContext();
        auto *I8 = Type::getInt8Ty(Ctx);
        auto *I32 = Type::getInt32Ty(Ctx);
        auto *IP = platformWordTy(M);
        auto *HeaderTy =
            StructType::get(Ctx, {I32, I32, I32, I32, I32, I32});
        auto *NdrTy = ArrayType::get(I8, 8);
        auto *ReqTy = StructType::get(Ctx, {HeaderTy, NdrTy, I32});
        auto *MsgTy = ArrayType::get(I8, 816);

        constexpr std::uint32_t kMaxExceptionPorts = 32;
        constexpr std::uint32_t kRequestSize = 36;
        constexpr std::uint32_t kMessageBufferSize = 816;
        constexpr std::uint32_t kReplyDescriptorCountOffset = 24;
        constexpr std::uint32_t kReplyDescriptorsOffset = 28;
        constexpr std::uint32_t kMachPortDescriptorSize = 12;
        constexpr std::uint32_t kNdrSize = 8;
        constexpr std::uint32_t kI32Size = 4;
        constexpr std::uint32_t kTaskGetExceptionPortsId = 3414;
        constexpr std::uint32_t kTaskGetExceptionPortsReplyId = 3514;
        constexpr std::uint32_t kMachMsgBitsCopySendMakeSendOnce =
            19U | (21U << 8);
        constexpr std::uint32_t kMachMsgBitsComplex = 0x80000000U;
        constexpr std::int32_t kMigReplyMismatch = -301;

        AllocaInst *Msg =
            B.CreateAlloca(MsgTy, nullptr, Name + ".mig.message");
        B.CreateMemSet(Msg, ConstantInt::get(I8, 0),
                       ConstantInt::get(IP, kMessageBufferSize), MaybeAlign(4));
        auto gepI8 = [&](IRBuilder<> &Builder, Value *Offset,
                         const Twine &GepName) -> Value * {
            return Builder.CreateInBoundsGEP(I8, Msg, Offset, GepName);
        };
        auto gepI8Const = [&](IRBuilder<> &Builder, std::uint32_t Offset,
                              const Twine &GepName) -> Value * {
            return gepI8(Builder, ConstantInt::get(IP, Offset), GepName);
        };
        auto loadI32At = [&](IRBuilder<> &Builder, Value *Offset,
                             const Twine &LoadName) -> LoadInst * {
            Value *Ptr = gepI8(Builder, Offset, LoadName + ".ptr");
            return Builder.CreateAlignedLoad(I32, Ptr, Align(4), LoadName);
        };
        auto loadI32AtConst = [&](IRBuilder<> &Builder, std::uint32_t Offset,
                                  const Twine &LoadName) -> LoadInst * {
            Value *Ptr = gepI8Const(Builder, Offset, LoadName + ".ptr");
            return Builder.CreateAlignedLoad(I32, Ptr, Align(4), LoadName);
        };

        Value *ReplyPort =
            emitDarwinMachTrap0(B, M, TT, -26, Name + ".reply_port");
        Value *ReplyPort32 = B.CreateTruncOrBitCast(
            ReplyPort, I32, Name + ".reply_port.name");
        Value *Task32 = B.CreateTruncOrBitCast(Task, I32, Name + ".task.name");

        Value *ReqHeader = B.CreateStructGEP(ReqTy, Msg, 0);
        B.CreateStore(ConstantInt::get(I32, kMachMsgBitsCopySendMakeSendOnce),
                      B.CreateStructGEP(HeaderTy, ReqHeader, 0));
        B.CreateStore(ConstantInt::get(I32, kRequestSize),
                      B.CreateStructGEP(HeaderTy, ReqHeader, 1));
        B.CreateStore(Task32, B.CreateStructGEP(HeaderTy, ReqHeader, 2));
        B.CreateStore(ReplyPort32, B.CreateStructGEP(HeaderTy, ReqHeader, 3));
        B.CreateStore(ConstantInt::get(I32, 0),
                      B.CreateStructGEP(HeaderTy, ReqHeader, 4));
        B.CreateStore(ConstantInt::get(I32, kTaskGetExceptionPortsId),
                      B.CreateStructGEP(HeaderTy, ReqHeader, 5));

        Value *Ndr = B.CreateStructGEP(ReqTy, Msg, 1);
        constexpr std::array<std::uint8_t, 8> kNdrRecord = {0, 0, 0, 0,
                                                            1, 0, 0, 0};
        for (std::uint32_t I = 0; I < kNdrRecord.size(); ++I) {
            Value *Slot = B.CreateInBoundsGEP(
                NdrTy, Ndr, {ConstantInt::get(IP, 0), ConstantInt::get(IP, I)},
                Name + ".ndr");
            B.CreateStore(ConstantInt::get(I8, kNdrRecord[I]), Slot);
        }
        B.CreateStore(B.CreateTruncOrBitCast(ExceptionMask, I32),
                      B.CreateStructGEP(ReqTy, Msg, 2));

        Value *ReplyPortIP =
            B.CreateZExtOrTrunc(ReplyPort32, IP, Name + ".reply_port.ip");
        Value *MsgRc = nullptr;
        if (TT.getArch() == Triple::aarch64) {
            Value *RemoteLocal = B.CreateOr(
                B.CreateShl(ReplyPortIP, ConstantInt::get(IP, 32),
                            Name + ".msg2.local"),
                B.CreateZExtOrTrunc(Task32, IP), Name + ".msg2.ports");
            Value *TimeoutReceive = B.CreateShl(
                ReplyPortIP, ConstantInt::get(IP, 32), Name + ".msg2.receive");
            std::array<Value *, 8> Args = {
                toSyscallArg(B, Msg),
                ConstantInt::get(IP, (std::uint64_t{0x2} << 32) |
                                         (0x00000001U | 0x00000002U)),
                ConstantInt::get(IP, (std::uint64_t{kRequestSize} << 32) |
                                         kMachMsgBitsCopySendMakeSendOnce),
                RemoteLocal,
                ConstantInt::get(IP,
                                 std::uint64_t{kTaskGetExceptionPortsId}
                                     << 32),
                TimeoutReceive,
                ConstantInt::get(IP, kMessageBufferSize),
                ConstantInt::get(IP, 0),
            };
            MsgRc = emitArm64Svc8InlineAsm(
                B, M, ConstantInt::getSigned(IP, -47), Args, Name + ".mach_msg");
        } else {
            std::array<Value *, 7> Args = {
                toSyscallArg(B, Msg),
                ConstantInt::get(IP, 0x00000001U | 0x00000002U),
                ConstantInt::get(IP, kRequestSize),
                ConstantInt::get(IP, kMessageBufferSize),
                ReplyPortIP,
                ConstantInt::get(IP, 0),
                ConstantInt::get(IP, 0),
            };
            MsgRc = emitDarwinMachTrap7(B, M, TT, -31, Args,
                                        Name + ".mach_msg");
        }
        Value *MsgRc32 = B.CreateTruncOrBitCast(MsgRc, I32, Name + ".rc");

        Value *ReplyBits =
            B.CreateLoad(I32, B.CreateStructGEP(HeaderTy, Msg, 0),
                         Name + ".reply.bits");
        Value *ReplyId =
            B.CreateLoad(I32, B.CreateStructGEP(HeaderTy, Msg, 5),
                         Name + ".reply.id");
        Value *DescriptorCount =
            loadI32AtConst(B, kReplyDescriptorCountOffset,
                           Name + ".reply.descriptors");

        Value *MsgOk =
            B.CreateICmpEQ(MsgRc32, ConstantInt::get(I32, 0), Name + ".msg.ok");
        Value *IdOk = B.CreateICmpEQ(ReplyId,
                                     ConstantInt::get(I32,
                                                      kTaskGetExceptionPortsReplyId),
                                     Name + ".reply.id.ok");
        Value *ComplexOk = B.CreateICmpNE(
            B.CreateAnd(ReplyBits, ConstantInt::get(I32, kMachMsgBitsComplex),
                        Name + ".reply.complex.bit"),
            ConstantInt::get(I32, 0), Name + ".reply.complex.ok");
        Value *CountBounded =
            B.CreateICmpULE(DescriptorCount,
                            ConstantInt::get(I32, kMaxExceptionPorts),
                            Name + ".reply.descriptor_count.ok");
        Value *Ok = B.CreateAnd(MsgOk, IdOk, Name + ".ok.id");
        Ok = B.CreateAnd(Ok, ComplexOk, Name + ".ok.complex");
        Ok = B.CreateAnd(Ok, CountBounded, Name + ".ok.count");

        Function *Fn = B.GetInsertBlock()->getParent();
        BasicBlock *StartBB = B.GetInsertBlock();
        BasicBlock *ValidateBB =
            BasicBlock::Create(Ctx, (Name + ".validate").str(), Fn);
        BasicBlock *CopyInitBB =
            BasicBlock::Create(Ctx, (Name + ".copy.init").str(), Fn);
        BasicBlock *CopyLoopBB =
            BasicBlock::Create(Ctx, (Name + ".copy.loop").str(), Fn);
        BasicBlock *CopyBodyBB =
            BasicBlock::Create(Ctx, (Name + ".copy.body").str(), Fn);
        BasicBlock *CopyDoneBB =
            BasicBlock::Create(Ctx, (Name + ".copy.done").str(), Fn);
        BasicBlock *DoneBB =
            BasicBlock::Create(Ctx, (Name + ".done").str(), Fn);
        Value *FailureRc = B.CreateSelect(
            B.CreateICmpNE(MsgRc32, ConstantInt::get(I32, 0)),
            MsgRc32, ConstantInt::getSigned(I32, kMigReplyMismatch),
            Name + ".failure");
        B.CreateCondBr(Ok, ValidateBB, DoneBB);

        IRBuilder<> VB(ValidateBB);
        Value *DescriptorCountIP = VB.CreateZExtOrTrunc(
            DescriptorCount, IP, Name + ".reply.descriptors.ip");
        Value *DescriptorBytes = VB.CreateMul(
            DescriptorCountIP,
            ConstantInt::get(IP, kMachPortDescriptorSize),
            Name + ".reply.descriptor.bytes");
        Value *NdrOffset =
            VB.CreateAdd(ConstantInt::get(IP, kReplyDescriptorsOffset),
                         DescriptorBytes, Name + ".reply.ndr.offset");
        Value *ReplyCountOffset =
            VB.CreateAdd(NdrOffset, ConstantInt::get(IP, kNdrSize),
                         Name + ".reply.count.offset");
        Value *ReplyCount =
            loadI32At(VB, ReplyCountOffset, Name + ".reply.count.dynamic");
        Value *CountMatches = VB.CreateICmpEQ(
            ReplyCount, DescriptorCount, Name + ".reply.count.match");
        Value *ArrayBytes =
            VB.CreateMul(DescriptorCountIP, ConstantInt::get(IP, kI32Size),
                         Name + ".reply.array.bytes");
        Value *MasksOffset =
            VB.CreateAdd(ReplyCountOffset, ConstantInt::get(IP, kI32Size),
                         Name + ".reply.masks.offset");
        Value *BehaviorsOffset =
            VB.CreateAdd(MasksOffset, ArrayBytes,
                         Name + ".reply.behaviors.offset");
        Value *FlavorsOffset =
            VB.CreateAdd(BehaviorsOffset, ArrayBytes,
                         Name + ".reply.flavors.offset");
        VB.CreateCondBr(CountMatches, CopyInitBB, DoneBB);

        IRBuilder<> IB(CopyInitBB);
        IB.CreateStore(DescriptorCount, MaskCount);
        IB.CreateBr(CopyLoopBB);

        IRBuilder<> LB(CopyLoopBB);
        PHINode *Index = LB.CreatePHI(I32, 2, Name + ".copy.index");
        Index->addIncoming(ConstantInt::get(I32, 0), CopyInitBB);
        Value *More = LB.CreateICmpULT(Index, DescriptorCount,
                                       Name + ".copy.more");
        LB.CreateCondBr(More, CopyBodyBB, CopyDoneBB);

        IRBuilder<> CB(CopyBodyBB);
        Value *IndexIP =
            CB.CreateZExtOrTrunc(Index, IP, Name + ".copy.index.ip");
        Value *EntryBytes =
            CB.CreateMul(IndexIP, ConstantInt::get(IP, kI32Size),
                         Name + ".copy.entry.bytes");
        Value *DescBytes =
            CB.CreateMul(IndexIP,
                         ConstantInt::get(IP, kMachPortDescriptorSize),
                         Name + ".copy.descriptor.bytes");
        Value *HandlerOffset =
            CB.CreateAdd(ConstantInt::get(IP, kReplyDescriptorsOffset),
                         DescBytes, Name + ".copy.handler.offset");
        Value *MaskOffset =
            CB.CreateAdd(MasksOffset, EntryBytes, Name + ".copy.mask.offset");
        Value *BehaviorOffset = CB.CreateAdd(
            BehaviorsOffset, EntryBytes, Name + ".copy.behavior.offset");
        Value *FlavorOffset =
            CB.CreateAdd(FlavorsOffset, EntryBytes, Name + ".copy.flavor.offset");

        Value *Mask = loadI32At(CB, MaskOffset, Name + ".copy.mask");
        CB.CreateStore(Mask, CB.CreateInBoundsGEP(I32, Masks, IndexIP,
                                                  Name + ".copy.mask.out"));

        Value *Handler = loadI32At(CB, HandlerOffset, Name + ".copy.handler");
        CB.CreateStore(Handler, CB.CreateInBoundsGEP(I32, Handlers, IndexIP,
                                                     Name + ".copy.handler.out"));

        Value *Behavior =
            loadI32At(CB, BehaviorOffset, Name + ".copy.behavior");
        CB.CreateStore(
            Behavior,
            CB.CreateInBoundsGEP(I32, Behaviors, IndexIP,
                                 Name + ".copy.behavior.out"));

        Value *Flavor = loadI32At(CB, FlavorOffset, Name + ".copy.flavor");
        CB.CreateStore(Flavor, CB.CreateInBoundsGEP(I32, Flavors, IndexIP,
                                                    Name + ".copy.flavor.out"));

        Value *Next = CB.CreateAdd(Index, ConstantInt::get(I32, 1),
                                   Name + ".copy.next");
        Index->addIncoming(Next, CopyBodyBB);
        CB.CreateBr(CopyLoopBB);

        IRBuilder<> DB(CopyDoneBB);
        DB.CreateBr(DoneBB);

        B.SetInsertPoint(DoneBB);
        PHINode *Result = B.CreatePHI(I32, 3, Name + ".direct.rc");
        Result->addIncoming(ConstantInt::get(I32, 0), CopyDoneBB);
        Result->addIncoming(FailureRc, StartBB);
        Result->addIncoming(FailureRc, ValidateBB);
        return Result;
    }

    auto *I32 = Type::getInt32Ty(M.getContext());
    auto *Ptr = PointerType::getUnqual(M.getContext());
    FunctionCallee TaskGetExceptionPorts = M.getOrInsertFunction(
        "task_get_exception_ports",
        FunctionType::get(I32, {I32, I32, Ptr, Ptr, Ptr, Ptr, Ptr}, false));
    return B.CreateCall(TaskGetExceptionPorts,
                        {B.CreateTruncOrBitCast(Task, I32),
                         B.CreateTruncOrBitCast(ExceptionMask, I32), Masks,
                         MaskCount, Handlers, Behaviors, Flavors},
                        Name + ".import");
}

Value *emitLinuxReadlink(IRBuilder<> &B, Module &M, const Triple &TT,
                         Value *Path, Value *Buf, Value *Size) {
    LinuxCleanCopySyscalls Sys;
    if (useDirectLinuxSyscalls(M, TT) && lookupLinuxCleanCopySyscalls(TT, Sys))
        return emitLinuxSyscall(B, M, TT, Sys.readlink, {Path, Buf, Size});
    return B.CreateCall(readlinkDecl(M), {Path, Buf, Size},
                        "morok.clean.readlink");
}

Value *emitLinuxLseek(IRBuilder<> &B, Module &M, const Triple &TT, Value *Fd,
                      std::int64_t Offset, std::int32_t Whence) {
    LinuxCleanCopySyscalls Sys;
    if (useDirectLinuxSyscalls(M, TT) && lookupLinuxCleanCopySyscalls(TT, Sys))
        return emitLinuxSyscall(
            B, M, TT, Sys.lseek,
            {Fd, ConstantInt::getSigned(platformWordTy(M), Offset),
             ConstantInt::getSigned(Type::getInt32Ty(M.getContext()), Whence)});
    return B.CreateCall(
        lseekDecl(M),
        {B.CreateTruncOrBitCast(Fd, Type::getInt32Ty(M.getContext())),
         ConstantInt::getSigned(platformWordTy(M), Offset),
         ConstantInt::getSigned(Type::getInt32Ty(M.getContext()), Whence)},
        "morok.clean.lseek");
}

Value *emitLinuxMmapAddr(IRBuilder<> &B, Module &M, const Triple &TT,
                         Value *Size, Value *Fd) {
    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *IP = platformWordTy(M);
    auto *Ptr = PointerType::getUnqual(Ctx);
    constexpr std::uint32_t kProtRead = 1;
    constexpr std::uint32_t kMapPrivate = 2;

    LinuxCleanCopySyscalls Sys;
    if (useDirectLinuxSyscalls(M, TT) && lookupLinuxCleanCopySyscalls(TT, Sys))
        return emitLinuxSyscall(B, M, TT, Sys.mmap,
                                {ConstantPointerNull::get(Ptr), Size,
                                 ConstantInt::get(I32, kProtRead),
                                 ConstantInt::get(I32, kMapPrivate), Fd,
                                 ConstantInt::get(IP, 0)});

    Value *Mapped = B.CreateCall(
        mmapDecl(M),
        {ConstantPointerNull::get(Ptr), Size, ConstantInt::get(I32, kProtRead),
         ConstantInt::get(I32, kMapPrivate), B.CreateTruncOrBitCast(Fd, I32),
         ConstantInt::get(IP, 0)},
        "morok.clean.mmap");
    return B.CreatePtrToInt(Mapped, IP);
}

void emitLinuxMunmap(IRBuilder<> &B, Module &M, const Triple &TT, Value *Addr,
                     Value *Size) {
    LinuxCleanCopySyscalls Sys;
    if (useDirectLinuxSyscalls(M, TT) && lookupLinuxCleanCopySyscalls(TT, Sys)) {
        emitLinuxSyscall(B, M, TT, Sys.munmap, {Addr, Size});
        return;
    }
    B.CreateCall(
        munmapDecl(M),
        {B.CreateIntToPtr(Addr, PointerType::getUnqual(M.getContext())), Size});
}

Value *emitLinuxMprotect(IRBuilder<> &B, Module &M, const Triple &TT,
                         Value *Addr, Value *Size, Value *Prot) {
    std::uint32_t MprotectNr = 0;
    if (TT.getArch() == Triple::x86_64)
        MprotectNr = 10;
    if (useDirectLinuxSyscalls(M, TT) && MprotectNr != 0)
        return B.CreateTruncOrBitCast(
            emitLinuxSyscall(B, M, TT, MprotectNr, {Addr, Size, Prot}),
            Type::getInt32Ty(M.getContext()));

    auto *I32 = Type::getInt32Ty(M.getContext());
    auto *Ptr = PointerType::getUnqual(M.getContext());
    return B.CreateCall(mprotectDecl(M), {B.CreateIntToPtr(Addr, Ptr), Size,
                                          B.CreateTruncOrBitCast(Prot, I32)});
}

void emitLinuxClose(IRBuilder<> &B, Module &M, const Triple &TT, Value *Fd) {
    LinuxCoreSyscalls Sys;
    if (lookupLinuxCoreSyscalls(TT, Sys)) {
        emitLinuxSyscall(B, M, TT, Sys.close, {Fd});
        return;
    }
    B.CreateCall(closeDecl(M), {B.CreateTruncOrBitCast(
                                   Fd, Type::getInt32Ty(M.getContext()))});
}

Value *emitDarwinOpen(IRBuilder<> &B, Module &M, const Triple &TT, Value *Path,
                      std::int32_t Flags, std::int32_t Mode) {
    auto *I32 = Type::getInt32Ty(M.getContext());
    if (useDirectDarwinSyscalls(M, TT))
        return B.CreateTruncOrBitCast(
            emitDarwinSyscall(B, M, TT, 5,
                              {Path, ConstantInt::getSigned(I32, Flags),
                               ConstantInt::getSigned(I32, Mode)}),
            I32);
    return B.CreateCall(openDecl(M),
                        {Path, ConstantInt::getSigned(I32, Flags),
                         ConstantInt::getSigned(I32, Mode)},
                        "morok.clean.open");
}

void emitDarwinClose(IRBuilder<> &B, Module &M, const Triple &TT, Value *Fd) {
    if (useDirectDarwinSyscalls(M, TT)) {
        emitDarwinSyscall(B, M, TT, 6, {Fd});
        return;
    }
    B.CreateCall(closeDecl(M), {B.CreateTruncOrBitCast(
                                   Fd, Type::getInt32Ty(M.getContext()))});
}

Value *emitDarwinLseek(IRBuilder<> &B, Module &M, const Triple &TT, Value *Fd,
                       std::int64_t Offset, std::int32_t Whence) {
    auto *I32 = Type::getInt32Ty(M.getContext());
    if (useDirectDarwinSyscalls(M, TT))
        return emitDarwinSyscall(B, M, TT, 199,
                                 {Fd, ConstantInt::getSigned(platformWordTy(M),
                                                             Offset),
                                  ConstantInt::getSigned(I32, Whence)});
    return B.CreateCall(lseekDecl(M),
                        {B.CreateTruncOrBitCast(Fd, I32),
                         ConstantInt::getSigned(platformWordTy(M), Offset),
                         ConstantInt::getSigned(I32, Whence)},
                        "morok.clean.lseek");
}

Value *emitDarwinMmap(IRBuilder<> &B, Module &M, const Triple &TT, Value *Size,
                      Value *Fd) {
    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *IP = platformWordTy(M);
    auto *Ptr = PointerType::getUnqual(Ctx);
    constexpr std::uint32_t kProtRead = 1;
    constexpr std::uint32_t kMapPrivate = 2;

    if (useDirectDarwinSyscalls(M, TT)) {
        Value *Addr = emitDarwinSyscall(
            B, M, TT, 197,
            {ConstantPointerNull::get(Ptr), Size, ConstantInt::get(I32, kProtRead),
             ConstantInt::get(I32, kMapPrivate), Fd, ConstantInt::get(IP, 0)});
        return B.CreateIntToPtr(Addr, Ptr, "morok.clean.mmap.ptr");
    }

    return B.CreateCall(
        mmapDecl(M),
        {ConstantPointerNull::get(Ptr), Size, ConstantInt::get(I32, kProtRead),
         ConstantInt::get(I32, kMapPrivate), B.CreateTruncOrBitCast(Fd, I32),
         ConstantInt::get(IP, 0)},
        "morok.clean.mmap");
}

void emitDarwinMunmap(IRBuilder<> &B, Module &M, const Triple &TT,
                      Value *Mapped, Value *Size) {
    if (useDirectDarwinSyscalls(M, TT)) {
        emitDarwinSyscall(B, M, TT, 73, {Mapped, Size});
        return;
    }
    B.CreateCall(munmapDecl(M), {Mapped, Size});
}

Value *emitDarwinMprotect(IRBuilder<> &B, Module &M, const Triple &TT,
                          Value *Addr, Value *Size, Value *Prot) {
    auto *I32 = Type::getInt32Ty(M.getContext());
    if (useDirectDarwinSyscalls(M, TT))
        return B.CreateTruncOrBitCast(
            emitDarwinSyscall(B, M, TT, 74, {Addr, Size, Prot}), I32);

    auto *Ptr = PointerType::getUnqual(M.getContext());
    return B.CreateCall(mprotectDecl(M), {B.CreateIntToPtr(Addr, Ptr), Size,
                                          B.CreateTruncOrBitCast(Prot, I32)});
}

Value *emitPosixAnonMmapAddr(IRBuilder<> &B, Module &M, const Triple &TT,
                             Value *Size, Value *Prot, Value *Flags,
                             const Twine &Name) {
    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *IP = platformWordTy(M);
    auto *Ptr = PointerType::getUnqual(Ctx);
    if (TT.isOSLinux() && useDirectLinuxSyscalls(M, TT))
        return emitLinuxSyscall(B, M, TT, 9,
                                {ConstantPointerNull::get(Ptr), Size, Prot,
                                 Flags, ConstantInt::getSigned(I32, -1),
                                 ConstantInt::get(IP, 0)});
    if (TT.isOSDarwin() && useDirectDarwinSyscalls(M, TT))
        return emitDarwinSyscall(B, M, TT, 197,
                                 {ConstantPointerNull::get(Ptr), Size, Prot,
                                  Flags, ConstantInt::getSigned(I32, -1),
                                  ConstantInt::get(IP, 0)});

    Value *Mapped = B.CreateCall(
        mmapDecl(M),
        {ConstantPointerNull::get(Ptr), Size, B.CreateTruncOrBitCast(Prot, I32),
         B.CreateTruncOrBitCast(Flags, I32), ConstantInt::getSigned(I32, -1),
         ConstantInt::get(IP, 0)},
        Name);
    return B.CreatePtrToInt(Mapped, IP, Name + ".addr");
}

Value *emitPosixMprotect(IRBuilder<> &B, Module &M, const Triple &TT,
                         Value *Addr, Value *Size, Value *Prot) {
    if (TT.isOSLinux())
        return emitLinuxMprotect(B, M, TT, Addr, Size, Prot);
    if (TT.isOSDarwin())
        return emitDarwinMprotect(B, M, TT, Addr, Size, Prot);
    return B.CreateCall(
        mprotectDecl(M),
        {B.CreateIntToPtr(Addr, PointerType::getUnqual(M.getContext())), Size,
         B.CreateTruncOrBitCast(Prot, Type::getInt32Ty(M.getContext()))});
}

} // namespace morok::runtime
