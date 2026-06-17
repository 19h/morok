// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/HashGatedSelfDecrypt.cpp
//
// IR-safe hash-gated self-decrypting blocks.  Native block encryption requires
// post-link addresses and W^X cooperation, so this pass implements the
// roadmap's bytecode route: selected VM bytecode globals receive an outer
// encrypted layer, a mutable payload, and a per-invocation decryptor gated by a
// runtime hash of the still-encrypted payload.  The VM helper decrypts before
// reading bytecode and seals the payload again before returning.

#include "morok/passes/HashGatedSelfDecrypt.hpp"

#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Support/ModRef.h"
#include "llvm/TargetParser/Triple.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr StringLiteral kBytecodePrefix("morok.vm.bytecode.");

using Builder = IRBuilder<NoFolder>;

struct StreamSchedule {
    std::uint64_t key = 0;
    std::uint64_t key_mask = 0;
    std::uint64_t hash_seed = 0;
    std::uint64_t expected_hash = 0;
    std::uint32_t mul = 1;
    std::uint32_t add = 0;
    std::uint8_t xork = 0;
};

struct Payload {
    GlobalVariable *bytecode = nullptr;
    Function *helper = nullptr;
    std::string suffix;
    std::vector<std::uint8_t> original;
};

std::uint64_t hashStep(std::uint64_t H, std::uint8_t B) {
    H ^= static_cast<std::uint64_t>(B);
    H *= 0xff51afd7ed558ccdULL;
    H ^= H >> 32;
    H *= 0xc4ceb9fe1a85ec53ULL;
    H ^= H >> 29;
    return H;
}

std::uint64_t hashBytes(ArrayRef<std::uint8_t> Bytes, std::uint64_t Seed) {
    std::uint64_t H = Seed;
    for (std::uint8_t B : Bytes)
        H = hashStep(H, B);
    return H;
}

std::uint8_t keyByte(std::uint32_t Offset, std::uint64_t Key,
                     const StreamSchedule &S) {
    std::uint64_t X = Key + S.add;
    X += static_cast<std::uint64_t>(Offset) * S.mul;
    X ^= X >> 11;
    X ^= X >> 29;
    return static_cast<std::uint8_t>(X) ^ S.xork;
}

StreamSchedule makeSchedule(ir::IRRandom &Rng) {
    StreamSchedule S;
    S.key = Rng.next();
    S.hash_seed = Rng.next();
    S.mul = static_cast<std::uint32_t>(Rng.next()) | 1u;
    S.add = static_cast<std::uint32_t>(Rng.next());
    S.xork = static_cast<std::uint8_t>(Rng.next());
    return S;
}

Value *emitHashStep(Builder &B, Value *H, Value *Byte) {
    auto *I64 = B.getInt64Ty();
    Value *Wide = B.CreateZExt(Byte, I64, "morok.sdb.hash.byte");
    Value *X = B.CreateXor(H, Wide, "morok.sdb.hash.mix");
    X = B.CreateMul(X, ConstantInt::get(I64, 0xff51afd7ed558ccdULL),
                    "morok.sdb.hash.mix");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 32)),
                    "morok.sdb.hash.mix");
    X = B.CreateMul(X, ConstantInt::get(I64, 0xc4ceb9fe1a85ec53ULL),
                    "morok.sdb.hash.mix");
    return B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 29)),
                       "morok.sdb.hash.mix");
}

Value *emitKeyByte(Builder &B, Value *Index, Value *ComputedHash,
                   Value *KeyMask, Value *ContextZero,
                   const StreamSchedule &S) {
    auto *I64 = B.getInt64Ty();
    auto *I8 = B.getInt8Ty();
    Value *Idx64 = B.CreateZExt(Index, I64, "morok.sdb.key.idx");
    Value *Key = B.CreateXor(ComputedHash, KeyMask, "morok.sdb.key.gate");
    Key = B.CreateXor(Key, ContextZero, "morok.sdb.key.context");
    Value *X =
        B.CreateAdd(Key, ConstantInt::get(I64, S.add), "morok.sdb.key.mix");
    X = B.CreateAdd(
        X,
        B.CreateMul(Idx64, ConstantInt::get(I64, S.mul), "morok.sdb.key.mul"),
        "morok.sdb.key.mix");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 11)),
                    "morok.sdb.key.mix");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 29)),
                    "morok.sdb.key.mix");
    Value *K = B.CreateTrunc(X, I8, "morok.sdb.key.trunc");
    return B.CreateXor(K, ConstantInt::get(I8, S.xork), "morok.sdb.key");
}

std::vector<std::uint8_t> outerEncrypt(ArrayRef<std::uint8_t> Inner,
                                       StreamSchedule &S) {
    std::vector<std::uint8_t> Outer;
    Outer.reserve(Inner.size());
    for (std::uint32_t I = 0; I < Inner.size(); ++I)
        Outer.push_back(
            static_cast<std::uint8_t>(Inner[I] ^ keyByte(I, S.key, S)));
    S.expected_hash = hashBytes(Outer, S.hash_seed);
    S.key_mask = S.key ^ S.expected_hash;
    return Outer;
}

void addRuntimeAttrs(Function *F) {
    F->addFnAttr(Attribute::NoInline);
    F->addFnAttr(Attribute::OptimizeNone);
    F->setMemoryEffects(MemoryEffects::unknown());
}

Function *helperFor(Module &M, StringRef Suffix) {
    return M.getFunction(std::string("morok.vm.") + Suffix.str() + ".exec");
}

std::vector<std::uint8_t> readBytes(GlobalVariable &GV) {
    std::vector<std::uint8_t> Bytes;
    auto *Data = dyn_cast<ConstantDataArray>(GV.getInitializer());
    if (!Data)
        return Bytes;
    Bytes.reserve(Data->getNumElements());
    for (unsigned I = 0; I < Data->getNumElements(); ++I)
        Bytes.push_back(
            static_cast<std::uint8_t>(Data->getElementAsInteger(I)));
    return Bytes;
}

std::vector<Payload> collectPayloads(Module &M) {
    std::vector<Payload> Payloads;
    for (GlobalVariable &GV : M.globals()) {
        if (!GV.getName().starts_with(kBytecodePrefix))
            continue;
        if (!GV.hasInitializer() || !GV.isConstant())
            continue;
        auto *ArrTy = dyn_cast<ArrayType>(GV.getValueType());
        if (!ArrTy || !ArrTy->getElementType()->isIntegerTy(8) ||
            ArrTy->getNumElements() == 0)
            continue;
        std::string Suffix =
            GV.getName().drop_front(kBytecodePrefix.size()).str();
        Function *Helper = helperFor(M, Suffix);
        if (!Helper || Helper->isDeclaration())
            continue;
        const std::string EnsureName = "morok.sdb.ensure." + Suffix;
        if (M.getFunction(EnsureName))
            continue;
        std::vector<std::uint8_t> Bytes = readBytes(GV);
        if (Bytes.empty())
            continue;
        Payloads.push_back({&GV, Helper, std::move(Suffix), std::move(Bytes)});
    }
    return Payloads;
}

void shufflePayloads(std::vector<Payload> &Payloads, ir::IRRandom &Rng) {
    for (std::size_t I = Payloads.size(); I > 1; --I) {
        const std::size_t J = Rng.range(static_cast<std::uint32_t>(I));
        std::swap(Payloads[I - 1], Payloads[J]);
    }
}

void makeMutablePayload(GlobalVariable &GV, ArrayRef<std::uint8_t> Outer) {
    auto &Ctx = GV.getContext();
    auto *Init = ConstantDataArray::get(
        Ctx, ArrayRef<std::uint8_t>(Outer.data(), Outer.size()));
    GV.setInitializer(Init);
    GV.setConstant(false);
    GV.setUnnamedAddr(GlobalValue::UnnamedAddr::None);
    GV.setAlignment(Align(1));
}

GlobalVariable *createReady(Module &M, StringRef Suffix) {
    auto *I1 = Type::getInt1Ty(M.getContext());
    auto *Ready = new GlobalVariable(
        M, I1, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I1, false), ("morok.sdb.ready." + Suffix).str());
    Ready->setAlignment(Align(1));
    return Ready;
}

GlobalVariable *createI1State(Module &M, StringRef Name, bool Initial) {
    auto *I1 = Type::getInt1Ty(M.getContext());
    auto *State = new GlobalVariable(M, I1, /*isConstant=*/false,
                                     GlobalValue::PrivateLinkage,
                                     ConstantInt::get(I1, Initial), Name.str());
    State->setAlignment(Align(1));
    return State;
}

GlobalVariable *createI64State(Module &M, StringRef Name,
                               std::uint64_t Initial) {
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *State = new GlobalVariable(
        M, I64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I64, Initial), Name.str());
    State->setAlignment(Align(8));
    return State;
}

Value *payloadPtr(Builder &B, GlobalVariable *Payload, Value *Idx) {
    auto *I32 = B.getInt32Ty();
    auto *ArrTy = cast<ArrayType>(Payload->getValueType());
    return B.CreateInBoundsGEP(ArrTy, Payload, {ConstantInt::get(I32, 0), Idx},
                               "morok.sdb.payload.ptr");
}

Value *asI64(Builder &B, Value *V) {
    auto *I64 = B.getInt64Ty();
    Type *Ty = V->getType();
    if (Ty->isIntegerTy()) {
        auto *IT = cast<IntegerType>(Ty);
        if (IT->getBitWidth() == 64)
            return V;
        if (IT->getBitWidth() < 64)
            return B.CreateZExt(V, I64, "morok.sdb.context.arg");
        return B.CreateTrunc(V, I64, "morok.sdb.context.arg");
    }
    if (Ty->isPointerTy())
        return B.CreatePtrToInt(V, I64, "morok.sdb.context.ptr");
    return ConstantInt::get(I64, 0);
}

Value *volatileStableZero(Builder &B, Value *V, StringRef Name) {
    auto *I64 = B.getInt64Ty();
    Value *Wide = asI64(B, V);
    auto *Slot = B.CreateAlloca(I64, nullptr, "morok.sdb.env.slot");
    Slot->setAlignment(Align(8));
    auto *Store = B.CreateStore(Wide, Slot);
    Store->setVolatile(true);
    Store->setAlignment(Align(8));
    auto *A = B.CreateLoad(I64, Slot, Twine(Name) + ".a");
    A->setVolatile(true);
    A->setAlignment(Align(8));
    auto *C = B.CreateLoad(I64, Slot, Twine(Name) + ".b");
    C->setVolatile(true);
    C->setAlignment(Align(8));
    Value *Delta = B.CreateXor(A, C, "morok.sdb.env.zero");
    return B.CreateMul(Delta, ConstantInt::get(I64, 0x9e3779b97f4a7c15ULL),
                       "morok.sdb.env.mix");
}

Value *volatileStableValue(Builder &B, Value *V, StringRef Name) {
    auto *I64 = B.getInt64Ty();
    Value *Wide = asI64(B, V);
    auto *Slot = B.CreateAlloca(I64, nullptr, "morok.sdb.env.value.slot");
    Slot->setAlignment(Align(8));
    auto *Store = B.CreateStore(Wide, Slot);
    Store->setVolatile(true);
    Store->setAlignment(Align(8));
    auto *Loaded = B.CreateLoad(I64, Slot, Twine(Name) + ".value");
    Loaded->setVolatile(true);
    Loaded->setAlignment(Align(8));
    return Loaded;
}

Value *mixEnvironmentValue(Builder &B, Value *Acc, Value *V, StringRef Name) {
    auto *I64 = B.getInt64Ty();
    Value *X =
        B.CreateXor(Acc, volatileStableValue(B, V, Name), "morok.sdb.env.live");
    X = B.CreateMul(X, ConstantInt::get(I64, 0xbf58476d1ce4e5b9ULL),
                    "morok.sdb.env.live");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 31)),
                    "morok.sdb.env.live");
    return B.CreateMul(X, ConstantInt::get(I64, 0x94d049bb133111ebULL),
                       "morok.sdb.env.live");
}

bool isX86Target(const Triple &TT) {
    return TT.getArch() == Triple::x86 || TT.getArch() == Triple::x86_64;
}

Value *emitCpuidProbe(Builder &B, Module &M, Value *Leaf, Value *Subleaf) {
    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *CpuidTy = StructType::get(Ctx, {I32, I32, I32, I32});
    auto *AsmTy = FunctionType::get(CpuidTy, {I32, I32}, false);
    InlineAsm *Cpuid = InlineAsm::get(
        AsmTy, "cpuid",
        "={eax},={ebx},={ecx},={edx},{eax},{ecx},~{dirflag},~{fpsr},~{flags}",
        /*hasSideEffects=*/true);
    return B.CreateCall(AsmTy, Cpuid, {Leaf, Subleaf}, "morok.sdb.env.cpuid");
}

Value *emitRdtscpProbe(Builder &B, Module &M) {
    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *PairTy = StructType::get(Ctx, {I32, I32});
    auto *AsmTy = FunctionType::get(PairTy, false);
    InlineAsm *Rdtscp =
        InlineAsm::get(AsmTy, "lfence\nrdtscp\nlfence",
                       "={eax},={edx},~{ecx},~{dirflag},~{fpsr},~{flags}",
                       /*hasSideEffects=*/true);
    Value *Pair = B.CreateCall(AsmTy, Rdtscp, {}, "morok.sdb.env.rdtscp");
    Value *Lo = B.CreateExtractValue(Pair, {0}, "morok.sdb.env.tsc.lo");
    Value *Hi = B.CreateExtractValue(Pair, {1}, "morok.sdb.env.tsc.hi");
    return B.CreateOr(
        B.CreateZExt(Lo, I64),
        B.CreateShl(B.CreateZExt(Hi, I64), ConstantInt::get(I64, 32)),
        "morok.sdb.env.tsc");
}

Value *emitCycleProbe(Builder &B, Module &M) {
    Function *ReadCycle =
        Intrinsic::getOrInsertDeclaration(&M, Intrinsic::readcyclecounter);
    return B.CreateCall(ReadCycle, {}, "morok.sdb.env.cycle");
}

Value *packRegs64(Builder &B, Value *High, Value *Low, const Twine &Name) {
    auto *I64 = B.getInt64Ty();
    return B.CreateOr(
        B.CreateShl(B.CreateZExt(High, I64), ConstantInt::get(I64, 32)),
        B.CreateZExt(Low, I64), Name);
}

Value *toSyscallArg(Builder &B, Value *V) {
    auto *I64 = B.getInt64Ty();
    if (V->getType()->isPointerTy())
        return B.CreatePtrToInt(V, I64, "morok.sdb.env.sys.arg");
    if (V->getType()->isIntegerTy(64))
        return V;
    if (V->getType()->isIntegerTy()) {
        auto *IT = cast<IntegerType>(V->getType());
        if (IT->getBitWidth() < 64)
            return B.CreateZExt(V, I64, "morok.sdb.env.sys.arg");
        return B.CreateTrunc(V, I64, "morok.sdb.env.sys.arg");
    }
    return ConstantInt::get(I64, 0);
}

Value *emitLinuxX64Syscall(Builder &B, std::uint64_t Number,
                           ArrayRef<Value *> Args) {
    auto *I64 = B.getInt64Ty();
    SmallVector<Value *, 7> CallArgs;
    CallArgs.push_back(ConstantInt::get(I64, Number));
    for (unsigned I = 0; I != 6; ++I)
        CallArgs.push_back(I < Args.size() ? toSyscallArg(B, Args[I])
                                           : ConstantInt::get(I64, 0));

    SmallVector<Type *, 7> Params(7, I64);
    auto *AsmTy = FunctionType::get(I64, Params, false);
    InlineAsm *Syscall = InlineAsm::get(
        AsmTy, "syscall",
        "={rax},{rax},{rdi},{rsi},{rdx},{r10},{r8},{r9},~{rcx},~{r11},"
        "~{memory},~{dirflag},~{fpsr},~{flags}",
        /*hasSideEffects=*/true);
    return B.CreateCall(AsmTy, Syscall, CallArgs, "morok.sdb.env.syscall");
}

Value *bytePtrAt(Builder &B, Value *Base, std::uint64_t Offset,
                 const Twine &Name) {
    auto *I8 = B.getInt8Ty();
    auto *I64 = B.getInt64Ty();
    return B.CreateInBoundsGEP(I8, Base, ConstantInt::get(I64, Offset), Name);
}

Value *loadI64At(Builder &B, Value *Base, std::uint64_t Offset,
                 const Twine &Name) {
    auto *I64 = B.getInt64Ty();
    auto *Load = B.CreateLoad(
        I64, bytePtrAt(B, Base, Offset, Twine(Name) + ".ptr"), Name);
    Load->setVolatile(true);
    Load->setAlignment(Align(1));
    return Load;
}

Value *emitLinuxVolumeFingerprint(Builder &B) {
    auto *I8 = B.getInt8Ty();
    auto *I64 = B.getInt64Ty();
    auto *PathTy = ArrayType::get(I8, 2);
    auto *BufTy = ArrayType::get(I8, 256);
    auto *Path = B.CreateAlloca(PathTy, nullptr, "morok.sdb.env.volume.path");
    Path->setAlignment(Align(1));
    auto *Buf = B.CreateAlloca(BufTy, nullptr, "morok.sdb.env.volume.buf");
    Buf->setAlignment(Align(8));
    Value *PathPtr = B.CreateInBoundsGEP(
        PathTy, Path, {ConstantInt::get(I64, 0), ConstantInt::get(I64, 0)},
        "morok.sdb.env.volume.path.ptr");
    Value *BufPtr = B.CreateInBoundsGEP(
        BufTy, Buf, {ConstantInt::get(I64, 0), ConstantInt::get(I64, 0)},
        "morok.sdb.env.volume.buf.ptr");

    B.CreateStore(ConstantInt::get(I8, '/'),
                  bytePtrAt(B, PathPtr, 0, "morok.sdb.env.volume"));
    B.CreateStore(ConstantInt::get(I8, 0),
                  bytePtrAt(B, PathPtr, 1, "morok.sdb.env.volume"));
    auto *ZeroType =
        B.CreateStore(ConstantInt::get(I64, 0),
                      bytePtrAt(B, BufPtr, 0, "morok.sdb.env.volume.type"));
    ZeroType->setAlignment(Align(1));
    auto *ZeroFsid =
        B.CreateStore(ConstantInt::get(I64, 0),
                      bytePtrAt(B, BufPtr, 16, "morok.sdb.env.volume.fsid"));
    ZeroFsid->setAlignment(Align(1));

    Value *Ret = emitLinuxX64Syscall(B, 137, {PathPtr, BufPtr});
    Value *FsType = loadI64At(B, BufPtr, 0, "morok.sdb.env.volume.type");
    Value *FsId = loadI64At(B, BufPtr, 16, "morok.sdb.env.volume.fsid");
    Value *Ok = B.CreateICmpEQ(Ret, ConstantInt::get(I64, 0),
                               "morok.sdb.env.volume.ok");
    FsType = B.CreateSelect(Ok, FsType, ConstantInt::get(I64, 0),
                            "morok.sdb.env.volume.type.live");
    FsId = B.CreateSelect(Ok, FsId, ConstantInt::get(I64, 0),
                          "morok.sdb.env.volume.fsid.live");
    Value *Rot = B.CreateOr(B.CreateShl(FsId, ConstantInt::get(I64, 17)),
                            B.CreateLShr(FsId, ConstantInt::get(I64, 47)),
                            "morok.sdb.env.volume.rot");
    return B.CreateXor(FsType, Rot, "morok.sdb.env.volume.live");
}

Value *emitEnvironmentZero(Builder &B, Module &M, Function *Fn,
                           GlobalVariable *Payload) {
    auto *I32 = B.getInt32Ty();
    auto *I64 = B.getInt64Ty();
    Value *Acc = ConstantInt::get(I64, 0);

    Value *FnAddr = B.CreatePtrToInt(Fn, I64, "morok.sdb.env.fn");
    Acc = B.CreateXor(Acc, volatileStableZero(B, FnAddr, "morok.sdb.env.fn"),
                      "morok.sdb.env.acc");
    Value *PayloadAddr =
        B.CreatePtrToInt(Payload, I64, "morok.sdb.env.payload");
    Acc = B.CreateXor(
        Acc, volatileStableZero(B, PayloadAddr, "morok.sdb.env.payload"),
        "morok.sdb.env.acc");
    Acc = B.CreateXor(
        Acc, volatileStableZero(B, emitCycleProbe(B, M), "morok.sdb.env.cycle"),
        "morok.sdb.env.acc");

    const Triple TT(M.getTargetTriple());
    if (isX86Target(TT)) {
        Value *Cpu0 = emitCpuidProbe(B, M, ConstantInt::get(I32, 0),
                                     ConstantInt::get(I32, 0));
        Value *Eax0 = B.CreateExtractValue(Cpu0, {0}, "morok.sdb.env.eax0");
        Value *Ebx0 = B.CreateExtractValue(Cpu0, {1}, "morok.sdb.env.ebx0");
        Value *Ecx0 = B.CreateExtractValue(Cpu0, {2}, "morok.sdb.env.ecx0");
        Value *Edx0 = B.CreateExtractValue(Cpu0, {3}, "morok.sdb.env.edx0");
        Acc = B.CreateXor(
            Acc,
            volatileStableZero(
                B, packRegs64(B, Eax0, Ebx0, "morok.sdb.env.cpuid.lo"),
                "morok.sdb.env.cpuid.lo"),
            "morok.sdb.env.acc");
        Acc = B.CreateXor(
            Acc,
            volatileStableZero(
                B, packRegs64(B, Ecx0, Edx0, "morok.sdb.env.cpuid.hi"),
                "morok.sdb.env.cpuid.hi"),
            "morok.sdb.env.acc");
        Acc = B.CreateXor(Acc,
                          volatileStableZero(B, emitRdtscpProbe(B, M),
                                             "morok.sdb.env.rdtscp"),
                          "morok.sdb.env.acc");
    }

    if (TT.isOSLinux() && TT.getArch() == Triple::x86_64)
        Acc = B.CreateXor(Acc,
                          volatileStableZero(B, emitLinuxVolumeFingerprint(B),
                                             "morok.sdb.env.volume"),
                          "morok.sdb.env.acc");

    return Acc;
}

Value *emitStableEnvironmentKey(Builder &B, Module &M, Function *IdentityFn,
                                GlobalVariable *Payload) {
    auto *I32 = B.getInt32Ty();
    auto *I64 = B.getInt64Ty();
    Value *Acc = ConstantInt::get(I64, 0x6a09e667f3bcc909ULL);

    Value *FnAddr =
        B.CreatePtrToInt(IdentityFn, I64, "morok.sdb.env.live.fn");
    Acc = mixEnvironmentValue(B, Acc, FnAddr, "morok.sdb.env.live.fn");
    Value *PayloadAddr =
        B.CreatePtrToInt(Payload, I64, "morok.sdb.env.live.payload");
    Acc =
        mixEnvironmentValue(B, Acc, PayloadAddr, "morok.sdb.env.live.payload");

    const Triple TT(M.getTargetTriple());
    if (isX86Target(TT)) {
        Value *Cpu0 = emitCpuidProbe(B, M, ConstantInt::get(I32, 0),
                                     ConstantInt::get(I32, 0));
        Value *Eax0 =
            B.CreateExtractValue(Cpu0, {0}, "morok.sdb.env.live.eax0");
        Value *Ebx0 =
            B.CreateExtractValue(Cpu0, {1}, "morok.sdb.env.live.ebx0");
        Value *Ecx0 =
            B.CreateExtractValue(Cpu0, {2}, "morok.sdb.env.live.ecx0");
        Value *Edx0 =
            B.CreateExtractValue(Cpu0, {3}, "morok.sdb.env.live.edx0");
        Acc = mixEnvironmentValue(
            B, Acc, packRegs64(B, Eax0, Ebx0, "morok.sdb.env.live.cpuid0.lo"),
            "morok.sdb.env.live.cpuid0.lo");
        Acc = mixEnvironmentValue(
            B, Acc, packRegs64(B, Ecx0, Edx0, "morok.sdb.env.live.cpuid0.hi"),
            "morok.sdb.env.live.cpuid0.hi");

        Value *Cpu1 = emitCpuidProbe(B, M, ConstantInt::get(I32, 1),
                                     ConstantInt::get(I32, 0));
        Value *Eax1 =
            B.CreateExtractValue(Cpu1, {0}, "morok.sdb.env.live.eax1");
        Value *Ecx1 =
            B.CreateExtractValue(Cpu1, {2}, "morok.sdb.env.live.ecx1");
        Value *Edx1 =
            B.CreateExtractValue(Cpu1, {3}, "morok.sdb.env.live.edx1");
        Acc = mixEnvironmentValue(
            B, Acc, packRegs64(B, Eax1, Ecx1, "morok.sdb.env.live.cpuid1.lo"),
            "morok.sdb.env.live.cpuid1.lo");
        Acc = mixEnvironmentValue(B, Acc, B.CreateZExt(Edx1, I64),
                                  "morok.sdb.env.live.cpuid1.hi");
    }

    if (TT.isOSLinux() && TT.getArch() == Triple::x86_64)
        Acc = mixEnvironmentValue(B, Acc, emitLinuxVolumeFingerprint(B),
                                  "morok.sdb.env.live.volume");

    return Acc;
}

Value *emitContextZero(Builder &B, Function *Fn) {
    auto *I64 = B.getInt64Ty();
    Value *Acc = ConstantInt::get(I64, 0);
    for (Argument &Arg : Fn->args()) {
        Value *Wide = asI64(B, &Arg);
        auto *Slot = B.CreateAlloca(I64, nullptr, "morok.sdb.context.slot");
        Slot->setAlignment(Align(8));
        auto *Store = B.CreateStore(Wide, Slot);
        Store->setVolatile(true);
        Store->setAlignment(Align(8));
        auto *A = B.CreateLoad(I64, Slot, "morok.sdb.context.load");
        A->setVolatile(true);
        A->setAlignment(Align(8));
        auto *C = B.CreateLoad(I64, Slot, "morok.sdb.context.load");
        C->setVolatile(true);
        C->setAlignment(Align(8));
        Value *Zero = B.CreateXor(A, C, "morok.sdb.context.zero");
        Acc = B.CreateXor(Acc, Zero, "morok.sdb.context.mix");
    }
    return Acc;
}

Function *createEnsure(Module &M, Payload &P, GlobalVariable *Ready,
                       GlobalVariable *Bound, GlobalVariable *CurrentHash,
                       GlobalVariable *CurrentKeyMask, const StreamSchedule &S,
                       bool ContextKeying) {
    LLVMContext &Ctx = M.getContext();
    auto *VoidTy = Type::getVoidTy(Ctx);
    auto *I1 = Type::getInt1Ty(Ctx);
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    const std::uint32_t Size = static_cast<std::uint32_t>(P.original.size());

    const std::string EnsureName = "morok.sdb.ensure." + P.suffix;
    SmallVector<Type *, 8> Params;
    for (Type *Ty : P.helper->getFunctionType()->params())
        Params.push_back(Ty);

    auto *Fn = Function::Create(FunctionType::get(VoidTy, Params, false),
                                GlobalValue::InternalLinkage, EnsureName, &M);
    addRuntimeAttrs(Fn);

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    BasicBlock *HashLoop = BasicBlock::Create(Ctx, "hash", Fn);
    BasicBlock *Gate = BasicBlock::Create(Ctx, "gate", Fn);
    BasicBlock *DecryptLoop = BasicBlock::Create(Ctx, "decrypt", Fn);
    BasicBlock *Decide = BasicBlock::Create(Ctx, "decide", Fn);
    BasicBlock *Fail = BasicBlock::Create(Ctx, "fail", Fn);
    BasicBlock *MarkReady = BasicBlock::Create(Ctx, "ready", Fn);
    BasicBlock *Exit = BasicBlock::Create(Ctx, "exit", Fn);

    Builder EB(Entry);
    Value *ContextZero =
        ContextKeying ? emitContextZero(EB, Fn) : ConstantInt::get(I64, 0);
    Value *EnvironmentZero = emitEnvironmentZero(EB, M, Fn, P.bytecode);
    Value *StableEnvironmentKey =
        emitStableEnvironmentKey(EB, M, P.helper, P.bytecode);
    ContextZero =
        EB.CreateXor(ContextZero, EnvironmentZero, "morok.sdb.key.env.zero");
    auto *BoundLoad = EB.CreateLoad(I1, Bound, "morok.sdb.bound.load");
    BoundLoad->setVolatile(true);
    BoundLoad->setAlignment(Align(1));
    auto *HashLoad =
        EB.CreateLoad(I64, CurrentHash, "morok.sdb.bound.hash.load");
    HashLoad->setVolatile(true);
    HashLoad->setAlignment(Align(8));
    auto *KeyMaskLoad =
        EB.CreateLoad(I64, CurrentKeyMask, "morok.sdb.bound.keymask.load");
    KeyMaskLoad->setVolatile(true);
    KeyMaskLoad->setAlignment(Align(8));
    Value *ExpectedHash = EB.CreateSelect(
        BoundLoad, HashLoad, ConstantInt::get(I64, S.expected_hash),
        "morok.sdb.bound.hash");
    Value *KeyMask = EB.CreateSelect(BoundLoad, KeyMaskLoad,
                                     ConstantInt::get(I64, S.key_mask),
                                     "morok.sdb.bound.keymask");
    Value *ActiveEnvironmentKey =
        EB.CreateSelect(BoundLoad, StableEnvironmentKey,
                        ConstantInt::get(I64, 0), "morok.sdb.key.env.live");
    ContextZero =
        EB.CreateXor(ContextZero, ActiveEnvironmentKey, "morok.sdb.key.env");
    auto *ReadyLoad = EB.CreateLoad(I1, Ready, "morok.sdb.ready.load");
    ReadyLoad->setVolatile(true);
    ReadyLoad->setAlignment(Align(1));
    EB.CreateCondBr(ReadyLoad, Fail, HashLoop);

    Builder HB(HashLoop);
    PHINode *HashI = HB.CreatePHI(I32, 2, "morok.sdb.hash.i");
    PHINode *Hash = HB.CreatePHI(I64, 2, "morok.sdb.hash");
    HashI->addIncoming(ConstantInt::get(I32, 0), Entry);
    Hash->addIncoming(ConstantInt::get(I64, S.hash_seed), Entry);
    auto *Enc = HB.CreateLoad(I8, payloadPtr(HB, P.bytecode, HashI),
                              "morok.sdb.hash.byte.enc");
    Enc->setVolatile(true);
    Enc->setAlignment(Align(1));
    Value *NextHash = emitHashStep(HB, Hash, Enc);
    Value *NextHashI =
        HB.CreateAdd(HashI, ConstantInt::get(I32, 1), "morok.sdb.hash.next");
    HashI->addIncoming(NextHashI, HashLoop);
    Hash->addIncoming(NextHash, HashLoop);
    Value *HashDone = HB.CreateICmpEQ(NextHashI, ConstantInt::get(I32, Size),
                                      "morok.sdb.hash.done");
    HB.CreateCondBr(HashDone, Gate, HashLoop);

    Builder GB(Gate);
    Value *GateOk = GB.CreateICmpEQ(NextHash, ExpectedHash, "morok.sdb.gate");
    GB.CreateBr(DecryptLoop);

    Builder FB(Fail);
    Function *Trap = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::trap);
    FB.CreateCall(Trap);
    FB.CreateUnreachable();

    Builder DB(DecryptLoop);
    PHINode *DecI = DB.CreatePHI(I32, 2, "morok.sdb.dec.i");
    DecI->addIncoming(ConstantInt::get(I32, 0), Gate);
    Value *DecPtr = payloadPtr(DB, P.bytecode, DecI);
    auto *Outer = DB.CreateLoad(I8, DecPtr, "morok.sdb.outer");
    Outer->setVolatile(true);
    Outer->setAlignment(Align(1));
    Value *Key = emitKeyByte(DB, DecI, NextHash, KeyMask, ContextZero, S);
    Value *Inner = DB.CreateXor(Outer, Key, "morok.sdb.inner");
    auto *Store = DB.CreateStore(Inner, DecPtr);
    Store->setVolatile(true);
    Store->setAlignment(Align(1));
    Value *NextDecI =
        DB.CreateAdd(DecI, ConstantInt::get(I32, 1), "morok.sdb.dec.next");
    DecI->addIncoming(NextDecI, DecryptLoop);
    Value *DecryptDone = DB.CreateICmpEQ(NextDecI, ConstantInt::get(I32, Size),
                                         "morok.sdb.dec.done");
    DB.CreateCondBr(DecryptDone, Decide, DecryptLoop);

    Builder ZB(Decide);
    ZB.CreateCondBr(GateOk, MarkReady, Fail);

    Builder RB(MarkReady);
    auto *ReadyStore = RB.CreateStore(ConstantInt::get(I1, true), Ready);
    ReadyStore->setVolatile(true);
    ReadyStore->setAlignment(Align(1));
    RB.CreateBr(Exit);

    Builder XB(Exit);
    XB.CreateRetVoid();
    return Fn;
}

Function *createSeal(Module &M, Payload &P, GlobalVariable *Ready,
                     GlobalVariable *Bound, GlobalVariable *CurrentHash,
                     GlobalVariable *CurrentKeyMask, const StreamSchedule &S,
                     bool ContextKeying) {
    LLVMContext &Ctx = M.getContext();
    auto *VoidTy = Type::getVoidTy(Ctx);
    auto *I1 = Type::getInt1Ty(Ctx);
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    const std::uint32_t Size = static_cast<std::uint32_t>(P.original.size());

    const std::string SealName = "morok.sdb.seal." + P.suffix;
    SmallVector<Type *, 8> Params;
    for (Type *Ty : P.helper->getFunctionType()->params())
        Params.push_back(Ty);

    auto *Fn = Function::Create(FunctionType::get(VoidTy, Params, false),
                                GlobalValue::InternalLinkage, SealName, &M);
    addRuntimeAttrs(Fn);

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    BasicBlock *SealLoop = BasicBlock::Create(Ctx, "seal", Fn);
    BasicBlock *Done = BasicBlock::Create(Ctx, "done", Fn);
    BasicBlock *Exit = BasicBlock::Create(Ctx, "exit", Fn);

    Builder EB(Entry);
    Value *ContextZero =
        ContextKeying ? emitContextZero(EB, Fn) : ConstantInt::get(I64, 0);
    Value *EnvironmentZero = emitEnvironmentZero(EB, M, Fn, P.bytecode);
    Value *StableEnvironmentKey =
        emitStableEnvironmentKey(EB, M, P.helper, P.bytecode);
    ContextZero =
        EB.CreateXor(ContextZero, EnvironmentZero, "morok.sdb.key.env.zero");
    ContextZero =
        EB.CreateXor(ContextZero, StableEnvironmentKey, "morok.sdb.key.env");
    auto *BoundLoad = EB.CreateLoad(I1, Bound, "morok.sdb.bound.load");
    BoundLoad->setVolatile(true);
    BoundLoad->setAlignment(Align(1));
    auto *HashLoad =
        EB.CreateLoad(I64, CurrentHash, "morok.sdb.bound.hash.load");
    HashLoad->setVolatile(true);
    HashLoad->setAlignment(Align(8));
    auto *KeyMaskLoad =
        EB.CreateLoad(I64, CurrentKeyMask, "morok.sdb.bound.keymask.load");
    KeyMaskLoad->setVolatile(true);
    KeyMaskLoad->setAlignment(Align(8));
    Value *ExpectedHash = EB.CreateSelect(
        BoundLoad, HashLoad, ConstantInt::get(I64, S.expected_hash),
        "morok.sdb.bound.hash");
    Value *KeyMask = EB.CreateSelect(BoundLoad, KeyMaskLoad,
                                     ConstantInt::get(I64, S.key_mask),
                                     "morok.sdb.bound.keymask");
    auto *ReadyLoad = EB.CreateLoad(I1, Ready, "morok.sdb.ready.load");
    ReadyLoad->setVolatile(true);
    ReadyLoad->setAlignment(Align(1));
    EB.CreateCondBr(ReadyLoad, SealLoop, Exit);

    Builder SB(SealLoop);
    PHINode *SealI = SB.CreatePHI(I32, 2, "morok.sdb.seal.i");
    PHINode *SealHash = SB.CreatePHI(I64, 2, "morok.sdb.seal.hash");
    SealI->addIncoming(ConstantInt::get(I32, 0), Entry);
    SealHash->addIncoming(ConstantInt::get(I64, S.hash_seed), Entry);
    Value *SealPtr = payloadPtr(SB, P.bytecode, SealI);
    auto *Inner = SB.CreateLoad(I8, SealPtr, "morok.sdb.inner.seal");
    Inner->setVolatile(true);
    Inner->setAlignment(Align(1));
    Value *Key = emitKeyByte(SB, SealI, ExpectedHash, KeyMask, ContextZero, S);
    Value *Outer = SB.CreateXor(Inner, Key, "morok.sdb.outer.seal");
    Value *NextSealHash = emitHashStep(SB, SealHash, Outer);
    auto *Store = SB.CreateStore(Outer, SealPtr);
    Store->setVolatile(true);
    Store->setAlignment(Align(1));
    Value *NextSealI =
        SB.CreateAdd(SealI, ConstantInt::get(I32, 1), "morok.sdb.seal.next");
    SealI->addIncoming(NextSealI, SealLoop);
    SealHash->addIncoming(NextSealHash, SealLoop);
    Value *SealDone = SB.CreateICmpEQ(NextSealI, ConstantInt::get(I32, Size),
                                      "morok.sdb.seal.done");
    SB.CreateCondBr(SealDone, Done, SealLoop);

    Builder DB(Done);
    auto *HashStore = DB.CreateStore(NextSealHash, CurrentHash);
    HashStore->setVolatile(true);
    HashStore->setAlignment(Align(8));
    Value *BaseKey = ConstantInt::get(I64, S.key_mask ^ S.expected_hash);
    Value *NextKeyMask =
        DB.CreateXor(NextSealHash, BaseKey, "morok.sdb.bound.keymask.next");
    auto *KeyMaskStore = DB.CreateStore(NextKeyMask, CurrentKeyMask);
    KeyMaskStore->setVolatile(true);
    KeyMaskStore->setAlignment(Align(8));
    auto *BoundStore = DB.CreateStore(ConstantInt::get(I1, true), Bound);
    BoundStore->setVolatile(true);
    BoundStore->setAlignment(Align(1));
    auto *ReadyStore = DB.CreateStore(ConstantInt::get(I1, false), Ready);
    ReadyStore->setVolatile(true);
    ReadyStore->setAlignment(Align(1));
    DB.CreateBr(Exit);

    Builder XB(Exit);
    XB.CreateRetVoid();
    return Fn;
}

bool helperAlreadyCalls(Function *Helper, Function *Callee) {
    for (Instruction &I : instructions(*Helper))
        if (auto *CI = dyn_cast<CallInst>(&I))
            if (CI->getCalledFunction() == Callee)
                return true;
    return false;
}

void insertEnsureCall(Function *Helper, Function *Ensure) {
    if (helperAlreadyCalls(Helper, Ensure))
        return;
    Instruction *Term = Helper->getEntryBlock().getTerminator();
    Builder B(Term);
    SmallVector<Value *, 8> Args;
    for (Argument &Arg : Helper->args())
        Args.push_back(&Arg);
    B.CreateCall(Ensure->getFunctionType(), Ensure, Args);
    Helper->setMemoryEffects(MemoryEffects::unknown());
    Helper->removeFnAttr(Attribute::NoSync);
}

void insertSealCalls(Function *Helper, Function *Seal) {
    if (helperAlreadyCalls(Helper, Seal))
        return;

    SmallVector<ReturnInst *, 4> Returns;
    for (BasicBlock &BB : *Helper)
        if (auto *RI = dyn_cast<ReturnInst>(BB.getTerminator()))
            Returns.push_back(RI);

    for (ReturnInst *RI : Returns) {
        Builder B(RI);
        SmallVector<Value *, 8> Args;
        for (Argument &Arg : Helper->args())
            Args.push_back(&Arg);
        B.CreateCall(Seal->getFunctionType(), Seal, Args);
    }
    Helper->setMemoryEffects(MemoryEffects::unknown());
    Helper->removeFnAttr(Attribute::NoSync);
}

bool wrapPayload(Module &M, Payload &P,
                 const HashGatedSelfDecryptParams &Params, ir::IRRandom &Rng) {
    StreamSchedule S = makeSchedule(Rng);
    std::vector<std::uint8_t> Outer = outerEncrypt(
        ArrayRef<std::uint8_t>(P.original.data(), P.original.size()), S);
    makeMutablePayload(*P.bytecode, Outer);
    GlobalVariable *Ready = createReady(M, P.suffix);
    GlobalVariable *Bound =
        createI1State(M, "morok.sdb.bound." + P.suffix, false);
    GlobalVariable *CurrentHash =
        createI64State(M, "morok.sdb.bound.hash." + P.suffix, S.expected_hash);
    GlobalVariable *CurrentKeyMask =
        createI64State(M, "morok.sdb.bound.keymask." + P.suffix, S.key_mask);
    Function *Ensure = createEnsure(M, P, Ready, Bound, CurrentHash,
                                    CurrentKeyMask, S, Params.context_keying);
    Function *Seal = createSeal(M, P, Ready, Bound, CurrentHash, CurrentKeyMask,
                                S, Params.context_keying);
    insertEnsureCall(P.helper, Ensure);
    insertSealCalls(P.helper, Seal);
    return true;
}

} // namespace

bool hashGatedSelfDecryptModule(Module &M,
                                const HashGatedSelfDecryptParams &Params,
                                ir::IRRandom &Rng) {
    if (Params.probability == 0 || Params.max_payloads == 0)
        return false;

    std::vector<Payload> Payloads = collectPayloads(M);
    if (Payloads.empty())
        return false;
    shufflePayloads(Payloads, Rng);

    bool Changed = false;
    std::uint32_t Wrapped = 0;
    for (Payload &P : Payloads) {
        if (Wrapped >= Params.max_payloads)
            break;
        if (!Rng.chance(Params.probability))
            continue;
        Changed |= wrapPayload(M, P, Params, Rng);
        ++Wrapped;
    }
    return Changed;
}

PreservedAnalyses HashGatedSelfDecryptPass::run(Module &M,
                                                ModuleAnalysisManager &) {
    ir::IRRandom Rng(engine_);
    return hashGatedSelfDecryptModule(M, params_, Rng)
               ? PreservedAnalyses::none()
               : PreservedAnalyses::all();
}

} // namespace morok::passes
