// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/ir/SymbolCloak.cpp

#include "morok/ir/SymbolCloak.hpp"

#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Module.h"
#include "llvm/TargetParser/Triple.h"

#include "llvm/ADT/SmallVector.h"

#include <cstdint>
#include <string>

using namespace llvm;

namespace morok::ir {

namespace {

// Finalizer constants for the three keystream generators.  The SAME arithmetic
// runs at pass time (producing ciphertext) and in the emitted IR (recovering
// plaintext), so these must stay byte-for-byte identical.
constexpr std::uint64_t kMurmur1 = 0xFF51AFD7ED558CCDULL;
constexpr std::uint64_t kMurmur2 = 0xC4CEB9FE1A85EC53ULL;
constexpr std::uint64_t kSplit1 = 0xBF58476D1CE4E5B9ULL;
constexpr std::uint64_t kSplit2 = 0x94D049BB133111EBULL;
constexpr std::uint64_t kXorMul = 0x2545F4914F6CDD1DULL;

void emitStaticAnalysisBarrier(IRBuilderBase &B, const Module &M) {
    const Triple TT(M.getTargetTriple());
    StringRef Asm;
    StringRef Constraints;
    switch (TT.getArch()) {
    case Triple::aarch64:
    case Triple::aarch64_be:
        Asm = "ccmn wzr, #0, #4, eq";
        Constraints = "~{cc},~{memory}";
        break;
    case Triple::x86:
    case Triple::x86_64:
        Asm = "pause";
        Constraints = "~{dirflag},~{fpsr},~{flags},~{memory}";
        break;
    default:
        return;
    }

    auto *AsmTy = FunctionType::get(Type::getVoidTy(B.getContext()), false);
    InlineAsm *IA =
        InlineAsm::get(AsmTy, Asm, Constraints, /*hasSideEffects=*/true);
    B.CreateCall(AsmTy, IA);
}

// Shared finalizer: T already holds `K0 + (j+1)*mul`; spread it per variant.
Value *emitFinalizer(IRBuilderBase &B, unsigned variant, Value *T) {
    auto *I64 = B.getInt64Ty();
    auto R = [&](Value *v, unsigned s) {
        return B.CreateLShr(v, ConstantInt::get(I64, s));
    };
    auto L = [&](Value *v, unsigned s) {
        return B.CreateShl(v, ConstantInt::get(I64, s));
    };
    switch (variant) {
    case 1:
        T = B.CreateMul(B.CreateXor(T, R(T, 30)),
                        ConstantInt::get(I64, kSplit1));
        T = B.CreateMul(B.CreateXor(T, R(T, 27)),
                        ConstantInt::get(I64, kSplit2));
        return B.CreateXor(T, R(T, 31));
    case 2:
        T = B.CreateXor(T, L(T, 13));
        T = B.CreateXor(T, R(T, 7));
        T = B.CreateXor(T, L(T, 17));
        return B.CreateMul(T, ConstantInt::get(I64, kXorMul));
    default:
        T = B.CreateXor(T, R(T, 33));
        T = B.CreateMul(T, ConstantInt::get(I64, kMurmur1));
        T = B.CreateXor(T, R(T, 33));
        T = B.CreateMul(T, ConstantInt::get(I64, kMurmur2));
        return B.CreateXor(T, R(T, 33));
    }
}

Value *emitOpaqueMix(IRBuilderBase &B, Value *V, Value *Salt,
                     const Twine &name) {
    auto *I64 = B.getInt64Ty();
    Value *X = B.CreateXor(V, Salt, name + ".x");
    Value *Odd = B.CreateOr(Salt, ConstantInt::get(I64, 1), name + ".odd");
    X = B.CreateMul(X, Odd, name + ".m");
    Value *R = B.CreateOr(
        B.CreateShl(X, ConstantInt::get(I64, 13), name + ".l"),
        B.CreateLShr(X, ConstantInt::get(I64, 51), name + ".r"), name + ".rot");
    Value *SaltMix =
        B.CreateMul(Salt, ConstantInt::get(I64, kXorMul), name + ".sm");
    return B.CreateXor(R, SaltMix, name + ".y");
}

Function *opaqueZeroHelper(Module &M) {
    if (Function *Existing = M.getFunction("morok.opaque.zero"))
        return Existing;

    LLVMContext &Ctx = M.getContext();
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *FTy = FunctionType::get(I64, {I64, I64}, false);
    auto *Fn = Function::Create(FTy, GlobalValue::PrivateLinkage,
                                "morok.opaque.zero", &M);
    Fn->setDSOLocal(true);
    Fn->addFnAttr(Attribute::NoInline);
    Fn->addFnAttr(Attribute::OptimizeNone);
    Argument *Arg = Fn->getArg(0);
    Arg->setName("x");
    Argument *Salt = Fn->getArg(1);
    Salt->setName("salt");

    IRBuilder<> B(BasicBlock::Create(Ctx, "entry", Fn));
    AllocaInst *Slot = B.CreateAlloca(I64, nullptr, "morok.opaque.slot");
    B.CreateStore(Arg, Slot, /*isVolatile=*/true);
    LoadInst *A =
        B.CreateLoad(I64, Slot, /*isVolatile=*/true, "morok.opaque.a");
    emitStaticAnalysisBarrier(B, M);
    LoadInst *Bv =
        B.CreateLoad(I64, Slot, /*isVolatile=*/true, "morok.opaque.b");
    Value *MA = emitOpaqueMix(B, A, Salt, "morok.opaque.ma");
    Value *MB = emitOpaqueMix(B, Bv, Salt, "morok.opaque.mb");
    B.CreateRet(B.CreateXor(MA, MB, "morok.opaque.zero"));
    return Fn;
}

} // namespace

std::uint64_t keystreamValue(unsigned variant, std::uint64_t k0,
                             std::uint32_t j, std::uint64_t mul) {
    std::uint64_t t = k0 + static_cast<std::uint64_t>(j + 1) * mul;
    switch (variant) {
    case 1: // splitmix64 finalizer
        t = (t ^ (t >> 30)) * kSplit1;
        t = (t ^ (t >> 27)) * kSplit2;
        t = t ^ (t >> 31);
        return t;
    case 2: // xorshift*
        t ^= t << 13;
        t ^= t >> 7;
        t ^= t << 17;
        t *= kXorMul;
        return t;
    default: // MurmurHash3 finalizer
        t ^= t >> 33;
        t *= kMurmur1;
        t ^= t >> 33;
        t *= kMurmur2;
        t ^= t >> 33;
        return t;
    }
}

Value *emitKeystream(IRBuilderBase &B, unsigned variant, Value *K0,
                     std::uint32_t j, std::uint64_t mul) {
    auto *I64 = B.getInt64Ty();
    Value *T = B.CreateAdd(
        K0, ConstantInt::get(I64, static_cast<std::uint64_t>(j + 1) * mul));
    return emitFinalizer(B, variant, T);
}

Value *emitKeystreamDynamic(IRBuilderBase &B, unsigned variant, Value *K0,
                            Value *JVal, std::uint64_t mul) {
    auto *I64 = B.getInt64Ty();
    Value *Jp1 = B.CreateAdd(JVal, ConstantInt::get(I64, 1));
    Value *T = B.CreateAdd(K0, B.CreateMul(Jp1, ConstantInt::get(I64, mul)));
    return emitFinalizer(B, variant, T);
}

Value *emitRuntimeOpaqueZero(IRBuilderBase &B, Module &M, std::uint64_t salt,
                             StringRef prefix) {
    auto *I8 = Type::getInt8Ty(M.getContext());
    auto *I64 = Type::getInt64Ty(M.getContext());

    AllocaInst *Anchor = B.CreateAlloca(I8, nullptr, Twine(prefix) + ".anchor");
    Value *Addr = B.CreatePtrToInt(Anchor, I64, Twine(prefix) + ".addr");
    Function *Helper = opaqueZeroHelper(M);
    return B.CreateCall(Helper->getFunctionType(), Helper,
                        {Addr, ConstantInt::get(I64, salt)},
                        Twine(prefix) + ".zero");
}

// The per-module runtime key: a private *mutable* global holding a random
// value, always read with a volatile load.  Mutable + volatile is the
// established anti-fold pattern — the optimizer must treat the loaded value as
// unknown, so the keystream never folds back to readable text.
GlobalVariable *cloakSeed(Module &M, IRRandom &rng) {
    if (GlobalVariable *Existing =
            M.getGlobalVariable("morok.cloak.seed", /*AllowInternal=*/true))
        return Existing;
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *GV = new GlobalVariable(
        M, I64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I64, rng.next()), "morok.cloak.seed");
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return GV;
}

Value *emitCloakedSymbol(IRBuilderBase &B, Module &M, StringRef symbol,
                         IRRandom &rng) {
    auto *I8 = Type::getInt8Ty(M.getContext());
    auto *I64 = Type::getInt64Ty(M.getContext());

    GlobalVariable *Seed = cloakSeed(M, rng);
    const std::uint64_t SeedVal =
        cast<ConstantInt>(Seed->getInitializer())->getZExtValue();

    // Per-site choices: keystream variant, combine operation, and key material.
    const unsigned Variant = rng.range(kKeystreamVariants);
    const bool AddCombine = rng.range(2) == 0;
    const std::uint64_t SiteKey = rng.next();
    const std::uint64_t Mul = rng.next() | 1ull;
    const std::uint64_t K0 = SeedVal ^ SiteKey;

    std::string Bytes(symbol.begin(), symbol.end());
    Bytes.push_back('\0');
    const std::size_t Len = Bytes.size();

    // Ciphertext — just opaque bytes; combined with the per-site keystream.
    SmallVector<Constant *, 32> CipherBytes;
    CipherBytes.reserve(Len);
    for (std::uint32_t j = 0; j < Len; ++j) {
        const auto Ks = static_cast<std::uint8_t>(
            keystreamValue(Variant, K0, j, Mul) & 0xFFu);
        const auto Plain = static_cast<std::uint8_t>(Bytes[j]);
        const auto C = AddCombine ? static_cast<std::uint8_t>(Plain + Ks)
                                  : static_cast<std::uint8_t>(Plain ^ Ks);
        CipherBytes.push_back(ConstantInt::get(I8, C));
    }
    auto *ArrTy = ArrayType::get(I8, Len);
    auto *CipherGV = new GlobalVariable(
        M, ArrTy, /*isConstant=*/true, GlobalValue::PrivateLinkage,
        ConstantArray::get(ArrTy, CipherBytes), "morok.cloak.c");
    CipherGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

    AllocaInst *Buf = B.CreateAlloca(ArrTy, nullptr, "morok.cloak.buf");
    LoadInst *SeedLoad =
        B.CreateLoad(I64, Seed, /*isVolatile=*/true, "morok.cloak.k");
    emitStaticAnalysisBarrier(B, M);
    Value *SeedMix = B.CreateAdd(
        SeedLoad, emitRuntimeOpaqueZero(B, M, rng.next(), "morok.cloak.mix"),
        "morok.cloak.k.mix");
    Value *RtKey =
        B.CreateXor(SeedMix, ConstantInt::get(I64, SiteKey), "morok.cloak.k0");
    Value *StoreMask = B.CreateTrunc(
        emitRuntimeOpaqueZero(B, M, rng.next(), "morok.cloak.store"), I8,
        "morok.cloak.store.byte");

    for (std::uint32_t j = 0; j < Len; ++j) {
        Value *Ks = emitKeystream(B, Variant, RtKey, j, Mul);
        Value *KsByte = B.CreateTrunc(Ks, I8);
        Value *CipherPtr = B.CreateInBoundsGEP(
            ArrTy, CipherGV,
            {ConstantInt::get(I64, 0), ConstantInt::get(I64, j)});
        Value *CipherByte = B.CreateLoad(I8, CipherPtr);
        Value *Plain = AddCombine ? B.CreateSub(CipherByte, KsByte)
                                  : B.CreateXor(CipherByte, KsByte);
        Value *MaskedPlain =
            B.CreateXor(Plain, StoreMask, "morok.cloak.masked");
        Value *BufPtr = B.CreateInBoundsGEP(
            ArrTy, Buf, {ConstantInt::get(I64, 0), ConstantInt::get(I64, j)});
        B.CreateStore(MaskedPlain, BufPtr);
    }
    emitStaticAnalysisBarrier(B, M);
    return B.CreateInBoundsGEP(
        ArrTy, Buf, {ConstantInt::get(I64, 0), ConstantInt::get(I64, 0)},
        "morok.cloak.sym");
}

} // namespace morok::ir
