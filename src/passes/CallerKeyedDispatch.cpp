// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/CallerKeyedDispatch.cpp
//
// Direct internal calls are rewritten to call a shared native dispatcher.  The
// original callee address is carried in a callee-saved register and is decoded
// from a per-site encoded dispatcher-relative delta.  A per-site cache may keep
// the sealed encoded value locally, but the volatile caller-byte hash is still
// recomputed on every call so warmed sites remain sensitive to live patches.
//
// Each routed site also emits a post-link manifest.  The sealer patches the
// encoded target against final native bytes and flips a per-site seal-state
// word.  Sealed binaries therefore cannot self-adapt to pre-start static
// patches by resetting the mutable code-size slot, while unsealed dev/test
// builds still compute their encoded targets in the constructor.

#include "morok/passes/CallerKeyedDispatch.hpp"

#include "morok/passes/CodeRegionKdf.hpp"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Twine.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

using Builder = IRBuilder<NoFolder>;

constexpr std::uint32_t kMaxCallsPerModule = 4096;
constexpr std::uint32_t kMaxRegionBytes = 32;
constexpr std::uint64_t kPostlinkMagic = 0xC30D5B11A6E48F27ULL;
constexpr std::uint32_t kPostlinkVersion = 2;

struct ArchLayout {
    std::string dispatcher_asm;
    std::string dispatcher_constraints;
    std::string carrier_save_asm;
    std::string carrier_save_constraints;
    std::string carrier_def_asm;
    std::string carrier_def_constraints;
    std::string carrier_anchor_constraints;
    std::string carrier_restore_asm;
    std::string carrier_restore_constraints;
};

enum class Arch { AArch64, X86_64 };

struct Site {
    CallInst *call = nullptr;
    Function *caller = nullptr;
    Function *callee = nullptr;
    BasicBlock *block = nullptr;
    Function *dispatcher = nullptr; ///< per-site carrier dispatcher
    std::string carrier;           ///< callee-saved carrier register name
    GlobalVariable *encoded = nullptr;
    GlobalVariable *cache = nullptr;
    GlobalVariable *code_size = nullptr;
    GlobalVariable *seal_state = nullptr;
    std::uint64_t salt = 0;
    std::uint64_t mul = 0;
    std::uint64_t add = 0;
    std::uint64_t seal_unsealed = 0;
    std::uint64_t seal_salt = 0;
    std::uint32_t rot = 0;
};

std::optional<Arch> archOf(const Triple &TT) {
    switch (TT.getArch()) {
    case Triple::x86_64:
        return Arch::X86_64;
    case Triple::aarch64:
    case Triple::aarch64_be:
        return Arch::AArch64;
    default:
        return std::nullopt;
    }
}

// Callee-saved registers that the C convention never uses for argument passing,
// so the carried jump target survives the dispatcher call's argument setup.  CKD
// saves/restores the chosen physical register around each dispatched call; the
// target callee preserves the temporary branch target, not the caller's original
// register contents.  The legacy register (x19 / r14) is first so
// `carriers == 1` keeps the original dispatcher identity.
std::vector<std::string> carrierPool(Arch A) {
    if (A == Arch::AArch64)
        return {"x19", "x20", "x21", "x22", "x23",
                "x24", "x25", "x26", "x27", "x28"};
    return {"r14", "r12", "r13", "r15"};
}

ArchLayout layoutForRegister(Arch A, StringRef Reg) {
    ArchLayout L;
    if (A == Arch::AArch64) {
        L.dispatcher_asm = (Twine("br ") + Reg).str();
        L.dispatcher_constraints = "~{memory}";
        L.carrier_save_asm = (Twine("mov $0, ") + Reg).str();
        L.carrier_save_constraints = "=r,~{memory}";
        L.carrier_def_asm = "mov $0, $1";
        L.carrier_def_constraints = (Twine("={") + Reg + "},r,~{memory}").str();
        L.carrier_anchor_constraints = (Twine("{") + Reg + "},~{memory}").str();
        L.carrier_restore_asm = L.carrier_def_asm;
        L.carrier_restore_constraints = L.carrier_def_constraints;
    } else {
        L.dispatcher_asm = (Twine("jmpq *%") + Reg).str();
        L.dispatcher_constraints = "~{memory},~{dirflag},~{fpsr},~{flags}";
        L.carrier_save_asm = (Twine("movq %") + Reg + ", $0").str();
        L.carrier_save_constraints =
            "=r,~{memory},~{dirflag},~{fpsr},~{flags}";
        L.carrier_def_asm = "movq $1, $0";
        L.carrier_def_constraints =
            (Twine("={") + Reg + "},r,~{memory},~{dirflag},~{fpsr},~{flags}")
                .str();
        L.carrier_anchor_constraints =
            (Twine("{") + Reg + "},~{memory},~{dirflag},~{fpsr},~{flags}").str();
        L.carrier_restore_asm = L.carrier_def_asm;
        L.carrier_restore_constraints = L.carrier_def_constraints;
    }
    return L;
}

// Legacy bare name for the default carrier (keeps existing manifests/tests
// unchanged); a per-register suffix for the rotated dispatchers.
std::string dispatcherName(StringRef Reg, bool IsDefault) {
    if (IsDefault)
        return "morok.ckd.dispatch";
    return (Twine("morok.ckd.dispatch.") + Reg).str();
}

bool eligible(CallInst &CI) {
    if (CI.isInlineAsm() || CI.hasOperandBundles())
        return false;
    if (CI.isMustTailCall())
        return false;
    Function *Callee = CI.getCalledFunction();
    if (!Callee || Callee->isIntrinsic() || Callee->isDeclaration())
        return false;
    if (Callee->isVarArg())
        return false;
    if (Callee->getName().starts_with("morok."))
        return false;
    // The carrier register pool (x19-x28 / r12-r15) must stay callee-saved and
    // never used for argument passing under the call's convention, or the
    // dispatcher call's argument setup would overwrite the loaded jump target
    // and the naked `br`/`jmp` would land on an argument value.  C and fastcc
    // both keep that pool callee-saved and pass integer arguments in the normal
    // argument registers, so both are safe — and clang promotes static internal
    // functions to fastcc at -O2/-O3, so restricting to C alone silently skips
    // most internal call graphs (e.g. a `static`-heavy license verdict).  Other
    // conventions (x86_regcallcc, vectorcall, preserve_*, numbered) may pass
    // arguments in the carrier pool and are still excluded.
    const auto carrierSafeCC = [](CallingConv::ID CC) {
        return CC == CallingConv::C || CC == CallingConv::Fast;
    };
    if (!carrierSafeCC(CI.getCallingConv()) ||
        !carrierSafeCC(Callee->getCallingConv()))
        return false;
    Function *Caller = CI.getFunction();
    if (!Caller || Caller->isDeclaration() || Caller->hasPersonalityFn())
        return false;
    if (Caller->getName().starts_with("morok."))
        return false;
    // Direct self-recursion re-enters the same carrier protocol on nested
    // frames; leave those edges direct and still dispatch the surrounding graph.
    if (Caller == Callee)
        return false;
    return true;
}

void shuffleCalls(std::vector<CallInst *> &Calls, ir::IRRandom &Rng) {
    for (std::size_t I = Calls.size(); I > 1; --I) {
        const std::size_t J = Rng.range(static_cast<std::uint32_t>(I));
        std::swap(Calls[I - 1], Calls[J]);
    }
}

Function *ensureDispatcher(Module &M, StringRef Name,
                          const ArchLayout &Layout) {
    if (Function *Existing = M.getFunction(Name))
        return Existing;

    LLVMContext &Ctx = M.getContext();
    auto *FTy = FunctionType::get(Type::getVoidTy(Ctx), false);
    auto *Fn = Function::Create(FTy, GlobalValue::InternalLinkage, Name, &M);
    Fn->setDSOLocal(true);
    Fn->addFnAttr(Attribute::Naked);
    Fn->addFnAttr(Attribute::NoInline);
    Fn->setAlignment(Align(16));

    IRBuilder<> B(BasicBlock::Create(Ctx, "entry", Fn));
    InlineAsm *IA = InlineAsm::get(FTy, Layout.dispatcher_asm,
                                   Layout.dispatcher_constraints,
                                   /*hasSideEffects=*/true);
    B.CreateCall(FTy, IA);
    B.CreateUnreachable();
    appendToUsed(M, {Fn});
    appendToCompilerUsed(M, {Fn});
    return Fn;
}

Value *ptrToI64(Builder &B, Value *Ptr) {
    return B.CreatePtrToInt(Ptr, B.getInt64Ty(), "morok.ckd.ptr");
}

Value *rotl64(Builder &B, Value *V, std::uint32_t Bits, const Twine &Name) {
    Bits &= 63u;
    if (Bits == 0)
        return V;
    auto *I64 = B.getInt64Ty();
    return B.CreateOr(
        B.CreateShl(V, ConstantInt::get(I64, Bits), Name + ".l"),
        B.CreateLShr(V, ConstantInt::get(I64, 64u - Bits), Name + ".r"), Name);
}

Value *mixSeal64(Builder &B, Value *V, const Twine &Name) {
    auto *I64 = B.getInt64Ty();
    V = B.CreateXor(V, B.CreateLShr(V, ConstantInt::get(I64, 33)),
                    Name + ".x0");
    V = B.CreateMul(V, ConstantInt::get(I64, 0xff51afd7ed558ccdULL),
                    Name + ".m0");
    V = B.CreateXor(V, B.CreateLShr(V, ConstantInt::get(I64, 29)),
                    Name + ".x1");
    V = B.CreateMul(V, ConstantInt::get(I64, 0xc4ceb9fe1a85ec53ULL),
                    Name + ".m1");
    return B.CreateXor(V, B.CreateLShr(V, ConstantInt::get(I64, 32)), Name);
}

std::uint64_t mixSealConstant(std::uint64_t V) {
    V ^= V >> 33;
    V *= 0xff51afd7ed558ccdULL;
    V ^= V >> 29;
    V *= 0xc4ceb9fe1a85ec53ULL;
    V ^= V >> 32;
    return V;
}

std::uint64_t sealFailurePoison(const Site &S, std::uint32_t RegionBytes) {
    std::uint64_t X = kPostlinkMagic ^ S.seal_salt;
    X = mixSealConstant(X + S.salt);
    X = mixSealConstant(X ^ (S.mul | 1ULL));
    X = mixSealConstant(X + S.add);
    std::uint64_t Shape =
        (static_cast<std::uint64_t>(S.rot) << 32) | RegionBytes;
    X = mixSealConstant(X ^ Shape);
    return X | 1ULL;
}

Value *emitSealFailurePoison(Builder &B, const Site &S,
                             std::uint32_t RegionBytes, const Twine &Name) {
    auto *I64 = B.getInt64Ty();
    std::uint64_t Poison = sealFailurePoison(S, RegionBytes);
    return B.CreateXor(ConstantInt::get(I64, Poison),
                       ConstantInt::get(I64, 0), Name);
}

Value *emitSealState(Builder &B, Function *Dispatcher, const Site &S,
                     Value *Encoded, Value *CodeSize, std::uint32_t RegionBytes,
                     const Twine &Name) {
    auto *I64 = B.getInt64Ty();
    Value *CodeSize64 = B.CreateZExt(CodeSize, I64, Name + ".code.size");
    Value *Disp = ptrToI64(B, Dispatcher);
    Value *Site = ptrToI64(B, BlockAddress::get(S.caller, S.block));
    Value *Target = ptrToI64(B, S.callee);
    Value *SiteDelta = B.CreateSub(Site, Disp, Name + ".site.delta");
    Value *TargetDelta = B.CreateSub(Target, Disp, Name + ".target.delta");
    Value *X = B.CreateXor(Encoded, ConstantInt::get(I64, S.seal_salt),
                           Name + ".seed");
    X = mixSeal64(B, B.CreateXor(X, CodeSize64, Name + ".fold.size"),
                  Name + ".mix.size");
    X = mixSeal64(B, B.CreateAdd(X, SiteDelta, Name + ".fold.site"),
                  Name + ".mix.site");
    X = mixSeal64(B, B.CreateXor(X, TargetDelta, Name + ".fold.target"),
                  Name + ".mix.target");
    X = mixSeal64(
        B, B.CreateAdd(X, ConstantInt::get(I64, S.salt), Name + ".fold.salt"),
        Name + ".mix.salt");
    X = mixSeal64(
        B,
        B.CreateXor(X, ConstantInt::get(I64, S.mul | 1ULL), Name + ".fold.mul"),
        Name + ".mix.mul");
    X = mixSeal64(
        B, B.CreateAdd(X, ConstantInt::get(I64, S.add), Name + ".fold.add"),
        Name + ".mix.add");
    std::uint64_t Shape =
        (static_cast<std::uint64_t>(S.rot) << 32) | RegionBytes;
    X = mixSeal64(
        B, B.CreateXor(X, ConstantInt::get(I64, Shape), Name + ".fold.shape"),
        Name + ".mix.shape");
    return X;
}

Value *emitSiteHash(Builder &B, Module &M, Function *Dispatcher,
                    Function *Caller, BasicBlock *SiteBlock, const Site &S,
                    std::uint32_t RegionBytes) {
    auto *I8 = B.getInt8Ty();
    auto *I64 = B.getInt64Ty();
    auto *Ptr = PointerType::getUnqual(M.getContext());

    Value *Base = ptrToI64(B, Dispatcher);
    Value *Start = ptrToI64(B, BlockAddress::get(Caller, SiteBlock));
    Value *SiteDelta = B.CreateSub(Start, Base, "morok.ckd.site.delta");
    Value *H =
        B.CreateXor(ConstantInt::get(I64, S.salt), SiteDelta, "morok.ckd.hash");

    for (std::uint32_t I = 0; I != RegionBytes; ++I) {
        Value *Addr =
            B.CreateAdd(Start, ConstantInt::get(I64, I), "morok.ckd.byte.addr");
        Value *BytePtr = B.CreateIntToPtr(Addr, Ptr, "morok.ckd.byte.ptr");
        LoadInst *Byte =
            B.CreateLoad(I8, BytePtr, /*isVolatile=*/true, "morok.ckd.byte");
        Value *Wide = B.CreateZExt(Byte, I64, "morok.ckd.byte.wide");
        Value *Salted = B.CreateAdd(
            Wide, ConstantInt::get(I64, S.add + (0x9e3779b97f4a7c15ULL * I)),
            "morok.ckd.byte.salted");
        H = B.CreateXor(H, Salted, "morok.ckd.hash.x");
        H = B.CreateMul(H, ConstantInt::get(I64, S.mul | 1ULL),
                        "morok.ckd.hash.m");
        H = rotl64(B, H, (S.rot + I) & 63u, "morok.ckd.hash.rot");
        H = B.CreateAdd(H, SiteDelta, "morok.ckd.hash.site");
        H = B.CreateXor(H, B.CreateLShr(H, ConstantInt::get(I64, 29)),
                        "morok.ckd.hash.av");
    }
    return H;
}

GlobalVariable *makeEncodedSlot(Module &M, ir::IRRandom &Rng) {
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *GV = new GlobalVariable(
        M, I64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I64, Rng.next()), "morok.ckd.enc");
    GV->setAlignment(Align(8));
    appendToCompilerUsed(M, {GV});
    return GV;
}

GlobalVariable *makeCacheSlot(Module &M) {
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *GV = new GlobalVariable(M, I64, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage,
                                  ConstantInt::get(I64, 0), "morok.ckd.cache");
    GV->setAlignment(Align(8));
    appendToCompilerUsed(M, {GV});
    return GV;
}

GlobalVariable *makeCodeSizeSlot(Module &M) {
    auto *I32 = Type::getInt32Ty(M.getContext());
    auto *GV = new GlobalVariable(
        M, I32, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I32, code_region_kdf::kUnsealedCodeSize),
        "morok.ckd.code.size");
    GV->setAlignment(Align(4));
    appendToCompilerUsed(M, {GV});
    return GV;
}

GlobalVariable *makeSealStateSlot(Module &M, std::uint64_t Unsealed) {
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *GV = new GlobalVariable(
        M, I64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I64, Unsealed), "morok.ckd.seal.state");
    GV->setAlignment(Align(8));
    appendToCompilerUsed(M, {GV});
    return GV;
}

void emitPostlinkManifest(Module &M, ArrayRef<Site> Sites,
                          std::uint32_t RegionBytes) {
    if (Sites.empty())
        return;

    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);

    auto *RecordTy = StructType::get(
        Ctx, {Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, I64, I64, I64, I64, I32, I32});
    SmallVector<Constant *, 16> Records;
    Records.reserve(Sites.size());
    for (const Site &S : Sites) {
        Records.push_back(ConstantStruct::get(
            RecordTy,
            {S.encoded, S.code_size, S.seal_state, S.dispatcher,
             BlockAddress::get(S.caller, S.block), S.callee,
             ConstantInt::get(I64, S.salt), ConstantInt::get(I64, S.mul),
             ConstantInt::get(I64, S.add), ConstantInt::get(I64, S.seal_salt),
             ConstantInt::get(I32, S.rot),
             ConstantInt::get(I32, RegionBytes)}));
    }

    auto *RecordsTy = ArrayType::get(RecordTy, Records.size());
    auto *ManifestTy = StructType::get(Ctx, {I64, I32, I32, RecordsTy});
    auto *Manifest = new GlobalVariable(
        M, ManifestTy, /*isConstant=*/true, GlobalValue::PrivateLinkage,
        ConstantStruct::get(ManifestTy,
                            {ConstantInt::get(I64, kPostlinkMagic),
                             ConstantInt::get(I32, kPostlinkVersion),
                             ConstantInt::get(I32, Records.size()),
                             ConstantArray::get(RecordsTy, Records)}),
        "morok.postlink.ckd");
    Manifest->setAlignment(Align(8));
    appendToCompilerUsed(M, {Manifest});
}

Value *emitCarrierDefine(IRBuilder<> &B, Value *Target,
                         const ArchLayout &Layout) {
    auto *FTy =
        FunctionType::get(Target->getType(), {Target->getType()}, false);
    InlineAsm *IA = InlineAsm::get(FTy, Layout.carrier_def_asm,
                                   Layout.carrier_def_constraints,
                                   /*hasSideEffects=*/true);
    return B.CreateCall(FTy, IA, {Target}, "morok.ckd.carrier");
}

Value *emitCarrierSave(IRBuilder<> &B, Type *CarrierTy,
                       const ArchLayout &Layout) {
    auto *FTy = FunctionType::get(CarrierTy, false);
    InlineAsm *IA = InlineAsm::get(FTy, Layout.carrier_save_asm,
                                   Layout.carrier_save_constraints,
                                   /*hasSideEffects=*/true);
    return B.CreateCall(FTy, IA, {}, "morok.ckd.carrier.saved");
}

void emitCarrierAnchor(IRBuilder<> &B, Value *Carrier,
                       const ArchLayout &Layout) {
    auto *FTy = FunctionType::get(Type::getVoidTy(B.getContext()),
                                  {Carrier->getType()}, false);
    InlineAsm *IA = InlineAsm::get(FTy, "", Layout.carrier_anchor_constraints,
                                   /*hasSideEffects=*/true);
    B.CreateCall(FTy, IA, {Carrier});
}

Value *emitCarrierRestore(IRBuilder<> &B, Value *Saved,
                          const ArchLayout &Layout) {
    auto *FTy = FunctionType::get(Saved->getType(), {Saved->getType()}, false);
    InlineAsm *IA = InlineAsm::get(FTy, Layout.carrier_restore_asm,
                                   Layout.carrier_restore_constraints,
                                   /*hasSideEffects=*/true);
    return B.CreateCall(FTy, IA, {Saved}, "morok.ckd.carrier.restored");
}

void emitInit(Module &M, ArrayRef<Site> Sites, std::uint32_t RegionBytes,
              bool SealRequired) {
    if (Sites.empty())
        return;

    LLVMContext &Ctx = M.getContext();
    auto *Void = Type::getVoidTy(Ctx);
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *FTy = FunctionType::get(Void, false);
    auto *Init = Function::Create(FTy, GlobalValue::InternalLinkage,
                                  "morok.ckd.init", &M);
    Init->setDSOLocal(true);
    Init->addFnAttr(Attribute::NoInline);

    BasicBlock *CurBB = BasicBlock::Create(Ctx, "entry", Init);
    for (std::size_t I = 0; I != Sites.size(); ++I) {
        const Site &S = Sites[I];
        BasicBlock *FallbackBB =
            SealRequired
                ? nullptr
                : BasicBlock::Create(Ctx, "morok.ckd.init.fallback", Init);
        BasicBlock *SealedBB =
            BasicBlock::Create(Ctx, "morok.ckd.init.sealed", Init);
        BasicBlock *StoreBB =
            SealRequired
                ? nullptr
                : BasicBlock::Create(Ctx, "morok.ckd.init.store", Init);
        BasicBlock *NextBB =
            (I + 1 == Sites.size())
                ? nullptr
                : BasicBlock::Create(Ctx, "morok.ckd.init.next", Init);

        Builder B(CurBB);
        LoadInst *CodeSize = B.CreateLoad(I32, S.code_size, /*isVolatile=*/true,
                                          "morok.ckd.code.size.load");
        CodeSize->setAlignment(Align(4));
        LoadInst *Existing = B.CreateLoad(I64, S.encoded, /*isVolatile=*/true,
                                          "morok.ckd.enc.sealed");
        Existing->setAlignment(Align(8));
        LoadInst *SealState = B.CreateLoad(
            I64, S.seal_state, /*isVolatile=*/true, "morok.ckd.seal.state");
        SealState->setAlignment(Align(8));
        Value *NonZero = B.CreateICmpNE(CodeSize, ConstantInt::get(I32, 0),
                                        "morok.ckd.code.nz");
        Value *Sealed = B.CreateICmpNE(
            CodeSize, ConstantInt::get(I32, code_region_kdf::kUnsealedCodeSize),
            "morok.ckd.code.sealed");
        Value *HasCode = B.CreateAnd(NonZero, Sealed, "morok.ckd.code.has");
        Value *UnsealedState =
            B.CreateICmpEQ(SealState, ConstantInt::get(I64, S.seal_unsealed),
                           "morok.ckd.seal.unsealed");
        Value *ExpectedSeal =
            emitSealState(B, S.dispatcher, S, Existing, CodeSize, RegionBytes,
                          "morok.ckd.seal.expected");
        Value *SealOk =
            B.CreateICmpEQ(SealState, ExpectedSeal, "morok.ckd.seal.ok");
        Value *ValidSealed =
            B.CreateAnd(B.CreateNot(UnsealedState, "morok.ckd.seal.engaged"),
                        HasCode, "morok.ckd.seal.has.code");
        ValidSealed = B.CreateAnd(ValidSealed, SealOk, "morok.ckd.seal.valid");

        if (SealRequired) {
            B.CreateBr(SealedBB);

            Builder SB(SealedBB);
            Value *Poison =
                emitSealFailurePoison(SB, S, RegionBytes,
                                      "morok.ckd.enc.poison");
            Value *SealedEncoded = SB.CreateSelect(
                ValidSealed, Existing, Poison, "morok.ckd.target.sealed");
            auto *Store = SB.CreateStore(SealedEncoded, S.encoded,
                                         /*isVolatile=*/true);
            Store->setAlignment(Align(8));
            if (NextBB) {
                SB.CreateBr(NextBB);
                CurBB = NextBB;
            } else {
                SB.CreateRetVoid();
            }
            continue;
        }

        Value *MissingCode = B.CreateNot(HasCode, "morok.ckd.code.missing");
        Value *UseFallback = B.CreateAnd(UnsealedState, MissingCode,
                                         "morok.ckd.init.allow.fallback");
        B.CreateCondBr(UseFallback, FallbackBB, SealedBB);

        Builder FB(FallbackBB);
        Value *Disp = ptrToI64(FB, S.dispatcher);
        Value *Target = ptrToI64(FB, S.callee);
        Value *Delta = FB.CreateSub(Target, Disp, "morok.ckd.target.delta");
        Value *H = emitSiteHash(FB, M, S.dispatcher, S.caller, S.block, S,
                                RegionBytes);
        Value *Computed = FB.CreateAdd(Delta, H, "morok.ckd.target.enc");
        FB.CreateBr(StoreBB);

        Builder SB(SealedBB);
        Value *Poison =
            emitSealFailurePoison(SB, S, RegionBytes, "morok.ckd.seal.bad");
        Value *SealedEncoded = SB.CreateSelect(ValidSealed, Existing, Poison,
                                               "morok.ckd.target.sealed");
        SB.CreateBr(StoreBB);

        Builder StoreB(StoreBB);
        PHINode *Encoded = StoreB.CreatePHI(I64, 2, "morok.ckd.target.enc");
        Encoded->addIncoming(Computed, FallbackBB);
        Encoded->addIncoming(SealedEncoded, SealedBB);
        auto *Store = StoreB.CreateStore(Encoded, S.encoded,
                                         /*isVolatile=*/true);
        Store->setAlignment(Align(8));
        if (NextBB) {
            StoreB.CreateBr(NextBB);
            CurBB = NextBB;
        } else {
            StoreB.CreateRetVoid();
        }
    }
    appendToGlobalCtors(M, Init, 0);
    appendToUsed(M, {Init});
    appendToCompilerUsed(M, {Init});
}

void rewriteSite(Module &M, const Site &S, Arch A,
                 std::uint32_t RegionBytes) {
    Function *Dispatcher = S.dispatcher;
    const ArchLayout Layout = layoutForRegister(A, S.carrier);
    CallInst *Old = S.call;
    BasicBlock *EntryBB = Old->getParent();
    BasicBlock *JoinBB = SplitBlock(EntryBB, Old);
    JoinBB->setName(EntryBB->getName() + ".ckd.call");
    EntryBB->getTerminator()->eraseFromParent();

    LLVMContext &Ctx = M.getContext();
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *HitBB =
        BasicBlock::Create(Ctx, "morok.ckd.cache.hit", S.caller, JoinBB);
    auto *MissBB =
        BasicBlock::Create(Ctx, "morok.ckd.cache.miss", S.caller, JoinBB);

    Builder EntryB(EntryBB);
    Value *H =
        emitSiteHash(EntryB, M, Dispatcher, S.caller, S.block, S, RegionBytes);
    LoadInst *Cached =
        EntryB.CreateLoad(I64, S.cache, /*isVolatile=*/true, "morok.ckd.cache");
    Value *CachedReady = EntryB.CreateICmpNE(Cached, ConstantInt::get(I64, 0),
                                             "morok.ckd.cache.ready");
    EntryB.CreateCondBr(CachedReady, HitBB, MissBB);

    Builder HitB(HitBB);
    HitB.CreateBr(JoinBB);

    Builder MissB(MissBB);
    LoadInst *Encoded = MissB.CreateLoad(I64, S.encoded,
                                         /*isVolatile=*/true, "morok.ckd.enc");
    MissB.CreateStore(Encoded, S.cache, /*isVolatile=*/true);
    MissB.CreateBr(JoinBB);

    Builder CallB(Old);
    PHINode *EncodedForCall =
        CallB.CreatePHI(I64, 2, "morok.ckd.target.enc.cached");
    EncodedForCall->addIncoming(Cached, HitBB);
    EncodedForCall->addIncoming(Encoded, MissBB);
    Value *Delta = CallB.CreateSub(EncodedForCall, H, "morok.ckd.target.delta");
    Value *Base = ptrToI64(CallB, Dispatcher);
    Value *TargetInt = CallB.CreateAdd(Base, Delta, "morok.ckd.target.decoded");
    Value *Target = CallB.CreateIntToPtr(
        TargetInt, PointerType::getUnqual(M.getContext()), "morok.ckd.target");

    IRBuilder<> SideB(Old);
    Value *SavedCarrier = emitCarrierSave(SideB, Target->getType(), Layout);
    Value *Carrier = emitCarrierDefine(SideB, Target, Layout);

    SmallVector<Value *, 16> Args;
    for (Use &Arg : Old->args())
        Args.push_back(Arg.get());

    CallInst *New = SideB.CreateCall(S.callee->getFunctionType(), Dispatcher,
                                     Args, "morok.ckd.call");
    New->setCallingConv(Old->getCallingConv());
    New->setAttributes(Old->getAttributes());
    New->setDebugLoc(Old->getDebugLoc());
    New->copyMetadata(*Old);
    IRBuilder<> AnchorB(Old);
    emitCarrierAnchor(AnchorB, Carrier, Layout);
    emitCarrierRestore(AnchorB, SavedCarrier, Layout);

    if (!Old->getType()->isVoidTy())
        Old->replaceAllUsesWith(New);
    Old->eraseFromParent();
}

} // namespace

bool callerKeyedDispatchModule(Module &M,
                               const CallerKeyedDispatchParams &params,
                               ir::IRRandom &rng) {
    if (params.probability == 0 || params.max_calls == 0 ||
        params.region_bytes == 0)
        return false;

    auto A = archOf(Triple(M.getTargetTriple()));
    if (!A)
        return false;

    const std::vector<std::string> Pool = carrierPool(*A);
    const std::uint32_t NCarriers =
        params.carriers == 0
            ? 1u
            : std::min(params.carriers, static_cast<std::uint32_t>(Pool.size()));

    const std::uint32_t Limit = std::min(params.max_calls, kMaxCallsPerModule);
    std::vector<CallInst *> Calls;
    Calls.reserve(Limit);
    for (Function &F : M) {
        if (Calls.size() >= Limit)
            break;
        if (F.isDeclaration() || F.getName().starts_with("morok."))
            continue;
        for (Instruction &I : instructions(F)) {
            if (Calls.size() >= Limit)
                break;
            auto *CI = dyn_cast<CallInst>(&I);
            if (!CI || !eligible(*CI))
                continue;
            if (rng.chance(params.probability))
                Calls.push_back(CI);
        }
    }
    if (Calls.empty())
        return false;

    shuffleCalls(Calls, rng);
    if (Calls.size() > Limit)
        Calls.resize(Limit);

    const std::uint32_t RegionBytes =
        std::min(params.region_bytes, kMaxRegionBytes);

    std::vector<Site> Sites;
    Sites.reserve(Calls.size());
    for (CallInst *CI : Calls) {
        if (!eligible(*CI))
            continue;
        SplitBlock(CI->getParent(), CI);
        Function *Caller = CI->getFunction();
        BasicBlock *SiteBlock = CI->getParent();
        auto *Callee = CI->getCalledFunction();
        if (!Caller || !Callee || SiteBlock->isEntryBlock())
            continue;
        Site S;
        S.call = CI;
        S.caller = Caller;
        S.callee = Callee;
        S.block = SiteBlock;
        S.salt = rng.next();
        S.mul = rng.next() | 1ULL;
        S.add = rng.next();
        S.seal_unsealed = rng.next() | 1ULL;
        S.seal_salt = rng.next();
        S.rot = (rng.range(63) + 1u) & 63u;
        S.encoded = makeEncodedSlot(M, rng);
        S.cache = makeCacheSlot(M);
        S.code_size = makeCodeSizeSlot(M);
        S.seal_state = makeSealStateSlot(M, S.seal_unsealed);
        // Rotate the carrier register per site.  `carriers == 1` consumes no RNG
        // and resolves to the legacy `morok.ckd.dispatch` (x19 / r14), so the
        // single-carrier path stays byte-identical to the original.
        const std::uint32_t Ci = NCarriers <= 1 ? 0u : rng.range(NCarriers);
        S.carrier = Pool[Ci];
        S.dispatcher = ensureDispatcher(M, dispatcherName(Pool[Ci], Ci == 0),
                                        layoutForRegister(*A, Pool[Ci]));
        Sites.push_back(S);
    }
    if (Sites.empty())
        return false;

    emitPostlinkManifest(M, Sites, RegionBytes);
    emitInit(M, Sites, RegionBytes, params.seal_required);
    for (const Site &S : Sites)
        rewriteSite(M, S, *A, RegionBytes);
    return true;
}

PreservedAnalyses CallerKeyedDispatchPass::run(Module &M,
                                               ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return callerKeyedDispatchModule(M, params_, rng)
               ? PreservedAnalyses::none()
               : PreservedAnalyses::all();
}

} // namespace morok::passes
