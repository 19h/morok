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
// encoded target against final native bytes and marks the site sealed; sealed
// binaries therefore cannot self-adapt to pre-start static patches, while
// unsealed dev/test builds still compute their encoded targets in the
// constructor.

#include "morok/passes/CallerKeyedDispatch.hpp"

#include "morok/passes/CodeRegionKdf.hpp"

#include "llvm/ADT/SmallVector.h"
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
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

using Builder = IRBuilder<NoFolder>;

constexpr std::uint32_t kMaxCallsPerModule = 4096;
constexpr std::uint32_t kMaxRegionBytes = 32;
constexpr std::uint64_t kPostlinkMagic = 0xC30D5B11A6E48F27ULL;

struct ArchLayout {
    StringRef dispatcher_asm;
    StringRef dispatcher_constraints;
    StringRef carrier_def_asm;
    StringRef carrier_def_constraints;
    StringRef carrier_anchor_constraints;
};

struct Site {
    CallInst *call = nullptr;
    Function *caller = nullptr;
    Function *callee = nullptr;
    BasicBlock *block = nullptr;
    GlobalVariable *encoded = nullptr;
    GlobalVariable *cache = nullptr;
    GlobalVariable *code_size = nullptr;
    std::uint64_t salt = 0;
    std::uint64_t mul = 0;
    std::uint64_t add = 0;
    std::uint32_t rot = 0;
};

std::optional<ArchLayout> layoutFor(const Triple &TT) {
    switch (TT.getArch()) {
    case Triple::x86_64:
        return ArchLayout{
            "jmpq *%r14",
            "~{memory},~{dirflag},~{fpsr},~{flags}",
            "movq $1, $0",
            "={r14},r,~{memory},~{dirflag},~{fpsr},~{flags}",
            "{r14},~{memory},~{dirflag},~{fpsr},~{flags}"};
    case Triple::aarch64:
    case Triple::aarch64_be:
        return ArchLayout{"br x19", "~{memory}", "mov $0, $1",
                          "={x19},r,~{memory}", "{x19},~{memory}"};
    default:
        return std::nullopt;
    }
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
    // The carrier register (r14 / x19) is only a safe, callee-saved hidden slot
    // under the standard C calling convention.  Non-C conventions
    // (e.g. x86_regcallcc, vectorcall) may pass integer arguments in that very
    // register, so the call's argument setup would overwrite the loaded jump
    // target after the carrier asm — and the naked `jmp *%r14` would then jump
    // to an argument value, turning attacker-influenced input into the
    // instruction pointer.  Only rewrite plain C-convention calls.
    if (CI.getCallingConv() != CallingConv::C ||
        Callee->getCallingConv() != CallingConv::C)
        return false;
    Function *Caller = CI.getFunction();
    if (!Caller || Caller->isDeclaration() || Caller->hasPersonalityFn())
        return false;
    if (Caller->getName().starts_with("morok."))
        return false;
    return true;
}

void shuffleCalls(std::vector<CallInst *> &Calls, ir::IRRandom &Rng) {
    for (std::size_t I = Calls.size(); I > 1; --I) {
        const std::size_t J = Rng.range(static_cast<std::uint32_t>(I));
        std::swap(Calls[I - 1], Calls[J]);
    }
}

Function *ensureDispatcher(Module &M, const ArchLayout &Layout) {
    if (Function *Existing = M.getFunction("morok.ckd.dispatch"))
        return Existing;

    LLVMContext &Ctx = M.getContext();
    auto *FTy = FunctionType::get(Type::getVoidTy(Ctx), false);
    auto *Fn = Function::Create(FTy, GlobalValue::InternalLinkage,
                                "morok.ckd.dispatch", &M);
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

Value *emitSiteHash(Builder &B, Module &M, Function *Dispatcher,
                    Function *Caller, BasicBlock *SiteBlock,
                    const Site &S, std::uint32_t RegionBytes) {
    auto *I8 = B.getInt8Ty();
    auto *I64 = B.getInt64Ty();
    auto *Ptr = PointerType::getUnqual(M.getContext());

    Value *Base = ptrToI64(B, Dispatcher);
    Value *Start = ptrToI64(B, BlockAddress::get(Caller, SiteBlock));
    Value *SiteDelta = B.CreateSub(Start, Base, "morok.ckd.site.delta");
    Value *H = B.CreateXor(ConstantInt::get(I64, S.salt), SiteDelta,
                           "morok.ckd.hash");

    for (std::uint32_t I = 0; I != RegionBytes; ++I) {
        Value *Addr = B.CreateAdd(Start, ConstantInt::get(I64, I),
                                  "morok.ckd.byte.addr");
        Value *BytePtr = B.CreateIntToPtr(Addr, Ptr, "morok.ckd.byte.ptr");
        LoadInst *Byte = B.CreateLoad(I8, BytePtr, /*isVolatile=*/true,
                                      "morok.ckd.byte");
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
    auto *GV = new GlobalVariable(
        M, I64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
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

void emitPostlinkManifest(Module &M, Function *Dispatcher,
                          ArrayRef<Site> Sites,
                          std::uint32_t RegionBytes) {
    if (Sites.empty())
        return;

    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);

    auto *RecordTy = StructType::get(
        Ctx, {Ptr, Ptr, Ptr, Ptr, Ptr, I64, I64, I64, I32, I32});
    SmallVector<Constant *, 16> Records;
    Records.reserve(Sites.size());
    for (const Site &S : Sites) {
        Records.push_back(ConstantStruct::get(
            RecordTy,
            {S.encoded, S.code_size, Dispatcher,
             BlockAddress::get(S.caller, S.block), S.callee,
             ConstantInt::get(I64, S.salt), ConstantInt::get(I64, S.mul),
             ConstantInt::get(I64, S.add), ConstantInt::get(I32, S.rot),
             ConstantInt::get(I32, RegionBytes)}));
    }

    auto *RecordsTy = ArrayType::get(RecordTy, Records.size());
    auto *ManifestTy =
        StructType::get(Ctx, {I64, I32, I32, RecordsTy});
    auto *Manifest = new GlobalVariable(
        M, ManifestTy, /*isConstant=*/true, GlobalValue::PrivateLinkage,
        ConstantStruct::get(
            ManifestTy,
            {ConstantInt::get(I64, kPostlinkMagic), ConstantInt::get(I32, 1),
             ConstantInt::get(I32, Records.size()),
             ConstantArray::get(RecordsTy, Records)}),
        "morok.postlink.ckd");
    Manifest->setAlignment(Align(8));
    appendToCompilerUsed(M, {Manifest});
}

Value *emitCarrierDefine(IRBuilder<> &B, Value *Target,
                         const ArchLayout &Layout) {
    auto *FTy = FunctionType::get(Target->getType(), {Target->getType()},
                                  false);
    InlineAsm *IA = InlineAsm::get(FTy, Layout.carrier_def_asm,
                                   Layout.carrier_def_constraints,
                                   /*hasSideEffects=*/true);
    return B.CreateCall(FTy, IA, {Target}, "morok.ckd.carrier");
}

void emitCarrierAnchor(IRBuilder<> &B, Value *Carrier,
                       const ArchLayout &Layout) {
    auto *FTy =
        FunctionType::get(Type::getVoidTy(B.getContext()),
                          {Carrier->getType()}, false);
    InlineAsm *IA = InlineAsm::get(FTy, "", Layout.carrier_anchor_constraints,
                                   /*hasSideEffects=*/true);
    B.CreateCall(FTy, IA, {Carrier});
}

void emitInit(Module &M, Function *Dispatcher, ArrayRef<Site> Sites,
              std::uint32_t RegionBytes, bool SealRequired) {
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

    Builder B(BasicBlock::Create(Ctx, "entry", Init));
    Value *Disp = ptrToI64(B, Dispatcher);
    for (const Site &S : Sites) {
        LoadInst *CodeSize =
            B.CreateLoad(I32, S.code_size, /*isVolatile=*/true,
                         "morok.ckd.code.size.load");
        CodeSize->setAlignment(Align(4));
        Value *NonZero = B.CreateICmpNE(CodeSize, ConstantInt::get(I32, 0),
                                        "morok.ckd.code.nz");
        Value *Sealed = B.CreateICmpNE(
            CodeSize,
            ConstantInt::get(I32, code_region_kdf::kUnsealedCodeSize),
            "morok.ckd.code.sealed");
        Value *HasCode = B.CreateAnd(NonZero, Sealed, "morok.ckd.code.has");
        LoadInst *Existing =
            B.CreateLoad(I64, S.encoded, /*isVolatile=*/true,
                         "morok.ckd.enc.sealed");
        Value *Fallback;
        if (SealRequired) {
            // Sealed-release build: the post-link sealer is the sole source of
            // the encoded target, so NEVER recompute it from the live code
            // bytes.  Recomputing is exactly the self-seal hole (#21): a static
            // attacker who patches a caller region and also resets the mutable
            // code_size slot back to the unsealed sentinel would otherwise make
            // this constructor re-hash and re-seal the tampered bytes at start.
            // When the slot reads unsealed here — never sealed, or a downgrade
            // patch reset the sentinel — poison the encoded target so the
            // dispatcher decodes a wrong address (silent mis-dispatch) instead
            // of adapting to the patch.  A nonzero per-site twist guarantees the
            // poisoned value differs from any genuine sealed target.
            Fallback = B.CreateXor(Existing,
                                   ConstantInt::get(I64, S.salt | 1ULL),
                                   "morok.ckd.enc.poison");
        } else {
            // Unsealed dev/differential build: no sealer ran, so recover the
            // encoded target from the live bytes at startup.  This mode makes no
            // tamper-resistance claim; it only keeps unsealed builds runnable.
            Value *Target = ptrToI64(B, S.callee);
            Value *Delta = B.CreateSub(Target, Disp, "morok.ckd.target.delta");
            Value *H = emitSiteHash(B, M, Dispatcher, S.caller, S.block, S,
                                    RegionBytes);
            Fallback = B.CreateAdd(Delta, H, "morok.ckd.target.enc");
        }
        Value *Encoded =
            B.CreateSelect(HasCode, Existing, Fallback, "morok.ckd.target.sel");
        B.CreateStore(Encoded, S.encoded, /*isVolatile=*/true);
    }
    B.CreateRetVoid();
    appendToGlobalCtors(M, Init, 0);
    appendToUsed(M, {Init});
    appendToCompilerUsed(M, {Init});
}

void rewriteSite(Module &M, Function *Dispatcher, const Site &S,
                 const ArchLayout &Layout, std::uint32_t RegionBytes) {
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
    Value *H = emitSiteHash(EntryB, M, Dispatcher, S.caller, S.block, S,
                            RegionBytes);
    LoadInst *Cached = EntryB.CreateLoad(I64, S.cache, /*isVolatile=*/true,
                                         "morok.ckd.cache");
    Value *CachedReady =
        EntryB.CreateICmpNE(Cached, ConstantInt::get(I64, 0),
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
    Value *Delta =
        CallB.CreateSub(EncodedForCall, H, "morok.ckd.target.delta");
    Value *Base = ptrToI64(CallB, Dispatcher);
    Value *TargetInt = CallB.CreateAdd(Base, Delta, "morok.ckd.target.decoded");
    Value *Target = CallB.CreateIntToPtr(
        TargetInt, PointerType::getUnqual(M.getContext()), "morok.ckd.target");

    IRBuilder<> SideB(Old);
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

    auto Layout = layoutFor(Triple(M.getTargetTriple()));
    if (!Layout)
        return false;

    const std::uint32_t Limit =
        std::min(params.max_calls, kMaxCallsPerModule);
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

    Function *Dispatcher = ensureDispatcher(M, *Layout);
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
        S.encoded = makeEncodedSlot(M, rng);
        S.cache = makeCacheSlot(M);
        S.code_size = makeCodeSizeSlot(M);
        S.salt = rng.next();
        S.mul = rng.next() | 1ULL;
        S.add = rng.next();
        S.rot = (rng.range(63) + 1u) & 63u;
        Sites.push_back(S);
    }
    if (Sites.empty())
        return false;

    emitPostlinkManifest(M, Dispatcher, Sites, RegionBytes);
    emitInit(M, Dispatcher, Sites, RegionBytes, params.seal_required);
    for (const Site &S : Sites)
        rewriteSite(M, Dispatcher, S, *Layout, RegionBytes);
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
