// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/CallerKeyedDispatch.cpp
//
// Direct internal calls are rewritten to call a shared native dispatcher.  The
// original callee address is carried in a callee-saved register and is decoded
// from a per-site encoded dispatcher-relative delta.  The first hit at each
// site computes the volatile caller-byte hash and then caches the recovered
// target locally so hot loops do not replay the hash on every iteration.
//
// This is the strongest construction available at the IR layer without a
// post-link byte/RVA manifest: the hash is over final in-memory code bytes at
// runtime, so debugger breakpoints or inline hooks planted after constructors
// run perturb the dispatch target.  Pre-start static patching still requires a
// later post-link precompute stage.

#include "morok/passes/CallerKeyedDispatch.hpp"

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
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
              std::uint32_t RegionBytes) {
    if (Sites.empty())
        return;

    LLVMContext &Ctx = M.getContext();
    auto *Void = Type::getVoidTy(Ctx);
    auto *FTy = FunctionType::get(Void, false);
    auto *Init = Function::Create(FTy, GlobalValue::InternalLinkage,
                                  "morok.ckd.init", &M);
    Init->setDSOLocal(true);
    Init->addFnAttr(Attribute::NoInline);

    Builder B(BasicBlock::Create(Ctx, "entry", Init));
    Value *Disp = ptrToI64(B, Dispatcher);
    for (const Site &S : Sites) {
        Value *Target = ptrToI64(B, S.callee);
        Value *Delta = B.CreateSub(Target, Disp, "morok.ckd.target.delta");
        Value *H = emitSiteHash(B, M, Dispatcher, S.caller, S.block, S,
                                RegionBytes);
        Value *Encoded = B.CreateAdd(Delta, H, "morok.ckd.target.enc");
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
    LoadInst *Cached = EntryB.CreateLoad(I64, S.cache, /*isVolatile=*/true,
                                         "morok.ckd.cache");
    Value *CachedReady =
        EntryB.CreateICmpNE(Cached, ConstantInt::get(I64, 0),
                            "morok.ckd.cache.ready");
    EntryB.CreateCondBr(CachedReady, HitBB, MissBB);

    Builder HitB(HitBB);
    HitB.CreateBr(JoinBB);

    Builder MissB(MissBB);
    Value *H = emitSiteHash(MissB, M, Dispatcher, S.caller, S.block, S,
                            RegionBytes);
    LoadInst *Encoded = MissB.CreateLoad(I64, S.encoded,
                                         /*isVolatile=*/true, "morok.ckd.enc");
    Value *Delta = MissB.CreateSub(Encoded, H, "morok.ckd.target.delta");
    Value *Base = ptrToI64(MissB, Dispatcher);
    Value *DecodedTarget =
        MissB.CreateAdd(Base, Delta, "morok.ckd.target.decoded");
    MissB.CreateStore(DecodedTarget, S.cache, /*isVolatile=*/true);
    MissB.CreateBr(JoinBB);

    Builder CallB(Old);
    PHINode *TargetInt = CallB.CreatePHI(I64, 2, "morok.ckd.target.int");
    TargetInt->addIncoming(Cached, HitBB);
    TargetInt->addIncoming(DecodedTarget, MissBB);
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
        S.salt = rng.next();
        S.mul = rng.next() | 1ULL;
        S.add = rng.next();
        S.rot = (rng.range(63) + 1u) & 63u;
        Sites.push_back(S);
    }
    if (Sites.empty())
        return false;

    emitInit(M, Dispatcher, Sites, RegionBytes);
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
