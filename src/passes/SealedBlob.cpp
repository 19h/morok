// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// Explicit sealed byte blobs: encrypted storage plus per-blob lazy accessors.

#include "morok/passes/SealedBlob.hpp"

#include "morok/passes/RuntimeSeal.hpp"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

using namespace llvm;

namespace morok::passes {
namespace {

constexpr StringLiteral kSection = ".morok.sealed";
constexpr StringLiteral kSelectedPrefix = "morok.sealed.";
constexpr StringLiteral kCipherPrefix = "morok.sealed.cipher.";
constexpr StringLiteral kOpenPrefix = "morok.sealed.open.";
constexpr StringLiteral kTagSinkPrefix = "morok.sealed.tag.sink.";
constexpr std::uint64_t kDefaultMaxBlobBytes = 64 * 1024;
constexpr std::uint64_t kRuntimeTagDomain = 0x6d726b3574397362ULL;

struct RewriteSite {
    Instruction *inst = nullptr;
    unsigned operand = 0;
};

struct BlobPlan {
    GlobalVariable *gv = nullptr;
    std::vector<std::uint8_t> plain;
    std::uint64_t key = 0;
    std::uint64_t salt0 = 0;
    std::uint64_t salt1 = 0;
    std::uint32_t id = 0;
    std::uint32_t magic_bytes = 0;
    GlobalVariable *magic_sink = nullptr;
    SmallVector<RewriteSite, 8> sites;
};

bool hasSource(const SealedBlobParams &Params, StringRef Source) {
    return std::find(Params.key_sources.begin(), Params.key_sources.end(),
                     Source) != Params.key_sources.end();
}

std::uint64_t mix64(std::uint64_t X, std::uint64_t Salt) {
    X += Salt;
    X ^= X >> 33;
    X *= 0xff51afd7ed558ccdULL;
    X ^= X >> 29;
    X *= 0xc4ceb9fe1a85ec53ULL;
    return X ^ (X >> 32);
}

Value *mix64(IRBuilderBase &B, Value *X, std::uint64_t Salt,
             const Twine &Name) {
    auto *I64 = B.getInt64Ty();
    X = B.CreateAdd(X, ConstantInt::get(I64, Salt), Name + ".add");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 33)),
                    Name + ".fold33");
    X = B.CreateMul(X, ConstantInt::get(I64, 0xff51afd7ed558ccdULL),
                    Name + ".mul0");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 29)),
                    Name + ".fold29");
    X = B.CreateMul(X, ConstantInt::get(I64, 0xc4ceb9fe1a85ec53ULL),
                    Name + ".mul1");
    return B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 32)),
                       Name + ".fold32");
}

std::uint8_t keystreamByte(const BlobPlan &Plan, std::uint64_t Index) {
    std::uint64_t X = Plan.key ^ (Index * (Plan.salt0 | 1ULL));
    X ^= Plan.salt1 + (Index << 17);
    return static_cast<std::uint8_t>(mix64(X, Plan.salt0 ^ Plan.salt1));
}

Value *emitKeystreamByte(IRBuilderBase &B, const BlobPlan &Plan, Value *Key,
                         Value *Index) {
    auto *I64 = B.getInt64Ty();
    Value *IdxMix = B.CreateMul(Index, ConstantInt::get(I64, Plan.salt0 | 1ULL),
                                "morok.sealed.ks.idx");
    Value *X = B.CreateXor(Key, IdxMix, "morok.sealed.ks.seed");
    Value *Shifted =
        B.CreateShl(Index, ConstantInt::get(I64, 17), "morok.sealed.ks.shift");
    X = B.CreateXor(X,
                    B.CreateAdd(ConstantInt::get(I64, Plan.salt1), Shifted,
                                "morok.sealed.ks.salt"),
                    "morok.sealed.ks.input");
    X = mix64(B, X, Plan.salt0 ^ Plan.salt1, "morok.sealed.ks.mix");
    return B.CreateTrunc(X, B.getInt8Ty(), "morok.sealed.ks.byte");
}

Value *emitRuntimeTagByte(IRBuilderBase &B, const BlobPlan &Plan, Value *Seed,
                          Value *Index) {
    auto *I64 = B.getInt64Ty();
    Value *IdxA = B.CreateMul(
        Index,
        ConstantInt::get(I64, (Plan.salt1 ^ 0xA24BAED4963EE407ULL) | 1ULL),
        "morok.sealed.tag.idx.a");
    Value *IdxB =
        B.CreateAdd(B.CreateShl(Index, ConstantInt::get(I64, 11),
                                "morok.sealed.tag.idx.shl"),
                    ConstantInt::get(I64, Plan.salt0 ^ kRuntimeTagDomain),
                    "morok.sealed.tag.idx.b");
    Value *X = B.CreateXor(Seed, IdxA, "morok.sealed.tag.seed");
    X = B.CreateXor(X, IdxB, "morok.sealed.tag.input");
    X = mix64(B, X, Plan.salt0 + Plan.salt1 + kRuntimeTagDomain,
              "morok.sealed.tag.kdf");
    return B.CreateTrunc(X, B.getInt8Ty(), "morok.sealed.tag.byte");
}

bool selected(const GlobalVariable &GV) {
    StringRef Section = GV.getSection();
    // Mach-O section attributes are segment-qualified (for example
    // "__DATA,.morok.sealed"), while ELF/IR tests use the bare section name.
    return Section == kSection || Section.ends_with(",.morok.sealed") ||
           (GV.getName().starts_with(kSelectedPrefix) &&
            !GV.getName().starts_with(kCipherPrefix));
}

std::vector<std::uint8_t> constantBytes(const GlobalVariable &GV) {
    std::vector<std::uint8_t> Bytes;
    auto *CDA = dyn_cast_or_null<ConstantDataArray>(GV.getInitializer());
    if (!CDA || !CDA->getElementType()->isIntegerTy(8))
        return Bytes;

    const std::uint64_t N = CDA->getNumElements();
    Bytes.reserve(static_cast<std::size_t>(N));
    for (std::uint64_t I = 0; I != N; ++I)
        Bytes.push_back(static_cast<std::uint8_t>(CDA->getElementAsInteger(I)));
    return Bytes;
}

Constant *byteArrayConstant(LLVMContext &Ctx, ArrayRef<std::uint8_t> Bytes) {
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *ArrTy = ArrayType::get(I8, Bytes.size());
    SmallVector<Constant *, 64> Elts;
    Elts.reserve(Bytes.size());
    for (std::uint8_t B : Bytes)
        Elts.push_back(ConstantInt::get(I8, B));
    return ConstantArray::get(ArrTy, Elts);
}

bool containsBlob(Value *V, const GlobalVariable *GV,
                  SmallPtrSetImpl<Value *> &Seen) {
    if (V == GV)
        return true;
    if (!Seen.insert(V).second)
        return false;
    if (auto *CE = dyn_cast<ConstantExpr>(V))
        for (Value *Op : CE->operands())
            if (containsBlob(Op, GV, Seen))
                return true;
    return false;
}

bool containsBlob(Value *V, const GlobalVariable *GV) {
    SmallPtrSet<Value *, 8> Seen;
    return containsBlob(V, GV, Seen);
}

bool supportedLeafUse(Instruction *I, const Use &U) {
    if (!I || isa<PHINode>(I) || I->isTerminator())
        return false;

    if (auto *LI = dyn_cast<LoadInst>(I))
        return LI->getPointerOperand() == U.get();

    if (auto *CB = dyn_cast<CallBase>(I)) {
        if (!CB->isArgOperand(&U))
            return false;
        const unsigned ArgNo = CB->getArgOperandNo(&U);
        return CB->doesNotCapture(ArgNo) &&
               (CB->onlyReadsMemory(ArgNo) || CB->onlyReadsMemory());
    }

    return false;
}

bool collectSites(Value *Root, GlobalVariable *GV,
                  SmallVectorImpl<RewriteSite> &Sites,
                  SmallPtrSetImpl<Value *> &Seen) {
    if (!Seen.insert(Root).second)
        return true;

    for (Use &U : Root->uses()) {
        User *Usr = U.getUser();
        if (auto *I = dyn_cast<Instruction>(Usr)) {
            if (!supportedLeafUse(I, U))
                return false;
            Sites.push_back({I, U.getOperandNo()});
            continue;
        }
        if (auto *CE = dyn_cast<ConstantExpr>(Usr)) {
            if (!collectSites(CE, GV, Sites, Seen))
                return false;
            continue;
        }
        return false;
    }
    return true;
}

AllocaInst *entryAlloca(Function &F, Type *Ty, const Twine &Name) {
    IRBuilder<> B(&*F.getEntryBlock().getFirstInsertionPt());
    auto *AI = B.CreateAlloca(Ty, nullptr, Name);
    AI->setAlignment(Align(1));
    return AI;
}

Value *materialize(Value *V, Instruction *Before, GlobalVariable *GV,
                   Value *Base) {
    if (V == GV)
        return Base;

    auto *CE = dyn_cast<ConstantExpr>(V);
    if (!CE)
        return V;

    Instruction *I = CE->getAsInstruction();
    I->insertBefore(Before);
    for (unsigned OpNo = 0; OpNo != I->getNumOperands(); ++OpNo) {
        Value *Op = I->getOperand(OpNo);
        if (containsBlob(Op, GV))
            I->setOperand(OpNo, materialize(Op, I, GV, Base));
    }
    return I;
}

void zeroizeAfter(Instruction *I, Value *Base, std::uint64_t Size) {
    Instruction *Next = I->getNextNode();
    if (!Next)
        return;
    IRBuilder<> B(Next);
    B.CreateMemSet(Base, B.getInt8(0), ConstantInt::get(B.getInt64Ty(), Size),
                   MaybeAlign(1),
                   /*isVolatile=*/true);
}

void rewriteSite(const BlobPlan &Plan, Function *OpenFn, bool ZeroizeAfterUse) {
    Instruction *I = Plan.sites.front().inst;
    (void)I;
    for (const RewriteSite &Site : Plan.sites) {
        Instruction *UseInst = Site.inst;
        Function *F = UseInst->getFunction();
        auto *Local =
            entryAlloca(*F, Plan.gv->getValueType(), "morok.sealed.local");

        IRBuilder<> B(UseInst);
        B.CreateCall(OpenFn->getFunctionType(), OpenFn, {Local});

        Value *Original = UseInst->getOperand(Site.operand);
        Value *Replacement = materialize(Original, UseInst, Plan.gv, Local);
        UseInst->setOperand(Site.operand, Replacement);

        if (ZeroizeAfterUse)
            zeroizeAfter(UseInst, Local, Plan.plain.size());
    }
}

void addAccessorAttrs(Function &F) {
    F.addFnAttr(Attribute::NoUnwind);
    F.addFnAttr(Attribute::NoInline);
}

GlobalVariable *createTagSink(Module &M, const BlobPlan &Plan) {
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *GV = new GlobalVariable(
        M, I64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I64, 0),
        (Twine(kTagSinkPrefix) + Twine(Plan.id)).str());
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    GV->setAlignment(Align(8));
    return GV;
}

Value *emitStableAddressZero(IRBuilderBase &B, Function *Fn) {
    auto *I64 = B.getInt64Ty();
    auto *Slot = B.CreateAlloca(I64, nullptr, "morok.sealed.addr.slot");
    Value *Addr = B.CreatePtrToInt(Fn, I64, "morok.sealed.addr");
    auto *Store = B.CreateStore(Addr, Slot);
    Store->setVolatile(true);
    Store->setAlignment(Align(8));
    auto *A = B.CreateLoad(I64, Slot, "morok.sealed.addr.a");
    A->setVolatile(true);
    A->setAlignment(Align(8));
    auto *C = B.CreateLoad(I64, Slot, "morok.sealed.addr.b");
    C->setVolatile(true);
    C->setAlignment(Align(8));
    return B.CreateXor(A, C, "morok.sealed.addr.zero");
}

Function *defineAccessor(Module &M, const BlobPlan &Plan,
                         const SealedBlobParams &Params) {
    LLVMContext &Ctx = M.getContext();
    auto *Void = Type::getVoidTy(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);
    auto *FnTy = FunctionType::get(Void, {Ptr}, /*isVarArg=*/false);
    const std::string Name = (Twine(kOpenPrefix) + Twine(Plan.id)).str();
    auto *Fn = Function::Create(FnTy, GlobalValue::PrivateLinkage, Name, M);
    addAccessorAttrs(*Fn);
    Fn->getArg(0)->setName("dst");

    auto *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    auto *Loop = BasicBlock::Create(Ctx, "copy", Fn);
    auto *Done = BasicBlock::Create(Ctx, "done", Fn);

    IRBuilder<> EB(Entry);
    auto *I64 = EB.getInt64Ty();
    Value *Dynamic = ConstantInt::get(I64, 0);
    if (hasSource(Params, "runtime_seal")) {
        Value *Delta = runtime_seal::emitChannelDelta(
            EB, runtime_seal::kAntiDebugChannel, "morok.sealed.anti.delta");
        Dynamic = EB.CreateXor(Dynamic,
                               runtime_seal::emitKdf64(EB, Delta, Plan.salt0,
                                                       "morok.sealed.anti.kdf"),
                               "morok.sealed.anti.key");
    }
    if (hasSource(Params, "external_proof")) {
        Value *Delta = runtime_seal::emitChannelDelta(
            EB, runtime_seal::kExternalProofChannel,
            "morok.sealed.proof.delta");
        Dynamic =
            EB.CreateXor(Dynamic,
                         runtime_seal::emitKdf64(EB, Delta, Plan.salt1,
                                                 "morok.sealed.proof.kdf"),
                         "morok.sealed.proof.key");
    }
    if (hasSource(Params, "env_binding")) {
        Value *Delta = runtime_seal::emitChannelDelta(
            EB, runtime_seal::kEnvBindingChannel, "morok.sealed.env.delta");
        Dynamic = EB.CreateXor(
            Dynamic,
            runtime_seal::emitKdf64(EB, Delta,
                                    Plan.salt0 ^ Plan.salt1 ^
                                        0xE47C9143B51D6F2AULL,
                                    "morok.sealed.env.kdf"),
            "morok.sealed.env.key");
    }
    if (hasSource(Params, "code_region"))
        Dynamic = EB.CreateXor(Dynamic, emitStableAddressZero(EB, Fn),
                               "morok.sealed.code.key");

    Value *Key = EB.CreateXor(ConstantInt::get(I64, Plan.key), Dynamic,
                              "morok.sealed.key");
    Value *TagSeed = nullptr;
    if (Plan.magic_sink && Plan.magic_bytes > 0) {
        GlobalVariable *Seal =
            runtime_seal::findChannel(M, runtime_seal::kAntiDebugChannel);
        if (Seal) {
            auto *Root = EB.CreateLoad(I64, Seal, "morok.sealed.tag.root");
            Root->setVolatile(true);
            Root->setAlignment(Align(8));
            Value *SeedInput = EB.CreateXor(
                Root,
                ConstantInt::get(
                    I64, kRuntimeTagDomain ^
                             (static_cast<std::uint64_t>(Plan.id) << 32) ^
                             Plan.salt1),
                "morok.sealed.tag.root.mix");
            TagSeed = mix64(EB, SeedInput, Plan.salt0 ^ kRuntimeTagDomain,
                            "morok.sealed.tag.seed.kdf");
        } else {
            TagSeed = ConstantInt::get(I64, 0);
        }
    }
    Value *CipherBase = EB.CreateInBoundsGEP(
        Plan.gv->getValueType(), Plan.gv,
        {ConstantInt::get(I64, 0), ConstantInt::get(I64, 0)},
        "morok.sealed.cipher.base");
    EB.CreateBr(Loop);

    IRBuilder<> LB(Loop);
    auto *Idx = LB.CreatePHI(I64, 2, "morok.sealed.i");
    Idx->addIncoming(ConstantInt::get(I64, 0), Entry);
    PHINode *TagDiff = nullptr;
    if (TagSeed) {
        TagDiff = LB.CreatePHI(I64, 2, "morok.sealed.tag.diff");
        TagDiff->addIncoming(ConstantInt::get(I64, 0), Entry);
    }
    Value *CipherPtr = LB.CreateInBoundsGEP(LB.getInt8Ty(), CipherBase, Idx,
                                            "morok.sealed.cipher.ptr");
    auto *Cipher =
        LB.CreateLoad(LB.getInt8Ty(), CipherPtr, "morok.sealed.cipher.byte");
    Cipher->setVolatile(true);
    Cipher->setAlignment(Align(1));
    Value *Plain = LB.CreateXor(Cipher, emitKeystreamByte(LB, Plan, Key, Idx),
                                "morok.sealed.plain.byte");
    Value *NextTagDiff = nullptr;
    if (TagDiff) {
        Value *Expected = emitRuntimeTagByte(LB, Plan, TagSeed, Idx);
        Value *ByteDiff = LB.CreateZExt(
            LB.CreateXor(Plain, Expected, "morok.sealed.tag.byte.diff"), I64,
            "morok.sealed.tag.byte.diff64");
        Value *InWindow =
            LB.CreateICmpULT(Idx, ConstantInt::get(I64, Plan.magic_bytes),
                             "morok.sealed.tag.window");
        Value *Accum = LB.CreateOr(TagDiff, ByteDiff, "morok.sealed.tag.accum");
        NextTagDiff =
            LB.CreateSelect(InWindow, Accum, TagDiff, "morok.sealed.tag.next");
    }
    Value *DstPtr = LB.CreateInBoundsGEP(LB.getInt8Ty(), Fn->getArg(0), Idx,
                                         "morok.sealed.dst.ptr");
    auto *Store = LB.CreateStore(Plain, DstPtr);
    Store->setAlignment(Align(1));
    Value *NextI =
        LB.CreateAdd(Idx, ConstantInt::get(I64, 1), "morok.sealed.next");
    Idx->addIncoming(NextI, Loop);
    if (TagDiff)
        TagDiff->addIncoming(NextTagDiff, Loop);
    LB.CreateCondBr(LB.CreateICmpULT(NextI,
                                     ConstantInt::get(I64, Plan.plain.size()),
                                     "morok.sealed.more"),
                    Loop, Done);

    IRBuilder<> DB(Done);
    if (Plan.magic_sink && NextTagDiff) {
        Value *SinkWord = runtime_seal::emitKdf64(
            DB, NextTagDiff, Plan.salt0 ^ Plan.salt1 ^ kRuntimeTagDomain,
            "morok.sealed.tag.poison");
        auto *SinkStore = DB.CreateStore(SinkWord, Plan.magic_sink);
        SinkStore->setVolatile(true);
        SinkStore->setAlignment(Align(8));
    }
    DB.CreateRetVoid();
    return Fn;
}

bool collectPlan(GlobalVariable &GV, const SealedBlobParams &Params,
                 ir::IRRandom &Rng, std::uint32_t Id, BlobPlan &Out) {
    if (!selected(GV) || !GV.hasInitializer() || !GV.hasLocalLinkage() ||
        !GV.isConstant() || GV.isThreadLocal() ||
        GV.getName().starts_with(kCipherPrefix))
        return false;

    auto *ArrTy = dyn_cast<ArrayType>(GV.getValueType());
    if (!ArrTy || !ArrTy->getElementType()->isIntegerTy(8))
        return false;

    std::vector<std::uint8_t> Plain = constantBytes(GV);
    if (Plain.empty())
        return false;
    const std::uint64_t MaxBytes = Params.max_blob_bytes == 0
                                       ? kDefaultMaxBlobBytes
                                       : Params.max_blob_bytes;
    if (Plain.size() > MaxBytes)
        return false;

    SmallPtrSet<Value *, 16> Seen;
    SmallVector<RewriteSite, 8> Sites;
    if (!collectSites(&GV, &GV, Sites, Seen) || Sites.empty())
        return false;

    Out.gv = &GV;
    Out.plain = std::move(Plain);
    Out.key = Rng.next();
    Out.salt0 = Rng.next() | 1ULL;
    Out.salt1 = Rng.next() | 1ULL;
    Out.id = Id;
    Out.sites = std::move(Sites);
    return true;
}

void encryptStorage(const BlobPlan &Plan) {
    std::vector<std::uint8_t> Cipher;
    Cipher.reserve(Plan.plain.size());
    for (std::uint64_t I = 0; I != Plan.plain.size(); ++I)
        Cipher.push_back(Plan.plain[I] ^ keystreamByte(Plan, I));

    Plan.gv->setInitializer(byteArrayConstant(Plan.gv->getContext(), Cipher));
    Plan.gv->setConstant(true);
    Plan.gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    Plan.gv->setName((Twine(kCipherPrefix) + Twine(Plan.id)).str());
}

} // namespace

bool sealedBlobModule(Module &M, const SealedBlobParams &Params,
                      ir::IRRandom &Rng) {
    if (!Params.enabled || Params.delivery != "eager")
        return false;

    std::vector<BlobPlan> Plans;
    const std::uint32_t MaxBlobs = Params.max_blobs == 0 ? 8 : Params.max_blobs;
    Plans.reserve(MaxBlobs);

    for (GlobalVariable &GV : M.globals()) {
        if (Plans.size() >= MaxBlobs)
            break;
        BlobPlan Plan;
        if (collectPlan(GV, Params, Rng,
                        static_cast<std::uint32_t>(Plans.size()), Plan))
            Plans.push_back(std::move(Plan));
    }

    if (Plans.empty())
        return false;

    const bool UseRuntimeTags =
        Params.runtime_keyed_magic && Params.magic_bytes > 0;
    if (UseRuntimeTags)
        runtime_seal::getChannel(M, runtime_seal::kAntiDebugChannel, Rng);

    bool Changed = false;
    for (BlobPlan &Plan : Plans) {
        if (UseRuntimeTags) {
            Plan.magic_bytes = static_cast<std::uint32_t>(
                std::min<std::uint64_t>(Plan.plain.size(), Params.magic_bytes));
            if (Plan.magic_bytes > 0)
                Plan.magic_sink = createTagSink(M, Plan);
        }
        encryptStorage(Plan);
        Function *Open = defineAccessor(M, Plan, Params);
        rewriteSite(Plan, Open, Params.zeroize_after_use);
        Changed = true;
    }
    return Changed;
}

PreservedAnalyses SealedBlobPass::run(Module &M, ModuleAnalysisManager &) {
    ir::IRRandom Rng(engine_);
    return sealedBlobModule(M, params_, Rng) ? PreservedAnalyses::none()
                                             : PreservedAnalyses::all();
}

} // namespace morok::passes
