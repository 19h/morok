// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// Host identity binding material for RuntimeSeal.

#include "morok/passes/EnvBindingKdf.hpp"

#include "morok/passes/RuntimeSeal.hpp"
#include "morok/runtime/PlatformRuntime.hpp"

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <algorithm>
#include <cstdint>
#include <optional>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr StringLiteral kFeedName = "morok.envbind.feed";
constexpr StringLiteral kFinishName = "morok.envbind.finish";
constexpr StringLiteral kCtorName = "morok.envbind.collect";
constexpr StringLiteral kAccumName = "morok.envbind.accum";
constexpr StringLiteral kMaskName = "morok.envbind.mask";
constexpr StringLiteral kDoneName = "morok.envbind.done";
constexpr std::uint32_t kReadBytes = 256;
constexpr std::uint32_t kMaxFactors = 8;

struct FactorSpec {
    StringRef path;
    std::uint64_t domain;
};

void addHelperAttrs(Function &F, bool VirtualizeHelpers) {
    F.addFnAttr(Attribute::NoUnwind);
    F.addFnAttr(Attribute::NoInline);
    if (!VirtualizeHelpers)
        F.addFnAttr("morok.envbind.no_vm");
}

GlobalVariable *getI64Global(Module &M, StringRef Name, std::uint64_t Init,
                             Align Alignment = Align(8)) {
    if (auto *Existing = M.getGlobalVariable(Name, true))
        return Existing;
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *GV = new GlobalVariable(M, I64, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage,
                                  ConstantInt::get(I64, Init), Name);
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    GV->setAlignment(Alignment);
    return GV;
}

GlobalVariable *getDone(Module &M) {
    if (auto *Existing = M.getGlobalVariable(kDoneName, true))
        return Existing;
    auto *I1 = Type::getInt1Ty(M.getContext());
    auto *GV = new GlobalVariable(M, I1, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage,
                                  ConstantInt::getFalse(M.getContext()),
                                  kDoneName);
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    GV->setAlignment(Align(1));
    return GV;
}

Value *rotl64(IRBuilderBase &B, Value *X, unsigned Bits, const Twine &Name) {
    auto *I64 = B.getInt64Ty();
    return B.CreateOr(B.CreateShl(X, ConstantInt::get(I64, Bits),
                                  Name + ".shl"),
                      B.CreateLShr(X, ConstantInt::get(I64, 64 - Bits),
                                   Name + ".shr"),
                      Name + ".rot");
}

Value *mix64(IRBuilderBase &B, Value *X, std::uint64_t Salt,
             const Twine &Name) {
    auto *I64 = B.getInt64Ty();
    X = B.CreateXor(X, ConstantInt::get(I64, Salt), Name + ".salt");
    X = B.CreateAdd(rotl64(B, X, 19, Name + ".r0"),
                    ConstantInt::get(I64, 0xD1B54A32D192ED03ULL),
                    Name + ".bias0");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 37)),
                    Name + ".fold37");
    X = B.CreateMul(X, ConstantInt::get(I64, 0x9FB21C651E98DF25ULL),
                    Name + ".mul0");
    X = B.CreateXor(X, rotl64(B, X, 23, Name + ".r1"), Name + ".foldrot");
    X = B.CreateMul(X, ConstantInt::get(I64, (Salt | 1ULL)), Name + ".mul1");
    return B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 29)),
                       Name + ".fold29");
}

std::optional<std::uint64_t> parseExpectedDigest(StringRef Text) {
    Text = Text.trim();
    if (Text.empty())
        return std::nullopt;
    std::uint64_t Value = 0;
    if (Text.getAsInteger(0, Value))
        return std::nullopt;
    return Value;
}

Function *getApiFunction(Module &M, StringRef Name, FunctionType *Ty) {
    if (Function *F = M.getFunction(Name)) {
        if (F->getFunctionType() == Ty)
            return F;
        return nullptr;
    }
    return Function::Create(Ty, GlobalValue::ExternalLinkage, Name, M);
}

Value *canonicalByte(IRBuilder<> &B, Value *Byte, bool Canonicalize,
                     Value *&UseByte, const Twine &Name) {
    if (!Canonicalize) {
        UseByte = ConstantInt::getTrue(B.getContext());
        return Byte;
    }

    auto *I8 = B.getInt8Ty();
    Value *IsUpper =
        B.CreateAnd(B.CreateICmpUGE(Byte, ConstantInt::get(I8, 'A'),
                                    Name + ".upper.lo"),
                    B.CreateICmpULE(Byte, ConstantInt::get(I8, 'Z'),
                                    Name + ".upper.hi"),
                    Name + ".upper");
    Value *Lower = B.CreateAdd(Byte, ConstantInt::get(I8, 32),
                               Name + ".lower.byte");
    Value *Norm = B.CreateSelect(IsUpper, Lower, Byte, Name + ".norm.byte");
    Value *IsSpace =
        B.CreateOr(B.CreateICmpEQ(Byte, ConstantInt::get(I8, ' '),
                                  Name + ".sp"),
                   B.CreateICmpEQ(Byte, ConstantInt::get(I8, '\n'),
                                  Name + ".lf"),
                   Name + ".ws0");
    IsSpace = B.CreateOr(IsSpace,
                         B.CreateICmpEQ(Byte, ConstantInt::get(I8, '\r'),
                                        Name + ".cr"),
                         Name + ".ws1");
    IsSpace = B.CreateOr(IsSpace,
                         B.CreateICmpEQ(Byte, ConstantInt::get(I8, '\t'),
                                        Name + ".tab"),
                         Name + ".ws2");
    IsSpace = B.CreateOr(IsSpace,
                         B.CreateICmpEQ(Byte, ConstantInt::get(I8, 0),
                                        Name + ".nul"),
                         Name + ".ws");
    UseByte = B.CreateNot(IsSpace, Name + ".use");
    return Norm;
}

bool defineFeed(Module &M, GlobalVariable *Accum, GlobalVariable *Mask,
                bool Canonicalize, bool VirtualizeHelpers) {
    LLVMContext &Ctx = M.getContext();
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *Ptr = PointerType::getUnqual(Ctx);
    auto *Ty = FunctionType::get(Type::getVoidTy(Ctx), {I64, Ptr, I64},
                                 /*isVarArg=*/false);
    Function *Fn = getApiFunction(M, kFeedName, Ty);
    if (!Fn || !Fn->empty())
        return false;
    Fn->setLinkage(GlobalValue::ExternalLinkage);
    addHelperAttrs(*Fn, VirtualizeHelpers);

    auto It = Fn->arg_begin();
    Value *Domain = &*It++;
    Domain->setName("domain");
    Value *Data = &*It++;
    Data->setName("data");
    Value *Len = &*It++;
    Len->setName("len");

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    BasicBlock *Loop = BasicBlock::Create(Ctx, "hash", Fn);
    BasicBlock *Commit = BasicBlock::Create(Ctx, "commit", Fn);
    BasicBlock *Done = BasicBlock::Create(Ctx, "done", Fn);

    IRBuilder<> EB(Entry);
    auto *Initial = EB.CreateLoad(I64, Accum, "morok.envbind.accum.load");
    Initial->setVolatile(true);
    Initial->setAlignment(Align(8));
    Value *HasLen = EB.CreateICmpNE(Len, ConstantInt::get(I64, 0),
                                    "morok.envbind.has_len");
    Value *HasData =
        EB.CreateICmpNE(Data, ConstantPointerNull::get(Ptr),
                        "morok.envbind.has_data");
    EB.CreateCondBr(EB.CreateAnd(HasLen, HasData, "morok.envbind.feed.active"),
                    Loop, Done);

    IRBuilder<> LB(Loop);
    PHINode *I = LB.CreatePHI(I64, 2, "morok.envbind.feed.i");
    PHINode *Acc = LB.CreatePHI(I64, 2, "morok.envbind.feed.acc");
    I->addIncoming(ConstantInt::get(I64, 0), Entry);
    Acc->addIncoming(Initial, Entry);
    Value *BytePtr = LB.CreateGEP(I8, Data, I, "morok.envbind.feed.ptr");
    auto *Byte = LB.CreateLoad(I8, BytePtr, "morok.envbind.feed.byte");
    Byte->setVolatile(true);
    Byte->setAlignment(Align(1));
    Value *UseByte = nullptr;
    Value *NormByte =
        canonicalByte(LB, Byte, Canonicalize, UseByte, "morok.envbind.feed");
    Value *Byte64 = LB.CreateZExt(NormByte, I64, "morok.envbind.feed.byte64");
    Value *Input = LB.CreateAdd(Acc, Domain, "morok.envbind.feed.domain");
    Input = LB.CreateXor(Input, rotl64(LB, I, 7, "morok.envbind.feed.idx"),
                         "morok.envbind.feed.index");
    Input = LB.CreateXor(Input, Byte64, "morok.envbind.feed.input");
    Value *Mixed =
        mix64(LB, Input, 0xC3A5C85C97CB3127ULL, "morok.envbind.feed.mix");
    Value *NextAcc =
        LB.CreateSelect(UseByte, Mixed, Acc, "morok.envbind.feed.next.acc");
    Value *NextI =
        LB.CreateAdd(I, ConstantInt::get(I64, 1), "morok.envbind.feed.next");
    I->addIncoming(NextI, Loop);
    Acc->addIncoming(NextAcc, Loop);
    LB.CreateCondBr(LB.CreateICmpULT(NextI, Len, "morok.envbind.feed.more"),
                    Loop, Commit);

    IRBuilder<> CB(Commit);
    auto *StoreAcc = CB.CreateStore(NextAcc, Accum);
    StoreAcc->setVolatile(true);
    StoreAcc->setAlignment(Align(8));
    auto *OldMask = CB.CreateLoad(I64, Mask, "morok.envbind.mask.old");
    OldMask->setVolatile(true);
    OldMask->setAlignment(Align(8));
    Value *BitIndex =
        CB.CreateAnd(Domain, ConstantInt::get(I64, 63), "morok.envbind.bit");
    Value *Bit = CB.CreateShl(ConstantInt::get(I64, 1), BitIndex,
                              "morok.envbind.factor.bit");
    auto *StoreMask = CB.CreateStore(
        CB.CreateOr(OldMask, Bit, "morok.envbind.mask.next"), Mask);
    StoreMask->setVolatile(true);
    StoreMask->setAlignment(Align(8));
    CB.CreateBr(Done);

    IRBuilder<> DB(Done);
    DB.CreateRetVoid();
    return true;
}

bool defineFinish(Module &M, GlobalVariable *Accum, GlobalVariable *Mask,
                  GlobalVariable *DoneFlag, std::uint64_t ExpectedDigest,
                  std::uint32_t MinFactors, bool BindToRuntimeSeal,
                  bool VirtualizeHelpers) {
    LLVMContext &Ctx = M.getContext();
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *Ty = FunctionType::get(Type::getVoidTy(Ctx), {I64},
                                 /*isVarArg=*/false);
    Function *Fn = getApiFunction(M, kFinishName, Ty);
    if (!Fn || !Fn->empty())
        return false;
    Fn->setLinkage(GlobalValue::ExternalLinkage);
    addHelperAttrs(*Fn, VirtualizeHelpers);

    Value *Domain = Fn->getArg(0);
    Domain->setName("domain");
    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    BasicBlock *Compute = BasicBlock::Create(Ctx, "compute", Fn);
    BasicBlock *Done = BasicBlock::Create(Ctx, "done", Fn);

    IRBuilder<> EB(Entry);
    auto *AlreadyDone =
        EB.CreateLoad(EB.getInt1Ty(), DoneFlag, "morok.envbind.done.load");
    AlreadyDone->setVolatile(true);
    AlreadyDone->setAlignment(Align(1));
    EB.CreateCondBr(AlreadyDone, Done, Compute);

    IRBuilder<> B(Compute);
    auto *MaskLoad = B.CreateLoad(I64, Mask, "morok.envbind.mask.load");
    MaskLoad->setVolatile(true);
    MaskLoad->setAlignment(Align(8));
    auto *Acc = B.CreateLoad(I64, Accum, "morok.envbind.finish.accum");
    Acc->setVolatile(true);
    Acc->setAlignment(Align(8));
    Function *Ctpop =
        Intrinsic::getOrInsertDeclaration(&M, Intrinsic::ctpop, I64, {I64});
    Value *FactorCount =
        B.CreateCall(Ctpop, {MaskLoad}, "morok.envbind.factor.count");
    Value *EnoughFactors =
        B.CreateICmpUGE(FactorCount,
                        ConstantInt::get(I64, std::max(1u, MinFactors)),
                        "morok.envbind.enough_factors");
    Value *SeenDiff =
        B.CreateXor(Acc, ConstantInt::get(I64, ExpectedDigest),
                    "morok.envbind.finish.expected.diff");
    Value *Missing = B.CreateXor(Acc, Domain,
                                 "morok.envbind.finish.missing.domain");
    Missing = B.CreateXor(Missing, MaskLoad,
                          "morok.envbind.finish.missing.mask");
    Missing =
        mix64(B, Missing, 0xDB4F0B9175AE2165ULL,
              "morok.envbind.finish.missing");
    Missing = B.CreateOr(Missing, ConstantInt::get(I64, 1),
                         "morok.envbind.finish.missing.nonzero");
    Value *Contribution =
        B.CreateSelect(EnoughFactors, SeenDiff, Missing,
                       "morok.envbind.finish.contribution");
    if (BindToRuntimeSeal)
        runtime_seal::foldWord(B, runtime_seal::kEnvBindingChannel,
                               Contribution, 0xB8C4F1E35A7C2D19ULL,
                               "morok.envbind.finish.seal");
    Value *Scrub =
        mix64(B, Contribution, 0xA0761D6478BD642FULL,
              "morok.envbind.finish.scrub");
    auto *StoreAccum = B.CreateStore(Scrub, Accum);
    StoreAccum->setVolatile(true);
    StoreAccum->setAlignment(Align(8));
    auto *StoreMask = B.CreateStore(ConstantInt::get(I64, 0), Mask);
    StoreMask->setVolatile(true);
    StoreMask->setAlignment(Align(8));
    auto *StoreDone = B.CreateStore(ConstantInt::getTrue(Ctx), DoneFlag);
    StoreDone->setVolatile(true);
    StoreDone->setAlignment(Align(1));
    B.CreateBr(Done);

    IRBuilder<> DB(Done);
    DB.CreateRetVoid();
    return true;
}

Value *emitPathBuffer(IRBuilder<> &B, StringRef Path, std::uint64_t Salt,
                      const Twine &Name) {
    auto *I8 = B.getInt8Ty();
    auto *I64 = B.getInt64Ty();
    auto *ArrTy = ArrayType::get(I8, Path.size() + 1);
    AllocaInst *Slot = B.CreateAlloca(ArrTy, nullptr, Name + ".path");
    AllocaInst *MaskSlot = B.CreateAlloca(I8, nullptr, Name + ".path.mask");
    for (std::uint64_t I = 0; I <= Path.size(); ++I) {
        const auto Raw =
            static_cast<std::uint8_t>(I < Path.size() ? Path[I] : 0);
        const auto Mask = static_cast<std::uint8_t>(
            (Salt >> ((I % 8) * 8)) ^ (0x9Du + I * 37u));
        auto *MaskStore = B.CreateStore(ConstantInt::get(I8, Mask), MaskSlot);
        MaskStore->setVolatile(true);
        MaskStore->setAlignment(Align(1));
        auto *MaskLoad = B.CreateLoad(I8, MaskSlot, Name + ".path.mask.load");
        MaskLoad->setVolatile(true);
        MaskLoad->setAlignment(Align(1));
        Value *Decoded = B.CreateXor(ConstantInt::get(I8, Raw ^ Mask),
                                     MaskLoad, Name + ".path.dec");
        Value *Ptr = B.CreateInBoundsGEP(
            ArrTy, Slot, {ConstantInt::get(I64, 0), ConstantInt::get(I64, I)},
            Name + ".path.ptr");
        auto *Store = B.CreateStore(Decoded, Ptr);
        Store->setAlignment(Align(1));
    }
    return B.CreateInBoundsGEP(
        ArrTy, Slot, {ConstantInt::get(I64, 0), ConstantInt::get(I64, 0)},
        Name + ".path.base");
}

void emitLinuxFactorRead(Module &M, Function &Ctor, IRBuilder<> &B,
                         Function *Feed, const FactorSpec &Factor,
                         std::uint64_t PathSalt, StringRef Prefix) {
    LLVMContext &Ctx = M.getContext();
    const Triple TT(M.getTargetTriple());
    runtime::LinuxCoreSyscalls Sys;
    if (!runtime::lookupLinuxCoreSyscalls(TT, Sys))
        return;

    auto *I8 = Type::getInt8Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *IP = runtime::platformWordTy(M);
    auto *BufTy = ArrayType::get(I8, kReadBytes);
    AllocaInst *Buf =
        B.CreateAlloca(BufTy, nullptr, Twine(Prefix) + ".buf");
    Value *BufPtr = B.CreateInBoundsGEP(
        BufTy, Buf, {ConstantInt::get(I64, 0), ConstantInt::get(I64, 0)},
        Twine(Prefix) + ".buf.ptr");
    Value *Path = emitPathBuffer(B, Factor.path, PathSalt, Prefix);
    Value *Fd = runtime::emitLinuxSyscall(
        B, M, TT, Sys.openat,
        {ConstantInt::getSigned(IP, -100), Path, ConstantInt::get(IP, 0),
         ConstantInt::get(IP, 0)},
        Twine(Prefix) + ".open");

    BasicBlock *ReadBB =
        BasicBlock::Create(Ctx, Twine(Prefix) + ".read", &Ctor);
    BasicBlock *FeedBB =
        BasicBlock::Create(Ctx, Twine(Prefix) + ".feed", &Ctor);
    BasicBlock *CloseBB =
        BasicBlock::Create(Ctx, Twine(Prefix) + ".close", &Ctor);
    BasicBlock *DoneBB =
        BasicBlock::Create(Ctx, Twine(Prefix) + ".done", &Ctor);
    B.CreateCondBr(B.CreateICmpSGE(Fd, ConstantInt::get(IP, 0),
                                   Twine(Prefix) + ".open.ok"),
                   ReadBB, DoneBB);

    IRBuilder<> RB(ReadBB);
    Value *Len = runtime::emitLinuxSyscall(
        RB, M, TT, Sys.read,
        {Fd, BufPtr, ConstantInt::get(IP, kReadBytes)},
        Twine(Prefix) + ".read.rc");
    RB.CreateCondBr(RB.CreateICmpSGT(Len, ConstantInt::get(IP, 0),
                                     Twine(Prefix) + ".read.ok"),
                    FeedBB, CloseBB);

    IRBuilder<> FB(FeedBB);
    FB.CreateCall(Feed->getFunctionType(), Feed,
                  {ConstantInt::get(I64, Factor.domain), BufPtr,
                   FB.CreateZExtOrTrunc(Len, I64, Twine(Prefix) + ".len")});
    FB.CreateBr(CloseBB);

    IRBuilder<> CB(CloseBB);
    runtime::emitLinuxSyscall(CB, M, TT, Sys.close, {Fd},
                              Twine(Prefix) + ".close.rc");
    CB.CreateBr(DoneBB);

    B.SetInsertPoint(DoneBB);
}

bool supportsLinuxCollector(const Module &M) {
    const Triple TT(M.getTargetTriple());
    if (!TT.isOSLinux())
        return false;
    runtime::LinuxCoreSyscalls Sys;
    return runtime::lookupLinuxCoreSyscalls(TT, Sys);
}

bool defineLinuxCollector(Module &M, Function *Feed, Function *Finish,
                          ir::IRRandom &Rng) {
    if (M.getFunction(kCtorName))
        return false;
    auto *Fn = Function::Create(
        FunctionType::get(Type::getVoidTy(M.getContext()), false),
        GlobalValue::InternalLinkage, kCtorName, &M);
    Fn->setDSOLocal(true);
    Fn->addFnAttr(Attribute::NoUnwind);
    BasicBlock *Entry = BasicBlock::Create(M.getContext(), "entry", Fn);
    IRBuilder<> B(Entry);

    FactorSpec Factors[] = {
        {"/etc/machine-id", (Rng.next() & ~63ULL) | 0ULL},
        {"/sys/class/dmi/id/product_uuid", (Rng.next() & ~63ULL) | 1ULL},
        {"/sys/class/net/eth0/address", (Rng.next() & ~63ULL) | 2ULL},
        {"/sys/class/net/en0/address", (Rng.next() & ~63ULL) | 3ULL},
        {"/sys/block/sda/device/serial", (Rng.next() & ~63ULL) | 4ULL},
        {"/sys/block/nvme0n1/device/serial", (Rng.next() & ~63ULL) | 5ULL},
        {"/sys/block/vda/device/serial", (Rng.next() & ~63ULL) | 6ULL},
    };

    std::uint32_t Index = 0;
    for (const FactorSpec &Factor : Factors) {
        emitLinuxFactorRead(M, *Fn, B, Feed, Factor, Rng.next(),
                            (Twine("morok.envbind.factor.") + Twine(Index))
                                .str());
        ++Index;
    }
    B.CreateCall(Finish->getFunctionType(), Finish,
                 {ConstantInt::get(B.getInt64Ty(), Rng.next())});
    B.CreateRetVoid();
    appendToGlobalCtors(M, Fn, 0);
    return true;
}

bool defineFinishOnlyCollector(Module &M, Function *Finish, ir::IRRandom &Rng) {
    if (!Finish || M.getFunction(kCtorName))
        return false;
    auto *Fn = Function::Create(
        FunctionType::get(Type::getVoidTy(M.getContext()), false),
        GlobalValue::InternalLinkage, kCtorName, &M);
    Fn->setDSOLocal(true);
    Fn->addFnAttr(Attribute::NoUnwind);
    BasicBlock *Entry = BasicBlock::Create(M.getContext(), "entry", Fn);
    IRBuilder<> B(Entry);
    B.CreateCall(Finish->getFunctionType(), Finish,
                 {ConstantInt::get(B.getInt64Ty(), Rng.next())});
    B.CreateRetVoid();
    appendToGlobalCtors(M, Fn, 0);
    return true;
}

} // namespace

bool envBindingKdfModule(Module &M, const EnvBindingKdfParams &Params,
                         ir::IRRandom &Rng) {
    if (!Params.enabled)
        return false;

    if (Params.bind_to_runtime_seal)
        runtime_seal::getChannel(M, runtime_seal::kEnvBindingChannel, Rng);
    const std::uint64_t ExpectedDigest =
        parseExpectedDigest(Params.expected_digest).value_or(Rng.next() | 1ULL);
    GlobalVariable *Accum = getI64Global(M, kAccumName, Rng.next());
    GlobalVariable *Mask = getI64Global(M, kMaskName, 0);
    GlobalVariable *Done = getDone(M);
    const bool Canonicalize = Params.identity_policy != "raw";
    const std::uint32_t MinFactors =
        std::min<std::uint32_t>(std::max(Params.min_factors, 1u), kMaxFactors);

    bool Changed = false;
    Changed |= defineFeed(M, Accum, Mask, Canonicalize,
                          Params.virtualize_helpers);
    Changed |= defineFinish(M, Accum, Mask, Done, ExpectedDigest, MinFactors,
                            Params.bind_to_runtime_seal,
                            Params.virtualize_helpers);

    bool Collected = false;
    if (Params.mode != "feed_api" && supportsLinuxCollector(M)) {
        Function *Feed = M.getFunction(kFeedName);
        Function *Finish = M.getFunction(kFinishName);
        if (Feed && Finish) {
            Collected = defineLinuxCollector(M, Feed, Finish, Rng);
            Changed |= Collected;
        }
    }
    if (Params.bind_to_runtime_seal && !Collected)
        Changed |= defineFinishOnlyCollector(M, M.getFunction(kFinishName),
                                             Rng);
    return Changed;
}

PreservedAnalyses EnvBindingKdfPass::run(Module &M, ModuleAnalysisManager &) {
    ir::IRRandom Rng(engine_);
    return envBindingKdfModule(M, params_, Rng) ? PreservedAnalyses::none()
                                                : PreservedAnalyses::all();
}

} // namespace morok::passes
