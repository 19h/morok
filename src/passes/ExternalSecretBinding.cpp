// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.

#include "morok/passes/ExternalSecretBinding.hpp"

#include "morok/passes/RuntimeSeal.hpp"

#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"

using namespace llvm;

namespace morok::passes {

namespace {

constexpr StringLiteral kFeedName = "morok.proof.feed";
constexpr StringLiteral kFinishName = "morok.proof.finish";
constexpr StringLiteral kAccumName = "morok.proof.accum";
constexpr StringLiteral kSeenName = "morok.proof.seen";

void addHelperAttrs(Function &F, bool VirtualizeHelpers) {
    F.addFnAttr(Attribute::NoUnwind);
    F.addFnAttr(Attribute::NoInline);
    if (!VirtualizeHelpers)
        F.addFnAttr("morok.proof.no_vm");
}

GlobalVariable *getAccum(Module &M, ir::IRRandom &Rng) {
    if (auto *Existing = M.getGlobalVariable(kAccumName, true))
        return Existing;
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *GV = new GlobalVariable(M, I64, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage,
                                  ConstantInt::get(I64, Rng.next()),
                                  kAccumName);
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    GV->setAlignment(Align(8));
    return GV;
}

GlobalVariable *getSeen(Module &M) {
    if (auto *Existing = M.getGlobalVariable(kSeenName, true))
        return Existing;
    auto *I1 = Type::getInt1Ty(M.getContext());
    auto *GV = new GlobalVariable(M, I1, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage,
                                  ConstantInt::getFalse(M.getContext()),
                                  kSeenName);
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    GV->setAlignment(Align(1));
    return GV;
}

Value *mix64(IRBuilderBase &B, Value *X, std::uint64_t Salt,
             const Twine &Name) {
    auto *I64 = B.getInt64Ty();
    X = B.CreateXor(X, ConstantInt::get(I64, Salt), Name + ".salt");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 30)),
                    Name + ".fold30");
    X = B.CreateMul(X, ConstantInt::get(I64, 0xBF58476D1CE4E5B9ULL),
                    Name + ".mul0");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 27)),
                    Name + ".fold27");
    X = B.CreateMul(X, ConstantInt::get(I64, 0x94D049BB133111EBULL),
                    Name + ".mul1");
    return B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 31)),
                       Name + ".fold31");
}

Function *getApiFunction(Module &M, StringRef Name, FunctionType *Ty) {
    if (Function *F = M.getFunction(Name)) {
        if (F->getFunctionType() == Ty)
            return F;
        return nullptr;
    }
    return Function::Create(Ty, GlobalValue::ExternalLinkage, Name, M);
}

bool defineFeed(Module &M, GlobalVariable *Accum, GlobalVariable *Seen,
                bool VirtualizeHelpers) {
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
    auto *Initial = EB.CreateLoad(I64, Accum, "morok.proof.accum.load");
    Initial->setVolatile(true);
    Initial->setAlignment(Align(8));
    Value *HasLen = EB.CreateICmpNE(Len, ConstantInt::get(I64, 0),
                                    "morok.proof.has_len");
    Value *HasData =
        EB.CreateICmpNE(Data, ConstantPointerNull::get(Ptr),
                        "morok.proof.has_data");
    EB.CreateCondBr(EB.CreateAnd(HasLen, HasData, "morok.proof.feed.active"),
                    Loop, Done);

    IRBuilder<> LB(Loop);
    PHINode *I = LB.CreatePHI(I64, 2, "morok.proof.feed.i");
    PHINode *Acc = LB.CreatePHI(I64, 2, "morok.proof.feed.acc");
    I->addIncoming(ConstantInt::get(I64, 0), Entry);
    Acc->addIncoming(Initial, Entry);
    Value *BytePtr = LB.CreateGEP(I8, Data, I, "morok.proof.feed.ptr");
    auto *Byte = LB.CreateLoad(I8, BytePtr, "morok.proof.feed.byte");
    Byte->setVolatile(true);
    Byte->setAlignment(Align(1));
    Value *Byte64 = LB.CreateZExt(Byte, I64, "morok.proof.feed.byte64");
    Value *Input = LB.CreateXor(Acc, Domain, "morok.proof.feed.domain");
    Input = LB.CreateXor(Input, I, "morok.proof.feed.index");
    Input = LB.CreateXor(Input, Byte64, "morok.proof.feed.input");
    Value *NextAcc = mix64(LB, Input, 0x2D358DCCAA6C78A5ULL,
                           "morok.proof.feed.mix");
    Value *NextI = LB.CreateAdd(I, ConstantInt::get(I64, 1),
                                "morok.proof.feed.next");
    I->addIncoming(NextI, Loop);
    Acc->addIncoming(NextAcc, Loop);
    LB.CreateCondBr(LB.CreateICmpULT(NextI, Len, "morok.proof.feed.more"),
                    Loop, Commit);

    IRBuilder<> CB(Commit);
    auto *StoreAcc = CB.CreateStore(NextAcc, Accum);
    StoreAcc->setVolatile(true);
    StoreAcc->setAlignment(Align(8));
    auto *StoreSeen = CB.CreateStore(ConstantInt::getTrue(Ctx), Seen);
    StoreSeen->setVolatile(true);
    StoreSeen->setAlignment(Align(1));
    CB.CreateBr(Done);

    IRBuilder<> DB(Done);
    DB.CreateRetVoid();
    return true;
}

bool defineFinish(Module &M, GlobalVariable *Accum, GlobalVariable *Seen,
                  bool BindToRuntimeSeal, bool VirtualizeHelpers) {
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
    IRBuilder<> B(Entry);
    auto *SeenLoad = B.CreateLoad(B.getInt1Ty(), Seen, "morok.proof.seen.load");
    SeenLoad->setVolatile(true);
    SeenLoad->setAlignment(Align(1));
    auto *Acc = B.CreateLoad(I64, Accum, "morok.proof.finish.accum");
    Acc->setVolatile(true);
    Acc->setAlignment(Align(8));
    Value *Material =
        B.CreateXor(Acc, Domain, "morok.proof.finish.domain");
    Material = mix64(B, Material, 0x9B1A3B5D7F0E24C6ULL,
                     "morok.proof.finish.mix");
    Value *Contribution =
        B.CreateSelect(SeenLoad, Material, ConstantInt::get(I64, 0),
                       "morok.proof.finish.contribution");
    if (BindToRuntimeSeal)
        runtime_seal::foldWord(B, runtime_seal::kExternalProofChannel,
                               Contribution, 0xC5C9B9F06A4A793DULL,
                               "morok.proof.finish.seal");
    B.CreateRetVoid();
    return true;
}

} // namespace

bool externalSecretBindingModule(Module &M,
                                 const ExternalSecretBindingParams &Params,
                                 ir::IRRandom &Rng) {
    if (!Params.enabled)
        return false;

    if (Params.bind_to_runtime_seal)
        runtime_seal::getChannel(M, runtime_seal::kExternalProofChannel, Rng);
    GlobalVariable *Accum = getAccum(M, Rng);
    GlobalVariable *Seen = getSeen(M);

    bool Changed = false;
    Changed |= defineFeed(M, Accum, Seen, Params.virtualize_helpers);
    Changed |= defineFinish(M, Accum, Seen, Params.bind_to_runtime_seal,
                            Params.virtualize_helpers);
    return Changed;
}

PreservedAnalyses ExternalSecretBindingPass::run(Module &M,
                                                 ModuleAnalysisManager &) {
    ir::IRRandom Rng(engine_);
    return externalSecretBindingModule(M, params_, Rng)
               ? PreservedAnalyses::none()
               : PreservedAnalyses::all();
}

} // namespace morok::passes
