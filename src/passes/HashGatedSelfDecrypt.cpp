// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/HashGatedSelfDecrypt.cpp
//
// IR-safe hash-gated self-decrypting blocks.  Native block encryption requires
// post-link addresses and W^X cooperation, so this pass implements the
// roadmap's bytecode route: selected VM bytecode globals receive an outer
// encrypted layer, a mutable payload, and a lazy decryptor gated by a runtime
// hash of the still- encrypted payload.  The VM helper calls the decryptor
// before reading bytecode.

#include "morok/passes/HashGatedSelfDecrypt.hpp"

#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Support/ModRef.h"

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
                   Value *ContextZero, const StreamSchedule &S) {
    auto *I64 = B.getInt64Ty();
    auto *I8 = B.getInt8Ty();
    Value *Idx64 = B.CreateZExt(Index, I64, "morok.sdb.key.idx");
    Value *Key = B.CreateXor(ComputedHash, ConstantInt::get(I64, S.key_mask),
                             "morok.sdb.key.gate");
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
                       const StreamSchedule &S, bool ContextKeying) {
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
    auto *ReadyLoad = EB.CreateLoad(I1, Ready, "morok.sdb.ready.load");
    ReadyLoad->setVolatile(true);
    ReadyLoad->setAlignment(Align(1));
    EB.CreateCondBr(ReadyLoad, Exit, HashLoop);

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
    Value *GateOk = GB.CreateICmpEQ(
        NextHash, ConstantInt::get(I64, S.expected_hash), "morok.sdb.gate");
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
    Value *Key = emitKeyByte(DB, DecI, NextHash, ContextZero, S);
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

bool helperAlreadyCalls(Function *Helper, Function *Ensure) {
    for (Instruction &I : instructions(*Helper))
        if (auto *CI = dyn_cast<CallInst>(&I))
            if (CI->getCalledFunction() == Ensure)
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

bool wrapPayload(Module &M, Payload &P,
                 const HashGatedSelfDecryptParams &Params, ir::IRRandom &Rng) {
    StreamSchedule S = makeSchedule(Rng);
    std::vector<std::uint8_t> Outer = outerEncrypt(
        ArrayRef<std::uint8_t>(P.original.data(), P.original.size()), S);
    makeMutablePayload(*P.bytecode, Outer);
    GlobalVariable *Ready = createReady(M, P.suffix);
    Function *Ensure = createEnsure(M, P, Ready, S, Params.context_keying);
    insertEnsureCall(P.helper, Ensure);
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
