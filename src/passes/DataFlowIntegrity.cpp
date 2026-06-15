// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/DataFlowIntegrity.cpp
//
// Data-flow-entangled integrity.  Selected `i8 a OP b` operations become
// volatile loads from encoded lookup tables.  The decode key is derived from a
// runtime hash of a private byte region plus the expected hash; if the region
// or expected value changes, the operation result is corrupted as data rather
// than guarded by a separable branch.

#include "morok/passes/DataFlowIntegrity.hpp"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Support/ModRef.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

using Builder = IRBuilder<NoFolder>;

constexpr std::uint32_t kTableSize = 1u << 16;
constexpr std::uint32_t kMaxTablesPerInvocation = 8;

struct KeySchedule {
    std::uint64_t expected_hash = 0;
    std::uint32_t mul = 1;
    std::uint32_t add = 0;
    std::uint8_t xork = 0;
};

struct Runtime {
    Function *diff = nullptr;
    GlobalVariable *region = nullptr;
    GlobalVariable *expected = nullptr;
    std::uint64_t expected_hash = 0;
};

bool generatedFunction(const Function &F) {
    return F.getName().starts_with("morok.");
}

bool supportedOpcode(unsigned Opcode) {
    switch (Opcode) {
    case Instruction::Add:
    case Instruction::Sub:
    case Instruction::Mul:
    case Instruction::And:
    case Instruction::Or:
    case Instruction::Xor:
        return true;
    default:
        return false;
    }
}

bool eligible(BinaryOperator &BO) {
    auto *Ty = dyn_cast<IntegerType>(BO.getType());
    if (!Ty || Ty->getBitWidth() != 8)
        return false;
    if (!supportedOpcode(BO.getOpcode()))
        return false;
    if ((BO.getOpcode() == Instruction::Add ||
         BO.getOpcode() == Instruction::Sub ||
         BO.getOpcode() == Instruction::Mul) &&
        (BO.hasNoSignedWrap() || BO.hasNoUnsignedWrap()))
        return false;
    return true;
}

std::uint8_t eval(unsigned Opcode, std::uint8_t Lhs, std::uint8_t Rhs) {
    switch (Opcode) {
    case Instruction::Add:
        return static_cast<std::uint8_t>(Lhs + Rhs);
    case Instruction::Sub:
        return static_cast<std::uint8_t>(Lhs - Rhs);
    case Instruction::Mul:
        return static_cast<std::uint8_t>(Lhs * Rhs);
    case Instruction::And:
        return static_cast<std::uint8_t>(Lhs & Rhs);
    case Instruction::Or:
        return static_cast<std::uint8_t>(Lhs | Rhs);
    case Instruction::Xor:
        return static_cast<std::uint8_t>(Lhs ^ Rhs);
    default:
        return 0;
    }
}

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

std::uint8_t keyAt(std::uint32_t Idx, std::uint64_t Seed,
                   const KeySchedule &Key) {
    std::uint64_t X = Seed + Key.add;
    X += static_cast<std::uint64_t>(Idx) * Key.mul;
    X ^= X >> 11;
    X ^= X >> 29;
    return static_cast<std::uint8_t>(X) ^ Key.xork;
}

Value *emitHashStep(Builder &B, Value *H, Value *Byte) {
    auto *I64 = B.getInt64Ty();
    Value *Wide = B.CreateZExt(Byte, I64, "morok.dfi.hash.byte");
    Value *X = B.CreateXor(H, Wide, "morok.dfi.hash.mix");
    X = B.CreateMul(X, ConstantInt::get(I64, 0xff51afd7ed558ccdULL),
                    "morok.dfi.hash.mix");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 32)),
                    "morok.dfi.hash.mix");
    X = B.CreateMul(X, ConstantInt::get(I64, 0xc4ceb9fe1a85ec53ULL),
                    "morok.dfi.hash.mix");
    return B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 29)),
                       "morok.dfi.hash.mix");
}

Value *emitKey(Builder &B, Value *Idx, Value *Seed, const KeySchedule &Key) {
    auto *I64 = B.getInt64Ty();
    auto *I8 = B.getInt8Ty();
    Value *Idx64 = B.CreateZExt(Idx, I64, "morok.dfi.key.idx");
    Value *X =
        B.CreateAdd(Seed, ConstantInt::get(I64, Key.add), "morok.dfi.key.mix");
    X = B.CreateAdd(
        X,
        B.CreateMul(Idx64, ConstantInt::get(I64, Key.mul), "morok.dfi.key.mul"),
        "morok.dfi.key.mix");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 11)),
                    "morok.dfi.key.mix");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 29)),
                    "morok.dfi.key.mix");
    Value *K = B.CreateTrunc(X, I8, "morok.dfi.key.trunc");
    return B.CreateXor(K, ConstantInt::get(I8, Key.xork), "morok.dfi.key");
}

std::vector<std::uint8_t> randomRegion(std::uint32_t Size, ir::IRRandom &Rng) {
    std::vector<std::uint8_t> Bytes;
    Bytes.reserve(Size);
    for (std::uint32_t I = 0; I < Size; ++I)
        Bytes.push_back(static_cast<std::uint8_t>(Rng.next()));
    return Bytes;
}

std::string suffixFor(Function &F) { return F.getName().str(); }

void addRuntimeAttrs(Function *F) {
    F->addFnAttr(Attribute::NoInline);
    F->addFnAttr(Attribute::OptimizeNone);
    F->setMemoryEffects(MemoryEffects::unknown());
}

void relaxMemoryAttrs(Function &F) {
    F.setMemoryEffects(MemoryEffects::unknown());
    F.removeFnAttr(Attribute::NoSync);
}

void invalidateCallerEffects(Function &F) {
    SmallVector<Function *, 8> Worklist;
    SmallPtrSet<Function *, 16> Seen;
    Worklist.push_back(&F);
    Seen.insert(&F);

    while (!Worklist.empty()) {
        Function *Current = Worklist.pop_back_val();
        for (User *U : Current->users()) {
            auto *CB = dyn_cast<CallBase>(U);
            if (!CB)
                continue;
            CB->setMemoryEffects(MemoryEffects::unknown());
            CB->removeFnAttr(Attribute::NoSync);

            Function *Caller = CB->getFunction();
            if (!Caller || !Seen.insert(Caller).second)
                continue;
            relaxMemoryAttrs(*Caller);
            Worklist.push_back(Caller);
        }
    }
}

GlobalVariable *createRegion(Module &M, StringRef Suffix,
                             ArrayRef<std::uint8_t> Bytes) {
    LLVMContext &Ctx = M.getContext();
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *ArrTy = ArrayType::get(I8, Bytes.size());
    auto *Region = new GlobalVariable(
        M, ArrTy, /*isConstant=*/true, GlobalValue::PrivateLinkage,
        ConstantDataArray::get(Ctx, Bytes),
        (Twine("morok.dfi.region.") + Suffix).str());
    Region->setUnnamedAddr(GlobalValue::UnnamedAddr::None);
    Region->setAlignment(Align(1));
    return Region;
}

GlobalVariable *createExpected(Module &M, StringRef Suffix,
                               std::uint64_t ExpectedHash) {
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *Expected = new GlobalVariable(
        M, I64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I64, ExpectedHash),
        (Twine("morok.dfi.expected.") + Suffix).str());
    Expected->setAlignment(Align(8));
    return Expected;
}

Value *regionPtr(Builder &B, GlobalVariable *Region, Value *Idx) {
    auto *I32 = B.getInt32Ty();
    auto *ArrTy = cast<ArrayType>(Region->getValueType());
    return B.CreateInBoundsGEP(ArrTy, Region, {ConstantInt::get(I32, 0), Idx},
                               "morok.dfi.region.ptr");
}

Function *createHashFunction(Module &M, StringRef Suffix,
                             GlobalVariable *Region, GlobalVariable *Expected,
                             std::uint64_t Seed) {
    LLVMContext &Ctx = M.getContext();
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    const auto *ArrTy = cast<ArrayType>(Region->getValueType());
    const std::uint32_t Size =
        static_cast<std::uint32_t>(ArrTy->getNumElements());

    auto *Fn = Function::Create(FunctionType::get(I64, false),
                                GlobalValue::InternalLinkage,
                                (Twine("morok.dfi.hash.") + Suffix).str(), &M);
    addRuntimeAttrs(Fn);

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    BasicBlock *Loop = BasicBlock::Create(Ctx, "hash", Fn);
    BasicBlock *Exit = BasicBlock::Create(Ctx, "exit", Fn);

    Builder EB(Entry);
    EB.CreateBr(Loop);

    Builder LB(Loop);
    PHINode *I = LB.CreatePHI(I32, 2, "morok.dfi.hash.i");
    PHINode *H = LB.CreatePHI(I64, 2, "morok.dfi.hash");
    I->addIncoming(ConstantInt::get(I32, 0), Entry);
    H->addIncoming(ConstantInt::get(I64, Seed), Entry);
    auto *Byte =
        LB.CreateLoad(I8, regionPtr(LB, Region, I), "morok.dfi.region.byte");
    Byte->setVolatile(true);
    Byte->setAlignment(Align(1));
    Value *NextH = emitHashStep(LB, H, Byte);
    Value *NextI =
        LB.CreateAdd(I, ConstantInt::get(I32, 1), "morok.dfi.hash.next");
    I->addIncoming(NextI, Loop);
    H->addIncoming(NextH, Loop);
    Value *Done = LB.CreateICmpEQ(NextI, ConstantInt::get(I32, Size),
                                  "morok.dfi.hash.done");
    LB.CreateCondBr(Done, Exit, Loop);

    Builder XB(Exit);
    auto *ExpectedLoad =
        XB.CreateLoad(I64, Expected, "morok.dfi.expected.load");
    ExpectedLoad->setVolatile(true);
    ExpectedLoad->setAlignment(Align(8));
    Value *Diff = XB.CreateXor(NextH, ExpectedLoad, "morok.dfi.diff");
    XB.CreateRet(Diff);
    return Fn;
}

Runtime createRuntime(Function &F, const DataFlowIntegrityParams &Params,
                      ir::IRRandom &Rng) {
    Module &M = *F.getParent();
    const std::uint32_t RegionSize =
        std::clamp<std::uint32_t>(Params.region_bytes, 8, 1024);
    const std::string Suffix = suffixFor(F);
    const std::uint64_t Seed = Rng.next();
    std::vector<std::uint8_t> Bytes = randomRegion(RegionSize, Rng);
    Runtime R;
    R.expected_hash =
        hashBytes(ArrayRef<std::uint8_t>(Bytes.data(), Bytes.size()), Seed);
    R.region = createRegion(M, Suffix, Bytes);
    R.expected = createExpected(M, Suffix, R.expected_hash);
    R.diff = createHashFunction(M, Suffix, R.region, R.expected, Seed);
    return R;
}

KeySchedule makeKey(Runtime &R, ir::IRRandom &Rng) {
    return {R.expected_hash, static_cast<std::uint32_t>(Rng.next()) | 1u,
            static_cast<std::uint32_t>(Rng.next()),
            static_cast<std::uint8_t>(Rng.next())};
}

GlobalVariable *createTable(Module &M, Function &F, unsigned Opcode,
                            const KeySchedule &Key) {
    LLVMContext &Ctx = M.getContext();
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *TableTy = ArrayType::get(I8, kTableSize);

    std::array<std::uint8_t, kTableSize> Enc{};
    for (std::uint32_t Idx = 0; Idx < kTableSize; ++Idx) {
        const auto Lhs = static_cast<std::uint8_t>(Idx >> 8);
        const auto Rhs = static_cast<std::uint8_t>(Idx & 0xFFu);
        Enc[Idx] = eval(Opcode, Lhs, Rhs) ^ keyAt(Idx, Key.expected_hash, Key);
    }

    auto *Table = new GlobalVariable(
        M, TableTy, /*isConstant=*/true, GlobalValue::PrivateLinkage,
        ConstantDataArray::get(Ctx, ArrayRef(Enc)),
        (Twine("morok.dfi.table.") + suffixFor(F)).str());
    Table->setUnnamedAddr(GlobalValue::UnnamedAddr::None);
    Table->setAlignment(Align(1));
    return Table;
}

Value *emitLookup(Module &M, Function &F, Runtime &R, BinaryOperator &BO,
                  ir::IRRandom &Rng) {
    KeySchedule Key = makeKey(R, Rng);
    GlobalVariable *Table = createTable(M, F, BO.getOpcode(), Key);

    Builder B(&BO);
    auto *I8 = B.getInt8Ty();
    auto *I16 = B.getInt16Ty();
    auto *I32 = B.getInt32Ty();
    auto *I64 = B.getInt64Ty();
    auto *TableTy = cast<ArrayType>(Table->getValueType());

    auto *Diff = B.CreateCall(R.diff->getFunctionType(), R.diff, {},
                              "morok.dfi.hash.call");
    Value *Seed = B.CreateXor(Diff, ConstantInt::get(I64, Key.expected_hash),
                              "morok.dfi.seed");
    Value *L = B.CreateZExt(BO.getOperand(0), I16, "morok.dfi.lhs");
    Value *Rhs = B.CreateZExt(BO.getOperand(1), I16, "morok.dfi.rhs");
    Value *Hi = B.CreateShl(L, ConstantInt::get(I16, 8), "morok.dfi.hi");
    Value *Idx16 = B.CreateOr(Hi, Rhs, "morok.dfi.idx16");
    Value *Idx = B.CreateZExt(Idx16, I32, "morok.dfi.idx");
    Value *Cell = B.CreateInBoundsGEP(
        TableTy, Table, {ConstantInt::get(I32, 0), Idx}, "morok.dfi.cell");
    auto *Encoded = B.CreateLoad(I8, Cell, "morok.dfi.encoded");
    Encoded->setVolatile(true);
    Encoded->setAlignment(Align(1));
    Value *KeyByte = emitKey(B, Idx, Seed, Key);
    return B.CreateXor(Encoded, KeyByte, "morok.dfi.value");
}

} // namespace

bool dataFlowIntegrityFunction(Function &F,
                               const DataFlowIntegrityParams &Params,
                               ir::IRRandom &Rng) {
    if (F.isDeclaration() || generatedFunction(F) || Params.probability == 0 ||
        Params.max_tables == 0 || Params.region_bytes == 0)
        return false;

    const std::string HashName = "morok.dfi.hash." + suffixFor(F);
    if (F.getParent()->getFunction(HashName))
        return false;

    const std::uint32_t Limit =
        std::min(Params.max_tables, kMaxTablesPerInvocation);
    SmallVector<BinaryOperator *, 8> Selected;
    for (BasicBlock &BB : F) {
        if (Selected.size() >= Limit)
            break;
        for (Instruction &I : BB) {
            if (Selected.size() >= Limit)
                break;
            if (auto *BO = dyn_cast<BinaryOperator>(&I))
                if (eligible(*BO))
                    if (Rng.chance(Params.probability))
                        Selected.push_back(BO);
        }
    }
    if (Selected.empty())
        return false;

    Module &M = *F.getParent();
    Runtime R = createRuntime(F, Params, Rng);
    for (BinaryOperator *BO : Selected) {
        Value *Replacement = emitLookup(M, F, R, *BO, Rng);
        BO->replaceAllUsesWith(Replacement);
        BO->eraseFromParent();
    }

    relaxMemoryAttrs(F);
    invalidateCallerEffects(F);
    return true;
}

PreservedAnalyses DataFlowIntegrityPass::run(Function &F,
                                             FunctionAnalysisManager &) {
    ir::IRRandom Rng(engine_);
    return dataFlowIntegrityFunction(F, params_, Rng)
               ? PreservedAnalyses::none()
               : PreservedAnalyses::all();
}

} // namespace morok::passes
