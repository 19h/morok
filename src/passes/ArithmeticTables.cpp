// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/ArithmeticTables.cpp
//
// Arithmetic-as-table lowering for byte-width integer operators.  Each selected
// `i8 a OP b` becomes:
//   ensure(table)
//   load table[(zext(a) << 8) | zext(b)]
// Tables are stored encrypted and materialized lazily by a small internal
// decoder, so the original opcode disappears from the function body and the
// module does not contain a plaintext operation table.

#include "morok/passes/ArithmeticTables.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr std::uint32_t kTableSize = 1u << 16;
constexpr std::uint32_t kMaxTablesPerInvocation = 16;

struct KeySchedule {
    std::uint32_t mul;
    std::uint32_t add;
    std::uint8_t xork;
};

struct TableMaterial {
    GlobalVariable *table;
    Function *ensure;
};

bool supportedOpcode(unsigned opcode) {
    switch (opcode) {
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

std::uint8_t eval(unsigned opcode, std::uint8_t lhs, std::uint8_t rhs) {
    switch (opcode) {
    case Instruction::Add:
        return static_cast<std::uint8_t>(lhs + rhs);
    case Instruction::Sub:
        return static_cast<std::uint8_t>(lhs - rhs);
    case Instruction::Mul:
        return static_cast<std::uint8_t>(lhs * rhs);
    case Instruction::And:
        return static_cast<std::uint8_t>(lhs & rhs);
    case Instruction::Or:
        return static_cast<std::uint8_t>(lhs | rhs);
    case Instruction::Xor:
        return static_cast<std::uint8_t>(lhs ^ rhs);
    default:
        return 0;
    }
}

std::uint8_t keyAt(std::uint32_t idx, const KeySchedule &key) {
    std::uint32_t x = idx * key.mul + key.add;
    x ^= x >> 8;
    x ^= x >> 16;
    return static_cast<std::uint8_t>(x) ^ key.xork;
}

Value *emitKey(IRBuilder<> &B, Value *Idx, const KeySchedule &key) {
    auto *I32 = B.getInt32Ty();
    auto *I8 = B.getInt8Ty();
    Value *X = B.CreateMul(Idx, ConstantInt::get(I32, key.mul),
                           "morok.tablearith.key.mul");
    X = B.CreateAdd(X, ConstantInt::get(I32, key.add),
                    "morok.tablearith.key.add");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I32, 8)),
                    "morok.tablearith.key.fold8");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I32, 16)),
                    "morok.tablearith.key.fold16");
    Value *K = B.CreateTrunc(X, I8, "morok.tablearith.key.trunc");
    return B.CreateXor(K, ConstantInt::get(I8, key.xork),
                       "morok.tablearith.key");
}

Function *createEnsureFunction(Module &M, GlobalVariable *Table,
                               GlobalVariable *Ready, const KeySchedule &key) {
    LLVMContext &Ctx = M.getContext();
    auto *VoidTy = Type::getVoidTy(Ctx);
    auto *I1 = Type::getInt1Ty(Ctx);
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *TableTy = cast<ArrayType>(Table->getValueType());

    auto *Fn = Function::Create(FunctionType::get(VoidTy, false),
                                GlobalValue::InternalLinkage,
                                "morok.tablearith.ensure", &M);
    Fn->addFnAttr(Attribute::NoInline);

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    BasicBlock *Loop = BasicBlock::Create(Ctx, "loop", Fn);
    BasicBlock *Done = BasicBlock::Create(Ctx, "done", Fn);
    BasicBlock *Exit = BasicBlock::Create(Ctx, "exit", Fn);

    IRBuilder<> EB(Entry);
    auto *ReadyLoad = EB.CreateLoad(I1, Ready, "morok.tablearith.ready");
    ReadyLoad->setVolatile(true);
    EB.CreateCondBr(ReadyLoad, Exit, Loop);

    IRBuilder<> LB(Loop);
    PHINode *Idx = LB.CreatePHI(I32, 2, "morok.tablearith.idx");
    Idx->addIncoming(ConstantInt::get(I32, 0), Entry);
    Value *Ptr =
        LB.CreateInBoundsGEP(TableTy, Table, {ConstantInt::get(I32, 0), Idx},
                             "morok.tablearith.cell");
    Value *Enc = LB.CreateLoad(I8, Ptr, "morok.tablearith.enc");
    Value *Dec =
        LB.CreateXor(Enc, emitKey(LB, Idx, key), "morok.tablearith.dec");
    LB.CreateStore(Dec, Ptr);
    Value *Next =
        LB.CreateAdd(Idx, ConstantInt::get(I32, 1), "morok.tablearith.next");
    Idx->addIncoming(Next, Loop);
    Value *AtEnd = LB.CreateICmpEQ(Next, ConstantInt::get(I32, kTableSize),
                                   "morok.tablearith.done");
    LB.CreateCondBr(AtEnd, Done, Loop);

    IRBuilder<> DB(Done);
    auto *ReadyStore = DB.CreateStore(ConstantInt::get(I1, true), Ready);
    ReadyStore->setVolatile(true);
    DB.CreateBr(Exit);

    IRBuilder<> XB(Exit);
    XB.CreateRetVoid();
    return Fn;
}

TableMaterial createTable(Module &M, unsigned opcode, ir::IRRandom &rng) {
    LLVMContext &Ctx = M.getContext();
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *I1 = Type::getInt1Ty(Ctx);
    auto *TableTy = ArrayType::get(I8, kTableSize);
    const KeySchedule key{static_cast<std::uint32_t>(rng.next()) | 1u,
                          static_cast<std::uint32_t>(rng.next()),
                          static_cast<std::uint8_t>(rng.next())};

    std::array<std::uint8_t, kTableSize> encrypted{};
    for (std::uint32_t idx = 0; idx < kTableSize; ++idx) {
        const auto lhs = static_cast<std::uint8_t>(idx >> 8);
        const auto rhs = static_cast<std::uint8_t>(idx & 0xFFu);
        encrypted[idx] = eval(opcode, lhs, rhs) ^ keyAt(idx, key);
    }

    Constant *Init = ConstantDataArray::get(Ctx, ArrayRef(encrypted));
    auto *Table = new GlobalVariable(M, TableTy, /*isConstant=*/false,
                                     GlobalValue::PrivateLinkage, Init,
                                     "morok.tablearith.table");
    Table->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    auto *Ready = new GlobalVariable(
        M, I1, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I1, false), "morok.tablearith.ready");
    Function *Ensure = createEnsureFunction(M, Table, Ready, key);
    return {Table, Ensure};
}

Value *emitLookup(Module &M, BinaryOperator &BO, ir::IRRandom &rng) {
    TableMaterial Mat = createTable(M, BO.getOpcode(), rng);
    IRBuilder<NoFolder> B(&BO);
    auto *I8 = B.getInt8Ty();
    auto *I16 = B.getInt16Ty();
    auto *I32 = B.getInt32Ty();
    auto *TableTy = cast<ArrayType>(Mat.table->getValueType());

    B.CreateCall(Mat.ensure);
    Value *L = B.CreateZExt(BO.getOperand(0), I16, "morok.tablearith.lhs");
    Value *R = B.CreateZExt(BO.getOperand(1), I16, "morok.tablearith.rhs");
    Value *Hi = B.CreateShl(L, ConstantInt::get(I16, 8), "morok.tablearith.hi");
    Value *Idx16 = B.CreateOr(Hi, R, "morok.tablearith.idx16");
    Value *Idx = B.CreateZExt(Idx16, I32, "morok.tablearith.idx");
    Value *Ptr =
        B.CreateInBoundsGEP(TableTy, Mat.table, {ConstantInt::get(I32, 0), Idx},
                            "morok.tablearith.ptr");
    return B.CreateLoad(I8, Ptr, "morok.tablearith.value");
}

} // namespace

bool tableArithmeticFunction(Function &F, const TableArithParams &params,
                             ir::IRRandom &rng) {
    if (F.isDeclaration() || F.getName().starts_with("morok.") ||
        params.probability == 0 || params.max_tables == 0)
        return false;

    const std::uint32_t limit =
        std::min(params.max_tables, kMaxTablesPerInvocation);
    std::vector<BinaryOperator *> targets;
    targets.reserve(limit);
    for (BasicBlock &BB : F) {
        if (targets.size() >= limit)
            break;
        for (Instruction &I : BB) {
            if (targets.size() >= limit)
                break;
            if (auto *BO = dyn_cast<BinaryOperator>(&I))
                if (eligible(*BO))
                    if (rng.chance(params.probability))
                        targets.push_back(BO);
        }
    }
    if (targets.empty())
        return false;

    Module &M = *F.getParent();
    bool changed = false;
    for (BinaryOperator *BO : targets) {
        Value *Replacement = emitLookup(M, *BO, rng);
        BO->replaceAllUsesWith(Replacement);
        BO->eraseFromParent();
        changed = true;
    }
    return changed;
}

PreservedAnalyses ArithmeticTablesPass::run(Function &F,
                                            FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return tableArithmeticFunction(F, params_, rng) ? PreservedAnalyses::none()
                                                    : PreservedAnalyses::all();
}

} // namespace morok::passes
