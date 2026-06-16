// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/ArithmeticTables.cpp
//
// Arithmetic/comparison-as-table lowering for narrow integer operators.  Each
// selected `i1..i8 a OP b` or `icmp pred i1..i8 a, b` becomes:
//   ensure(table)
//   load table[(zext(a) << 8) | zext(b)]
// Tables are stored encrypted and materialized lazily by a small internal
// decoder, so the original opcode disappears from the function body and the
// module does not contain a plaintext operation table.

#include "morok/passes/ArithmeticTables.hpp"

#include "morok/ir/InstUtil.hpp"

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

enum class TableOpKind { Binary, ICmp };

struct TableOpSpec {
    TableOpKind kind;
    unsigned code;
    unsigned bitWidth;
};

struct Target {
    Instruction *inst;
    TableOpSpec spec;
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

bool supportedPredicate(CmpInst::Predicate pred) {
    switch (pred) {
    case CmpInst::ICMP_EQ:
    case CmpInst::ICMP_NE:
    case CmpInst::ICMP_UGT:
    case CmpInst::ICMP_UGE:
    case CmpInst::ICMP_ULT:
    case CmpInst::ICMP_ULE:
    case CmpInst::ICMP_SGT:
    case CmpInst::ICMP_SGE:
    case CmpInst::ICMP_SLT:
    case CmpInst::ICMP_SLE:
        return true;
    default:
        return false;
    }
}

bool eligible(BinaryOperator &BO) {
    auto *Ty = dyn_cast<IntegerType>(BO.getType());
    if (!Ty || Ty->getBitWidth() == 0 || Ty->getBitWidth() > 8)
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

bool eligible(ICmpInst &CI) {
    auto *Ty = dyn_cast<IntegerType>(CI.getOperand(0)->getType());
    if (!Ty || Ty != CI.getOperand(1)->getType() || Ty->getBitWidth() == 0 ||
        Ty->getBitWidth() > 8)
        return false;
    return supportedPredicate(CI.getPredicate());
}

std::uint8_t bitMask(unsigned width) {
    return width >= 8 ? 0xFFu : static_cast<std::uint8_t>((1u << width) - 1u);
}

std::int32_t signExtend(std::uint8_t value, unsigned width) {
    const std::uint32_t mask =
        width >= 8 ? 0xFFu : static_cast<std::uint32_t>((1u << width) - 1u);
    std::uint32_t v = value & mask;
    const std::uint32_t signBit = 1u << (width - 1u);
    if ((v & signBit) == 0)
        return static_cast<std::int32_t>(v);
    return static_cast<std::int32_t>(v | ~mask);
}

std::uint8_t eval(unsigned opcode, std::uint8_t lhs, std::uint8_t rhs,
                  unsigned width) {
    const std::uint8_t mask = bitMask(width);
    lhs &= mask;
    rhs &= mask;
    std::uint8_t result = 0;
    switch (opcode) {
    case Instruction::Add:
        result = static_cast<std::uint8_t>(lhs + rhs);
        break;
    case Instruction::Sub:
        result = static_cast<std::uint8_t>(lhs - rhs);
        break;
    case Instruction::Mul:
        result = static_cast<std::uint8_t>(lhs * rhs);
        break;
    case Instruction::And:
        result = static_cast<std::uint8_t>(lhs & rhs);
        break;
    case Instruction::Or:
        result = static_cast<std::uint8_t>(lhs | rhs);
        break;
    case Instruction::Xor:
        result = static_cast<std::uint8_t>(lhs ^ rhs);
        break;
    default:
        break;
    }
    return static_cast<std::uint8_t>(result & mask);
}

std::uint8_t evalPredicate(CmpInst::Predicate pred, std::uint8_t lhs,
                           std::uint8_t rhs, unsigned width) {
    const std::uint8_t mask = bitMask(width);
    const std::uint32_t ul = lhs & mask;
    const std::uint32_t ur = rhs & mask;
    const std::int32_t sl = signExtend(lhs, width);
    const std::int32_t sr = signExtend(rhs, width);
    bool result = false;
    switch (pred) {
    case CmpInst::ICMP_EQ:
        result = ul == ur;
        break;
    case CmpInst::ICMP_NE:
        result = ul != ur;
        break;
    case CmpInst::ICMP_UGT:
        result = ul > ur;
        break;
    case CmpInst::ICMP_UGE:
        result = ul >= ur;
        break;
    case CmpInst::ICMP_ULT:
        result = ul < ur;
        break;
    case CmpInst::ICMP_ULE:
        result = ul <= ur;
        break;
    case CmpInst::ICMP_SGT:
        result = sl > sr;
        break;
    case CmpInst::ICMP_SGE:
        result = sl >= sr;
        break;
    case CmpInst::ICMP_SLT:
        result = sl < sr;
        break;
    case CmpInst::ICMP_SLE:
        result = sl <= sr;
        break;
    default:
        break;
    }
    return static_cast<std::uint8_t>(result);
}

std::uint8_t eval(const TableOpSpec &op, std::uint8_t lhs, std::uint8_t rhs) {
    if (op.kind == TableOpKind::ICmp)
        return evalPredicate(static_cast<CmpInst::Predicate>(op.code), lhs, rhs,
                             op.bitWidth);
    return eval(op.code, lhs, rhs, op.bitWidth);
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

TableMaterial createTable(Module &M, const TableOpSpec &op,
                          ir::IRRandom &rng) {
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
        encrypted[idx] = eval(op, lhs, rhs) ^ keyAt(idx, key);
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

Value *emitLookup(Module &M, Target &T, ir::IRRandom &rng) {
    Instruction &I = *T.inst;
    const unsigned bitWidth = T.spec.bitWidth;
    TableMaterial Mat = createTable(M, T.spec, rng);
    IRBuilder<NoFolder> B(&I);
    auto *I8 = B.getInt8Ty();
    auto *I16 = B.getInt16Ty();
    auto *I32 = B.getInt32Ty();
    auto *TableTy = cast<ArrayType>(Mat.table->getValueType());

    B.CreateCall(Mat.ensure);
    Value *Lhs = I.getOperand(0);
    Value *Rhs = I.getOperand(1);
    Value *L8 = bitWidth == 8
                    ? Lhs
                    : B.CreateZExt(Lhs, I8, "morok.tablearith.lhs8");
    Value *R8 = bitWidth == 8
                    ? Rhs
                    : B.CreateZExt(Rhs, I8, "morok.tablearith.rhs8");
    Value *L = B.CreateZExt(L8, I16, "morok.tablearith.lhs");
    Value *R = B.CreateZExt(R8, I16, "morok.tablearith.rhs");
    Value *Hi = B.CreateShl(L, ConstantInt::get(I16, 8), "morok.tablearith.hi");
    Value *Idx16 = B.CreateOr(Hi, R, "morok.tablearith.idx16");
    Value *Idx = B.CreateZExt(Idx16, I32, "morok.tablearith.idx");
    Value *Ptr =
        B.CreateInBoundsGEP(TableTy, Mat.table, {ConstantInt::get(I32, 0), Idx},
                            "morok.tablearith.ptr");
    Value *Result = B.CreateLoad(I8, Ptr, "morok.tablearith.value");
    if (T.spec.kind == TableOpKind::ICmp)
        return B.CreateTrunc(Result, B.getInt1Ty(), "morok.tablearith.icmp");
    if (bitWidth == 8)
        return Result;
    auto *SourceTy = cast<IntegerType>(I.getType());
    return B.CreateTrunc(Result, SourceTy, "morok.tablearith.trunc");
}

} // namespace

bool tableArithmeticFunction(Function &F, const TableArithParams &params,
                             ir::IRRandom &rng) {
    if (F.isDeclaration() || F.getName().starts_with("morok.") ||
        params.probability == 0 || params.max_tables == 0)
        return false;
    // Inserted table-ensure calls in a funclet-colored block would need a
    // funclet operand bundle; skip WinEH functions entirely (no-op elsewhere).
    if (ir::usesFuncletEH(F))
        return false;

    const std::uint32_t limit =
        std::min(params.max_tables, kMaxTablesPerInvocation);
    std::vector<Target> targets;
    targets.reserve(limit);
    for (BasicBlock &BB : F) {
        if (targets.size() >= limit)
            break;
        for (Instruction &I : BB) {
            if (targets.size() >= limit)
                break;
            if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
                if (eligible(*BO) && rng.chance(params.probability))
                    targets.push_back(Target{
                        BO, {TableOpKind::Binary, BO->getOpcode(),
                             cast<IntegerType>(BO->getType())->getBitWidth()}});
            } else if (auto *CI = dyn_cast<ICmpInst>(&I)) {
                if (eligible(*CI) && rng.chance(params.probability))
                    targets.push_back(Target{
                        CI, {TableOpKind::ICmp,
                             static_cast<unsigned>(CI->getPredicate()),
                             cast<IntegerType>(CI->getOperand(0)->getType())
                                 ->getBitWidth()}});
            }
        }
    }
    if (targets.empty())
        return false;

    Module &M = *F.getParent();
    bool changed = false;
    for (Target &T : targets) {
        Value *Replacement = emitLookup(M, T, rng);
        T.inst->replaceAllUsesWith(Replacement);
        T.inst->eraseFromParent();
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
