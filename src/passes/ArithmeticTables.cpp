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
#include "llvm/Support/AtomicOrdering.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
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
enum class TableIndexKind { Pair8, ConstLhs, ConstRhs };

struct TableOpSpec {
    TableOpKind kind;
    unsigned code;
    unsigned bitWidth;
    TableIndexKind indexKind = TableIndexKind::Pair8;
    std::uint64_t constant = 0;
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
    case Instruction::Shl:
    case Instruction::LShr:
    case Instruction::AShr:
        return true;
    default:
        return false;
    }
}

bool shiftOpcode(unsigned opcode) {
    return opcode == Instruction::Shl || opcode == Instruction::LShr ||
           opcode == Instruction::AShr;
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

std::uint64_t bitMask64(unsigned width) {
    return width >= 64 ? ~0ULL : ((1ULL << width) - 1ULL);
}

std::optional<TableIndexKind> constantSide(Instruction &I) {
    const bool LConst = isa<ConstantInt>(I.getOperand(0));
    const bool RConst = isa<ConstantInt>(I.getOperand(1));
    if (LConst == RConst)
        return std::nullopt;
    return LConst ? TableIndexKind::ConstLhs : TableIndexKind::ConstRhs;
}

std::optional<TableOpSpec> eligibleSpec(BinaryOperator &BO) {
    auto *Ty = dyn_cast<IntegerType>(BO.getType());
    if (!Ty || Ty->getBitWidth() == 0 || Ty->getBitWidth() > 16)
        return std::nullopt;
    if (!supportedOpcode(BO.getOpcode()))
        return std::nullopt;
    if (shiftOpcode(BO.getOpcode())) {
        auto *Shift = dyn_cast<ConstantInt>(BO.getOperand(1));
        if (!Shift || Shift->getZExtValue() >= Ty->getBitWidth())
            return std::nullopt;
        if (BO.getOpcode() == Instruction::Shl &&
            (BO.hasNoSignedWrap() || BO.hasNoUnsignedWrap()))
            return std::nullopt;
        if ((BO.getOpcode() == Instruction::LShr ||
             BO.getOpcode() == Instruction::AShr) &&
            BO.isExact())
            return std::nullopt;
        TableOpSpec Spec{TableOpKind::Binary, BO.getOpcode(),
                         Ty->getBitWidth()};
        if (Ty->getBitWidth() > 8) {
            Spec.indexKind = TableIndexKind::ConstRhs;
            Spec.constant = Shift->getZExtValue() & bitMask64(Ty->getBitWidth());
        }
        return Spec;
    }
    if ((BO.getOpcode() == Instruction::Add ||
         BO.getOpcode() == Instruction::Sub ||
         BO.getOpcode() == Instruction::Mul) &&
        (BO.hasNoSignedWrap() || BO.hasNoUnsignedWrap()))
        return std::nullopt;

    TableOpSpec Spec{TableOpKind::Binary, BO.getOpcode(), Ty->getBitWidth()};
    if (Ty->getBitWidth() > 8) {
        std::optional<TableIndexKind> Side = constantSide(BO);
        if (!Side)
            return std::nullopt;
        Spec.indexKind = *Side;
        unsigned ConstIndex = *Side == TableIndexKind::ConstLhs ? 0 : 1;
        auto *C = cast<ConstantInt>(BO.getOperand(ConstIndex));
        Spec.constant = C->getZExtValue() & bitMask64(Ty->getBitWidth());
    }
    return Spec;
}

std::optional<TableOpSpec> eligibleSpec(ICmpInst &CI) {
    auto *Ty = dyn_cast<IntegerType>(CI.getOperand(0)->getType());
    if (!Ty || Ty != CI.getOperand(1)->getType() || Ty->getBitWidth() == 0 ||
        Ty->getBitWidth() > 16)
        return std::nullopt;
    if (!supportedPredicate(CI.getPredicate()))
        return std::nullopt;
    TableOpSpec Spec{TableOpKind::ICmp,
                     static_cast<unsigned>(CI.getPredicate()),
                     Ty->getBitWidth()};
    if (Ty->getBitWidth() > 8) {
        std::optional<TableIndexKind> Side = constantSide(CI);
        if (!Side)
            return std::nullopt;
        Spec.indexKind = *Side;
        unsigned ConstIndex = *Side == TableIndexKind::ConstLhs ? 0 : 1;
        auto *C = cast<ConstantInt>(CI.getOperand(ConstIndex));
        Spec.constant = C->getZExtValue() & bitMask64(Ty->getBitWidth());
    }
    return Spec;
}

std::uint64_t bitMask(unsigned width) {
    return width >= 64 ? ~0ULL : ((1ULL << width) - 1ULL);
}

std::int64_t signExtend(std::uint64_t value, unsigned width) {
    const std::uint64_t mask = bitMask(width);
    std::uint64_t v = value & mask;
    const std::uint64_t signBit = 1ULL << (width - 1u);
    if ((v & signBit) == 0)
        return static_cast<std::int64_t>(v);
    return static_cast<std::int64_t>(v | ~mask);
}

std::uint64_t eval(unsigned opcode, std::uint64_t lhs, std::uint64_t rhs,
                   unsigned width) {
    const std::uint64_t mask = bitMask(width);
    lhs &= mask;
    rhs &= mask;
    std::uint64_t result = 0;
    switch (opcode) {
    case Instruction::Add:
        result = lhs + rhs;
        break;
    case Instruction::Sub:
        result = lhs - rhs;
        break;
    case Instruction::Mul:
        result = lhs * rhs;
        break;
    case Instruction::And:
        result = lhs & rhs;
        break;
    case Instruction::Or:
        result = lhs | rhs;
        break;
    case Instruction::Xor:
        result = lhs ^ rhs;
        break;
    case Instruction::Shl: {
        const unsigned shift = static_cast<unsigned>(rhs & mask);
        result = shift >= width ? 0u : lhs << shift;
        break;
    }
    case Instruction::LShr: {
        const unsigned shift = static_cast<unsigned>(rhs & mask);
        result = shift >= width ? 0u : lhs >> shift;
        break;
    }
    case Instruction::AShr: {
        const unsigned shift = static_cast<unsigned>(rhs & mask);
        result =
            shift >= width ? 0u : static_cast<std::uint64_t>(
                                      signExtend(lhs, width) >> shift);
        break;
    }
    default:
        break;
    }
    return result & mask;
}

std::uint64_t evalPredicate(CmpInst::Predicate pred, std::uint64_t lhs,
                            std::uint64_t rhs, unsigned width) {
    const std::uint64_t mask = bitMask(width);
    const std::uint64_t ul = lhs & mask;
    const std::uint64_t ur = rhs & mask;
    const std::int64_t sl = signExtend(lhs, width);
    const std::int64_t sr = signExtend(rhs, width);
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
    return static_cast<std::uint64_t>(result);
}

std::uint64_t eval(const TableOpSpec &op, std::uint64_t lhs,
                   std::uint64_t rhs) {
    if (op.kind == TableOpKind::ICmp)
        return evalPredicate(static_cast<CmpInst::Predicate>(op.code), lhs, rhs,
                             op.bitWidth);
    return eval(op.code, lhs, rhs, op.bitWidth);
}

std::uint64_t evalAt(const TableOpSpec &op, std::uint32_t idx) {
    std::uint64_t lhs = 0;
    std::uint64_t rhs = 0;
    switch (op.indexKind) {
    case TableIndexKind::Pair8:
        lhs = static_cast<std::uint8_t>(idx >> 8);
        rhs = static_cast<std::uint8_t>(idx & 0xFFu);
        break;
    case TableIndexKind::ConstLhs:
        lhs = op.constant;
        rhs = idx;
        break;
    case TableIndexKind::ConstRhs:
        lhs = idx;
        rhs = op.constant;
        break;
    }
    return eval(op, lhs, rhs);
}

unsigned tableElementBits(const TableOpSpec &op) {
    if (op.kind == TableOpKind::ICmp || op.bitWidth <= 8)
        return 8;
    return 16;
}

std::uint64_t keyAt(std::uint32_t idx, const KeySchedule &key,
                    unsigned elementBits) {
    std::uint32_t x = idx * key.mul + key.add;
    x ^= x >> 8;
    x ^= x >> 16;
    return (x ^ key.xork) & bitMask(elementBits);
}

Value *emitKey(IRBuilder<> &B, Value *Idx, const KeySchedule &key,
               IntegerType *ElementTy) {
    auto *I32 = B.getInt32Ty();
    Value *X = B.CreateMul(Idx, ConstantInt::get(I32, key.mul),
                           "morok.tablearith.key.mul");
    X = B.CreateAdd(X, ConstantInt::get(I32, key.add),
                    "morok.tablearith.key.add");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I32, 8)),
                    "morok.tablearith.key.fold8");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I32, 16)),
                    "morok.tablearith.key.fold16");
    Value *K = B.CreateTrunc(X, ElementTy, "morok.tablearith.key.trunc");
    return B.CreateXor(K, ConstantInt::get(ElementTy, key.xork),
                       "morok.tablearith.key");
}

Function *createEnsureFunction(Module &M, GlobalVariable *Table,
                               GlobalVariable *Ready, const KeySchedule &key) {
    LLVMContext &Ctx = M.getContext();
    auto *VoidTy = Type::getVoidTy(Ctx);
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *TableTy = cast<ArrayType>(Table->getValueType());
    auto *ElementTy = cast<IntegerType>(TableTy->getElementType());
    Constant *Encoded = ConstantInt::get(I32, 0);
    Constant *Decoding = ConstantInt::get(I32, 1);
    Constant *ReadyValue = ConstantInt::get(I32, 2);

    auto *Fn = Function::Create(FunctionType::get(VoidTy, false),
                                GlobalValue::InternalLinkage,
                                "morok.tablearith.ensure", &M);
    Fn->addFnAttr(Attribute::NoInline);

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    BasicBlock *Claim = BasicBlock::Create(Ctx, "claim", Fn);
    BasicBlock *ClaimObserved = BasicBlock::Create(Ctx, "claim.observed", Fn);
    BasicBlock *Loop = BasicBlock::Create(Ctx, "loop", Fn);
    BasicBlock *Done = BasicBlock::Create(Ctx, "done", Fn);
    BasicBlock *Wait = BasicBlock::Create(Ctx, "wait", Fn);
    BasicBlock *MaybeClaim = BasicBlock::Create(Ctx, "maybe.claim", Fn);
    BasicBlock *Exit = BasicBlock::Create(Ctx, "exit", Fn);

    IRBuilder<> EB(Entry);
    auto *ReadyLoad = EB.CreateLoad(I32, Ready, "morok.tablearith.ready");
    ReadyLoad->setAtomic(AtomicOrdering::Acquire);
    ReadyLoad->setAlignment(Align(4));
    EB.CreateCondBr(
        EB.CreateICmpEQ(ReadyLoad, ReadyValue, "morok.tablearith.ready.done"),
        Exit, Claim);

    // The failure ordering must be Acquire, not Monotonic: when the claim CAS
    // fails it returns the Observed state, and the ClaimObserved block below
    // branches straight to Exit (skipping the Wait acquire load) whenever the
    // failed CAS already saw ReadyValue.  That fast path is the consumer's only
    // synchronization with the decoder's Release store of the decoded cells, so
    // a Monotonic failure ordering would let a losing thread observe Ready==2
    // yet read stale, still-encoded table entries on weak-memory targets
    // (AArch64/ARM).  Acquire failure ordering makes the failed CAS
    // synchronize-with the decoder's release, just like the Entry/Wait loads.
    IRBuilder<> CB(Claim);
    auto *StateClaim = CB.CreateAtomicCmpXchg(
        Ready, Encoded, Decoding, MaybeAlign(4),
        AtomicOrdering::AcquireRelease, AtomicOrdering::Acquire);
    Value *Claimed =
        CB.CreateExtractValue(StateClaim, 1, "morok.tablearith.claimed");
    Value *Observed =
        CB.CreateExtractValue(StateClaim, 0, "morok.tablearith.observed");
    CB.CreateCondBr(Claimed, Loop, ClaimObserved);

    IRBuilder<> OB(ClaimObserved);
    OB.CreateCondBr(
        OB.CreateICmpEQ(Observed, ReadyValue, "morok.tablearith.claim.ready"),
        Exit, Wait);

    IRBuilder<> LB(Loop);
    PHINode *Idx = LB.CreatePHI(I32, 2, "morok.tablearith.idx");
    Idx->addIncoming(ConstantInt::get(I32, 0), Claim);
    Value *Ptr =
        LB.CreateInBoundsGEP(TableTy, Table, {ConstantInt::get(I32, 0), Idx},
                             "morok.tablearith.cell");
    Value *Enc = LB.CreateLoad(ElementTy, Ptr, "morok.tablearith.enc");
    Value *Dec =
        LB.CreateXor(Enc, emitKey(LB, Idx, key, ElementTy),
                     "morok.tablearith.dec");
    LB.CreateStore(Dec, Ptr);
    Value *Next =
        LB.CreateAdd(Idx, ConstantInt::get(I32, 1), "morok.tablearith.next");
    Idx->addIncoming(Next, Loop);
    Value *AtEnd = LB.CreateICmpEQ(Next, ConstantInt::get(I32, kTableSize),
                                   "morok.tablearith.done");
    LB.CreateCondBr(AtEnd, Done, Loop);

    IRBuilder<> DB(Done);
    auto *ReadyStore = DB.CreateStore(ReadyValue, Ready);
    ReadyStore->setAtomic(AtomicOrdering::Release);
    ReadyStore->setAlignment(Align(4));
    DB.CreateBr(Exit);

    IRBuilder<> WB(Wait);
    auto *WaitLoad = WB.CreateLoad(I32, Ready, "morok.tablearith.wait");
    WaitLoad->setAtomic(AtomicOrdering::Acquire);
    WaitLoad->setAlignment(Align(4));
    WB.CreateCondBr(
        WB.CreateICmpEQ(WaitLoad, ReadyValue, "morok.tablearith.wait.ready"),
        Exit, MaybeClaim);

    IRBuilder<> MB(MaybeClaim);
    MB.CreateCondBr(
        MB.CreateICmpEQ(WaitLoad, Encoded, "morok.tablearith.wait.encoded"),
        Claim, Wait);

    IRBuilder<> XB(Exit);
    XB.CreateRetVoid();

    // Decode early during static init, and keep the function-body fallback
    // single-decoder for same-priority or unusual pre-main entry paths.
    appendToGlobalCtors(M, Fn, /*Priority=*/0);
    return Fn;
}

TableMaterial createTable(Module &M, const TableOpSpec &op,
                          ir::IRRandom &rng) {
    LLVMContext &Ctx = M.getContext();
    const unsigned ElementBits = tableElementBits(op);
    auto *ElementTy = IntegerType::get(Ctx, ElementBits);
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *TableTy = ArrayType::get(ElementTy, kTableSize);
    const KeySchedule key{static_cast<std::uint32_t>(rng.next()) | 1u,
                          static_cast<std::uint32_t>(rng.next()),
                          static_cast<std::uint8_t>(rng.next())};

    Constant *Init = nullptr;
    if (ElementBits == 8) {
        std::array<std::uint8_t, kTableSize> encrypted{};
        for (std::uint32_t idx = 0; idx < kTableSize; ++idx)
            encrypted[idx] = static_cast<std::uint8_t>(
                (evalAt(op, idx) ^ keyAt(idx, key, ElementBits)) &
                bitMask(ElementBits));
        Init = ConstantDataArray::get(Ctx, ArrayRef(encrypted));
    } else {
        std::array<std::uint16_t, kTableSize> encrypted{};
        for (std::uint32_t idx = 0; idx < kTableSize; ++idx)
            encrypted[idx] = static_cast<std::uint16_t>(
                (evalAt(op, idx) ^ keyAt(idx, key, ElementBits)) &
                bitMask(ElementBits));
        Init = ConstantDataArray::get(Ctx, ArrayRef(encrypted));
    }
    auto *Table = new GlobalVariable(M, TableTy, /*isConstant=*/false,
                                     GlobalValue::PrivateLinkage, Init,
                                     "morok.tablearith.table");
    Table->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    auto *Ready = new GlobalVariable(
        M, I32, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I32, 0), "morok.tablearith.ready");
    Function *Ensure = createEnsureFunction(M, Table, Ready, key);
    return {Table, Ensure};
}

Value *emitLookup(Module &M, Target &T, ir::IRRandom &rng) {
    Instruction &I = *T.inst;
    const unsigned bitWidth = T.spec.bitWidth;
    TableMaterial Mat = createTable(M, T.spec, rng);
    IRBuilder<NoFolder> B(&I);
    auto *I16 = B.getInt16Ty();
    auto *I32 = B.getInt32Ty();
    auto *TableTy = cast<ArrayType>(Mat.table->getValueType());
    auto *ElementTy = cast<IntegerType>(TableTy->getElementType());

    B.CreateCall(Mat.ensure);
    Value *Lhs = I.getOperand(0);
    Value *Rhs = I.getOperand(1);
    Value *Idx = nullptr;
    if (T.spec.indexKind == TableIndexKind::Pair8) {
        auto *I8 = B.getInt8Ty();
        Value *L8 = bitWidth == 8
                        ? Lhs
                        : B.CreateZExt(Lhs, I8, "morok.tablearith.lhs8");
        Value *R8 = bitWidth == 8
                        ? Rhs
                        : B.CreateZExt(Rhs, I8, "morok.tablearith.rhs8");
        Value *L = B.CreateZExt(L8, I16, "morok.tablearith.lhs");
        Value *R = B.CreateZExt(R8, I16, "morok.tablearith.rhs");
        Value *Hi =
            B.CreateShl(L, ConstantInt::get(I16, 8), "morok.tablearith.hi");
        Value *Idx16 = B.CreateOr(Hi, R, "morok.tablearith.idx16");
        Idx = B.CreateZExt(Idx16, I32, "morok.tablearith.idx");
    } else {
        Value *Variable =
            T.spec.indexKind == TableIndexKind::ConstLhs ? Rhs : Lhs;
        Idx = B.CreateZExt(Variable, I32, "morok.tablearith.idx");
    }
    Value *Ptr =
        B.CreateInBoundsGEP(TableTy, Mat.table, {ConstantInt::get(I32, 0), Idx},
                            "morok.tablearith.ptr");
    Value *Result = B.CreateLoad(ElementTy, Ptr, "morok.tablearith.value");
    if (T.spec.kind == TableOpKind::ICmp)
        return B.CreateTrunc(Result, B.getInt1Ty(), "morok.tablearith.icmp");
    if (Result->getType() == I.getType())
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
                if (std::optional<TableOpSpec> Spec = eligibleSpec(*BO);
                    Spec && rng.chance(params.probability))
                    targets.push_back(Target{BO, *Spec});
            } else if (auto *CI = dyn_cast<ICmpInst>(&I)) {
                if (std::optional<TableOpSpec> Spec = eligibleSpec(*CI);
                    Spec && rng.chance(params.probability))
                    targets.push_back(Target{CI, *Spec});
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
