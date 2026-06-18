// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/DataFlowIntegrity.cpp
//
// Data-flow-entangled integrity.  Selected `i1..i8 a OP b`, const-indexed
// `i9..i16` ops, and matching comparisons become volatile loads from encoded
// lookup tables.  The decode key is derived from a runtime hash of a private
// byte region plus the expected hash; if the region or expected value changes,
// the operation result is corrupted as data rather than guarded by a separable
// branch.  The same diff also perturbs the live table index, so tampering
// changes both the decode key and the semantic cell being read.  When coherent
// decoys are present, their hidden patch state is folded into the same diff.

#include "morok/passes/DataFlowIntegrity.hpp"

#include "morok/ir/InstUtil.hpp"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Support/ModRef.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

using Builder = IRBuilder<NoFolder>;

constexpr std::uint32_t kTableSize = 1u << 16;
constexpr std::uint32_t kMaxTablesPerInvocation = 8;
constexpr char kDecoyStateName[] = "morok.decoy.state";

struct KeySchedule {
    std::uint64_t expected_hash = 0;
    std::uint32_t mul = 1;
    std::uint32_t add = 0;
    std::uint16_t xork = 0;
};

struct Runtime {
    Function *diff = nullptr;
    GlobalVariable *region = nullptr;
    GlobalVariable *expected = nullptr;
    std::uint64_t expected_hash = 0;
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
    Instruction *inst = nullptr;
    TableOpSpec spec;
};

bool generatedFunction(const Function &F) {
    return F.getName().starts_with("morok.");
}

bool directlyRecursive(Function &F) {
    for (Instruction &I : instructions(F)) {
        auto *CB = dyn_cast<CallBase>(&I);
        if (CB && CB->getCalledFunction() == &F)
            return true;
    }
    return false;
}

SmallPtrSet<BasicBlock *, 32> naturalLoopBlocks(Function &F) {
    DominatorTree DT(F);
    SmallPtrSet<BasicBlock *, 32> Blocks;
    for (BasicBlock &BB : F) {
        for (BasicBlock *Succ : successors(&BB)) {
            if (!DT.dominates(Succ, &BB))
                continue;

            Blocks.insert(Succ);
            SmallVector<BasicBlock *, 16> Worklist;
            if (&BB != Succ) {
                Worklist.push_back(&BB);
                Blocks.insert(&BB);
            }
            while (!Worklist.empty()) {
                BasicBlock *Cur = Worklist.pop_back_val();
                for (BasicBlock *Pred : predecessors(Cur)) {
                    if (Blocks.insert(Pred).second && Pred != Succ)
                        Worklist.push_back(Pred);
                }
            }
        }
    }
    return Blocks;
}

bool supportedOpcode(unsigned Opcode) {
    switch (Opcode) {
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

bool shiftOpcode(unsigned Opcode) {
    return Opcode == Instruction::Shl || Opcode == Instruction::LShr ||
           Opcode == Instruction::AShr;
}

std::uint64_t bitMask64(unsigned Width) {
    return Width >= 64 ? ~0ULL : ((1ULL << Width) - 1ULL);
}

std::optional<TableIndexKind> constantSide(Instruction &I) {
    const bool LConst = isa<ConstantInt>(I.getOperand(0));
    const bool RConst = isa<ConstantInt>(I.getOperand(1));
    if (LConst == RConst)
        return std::nullopt;
    return LConst ? TableIndexKind::ConstLhs : TableIndexKind::ConstRhs;
}

bool supportedPredicate(CmpInst::Predicate Pred) {
    switch (Pred) {
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
            Spec.constant =
                Shift->getZExtValue() & bitMask64(Ty->getBitWidth());
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
        const unsigned ConstIndex = *Side == TableIndexKind::ConstLhs ? 0 : 1;
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
        const unsigned ConstIndex = *Side == TableIndexKind::ConstLhs ? 0 : 1;
        auto *C = cast<ConstantInt>(CI.getOperand(ConstIndex));
        Spec.constant = C->getZExtValue() & bitMask64(Ty->getBitWidth());
    }
    return Spec;
}

std::uint64_t bitMask(unsigned Width) {
    return Width >= 64 ? ~0ULL : ((1ULL << Width) - 1ULL);
}

std::int64_t signExtend(std::uint64_t Value, unsigned Width) {
    const std::uint64_t Mask = bitMask(Width);
    std::uint64_t V = Value & Mask;
    const std::uint64_t SignBit = 1ULL << (Width - 1u);
    if ((V & SignBit) == 0)
        return static_cast<std::int64_t>(V);
    return static_cast<std::int64_t>(V | ~Mask);
}

std::uint64_t eval(unsigned Opcode, std::uint64_t Lhs, std::uint64_t Rhs,
                   unsigned Width) {
    const std::uint64_t Mask = bitMask(Width);
    Lhs &= Mask;
    Rhs &= Mask;
    std::uint64_t Result = 0;
    switch (Opcode) {
    case Instruction::Add:
        Result = Lhs + Rhs;
        break;
    case Instruction::Sub:
        Result = Lhs - Rhs;
        break;
    case Instruction::Mul:
        Result = Lhs * Rhs;
        break;
    case Instruction::And:
        Result = Lhs & Rhs;
        break;
    case Instruction::Or:
        Result = Lhs | Rhs;
        break;
    case Instruction::Xor:
        Result = Lhs ^ Rhs;
        break;
    case Instruction::Shl: {
        const unsigned Shift = static_cast<unsigned>(Rhs & Mask);
        Result = Shift >= Width ? 0u : Lhs << Shift;
        break;
    }
    case Instruction::LShr: {
        const unsigned Shift = static_cast<unsigned>(Rhs & Mask);
        Result = Shift >= Width ? 0u : Lhs >> Shift;
        break;
    }
    case Instruction::AShr: {
        const unsigned Shift = static_cast<unsigned>(Rhs & Mask);
        Result =
            Shift >= Width
                ? 0u
                : static_cast<std::uint64_t>(signExtend(Lhs, Width) >> Shift);
        break;
    }
    default:
        break;
    }
    return Result & Mask;
}

std::uint64_t evalPredicate(CmpInst::Predicate Pred, std::uint64_t Lhs,
                            std::uint64_t Rhs, unsigned Width) {
    const std::uint64_t Mask = bitMask(Width);
    const std::uint64_t UL = Lhs & Mask;
    const std::uint64_t UR = Rhs & Mask;
    const std::int64_t SL = signExtend(Lhs, Width);
    const std::int64_t SR = signExtend(Rhs, Width);
    bool Result = false;
    switch (Pred) {
    case CmpInst::ICMP_EQ:
        Result = UL == UR;
        break;
    case CmpInst::ICMP_NE:
        Result = UL != UR;
        break;
    case CmpInst::ICMP_UGT:
        Result = UL > UR;
        break;
    case CmpInst::ICMP_UGE:
        Result = UL >= UR;
        break;
    case CmpInst::ICMP_ULT:
        Result = UL < UR;
        break;
    case CmpInst::ICMP_ULE:
        Result = UL <= UR;
        break;
    case CmpInst::ICMP_SGT:
        Result = SL > SR;
        break;
    case CmpInst::ICMP_SGE:
        Result = SL >= SR;
        break;
    case CmpInst::ICMP_SLT:
        Result = SL < SR;
        break;
    case CmpInst::ICMP_SLE:
        Result = SL <= SR;
        break;
    default:
        break;
    }
    return static_cast<std::uint64_t>(Result);
}

std::uint64_t eval(const TableOpSpec &Op, std::uint64_t Lhs,
                   std::uint64_t Rhs) {
    if (Op.kind == TableOpKind::ICmp)
        return evalPredicate(static_cast<CmpInst::Predicate>(Op.code), Lhs, Rhs,
                             Op.bitWidth);
    return eval(Op.code, Lhs, Rhs, Op.bitWidth);
}

std::uint64_t evalAt(const TableOpSpec &Op, std::uint32_t Idx) {
    std::uint64_t Lhs = 0;
    std::uint64_t Rhs = 0;
    switch (Op.indexKind) {
    case TableIndexKind::Pair8:
        Lhs = static_cast<std::uint8_t>(Idx >> 8);
        Rhs = static_cast<std::uint8_t>(Idx & 0xFFu);
        break;
    case TableIndexKind::ConstLhs:
        Lhs = Op.constant;
        Rhs = Idx;
        break;
    case TableIndexKind::ConstRhs:
        Lhs = Idx;
        Rhs = Op.constant;
        break;
    }
    return eval(Op, Lhs, Rhs);
}

unsigned tableElementBits(const TableOpSpec &Op) {
    if (Op.kind == TableOpKind::ICmp || Op.bitWidth <= 8)
        return 8;
    return 16;
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

std::uint64_t keyAt(std::uint32_t Idx, std::uint64_t Seed,
                    const KeySchedule &Key, unsigned ElementBits) {
    std::uint64_t X = Seed + Key.add;
    X += static_cast<std::uint64_t>(Idx) * Key.mul;
    X ^= X >> 11;
    X ^= X >> 29;
    return (X ^ Key.xork) & bitMask(ElementBits);
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

Value *emitKey(Builder &B, Value *Idx, Value *Seed, const KeySchedule &Key,
               IntegerType *ElementTy) {
    auto *I64 = B.getInt64Ty();
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
    Value *K = B.CreateTrunc(X, ElementTy, "morok.dfi.key.trunc");
    return B.CreateXor(
        K,
        ConstantInt::get(ElementTy,
                         Key.xork & bitMask(ElementTy->getBitWidth())),
        "morok.dfi.key");
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
            static_cast<std::uint16_t>(Rng.next())};
}

GlobalVariable *createTable(Module &M, Function &F, const TableOpSpec &Op,
                            const KeySchedule &Key) {
    LLVMContext &Ctx = M.getContext();
    const unsigned ElementBits = tableElementBits(Op);
    auto *ElementTy = IntegerType::get(Ctx, ElementBits);
    auto *TableTy = ArrayType::get(ElementTy, kTableSize);

    Constant *Init = nullptr;
    if (ElementBits == 8) {
        std::array<std::uint8_t, kTableSize> Enc{};
        for (std::uint32_t Idx = 0; Idx < kTableSize; ++Idx)
            Enc[Idx] = static_cast<std::uint8_t>(
                (evalAt(Op, Idx) ^
                 keyAt(Idx, Key.expected_hash, Key, ElementBits)) &
                bitMask(ElementBits));
        Init = ConstantDataArray::get(Ctx, ArrayRef(Enc));
    } else {
        std::array<std::uint16_t, kTableSize> Enc{};
        for (std::uint32_t Idx = 0; Idx < kTableSize; ++Idx)
            Enc[Idx] = static_cast<std::uint16_t>(
                (evalAt(Op, Idx) ^
                 keyAt(Idx, Key.expected_hash, Key, ElementBits)) &
                bitMask(ElementBits));
        Init = ConstantDataArray::get(Ctx, ArrayRef(Enc));
    }

    auto *Table = new GlobalVariable(
        M, TableTy, /*isConstant=*/true, GlobalValue::PrivateLinkage, Init,
        (Twine("morok.dfi.table.") + suffixFor(F)).str());
    Table->setUnnamedAddr(GlobalValue::UnnamedAddr::None);
    Table->setAlignment(Align(1));
    return Table;
}

Value *emitLookup(Module &M, Function &F, Runtime &R, Target &T,
                  ir::IRRandom &Rng) {
    Instruction &I = *T.inst;
    const unsigned BitWidth = T.spec.bitWidth;
    KeySchedule Key = makeKey(R, Rng);
    GlobalVariable *Table = createTable(M, F, T.spec, Key);

    Builder B(&I);
    auto *I8 = B.getInt8Ty();
    auto *I16 = B.getInt16Ty();
    auto *I32 = B.getInt32Ty();
    auto *I64 = B.getInt64Ty();
    auto *TableTy = cast<ArrayType>(Table->getValueType());
    auto *ElementTy = cast<IntegerType>(TableTy->getElementType());

    Value *Diff = B.CreateCall(R.diff->getFunctionType(), R.diff, {},
                               "morok.dfi.hash.call");
    if (auto *DecoyState = M.getGlobalVariable(kDecoyStateName, true)) {
        if (DecoyState->getValueType()->isIntegerTy(64)) {
            auto *State =
                B.CreateLoad(I64, DecoyState, "morok.dfi.decoy.state");
            State->setVolatile(true);
            State->setAlignment(Align(8));
            Diff = B.CreateXor(Diff, State, "morok.dfi.decoy.diff");
        }
    }
    Value *Seed = B.CreateXor(Diff, ConstantInt::get(I64, Key.expected_hash),
                              "morok.dfi.seed");
    Value *Lhs = I.getOperand(0);
    Value *RhsOp = I.getOperand(1);
    Value *Idx = nullptr;
    if (T.spec.indexKind == TableIndexKind::Pair8) {
        Value *L8 =
            BitWidth == 8 ? Lhs : B.CreateZExt(Lhs, I8, "morok.dfi.lhs8");
        Value *R8 =
            BitWidth == 8 ? RhsOp : B.CreateZExt(RhsOp, I8, "morok.dfi.rhs8");
        Value *L = B.CreateZExt(L8, I16, "morok.dfi.lhs");
        Value *Rhs = B.CreateZExt(R8, I16, "morok.dfi.rhs");
        Value *Hi = B.CreateShl(L, ConstantInt::get(I16, 8), "morok.dfi.hi");
        Value *Idx16 = B.CreateOr(Hi, Rhs, "morok.dfi.idx16");
        Idx = B.CreateZExt(Idx16, I32, "morok.dfi.idx");
    } else {
        Value *Variable =
            T.spec.indexKind == TableIndexKind::ConstLhs ? RhsOp : Lhs;
        Idx = B.CreateZExt(Variable, I32, "morok.dfi.idx");
    }
    Value *DiffIdx = B.CreateTrunc(Diff, I32, "morok.dfi.diff.idx");
    Value *EntangledIdx =
        B.CreateAnd(B.CreateXor(Idx, DiffIdx, "morok.dfi.idx.entangled"),
                    ConstantInt::get(I32, kTableSize - 1u),
                    "morok.dfi.idx.entangled.mask");
    Value *Cell = B.CreateInBoundsGEP(
        TableTy, Table, {ConstantInt::get(I32, 0), EntangledIdx},
        "morok.dfi.cell");
    auto *Encoded = B.CreateLoad(ElementTy, Cell, "morok.dfi.encoded");
    Encoded->setVolatile(true);
    Encoded->setAlignment(Align(ElementTy->getBitWidth() / 8u));
    Value *KeyValue = emitKey(B, EntangledIdx, Seed, Key, ElementTy);
    Value *Value = B.CreateXor(Encoded, KeyValue, "morok.dfi.value");
    if (T.spec.kind == TableOpKind::ICmp)
        return B.CreateTrunc(Value, B.getInt1Ty(), "morok.dfi.icmp");
    if (Value->getType() == I.getType())
        return Value;
    auto *SourceTy = cast<IntegerType>(I.getType());
    return B.CreateTrunc(Value, SourceTy, "morok.dfi.trunc");
}

} // namespace

bool dataFlowIntegrityFunction(Function &F,
                               const DataFlowIntegrityParams &Params,
                               ir::IRRandom &Rng) {
    if (F.isDeclaration() || generatedFunction(F) || Params.probability == 0 ||
        Params.max_tables == 0 || Params.region_bytes == 0)
        return false;
    if (directlyRecursive(F))
        return false;
    // Inserted integrity-diff calls in a funclet-colored block would need a
    // funclet operand bundle; skip WinEH functions entirely (no-op elsewhere).
    if (ir::usesFuncletEH(F))
        return false;

    const std::string HashName = "morok.dfi.hash." + suffixFor(F);
    if (F.getParent()->getFunction(HashName))
        return false;

    const std::uint32_t Limit =
        std::min(Params.max_tables, kMaxTablesPerInvocation);
    SmallVector<Target, 8> Selected;
    SmallPtrSet<BasicBlock *, 32> LoopBlocks = naturalLoopBlocks(F);
    for (BasicBlock &BB : F) {
        if (Selected.size() >= Limit)
            break;
        if (LoopBlocks.contains(&BB))
            continue;
        for (Instruction &I : BB) {
            if (Selected.size() >= Limit)
                break;
            if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
                if (std::optional<TableOpSpec> Spec = eligibleSpec(*BO);
                    Spec && Rng.chance(Params.probability))
                    Selected.push_back(Target{BO, *Spec});
            } else if (auto *CI = dyn_cast<ICmpInst>(&I)) {
                if (std::optional<TableOpSpec> Spec = eligibleSpec(*CI);
                    Spec && Rng.chance(Params.probability))
                    Selected.push_back(Target{CI, *Spec});
            }
        }
    }
    if (Selected.empty())
        return false;

    Module &M = *F.getParent();
    Runtime R = createRuntime(F, Params, Rng);
    for (Target &T : Selected) {
        Value *Replacement = emitLookup(M, F, R, T, Rng);
        T.inst->replaceAllUsesWith(Replacement);
        T.inst->eraseFromParent();
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
