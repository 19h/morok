// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/Virtualization.cpp
//
// A strict IR-level bytecode virtualizer.  Eligible straight-line integer
// functions are lifted into an encrypted per-function bytecode stream and an
// internal interpreter helper.  The helper uses threaded computed-goto dispatch
// (`indirectbr` over a blockaddress table), duplicated arithmetic handlers, and
// per-byte decryption keyed by the VM PC; the original function becomes a
// native wrapper that calls into the VM.

#include "morok/passes/Virtualization.hpp"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
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
#include <utility>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

using Builder = IRBuilder<NoFolder>;

constexpr std::uint32_t kInstrStride = 16;
constexpr std::uint64_t kImmPcSalt = 0x9E3779B97F4A7C15ULL;

enum class VmOp : std::uint8_t {
    Add,
    Sub,
    Xor,
    And,
    Or,
    Mul,
    Shl,
    LShr,
    AShr,
    UDiv,
    SDiv,
    URem,
    SRem,
    ICmpEQ,
    ICmpNE,
    ICmpULT,
    ICmpULE,
    ICmpUGT,
    ICmpUGE,
    ICmpSLT,
    ICmpSLE,
    ICmpSGT,
    ICmpSGE,
    Select,
    Const,
    Ret,
    Count,
};

struct VmInstr {
    VmOp op = VmOp::Ret;
    std::uint8_t dst = 0;
    std::uint8_t lhs = 0;
    std::uint8_t rhs = 0;
    std::uint64_t imm = 0;
};

struct Program {
    Function *source = nullptr;
    unsigned width = 0;
    std::uint32_t reg_count = 0;
    std::vector<VmInstr> code;
};

struct Encoding {
    std::uint32_t mul = 1;
    std::uint32_t add = 0;
    std::uint8_t xork = 0;
    std::uint8_t operand_key = 0;
    std::uint64_t imm_key = 0;
};

struct HandlerSpec {
    VmOp op = VmOp::Ret;
    std::uint8_t variant = 0;
    std::string name;
};

struct HandlerLayout {
    std::vector<HandlerSpec> specs;
    std::array<std::vector<std::uint8_t>, static_cast<std::size_t>(VmOp::Count)>
        ids;
};

std::size_t opIndex(VmOp Op) { return static_cast<std::size_t>(Op); }

bool generatedFunction(const Function &F) {
    return F.getName().starts_with("morok.");
}

std::uint64_t widthMask(unsigned Width) {
    return Width >= 64 ? ~0ULL : ((1ULL << Width) - 1ULL);
}

bool supportedWidth(unsigned Width) { return Width >= 1 && Width <= 64; }

std::optional<VmOp> binaryOpcode(BinaryOperator &BO, unsigned Width) {
    // Poison-generating flags (nsw/nuw on add/sub/mul/shl, exact on
    // div/shr) are intentionally ignored: the VM emits the ordinary wrapping /
    // non-exact operation, which is a sound refinement of the flagged form —
    // identical for every input the flag promised about, and merely defined
    // (instead of poison) for the inputs the flag declared could not occur.
    // Without this, virtualization never fires on optimized (-O2) code, where
    // essentially all arithmetic is flagged.
    switch (BO.getOpcode()) {
    case Instruction::Add:
        return VmOp::Add;
    case Instruction::Sub:
        return VmOp::Sub;
    case Instruction::Mul:
        return VmOp::Mul;
    case Instruction::And:
        return VmOp::And;
    case Instruction::Or:
        return VmOp::Or;
    case Instruction::Xor:
        return VmOp::Xor;
    case Instruction::UDiv:
        return VmOp::UDiv;
    case Instruction::SDiv:
        return VmOp::SDiv;
    case Instruction::URem:
        return VmOp::URem;
    case Instruction::SRem:
        return VmOp::SRem;
    case Instruction::Shl:
    case Instruction::LShr:
    case Instruction::AShr:
        break;
    default:
        return std::nullopt;
    }

    auto *Shift = dyn_cast<ConstantInt>(BO.getOperand(1));
    if (!Shift || Shift->getZExtValue() >= Width)
        return std::nullopt;
    if (BO.getOpcode() == Instruction::Shl)
        return VmOp::Shl;
    if (BO.getOpcode() == Instruction::LShr)
        return VmOp::LShr;
    return VmOp::AShr;
}

std::optional<VmOp> icmpOpcode(ICmpInst &Cmp, unsigned Width) {
    auto *LhsTy = dyn_cast<IntegerType>(Cmp.getOperand(0)->getType());
    auto *RhsTy = dyn_cast<IntegerType>(Cmp.getOperand(1)->getType());
    if (!LhsTy || !RhsTy || LhsTy->getBitWidth() != Width ||
        RhsTy->getBitWidth() != Width)
        return std::nullopt;

    switch (Cmp.getPredicate()) {
    case ICmpInst::ICMP_EQ:
        return VmOp::ICmpEQ;
    case ICmpInst::ICMP_NE:
        return VmOp::ICmpNE;
    case ICmpInst::ICMP_ULT:
        return VmOp::ICmpULT;
    case ICmpInst::ICMP_ULE:
        return VmOp::ICmpULE;
    case ICmpInst::ICMP_UGT:
        return VmOp::ICmpUGT;
    case ICmpInst::ICMP_UGE:
        return VmOp::ICmpUGE;
    case ICmpInst::ICMP_SLT:
        return VmOp::ICmpSLT;
    case ICmpInst::ICMP_SLE:
        return VmOp::ICmpSLE;
    case ICmpInst::ICMP_SGT:
        return VmOp::ICmpSGT;
    case ICmpInst::ICMP_SGE:
        return VmOp::ICmpSGE;
    default:
        return std::nullopt;
    }
}

std::optional<unsigned> signatureWidth(Function &F) {
    if (F.isDeclaration() || generatedFunction(F) || F.hasPersonalityFn())
        return std::nullopt;
    auto *RetTy = dyn_cast<IntegerType>(F.getReturnType());
    if (!RetTy || !supportedWidth(RetTy->getBitWidth()))
        return std::nullopt;
    const unsigned Width = RetTy->getBitWidth();
    if (F.arg_size() > 240)
        return std::nullopt;
    for (Argument &Arg : F.args()) {
        auto *ArgTy = dyn_cast<IntegerType>(Arg.getType());
        if (!ArgTy || !supportedWidth(ArgTy->getBitWidth()) ||
            ArgTy->getBitWidth() > Width)
            return std::nullopt;
    }
    return Width;
}

bool newRegister(std::uint32_t &Next, const VirtualizationParams &Params,
                 std::uint8_t &Out) {
    const std::uint32_t Limit = std::min<std::uint32_t>(
        Params.max_registers == 0 ? 0 : Params.max_registers, 255);
    if (Next >= Limit)
        return false;
    Out = static_cast<std::uint8_t>(Next++);
    return true;
}

bool appendInstr(Program &P, const VmInstr &Instr,
                 const VirtualizationParams &Params) {
    if (P.code.size() >= Params.max_instructions)
        return false;
    P.code.push_back(Instr);
    return true;
}

std::optional<std::uint8_t>
materializeImmediate(std::uint64_t Imm, Program &P, std::uint32_t &NextReg,
                     const VirtualizationParams &Params) {
    std::uint8_t Reg = 0;
    if (!newRegister(NextReg, Params, Reg))
        return std::nullopt;
    if (!appendInstr(P,
                     VmInstr{VmOp::Const, Reg, 0, 0,
                             Imm & widthMask(P.width)},
                     Params))
        return std::nullopt;
    return Reg;
}

std::optional<std::uint8_t>
materializeOperand(Value *V, Program &P,
                   DenseMap<const Value *, std::uint8_t> &Regs,
                   std::uint32_t &NextReg, const VirtualizationParams &Params) {
    if (auto It = Regs.find(V); It != Regs.end())
        return It->second;

    auto *CI = dyn_cast<ConstantInt>(V);
    if (!CI || CI->getBitWidth() > 64)
        return std::nullopt;

    const std::uint64_t Imm = CI->getZExtValue() & widthMask(P.width);
    std::optional<std::uint8_t> Reg =
        materializeImmediate(Imm, P, NextReg, Params);
    if (Reg)
        Regs[V] = *Reg;
    return Reg;
}

std::optional<std::uint8_t>
appendRegisterBinary(Program &P, VmOp Op, std::uint8_t L, std::uint8_t R,
                     std::uint32_t &NextReg,
                     const VirtualizationParams &Params) {
    std::uint8_t Dst = 0;
    if (!newRegister(NextReg, Params, Dst))
        return std::nullopt;
    if (!appendInstr(P, VmInstr{Op, Dst, L, R, 0}, Params))
        return std::nullopt;
    return Dst;
}

std::optional<std::uint8_t>
maskRegister(Program &P, std::uint8_t Reg, unsigned Bits,
             std::uint32_t &NextReg, const VirtualizationParams &Params) {
    if (Bits >= P.width)
        return Reg;
    auto Mask = materializeImmediate(widthMask(Bits), P, NextReg, Params);
    if (!Mask)
        return std::nullopt;
    std::uint8_t Dst = 0;
    if (!newRegister(NextReg, Params, Dst))
        return std::nullopt;
    if (!appendInstr(P, VmInstr{VmOp::And, Dst, Reg, *Mask, 0}, Params))
        return std::nullopt;
    return Dst;
}

std::optional<std::uint8_t>
signExtendRegister(Program &P, std::uint8_t Reg, unsigned SrcBits,
                   std::uint32_t &NextReg,
                   const VirtualizationParams &Params) {
    if (SrcBits == P.width)
        return Reg;
    if (SrcBits == 0 || SrcBits > P.width)
        return std::nullopt;
    auto Shift =
        materializeImmediate(P.width - SrcBits, P, NextReg, Params);
    if (!Shift)
        return std::nullopt;
    std::uint8_t Shifted = 0;
    if (!newRegister(NextReg, Params, Shifted))
        return std::nullopt;
    if (!appendInstr(P, VmInstr{VmOp::Shl, Shifted, Reg, *Shift, 0}, Params))
        return std::nullopt;
    std::uint8_t Dst = 0;
    if (!newRegister(NextReg, Params, Dst))
        return std::nullopt;
    if (!appendInstr(P, VmInstr{VmOp::AShr, Dst, Shifted, *Shift, 0}, Params))
        return std::nullopt;
    return Dst;
}

std::optional<Program> buildProgram(Function &F,
                                    const VirtualizationParams &Params) {
    std::optional<unsigned> Width = signatureWidth(F);
    if (!Width || F.size() != 1 || Params.max_instructions == 0 ||
        Params.max_registers == 0)
        return std::nullopt;

    Program P;
    P.source = &F;
    P.width = *Width;

    DenseMap<const Value *, std::uint8_t> Regs;
    std::uint32_t NextReg = 0;
    for (Argument &Arg : F.args()) {
        std::uint8_t Reg = 0;
        if (!newRegister(NextReg, Params, Reg))
            return std::nullopt;
        Regs[&Arg] = Reg;
    }

    BasicBlock &BB = F.getEntryBlock();
    bool SawReturn = false;
    for (Instruction &I : BB) {
        if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
            auto *BOTy = dyn_cast<IntegerType>(BO->getType());
            if (!BOTy || !supportedWidth(BOTy->getBitWidth()) ||
                BOTy->getBitWidth() > P.width)
                return std::nullopt;
            auto Op = binaryOpcode(*BO, BOTy->getBitWidth());
            if (!Op)
                return std::nullopt;
            const bool SameWidth = BOTy->getBitWidth() == P.width;
            const bool NarrowOp = BOTy->getBitWidth() < P.width;
            if (!SameWidth && !NarrowOp)
                return std::nullopt;
            auto L =
                materializeOperand(BO->getOperand(0), P, Regs, NextReg, Params);
            auto R =
                materializeOperand(BO->getOperand(1), P, Regs, NextReg, Params);
            if (!L || !R)
                return std::nullopt;
            if (!SameWidth && *Op == VmOp::AShr) {
                L = signExtendRegister(P, *L, BOTy->getBitWidth(), NextReg,
                                       Params);
                if (!L)
                    return std::nullopt;
            }
            // Signed division/remainder of a narrow type needs both operands
            // sign-extended into the register width so the handler's signed
            // re-extension reconstructs the value correctly.
            if (NarrowOp && (*Op == VmOp::SDiv || *Op == VmOp::SRem)) {
                L = signExtendRegister(P, *L, BOTy->getBitWidth(), NextReg,
                                       Params);
                R = signExtendRegister(P, *R, BOTy->getBitWidth(), NextReg,
                                       Params);
                if (!L || !R)
                    return std::nullopt;
            }
            auto Dst = appendRegisterBinary(P, *Op, *L, *R, NextReg, Params);
            if (!Dst)
                return std::nullopt;
            Dst = maskRegister(P, *Dst, BOTy->getBitWidth(), NextReg, Params);
            if (!Dst)
                return std::nullopt;
            Regs[&I] = *Dst;
            continue;
        }

        if (auto *SExt = dyn_cast<SExtInst>(&I)) {
            auto *DstTy = dyn_cast<IntegerType>(SExt->getType());
            auto *SrcTy = dyn_cast<IntegerType>(SExt->getOperand(0)->getType());
            if (!DstTy || !SrcTy || DstTy->getBitWidth() != P.width ||
                SrcTy->getBitWidth() >= P.width)
                return std::nullopt;
            auto R =
                materializeOperand(SExt->getOperand(0), P, Regs, NextReg,
                                   Params);
            if (!R)
                return std::nullopt;
            R = signExtendRegister(P, *R, SrcTy->getBitWidth(), NextReg,
                                   Params);
            if (!R)
                return std::nullopt;
            Regs[&I] = *R;
            continue;
        }

        if (auto *Cmp = dyn_cast<ICmpInst>(&I)) {
            auto *CmpTy =
                dyn_cast<IntegerType>(Cmp->getOperand(0)->getType());
            if (!CmpTy || !supportedWidth(CmpTy->getBitWidth()) ||
                CmpTy->getBitWidth() > P.width)
                return std::nullopt;
            auto Op = icmpOpcode(*Cmp, CmpTy->getBitWidth());
            if (!Op)
                return std::nullopt;
            auto L = materializeOperand(Cmp->getOperand(0), P, Regs, NextReg,
                                        Params);
            auto R = materializeOperand(Cmp->getOperand(1), P, Regs, NextReg,
                                        Params);
            if (!L || !R)
                return std::nullopt;
            if (Cmp->isSigned() && CmpTy->getBitWidth() < P.width) {
                L = signExtendRegister(P, *L, CmpTy->getBitWidth(), NextReg,
                                       Params);
                R = signExtendRegister(P, *R, CmpTy->getBitWidth(), NextReg,
                                       Params);
                if (!L || !R)
                    return std::nullopt;
            }
            std::uint8_t Dst = 0;
            if (!newRegister(NextReg, Params, Dst))
                return std::nullopt;
            if (!appendInstr(P, VmInstr{*Op, Dst, *L, *R, 0}, Params))
                return std::nullopt;
            Regs[&I] = Dst;
            continue;
        }

        if (auto *ZExt = dyn_cast<ZExtInst>(&I)) {
            auto *DstTy = dyn_cast<IntegerType>(ZExt->getType());
            auto *SrcTy = dyn_cast<IntegerType>(ZExt->getOperand(0)->getType());
            if (!DstTy || !SrcTy || DstTy->getBitWidth() != P.width ||
                SrcTy->getBitWidth() > P.width)
                return std::nullopt;
            auto R = materializeOperand(ZExt->getOperand(0), P, Regs, NextReg,
                                        Params);
            if (!R)
                return std::nullopt;
            Regs[&I] = *R;
            continue;
        }

        if (auto *Trunc = dyn_cast<TruncInst>(&I)) {
            auto *DstTy = dyn_cast<IntegerType>(Trunc->getType());
            auto *SrcTy =
                dyn_cast<IntegerType>(Trunc->getOperand(0)->getType());
            if (!DstTy || !SrcTy || !supportedWidth(DstTy->getBitWidth()) ||
                DstTy->getBitWidth() > P.width ||
                DstTy->getBitWidth() >= SrcTy->getBitWidth())
                return std::nullopt;
            auto R = materializeOperand(Trunc->getOperand(0), P, Regs, NextReg,
                                        Params);
            if (!R)
                return std::nullopt;
            R = maskRegister(P, *R, DstTy->getBitWidth(), NextReg, Params);
            if (!R)
                return std::nullopt;
            Regs[&I] = *R;
            continue;
        }

        if (auto *SI = dyn_cast<SelectInst>(&I)) {
            auto *DstTy = dyn_cast<IntegerType>(SI->getType());
            auto *CondTy = dyn_cast<IntegerType>(SI->getCondition()->getType());
            if (!DstTy || !CondTy || DstTy->getBitWidth() != P.width ||
                CondTy->getBitWidth() != 1)
                return std::nullopt;
            auto C = materializeOperand(SI->getCondition(), P, Regs, NextReg,
                                        Params);
            auto T = materializeOperand(SI->getTrueValue(), P, Regs, NextReg,
                                        Params);
            auto FalseReg = materializeOperand(SI->getFalseValue(), P, Regs,
                                               NextReg, Params);
            if (!C || !T || !FalseReg)
                return std::nullopt;
            std::uint8_t Dst = 0;
            if (!newRegister(NextReg, Params, Dst))
                return std::nullopt;
            if (!appendInstr(P,
                             VmInstr{VmOp::Select, Dst, *C, *T, *FalseReg},
                             Params))
                return std::nullopt;
            Regs[&I] = Dst;
            continue;
        }

        if (auto *RI = dyn_cast<ReturnInst>(&I)) {
            if (SawReturn || !RI->getReturnValue())
                return std::nullopt;
            auto R = materializeOperand(RI->getReturnValue(), P, Regs, NextReg,
                                        Params);
            if (!R)
                return std::nullopt;
            if (!appendInstr(P, VmInstr{VmOp::Ret, 0, *R, 0, 0}, Params))
                return std::nullopt;
            SawReturn = true;
            continue;
        }

        return std::nullopt;
    }

    if (!SawReturn || P.code.empty())
        return std::nullopt;
    P.reg_count = std::max<std::uint32_t>(NextReg, 1);
    return P;
}

void shuffleSpecs(std::vector<HandlerSpec> &Specs, ir::IRRandom &Rng) {
    for (std::size_t I = Specs.size(); I > 1; --I) {
        const std::size_t J = Rng.range(static_cast<std::uint32_t>(I));
        std::swap(Specs[I - 1], Specs[J]);
    }
}

HandlerLayout makeLayout(ir::IRRandom &Rng) {
    HandlerLayout Layout;
    Layout.specs = {
        {VmOp::Const, 0, "const"}, {VmOp::Ret, 0, "ret"},
        {VmOp::Add, 0, "add.a"},   {VmOp::Add, 1, "add.b"},
        {VmOp::Sub, 0, "sub.a"},   {VmOp::Sub, 1, "sub.b"},
        {VmOp::Xor, 0, "xor.a"},   {VmOp::Xor, 1, "xor.b"},
        {VmOp::And, 0, "and.a"},   {VmOp::And, 1, "and.b"},
        {VmOp::Or, 0, "or.a"},     {VmOp::Or, 1, "or.b"},
        {VmOp::Mul, 0, "mul.a"},   {VmOp::Mul, 1, "mul.b"},
        {VmOp::Shl, 0, "shl.a"},   {VmOp::Shl, 1, "shl.b"},
        {VmOp::LShr, 0, "lshr.a"}, {VmOp::LShr, 1, "lshr.b"},
        {VmOp::AShr, 0, "ashr.a"}, {VmOp::AShr, 1, "ashr.b"},
        {VmOp::UDiv, 0, "udiv.a"}, {VmOp::UDiv, 1, "udiv.b"},
        {VmOp::SDiv, 0, "sdiv.a"}, {VmOp::SDiv, 1, "sdiv.b"},
        {VmOp::URem, 0, "urem.a"}, {VmOp::URem, 1, "urem.b"},
        {VmOp::SRem, 0, "srem.a"}, {VmOp::SRem, 1, "srem.b"},
        {VmOp::ICmpEQ, 0, "icmp.eq"},   {VmOp::ICmpNE, 0, "icmp.ne"},
        {VmOp::ICmpULT, 0, "icmp.ult"}, {VmOp::ICmpULE, 0, "icmp.ule"},
        {VmOp::ICmpUGT, 0, "icmp.ugt"}, {VmOp::ICmpUGE, 0, "icmp.uge"},
        {VmOp::ICmpSLT, 0, "icmp.slt"}, {VmOp::ICmpSLE, 0, "icmp.sle"},
        {VmOp::ICmpSGT, 0, "icmp.sgt"}, {VmOp::ICmpSGE, 0, "icmp.sge"},
        {VmOp::Select, 0, "select"},
    };
    shuffleSpecs(Layout.specs, Rng);
    for (std::uint32_t I = 0; I < Layout.specs.size(); ++I)
        Layout.ids[opIndex(Layout.specs[I].op)].push_back(
            static_cast<std::uint8_t>(I));
    return Layout;
}

std::uint8_t streamKey(std::uint32_t Offset, const Encoding &Enc) {
    std::uint32_t X = Offset * Enc.mul + Enc.add;
    X ^= X >> 7;
    X ^= X >> 15;
    return static_cast<std::uint8_t>(X) ^ Enc.xork;
}

Encoding makeEncoding(ir::IRRandom &Rng) {
    Encoding Enc;
    Enc.mul = static_cast<std::uint32_t>(Rng.next()) | 1u;
    Enc.add = static_cast<std::uint32_t>(Rng.next());
    Enc.xork = static_cast<std::uint8_t>(Rng.next());
    Enc.operand_key = static_cast<std::uint8_t>(Rng.next());
    Enc.imm_key = Rng.next();
    return Enc;
}

std::uint64_t encodedImm(std::uint64_t Imm, std::uint32_t Pc,
                         const Encoding &Enc) {
    return Imm ^ Enc.imm_key ^ (static_cast<std::uint64_t>(Pc) * kImmPcSalt);
}

std::vector<std::uint8_t> encodeBytecode(const Program &P,
                                         const HandlerLayout &Layout,
                                         const Encoding &Enc,
                                         ir::IRRandom &Rng) {
    std::vector<std::uint8_t> Bytes(P.code.size() * kInstrStride, 0);
    for (std::uint32_t I = 0; I < P.code.size(); ++I) {
        const VmInstr &Instr = P.code[I];
        const std::vector<std::uint8_t> &Ids = Layout.ids[opIndex(Instr.op)];
        const std::uint8_t Handler =
            Ids[Rng.range(static_cast<std::uint32_t>(Ids.size()))];
        const std::uint32_t Pc = I * kInstrStride;
        std::array<std::uint8_t, kInstrStride> Plain{};
        Plain[0] = Handler;
        Plain[1] = Instr.dst ^ Enc.operand_key;
        Plain[2] = Instr.lhs ^ Enc.operand_key;
        Plain[3] = Instr.rhs ^ Enc.operand_key;
        const std::uint64_t Imm = encodedImm(Instr.imm, Pc, Enc);
        for (unsigned B = 0; B < 8; ++B)
            Plain[4 + B] = static_cast<std::uint8_t>((Imm >> (B * 8)) & 0xFFu);
        for (unsigned B = 12; B < kInstrStride; ++B)
            Plain[B] = static_cast<std::uint8_t>(Rng.next());
        for (unsigned B = 0; B < kInstrStride; ++B)
            Bytes[Pc + B] = Plain[B] ^ streamKey(Pc + B, Enc);
    }
    return Bytes;
}

GlobalVariable *createBytecode(Module &M, ArrayRef<std::uint8_t> Bytes,
                               StringRef SourceName) {
    LLVMContext &Ctx = M.getContext();
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *ArrTy = ArrayType::get(I8, Bytes.size());
    auto *Init = ConstantDataArray::get(Ctx, Bytes);
    const std::string Name =
        std::string("morok.vm.bytecode.") + SourceName.str();
    auto *GV = new GlobalVariable(M, ArrTy, /*isConstant=*/true,
                                  GlobalValue::PrivateLinkage, Init, Name);
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    GV->setAlignment(Align(1));
    return GV;
}

void addHelperAttrs(Function *F) {
    F->setCallingConv(CallingConv::C);
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

Value *maskToWidth(Builder &B, Value *V, unsigned Width) {
    if (Width >= 64)
        return V;
    return B.CreateAnd(V, ConstantInt::get(B.getInt64Ty(), widthMask(Width)),
                       "morok.vm.mask");
}

Value *emitStreamKey(Builder &B, Value *Offset, const Encoding &Enc) {
    auto *I32 = B.getInt32Ty();
    auto *I8 = B.getInt8Ty();
    Value *X =
        B.CreateMul(Offset, ConstantInt::get(I32, Enc.mul), "morok.vm.key.mul");
    X = B.CreateAdd(X, ConstantInt::get(I32, Enc.add), "morok.vm.key.add");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I32, 7)),
                    "morok.vm.key.fold7");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I32, 15)),
                    "morok.vm.key.fold15");
    Value *K = B.CreateTrunc(X, I8, "morok.vm.key.trunc");
    return B.CreateXor(K, ConstantInt::get(I8, Enc.xork), "morok.vm.key");
}

Value *emitDecodeByte(Builder &B, GlobalVariable *Bytecode, Value *Pc,
                      std::uint32_t Field, const Encoding &Enc) {
    auto *I32 = B.getInt32Ty();
    auto *I8 = B.getInt8Ty();
    auto *ArrTy = cast<ArrayType>(Bytecode->getValueType());
    Value *Offset =
        B.CreateAdd(Pc, ConstantInt::get(I32, Field), "morok.vm.bc.off");
    Value *Ptr = B.CreateInBoundsGEP(
        ArrTy, Bytecode, {ConstantInt::get(I32, 0), Offset}, "morok.vm.bc.ptr");
    auto *EncByte = B.CreateLoad(I8, Ptr, "morok.vm.bc.enc");
    EncByte->setVolatile(true);
    EncByte->setAlignment(Align(1));
    return B.CreateXor(EncByte, emitStreamKey(B, Offset, Enc),
                       "morok.vm.bc.dec");
}

Value *emitDecodeReg(Builder &B, GlobalVariable *Bytecode, Value *Pc,
                     std::uint32_t Field, const Encoding &Enc) {
    Value *Raw = emitDecodeByte(B, Bytecode, Pc, Field, Enc);
    Value *Reg =
        B.CreateXor(Raw, ConstantInt::get(B.getInt8Ty(), Enc.operand_key),
                    "morok.vm.reg.enc");
    return B.CreateZExt(Reg, B.getInt32Ty(), "morok.vm.reg.idx");
}

Value *emitDecodeImm(Builder &B, GlobalVariable *Bytecode, Value *Pc,
                     const Encoding &Enc, unsigned Width) {
    auto *I64 = B.getInt64Ty();
    Value *Acc = ConstantInt::get(I64, 0);
    for (unsigned I = 0; I < 8; ++I) {
        Value *Byte = emitDecodeByte(B, Bytecode, Pc, 4 + I, Enc);
        Value *Wide = B.CreateZExt(Byte, I64, "morok.vm.imm.byte");
        if (I != 0)
            Wide = B.CreateShl(Wide, ConstantInt::get(I64, I * 8),
                               "morok.vm.imm.shift");
        Acc = B.CreateOr(Acc, Wide, "morok.vm.imm.pack");
    }
    Acc = B.CreateXor(Acc, ConstantInt::get(I64, Enc.imm_key),
                      "morok.vm.imm.key");
    Value *PcWide = B.CreateZExt(Pc, I64, "morok.vm.imm.pc");
    Value *Salt = B.CreateMul(PcWide, ConstantInt::get(I64, kImmPcSalt),
                              "morok.vm.imm.salt");
    Acc = B.CreateXor(Acc, Salt, "morok.vm.imm.dec");
    return maskToWidth(B, Acc, Width);
}

Value *regPtr(Builder &B, AllocaInst *Regs, ArrayType *RegsTy, Value *Idx) {
    return B.CreateInBoundsGEP(RegsTy, Regs,
                               {ConstantInt::get(B.getInt32Ty(), 0), Idx},
                               "morok.vm.reg.ptr");
}

Value *loadReg(Builder &B, AllocaInst *Regs, ArrayType *RegsTy, Value *Idx) {
    Value *Ptr = regPtr(B, Regs, RegsTy, Idx);
    auto *Load = B.CreateLoad(B.getInt64Ty(), Ptr, "morok.vm.reg.load");
    Load->setAlignment(Align(8));
    return Load;
}

void storeReg(Builder &B, AllocaInst *Regs, ArrayType *RegsTy, Value *Idx,
              Value *Val) {
    auto *Store = B.CreateStore(Val, regPtr(B, Regs, RegsTy, Idx));
    Store->setAlignment(Align(8));
}

Value *bitwiseNot(Builder &B, Value *V, const Twine &Name) {
    return B.CreateXor(V, ConstantInt::get(B.getInt64Ty(), ~0ULL), Name);
}

Value *emitBinary(Builder &B, VmOp Op, std::uint8_t Variant, Value *L, Value *R,
                  Value *Pc, unsigned Width) {
    auto *I64 = B.getInt64Ty();
    Value *Out = nullptr;
    auto signedValue = [&](Value *V, const Twine &Name) -> Value * {
        if (Width >= 64)
            return V;
        auto *Ty = IntegerType::get(B.getContext(), Width);
        return B.CreateSExt(B.CreateTrunc(V, Ty, Name + ".trunc"), I64,
                            Name + ".sext");
    };
    switch (Op) {
    case VmOp::Add:
        if (Variant == 0) {
            Out = B.CreateAdd(L, R, "morok.vm.add");
        } else {
            Value *Carry = B.CreateAnd(L, R, "morok.vm.add.carry");
            Carry = B.CreateShl(Carry, ConstantInt::get(I64, 1),
                                "morok.vm.add.carry2");
            Out = B.CreateAdd(B.CreateXor(L, R, "morok.vm.add.sum"), Carry,
                              "morok.vm.add.alt");
        }
        break;
    case VmOp::Sub:
        if (Variant == 0) {
            Out = B.CreateSub(L, R, "morok.vm.sub");
        } else {
            Value *Neg =
                B.CreateAdd(bitwiseNot(B, R, "morok.vm.sub.not"),
                            ConstantInt::get(I64, 1), "morok.vm.sub.neg");
            Out = B.CreateAdd(L, Neg, "morok.vm.sub.alt");
        }
        break;
    case VmOp::Xor:
        if (Variant == 0) {
            Out = B.CreateXor(L, R, "morok.vm.xor");
        } else {
            Value *Both = B.CreateAnd(L, R, "morok.vm.xor.both");
            Value *Either = B.CreateOr(L, R, "morok.vm.xor.either");
            Out = B.CreateAnd(Either, bitwiseNot(B, Both, "morok.vm.xor.not"),
                              "morok.vm.xor.alt");
        }
        break;
    case VmOp::And:
        if (Variant == 0) {
            Out = B.CreateAnd(L, R, "morok.vm.and");
        } else {
            Value *NL = bitwiseNot(B, L, "morok.vm.and.nl");
            Value *NR = bitwiseNot(B, R, "morok.vm.and.nr");
            Out = bitwiseNot(B, B.CreateOr(NL, NR, "morok.vm.and.demorgan"),
                             "morok.vm.and.alt");
        }
        break;
    case VmOp::Or:
        if (Variant == 0) {
            Out = B.CreateOr(L, R, "morok.vm.or");
        } else {
            Value *NL = bitwiseNot(B, L, "morok.vm.or.nl");
            Value *NR = bitwiseNot(B, R, "morok.vm.or.nr");
            Out = bitwiseNot(B, B.CreateAnd(NL, NR, "morok.vm.or.demorgan"),
                             "morok.vm.or.alt");
        }
        break;
    case VmOp::Mul:
        Out = B.CreateMul(L, R,
                          Variant == 0 ? "morok.vm.mul" : "morok.vm.mul.alt");
        break;
    case VmOp::Shl:
        Out = B.CreateShl(L, R,
                          Variant == 0 ? "morok.vm.shl" : "morok.vm.shl.alt");
        break;
    case VmOp::LShr:
        Out = B.CreateLShr(
            L, R, Variant == 0 ? "morok.vm.lshr" : "morok.vm.lshr.alt");
        break;
    case VmOp::AShr: {
        Value *Signed = signedValue(L, "morok.vm.ashr");
        Out = B.CreateAShr(
            Signed, R, Variant == 0 ? "morok.vm.ashr" : "morok.vm.ashr.alt");
        break;
    }
    case VmOp::UDiv:
        Out = B.CreateUDiv(
            L, R, Variant == 0 ? "morok.vm.udiv" : "morok.vm.udiv.alt");
        break;
    case VmOp::SDiv:
        Out = B.CreateSDiv(
            signedValue(L, "morok.vm.sdiv.l"), signedValue(R, "morok.vm.sdiv.r"),
            Variant == 0 ? "morok.vm.sdiv" : "morok.vm.sdiv.alt");
        break;
    case VmOp::URem:
        Out = B.CreateURem(
            L, R, Variant == 0 ? "morok.vm.urem" : "morok.vm.urem.alt");
        break;
    case VmOp::SRem:
        Out = B.CreateSRem(
            signedValue(L, "morok.vm.srem.l"), signedValue(R, "morok.vm.srem.r"),
            Variant == 0 ? "morok.vm.srem" : "morok.vm.srem.alt");
        break;
    case VmOp::ICmpEQ:
        Out = B.CreateZExt(B.CreateICmpEQ(L, R, "morok.vm.icmp.eq"), I64,
                           "morok.vm.icmp.zext");
        break;
    case VmOp::ICmpNE:
        Out = B.CreateZExt(B.CreateICmpNE(L, R, "morok.vm.icmp.ne"), I64,
                           "morok.vm.icmp.zext");
        break;
    case VmOp::ICmpULT:
        Out = B.CreateZExt(B.CreateICmpULT(L, R, "morok.vm.icmp.ult"), I64,
                           "morok.vm.icmp.zext");
        break;
    case VmOp::ICmpULE:
        Out = B.CreateZExt(B.CreateICmpULE(L, R, "morok.vm.icmp.ule"), I64,
                           "morok.vm.icmp.zext");
        break;
    case VmOp::ICmpUGT:
        Out = B.CreateZExt(B.CreateICmpUGT(L, R, "morok.vm.icmp.ugt"), I64,
                           "morok.vm.icmp.zext");
        break;
    case VmOp::ICmpUGE:
        Out = B.CreateZExt(B.CreateICmpUGE(L, R, "morok.vm.icmp.uge"), I64,
                           "morok.vm.icmp.zext");
        break;
    case VmOp::ICmpSLT:
        Out = B.CreateZExt(B.CreateICmpSLT(signedValue(L, "morok.vm.icmp.l"),
                                           signedValue(R, "morok.vm.icmp.r"),
                                           "morok.vm.icmp.slt"),
                           I64, "morok.vm.icmp.zext");
        break;
    case VmOp::ICmpSLE:
        Out = B.CreateZExt(B.CreateICmpSLE(signedValue(L, "morok.vm.icmp.l"),
                                           signedValue(R, "morok.vm.icmp.r"),
                                           "morok.vm.icmp.sle"),
                           I64, "morok.vm.icmp.zext");
        break;
    case VmOp::ICmpSGT:
        Out = B.CreateZExt(B.CreateICmpSGT(signedValue(L, "morok.vm.icmp.l"),
                                           signedValue(R, "morok.vm.icmp.r"),
                                           "morok.vm.icmp.sgt"),
                           I64, "morok.vm.icmp.zext");
        break;
    case VmOp::ICmpSGE:
        Out = B.CreateZExt(B.CreateICmpSGE(signedValue(L, "morok.vm.icmp.l"),
                                           signedValue(R, "morok.vm.icmp.r"),
                                           "morok.vm.icmp.sge"),
                           I64, "morok.vm.icmp.zext");
        break;
    case VmOp::Const:
    case VmOp::Select:
    case VmOp::Ret:
    case VmOp::Count:
        Out = ConstantInt::get(I64, 0);
        break;
    }
    if (Variant != 0 &&
        (Op == VmOp::Mul || Op == VmOp::Shl || Op == VmOp::LShr ||
         Op == VmOp::AShr || Op == VmOp::UDiv || Op == VmOp::SDiv ||
         Op == VmOp::URem || Op == VmOp::SRem)) {
        Value *PcWide = B.CreateZExt(Pc, I64, "morok.vm.poly.pc");
        Value *Zero = B.CreateXor(PcWide, PcWide, "morok.vm.poly.zero");
        Out = B.CreateXor(Out, Zero, "morok.vm.poly.keep");
    }
    return maskToWidth(B, Out, Width);
}

void advancePc(Builder &B, AllocaInst *PcSlot, BasicBlock *Dispatch) {
    auto *I32 = B.getInt32Ty();
    Value *Pc = B.CreateLoad(I32, PcSlot, "morok.vm.pc.cur");
    Value *Next = B.CreateAdd(Pc, ConstantInt::get(I32, kInstrStride),
                              "morok.vm.pc.next");
    B.CreateStore(Next, PcSlot);
    B.CreateBr(Dispatch);
}

GlobalVariable *createTargetTable(Module &M, Function *Helper,
                                  ArrayRef<BasicBlock *> Blocks,
                                  StringRef SourceName) {
    LLVMContext &Ctx = M.getContext();
    auto *PtrTy = PointerType::getUnqual(Ctx);
    auto *ArrTy = ArrayType::get(PtrTy, Blocks.size());
    SmallVector<Constant *, 24> Entries;
    Entries.reserve(Blocks.size());
    for (BasicBlock *BB : Blocks)
        Entries.push_back(BlockAddress::get(Helper, BB));
    return new GlobalVariable(
        M, ArrTy, /*isConstant=*/true, GlobalValue::PrivateLinkage,
        ConstantArray::get(ArrTy, Entries),
        std::string("morok.vm.targets.") + SourceName.str());
}

Function *buildHelper(Module &M, const Program &P, GlobalVariable *Bytecode,
                      const HandlerLayout &Layout, const Encoding &Enc) {
    Function *Src = P.source;
    SmallVector<Type *, 8> Params;
    Params.reserve(Src->arg_size());
    for (Argument &Arg : Src->args())
        Params.push_back(Arg.getType());
    FunctionType *FT =
        FunctionType::get(Src->getReturnType(), Params, /*isVarArg=*/false);
    const std::string HelperName =
        std::string("morok.vm.") + Src->getName().str() + ".exec";
    Function *Helper =
        Function::Create(FT, GlobalValue::InternalLinkage, HelperName, &M);
    addHelperAttrs(Helper);

    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *PtrTy = PointerType::getUnqual(Ctx);
    auto *RegsTy = ArrayType::get(I64, P.reg_count);

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Helper);
    BasicBlock *Dispatch = BasicBlock::Create(Ctx, "morok.vm.dispatch", Helper);

    std::vector<BasicBlock *> Handlers;
    Handlers.reserve(Layout.specs.size());
    for (const HandlerSpec &Spec : Layout.specs) {
        Handlers.push_back(BasicBlock::Create(
            Ctx, std::string("morok.vm.h.") + Spec.name, Helper));
    }

    GlobalVariable *Targets =
        createTargetTable(M, Helper, Handlers, Src->getName());

    Builder EB(Entry);
    AllocaInst *Regs = EB.CreateAlloca(RegsTy, nullptr, "morok.vm.regs");
    Regs->setAlignment(Align(8));
    AllocaInst *PcSlot = EB.CreateAlloca(I32, nullptr, "morok.vm.pc");
    PcSlot->setAlignment(Align(4));
    EB.CreateStore(ConstantInt::get(I32, 0), PcSlot);

    std::uint32_t ArgIndex = 0;
    for (Argument &Arg : Helper->args()) {
        auto *ArgTy = cast<IntegerType>(Arg.getType());
        Value *Wide =
            ArgTy->getBitWidth() < 64
                ? EB.CreateZExt(&Arg, I64, "morok.vm.arg")
                : static_cast<Value *>(&Arg);
        Wide = maskToWidth(EB, Wide, P.width);
        storeReg(EB, Regs, RegsTy, ConstantInt::get(I32, ArgIndex), Wide);
        ++ArgIndex;
    }
    EB.CreateBr(Dispatch);

    Builder DB(Dispatch);
    Value *Pc = DB.CreateLoad(I32, PcSlot, "morok.vm.pc");
    Value *Op = DB.CreateZExt(emitDecodeByte(DB, Bytecode, Pc, 0, Enc), I32,
                              "morok.vm.op");
    auto *TargetsTy = cast<ArrayType>(Targets->getValueType());
    Value *Slot =
        DB.CreateInBoundsGEP(TargetsTy, Targets, {ConstantInt::get(I32, 0), Op},
                             "morok.vm.target.slot");
    Value *Target = DB.CreateLoad(PtrTy, Slot, "morok.vm.target");
    auto *IB =
        DB.CreateIndirectBr(Target, static_cast<unsigned>(Handlers.size()));
    for (BasicBlock *Handler : Handlers)
        IB->addDestination(Handler);

    for (std::size_t I = 0; I < Layout.specs.size(); ++I) {
        const HandlerSpec &Spec = Layout.specs[I];
        Builder B(Handlers[I]);
        Value *CurPc = B.CreateLoad(I32, PcSlot, "morok.vm.pc.h");

        if (Spec.op == VmOp::Const) {
            Value *Dst = emitDecodeReg(B, Bytecode, CurPc, 1, Enc);
            Value *Imm = emitDecodeImm(B, Bytecode, CurPc, Enc, P.width);
            storeReg(B, Regs, RegsTy, Dst, Imm);
            advancePc(B, PcSlot, Dispatch);
            continue;
        }

        if (Spec.op == VmOp::Ret) {
            Value *RetIdx = emitDecodeReg(B, Bytecode, CurPc, 2, Enc);
            Value *Ret = loadReg(B, Regs, RegsTy, RetIdx);
            if (P.width < 64)
                Ret = B.CreateTrunc(Ret, Src->getReturnType(),
                                    "morok.vm.ret.trunc");
            B.CreateRet(Ret);
            continue;
        }

        if (Spec.op == VmOp::Select) {
            Value *Dst = emitDecodeReg(B, Bytecode, CurPc, 1, Enc);
            Value *CondIdx = emitDecodeReg(B, Bytecode, CurPc, 2, Enc);
            Value *TrueIdx = emitDecodeReg(B, Bytecode, CurPc, 3, Enc);
            Value *FalseIdx = B.CreateTrunc(
                emitDecodeImm(B, Bytecode, CurPc, Enc, P.width), I32,
                "morok.vm.select.false.idx");
            Value *Cond = loadReg(B, Regs, RegsTy, CondIdx);
            Value *TrueVal = loadReg(B, Regs, RegsTy, TrueIdx);
            Value *FalseVal = loadReg(B, Regs, RegsTy, FalseIdx);
            Value *TakeTrue = B.CreateICmpNE(
                Cond, ConstantInt::get(I64, 0), "morok.vm.select.cond");
            Value *Out = B.CreateSelect(TakeTrue, TrueVal, FalseVal,
                                        "morok.vm.select");
            storeReg(B, Regs, RegsTy, Dst, Out);
            advancePc(B, PcSlot, Dispatch);
            continue;
        }

        Value *Dst = emitDecodeReg(B, Bytecode, CurPc, 1, Enc);
        Value *LIdx = emitDecodeReg(B, Bytecode, CurPc, 2, Enc);
        Value *RIdx = emitDecodeReg(B, Bytecode, CurPc, 3, Enc);
        Value *L = loadReg(B, Regs, RegsTy, LIdx);
        Value *R = loadReg(B, Regs, RegsTy, RIdx);
        Value *Out = emitBinary(B, Spec.op, Spec.variant, L, R, CurPc, P.width);
        storeReg(B, Regs, RegsTy, Dst, Out);
        advancePc(B, PcSlot, Dispatch);
    }

    return Helper;
}

void rewriteAsWrapper(Function &F, Function *Helper) {
    relaxMemoryAttrs(F);
    F.deleteBody();
    LLVMContext &Ctx = F.getContext();
    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", &F);
    Builder B(Entry);

    SmallVector<Value *, 8> Args;
    for (Argument &Arg : F.args())
        Args.push_back(&Arg);
    CallInst *Call =
        B.CreateCall(Helper->getFunctionType(), Helper, Args, "morok.vm.call");
    Call->setCallingConv(Helper->getCallingConv());
    B.CreateRet(Call);
}

bool materializeProgram(Module &M, Program &P, ir::IRRandom &Rng) {
    HandlerLayout Layout = makeLayout(Rng);
    Encoding Enc = makeEncoding(Rng);
    std::vector<std::uint8_t> Bytes = encodeBytecode(P, Layout, Enc, Rng);
    GlobalVariable *Bytecode = createBytecode(M, Bytes, P.source->getName());
    Function *Helper = buildHelper(M, P, Bytecode, Layout, Enc);
    rewriteAsWrapper(*P.source, Helper);
    invalidateCallerEffects(*P.source);
    return true;
}

} // namespace

bool virtualizeFunction(Function &F, const VirtualizationParams &Params,
                        ir::IRRandom &Rng) {
    if (Params.probability == 0 || Params.max_functions == 0 ||
        !Rng.chance(Params.probability))
        return false;
    std::optional<Program> P = buildProgram(F, Params);
    if (!P)
        return false;
    return materializeProgram(*F.getParent(), *P, Rng);
}

bool virtualizeModule(Module &M, const VirtualizationParams &Params,
                      ir::IRRandom &Rng) {
    if (Params.probability == 0 || Params.max_functions == 0 ||
        Params.max_instructions == 0 || Params.max_registers == 0)
        return false;

    bool Changed = false;
    std::uint32_t Lifted = 0;
    for (Function &F : M) {
        if (Lifted >= Params.max_functions)
            break;
        if (!Rng.chance(Params.probability))
            continue;
        std::optional<Program> P = buildProgram(F, Params);
        if (!P)
            continue;
        Changed |= materializeProgram(M, *P, Rng);
        ++Lifted;
    }
    return Changed;
}

PreservedAnalyses VirtualizationPass::run(Module &M, ModuleAnalysisManager &) {
    ir::IRRandom Rng(engine_);
    return virtualizeModule(M, params_, Rng) ? PreservedAnalyses::none()
                                             : PreservedAnalyses::all();
}

} // namespace morok::passes
