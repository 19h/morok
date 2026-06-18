// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/Virtualization.cpp
//
// An IR-level bytecode virtualizer.  Eligible functions are lifted into an
// encrypted per-function bytecode stream and an internal interpreter helper.
// The helper uses threaded computed-goto dispatch (`indirectbr` over a
// blockaddress table), duplicated arithmetic handlers, and per-byte decryption
// keyed by the VM PC; the original function becomes a native wrapper that calls
// into the VM.
//
// The lifter handles arbitrary (single- and multi-block) control flow.  Real
// CFGs are first de-SSA'd with `demoteToStack` (after critical-edge splitting),
// turning all cross-block dataflow into stack traffic and eliminating PHIs; the
// resulting per-block straight-line code, the demoted loads/stores, and the
// branch/switch terminators are then lifted into bytecode.  Branches become
// PC-jump opcodes (`Jmp`/`BrCond`) over the same dispatch loop, loops fall out
// for free once the PC is writable, and the demoted/user allocas are recreated
// as a VM-private stack arena inside the helper.
//
// Registers are a canonical 64-bit file: an integer value of width W lives as
// its zero-extension to 64 bits, a pointer as its address.  All width
// normalization (masking after wrapping ops, sign-extension before signed ops)
// is emitted explicitly into the bytecode, so the handlers are pure 64-bit and
// pointers are never truncated.

#include "morok/passes/Virtualization.hpp"

#include "morok/ir/InstUtil.hpp"
#include "morok/ir/Reg2Mem.hpp"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Support/ModRef.h"
#include "llvm/Support/TypeSize.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
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

// Bound the size of a function we are willing to demote + lift, so a giant
// function (e.g. a fully-inlined `main`) is never demoted-then-rejected (which
// would leave it in the uglier demoted form).  Functions over these bounds are
// rejected read-only, before any mutation.
constexpr std::uint32_t kMaxLiftBlocks = 192;
constexpr std::uint32_t kMaxLiftInstructions = 1200;

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
    Jmp,
    BrCond,
    Sext,
    Load8,
    Load16,
    Load32,
    Load64,
    Store8,
    Store16,
    Store32,
    Store64,
    PtrConst,
    Call,
    Count,
};

struct VmInstr {
    VmOp op = VmOp::Ret;
    std::uint8_t dst = 0;
    std::uint8_t lhs = 0;
    std::uint8_t rhs = 0;
    std::uint64_t imm = 0;
};

enum class RetKind { Void, Int, Ptr };

struct AllocaSpec {
    Type *type = nullptr;
    std::uint64_t num_elements = 1;
    Align align{1};
    std::uint8_t reg = 0;
};

// A lifted call.  Everything is fixed at lift time and baked into a dedicated
// per-call-site handler, so the bytecode Call instruction only has to select
// that handler (no operands) — which sidesteps the 3-register-field limit on
// arbitrary argument counts.
struct CallSite {
    FunctionType *fn_ty = nullptr;
    Value *direct = nullptr;        // non-null: direct call/inline asm target
    std::uint8_t callee_reg = 0;    // indirect: register holding the fn pointer
    bool indirect = false;
    CallingConv::ID cc = CallingConv::C;
    std::vector<std::uint8_t> args; // argument registers (canonical)
    bool has_result = false;
    std::uint8_t result_reg = 0;
};

struct Program {
    Function *source = nullptr;
    RetKind ret_kind = RetKind::Int;
    std::uint32_t reg_count = 0;
    std::uint32_t num_args = 0;
    std::vector<VmInstr> code;
    std::vector<AllocaSpec> allocas;
    std::vector<CallSite> calls;
    std::vector<Constant *> pointer_constants;
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

bool generatedProtectionFunction(const Function &F) {
    StringRef Name = F.getName();
    // Keep fault/page-protection choreography native; VM lifting can disturb
    // the exact signal and mprotect edge these probes rely on.
    if (Name == "morok.antihook" ||
        Name.starts_with("morok.antihook.clean.") ||
        Name.starts_with("morok.antihook.elf.") ||
        Name.starts_with("morok.antihook.got.") ||
        Name.starts_with("morok.antihook.mac.") ||
        Name.starts_with("morok.antihook.schro") ||
        Name.starts_with("morok.antihook.antidump"))
        return false;
    // Generated protection helpers are already hardened natively by the
    // scheduler.  Lifting startup checkers into the threaded VM makes normal
    // launches pay interpreter cost before user code runs, and can perturb
    // timing/trap probes enough to trip the very checks they implement.
    return false;
}

bool candidateFunctionAllowed(const Function &F,
                              const VirtualizationParams &Params) {
    if (Params.protection_helpers_only)
        return Params.include_protection_helpers &&
               generatedProtectionFunction(F);
    if (!generatedFunction(F))
        return true;
    return Params.include_protection_helpers && generatedProtectionFunction(F);
}

bool hasNaturalLoop(Function &F) {
    DominatorTree DT(F);
    for (BasicBlock &BB : F)
        for (BasicBlock *Succ : successors(&BB))
            if (DT.dominates(Succ, &BB))
                return true;
    return false;
}

bool hasRuntimeUsers(const Function &F) {
    for (const User *U : F.users()) {
        if (isa<CallBase>(U))
            return true;
        if (isa<GlobalValue>(U) || isa<ConstantExpr>(U))
            return true;
    }
    return false;
}

bool loopLikelyHot(Function &F) {
    if (generatedProtectionFunction(F))
        return false;
    if (!hasNaturalLoop(F))
        return false;
    return F.getName() == "main" || hasRuntimeUsers(F);
}

std::uint64_t widthMask(unsigned Width) {
    return Width >= 64 ? ~0ULL : ((1ULL << Width) - 1ULL);
}

bool isPtrAS0(Type *T) {
    auto *P = dyn_cast<PointerType>(T);
    return P && P->getAddressSpace() == 0;
}

// A lift-able integer is one whose width also has a fixed load/store handler:
// any value can escape its block and get demoted to a stack slot, so every
// integer the lifter accepts must be storable.  This keeps demotion from ever
// producing an alloca the memory ops cannot service.
bool isVmIntTy(Type *T) {
    auto *I = dyn_cast<IntegerType>(T);
    if (!I)
        return false;
    switch (I->getBitWidth()) {
    case 1:
    case 8:
    case 16:
    case 32:
    case 64:
        return true;
    default:
        return false;
    }
}

bool isScalarVmTy(Type *T) { return isVmIntTy(T) || isPtrAS0(T); }

// Byte size of a load/store access; only the {1,2,4,8}-byte accesses have a
// fixed handler, so other widths make the function ineligible.
std::optional<unsigned> accessBytes(Type *T) {
    if (isPtrAS0(T))
        return 8u;
    if (auto *IT = dyn_cast<IntegerType>(T)) {
        switch (IT->getBitWidth()) {
        case 1:
        case 8:
            return 1u;
        case 16:
            return 2u;
        case 32:
            return 4u;
        case 64:
            return 8u;
        default:
            return std::nullopt;
        }
    }
    return std::nullopt;
}

VmOp loadOpForBytes(unsigned Bytes) {
    switch (Bytes) {
    case 1:
        return VmOp::Load8;
    case 2:
        return VmOp::Load16;
    case 4:
        return VmOp::Load32;
    default:
        return VmOp::Load64;
    }
}

VmOp storeOpForBytes(unsigned Bytes) {
    switch (Bytes) {
    case 1:
        return VmOp::Store8;
    case 2:
        return VmOp::Store16;
    case 4:
        return VmOp::Store32;
    default:
        return VmOp::Store64;
    }
}

std::optional<VmOp> binaryOpcode(const BinaryOperator &BO) {
    // Poison-generating flags (nsw/nuw/exact) are intentionally ignored: the VM
    // emits the ordinary wrapping / non-exact operation, a sound refinement of
    // the flagged form.  Shift amounts may be variable; the handler masks the
    // count to <64, which is a valid refinement (an out-of-range shift is
    // poison, so any value is acceptable).
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
        return VmOp::Shl;
    case Instruction::LShr:
        return VmOp::LShr;
    case Instruction::AShr:
        return VmOp::AShr;
    default:
        return std::nullopt;
    }
}

std::optional<VmOp> icmpOpcode(ICmpInst::Predicate P) {
    switch (P) {
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

bool isSignedPredicate(ICmpInst::Predicate P) {
    return P == ICmpInst::ICMP_SLT || P == ICmpInst::ICMP_SLE ||
           P == ICmpInst::ICMP_SGT || P == ICmpInst::ICMP_SGE;
}

bool needsResultMask(VmOp Op) {
    // After these wrapping/signed ops the high bits above the operation width
    // may be dirty and must be re-canonicalized.  And/Or/Xor/LShr/UDiv/URem of
    // canonical operands stay canonical, so they are left unmasked.
    switch (Op) {
    case VmOp::Add:
    case VmOp::Sub:
    case VmOp::Mul:
    case VmOp::Shl:
    case VmOp::AShr:
    case VmOp::SDiv:
    case VmOp::SRem:
        return true;
    default:
        return false;
    }
}

bool isSkippableIntrinsic(const CallBase &CB) {
    const auto *II = dyn_cast<IntrinsicInst>(&CB);
    if (!II)
        return false;
    switch (II->getIntrinsicID()) {
    case Intrinsic::lifetime_start:
    case Intrinsic::lifetime_end:
    case Intrinsic::dbg_assign:
    case Intrinsic::dbg_declare:
    case Intrinsic::dbg_label:
    case Intrinsic::dbg_value:
    case Intrinsic::assume:
    case Intrinsic::donothing:
        return true;
    default:
        return false;
    }
}

// Pure scalar-integer intrinsics the lifter expands inline into existing VM ops
// (no native call, no new opcode).  Optimized code lowers idioms to these —
// rotates become fshl/fshr, min/max become smax/umin, etc. — so accepting them
// is what lets the VM lift real -O2/-O3 leaf and loop kernels (e.g. the rotate-
// heavy round functions of a crackme).
bool isLowerableIntrinsic(const CallBase &CB) {
    const auto *II = dyn_cast<IntrinsicInst>(&CB);
    if (!II)
        return false;
    switch (II->getIntrinsicID()) {
    case Intrinsic::fshl:
    case Intrinsic::fshr: {
        // Funnel shifts use a (width-1) modulo mask, so the width must be a
        // power of two — exactly {8,16,32,64} within the VM int set.
        auto *I = dyn_cast<IntegerType>(II->getType());
        if (!I)
            return false;
        switch (I->getBitWidth()) {
        case 8:
        case 16:
        case 32:
        case 64:
            return true;
        default:
            return false;
        }
    }
    case Intrinsic::smax:
    case Intrinsic::smin:
    case Intrinsic::umax:
    case Intrinsic::umin:
    case Intrinsic::abs:
        return isVmIntTy(II->getType());
    default:
        return false;
    }
}

// A generated-protection-helper call the VM can virtualize: scalar (int/ptr)
// signature, non-variadic, no by-value/sret-style aggregate ABI, and either a
// direct call to a DEFINED function, inline asm, or an indirect call through a
// value.  User functions still reject ordinary calls: lifting arbitrary call
// graphs changes too much ABI/backend surface.  Calls to external declarations
// (imports) are also gated out so a naked import call never appears inside a
// handler.  Pure intrinsics are handled elsewhere.
bool liftableCall(const CallBase &CB, bool AllowProtectionCalls,
                  bool AllowInlineAsm) {
    const auto *CI = dyn_cast<CallInst>(&CB);
    if (!CI || CI->isMustTailCall() || CI->hasOperandBundles())
        return false;
    FunctionType *FT = CB.getFunctionType();
    if (FT->isVarArg() || CB.arg_size() != FT->getNumParams())
        return false;
    Type *Ret = FT->getReturnType();
    if (!Ret->isVoidTy() && !isScalarVmTy(Ret))
        return false;
    for (Type *PT : FT->params())
        if (!isScalarVmTy(PT))
            return false;
    for (unsigned I = 0; I < CB.arg_size(); ++I)
        if (CB.paramHasAttr(I, Attribute::ByVal) ||
            CB.paramHasAttr(I, Attribute::StructRet) ||
            CB.paramHasAttr(I, Attribute::InAlloca) ||
            CB.paramHasAttr(I, Attribute::Preallocated) ||
            CB.paramHasAttr(I, Attribute::ByRef))
            return false;
    if (CI->isInlineAsm())
        return AllowInlineAsm;
    if (!AllowProtectionCalls)
        return false;
    if (const Function *Callee = CB.getCalledFunction())
        return !Callee->isDeclaration() && !Callee->isIntrinsic() &&
               !Callee->isVarArg();
    // Indirect call: the callee operand is materialized as a register at lift.
    return true;
}

// ---------------------------------------------------------------------------
// Eligibility (read-only): everything checked here guarantees the post-demotion
// build succeeds, so the lifter never mutates a function it cannot finish.
// ---------------------------------------------------------------------------

std::optional<RetKind> classifySignature(const Function &F) {
    Type *RetTy = F.getReturnType();
    RetKind RK;
    if (RetTy->isVoidTy())
        RK = RetKind::Void;
    else if (isVmIntTy(RetTy))
        RK = RetKind::Int;
    else if (isPtrAS0(RetTy))
        RK = RetKind::Ptr;
    else
        return std::nullopt;

    if (F.arg_size() > 240)
        return std::nullopt;
    for (const Argument &Arg : F.args()) {
        if (Arg.hasByValAttr() || Arg.hasStructRetAttr() ||
            Arg.hasInAllocaAttr() || Arg.hasPreallocatedAttr() ||
            Arg.hasNestAttr() || Arg.hasAttribute(Attribute::SwiftSelf) ||
            Arg.hasAttribute(Attribute::SwiftError) ||
            Arg.hasAttribute(Attribute::SwiftAsync))
            return std::nullopt;
        if (!isScalarVmTy(Arg.getType()))
            return std::nullopt;
    }
    return RK;
}

bool supportedTerminator(const Instruction &T) {
    return isa<ReturnInst>(T) || isa<BranchInst>(T) || isa<SwitchInst>(T) ||
           isa<UnreachableInst>(T);
}

bool sizedNonScalable(const DataLayout &DL, Type *T) {
    if (!T->isSized())
        return false;
    return !DL.getTypeAllocSize(T).isScalable();
}

bool liftableInstruction(const Instruction &I, const BasicBlock &Entry,
                         const DataLayout &DL, bool AllowProtectionCalls) {
    if (isa<PHINode>(I))
        return isScalarVmTy(I.getType()); // demoted to a stack slot of this type

    if (const auto *AI = dyn_cast<AllocaInst>(&I)) {
        return AI->getParent() == &Entry &&
               isa<ConstantInt>(AI->getArraySize()) &&
               sizedNonScalable(DL, AI->getAllocatedType()) &&
               AI->getType()->getAddressSpace() == 0;
    }
    if (const auto *BO = dyn_cast<BinaryOperator>(&I))
        return isVmIntTy(BO->getType()) && binaryOpcode(*BO).has_value();
    if (const auto *C = dyn_cast<ICmpInst>(&I))
        return isScalarVmTy(C->getOperand(0)->getType());
    if (isa<SExtInst>(I) || isa<ZExtInst>(I) || isa<TruncInst>(I)) {
        const auto &Cast = cast<CastInst>(I);
        return isVmIntTy(Cast.getSrcTy()) && isVmIntTy(Cast.getDestTy());
    }
    if (const auto *P2I = dyn_cast<PtrToIntInst>(&I))
        return isPtrAS0(P2I->getSrcTy()) && isVmIntTy(P2I->getDestTy());
    if (const auto *I2P = dyn_cast<IntToPtrInst>(&I))
        return isVmIntTy(I2P->getSrcTy()) && isPtrAS0(I2P->getDestTy());
    if (const auto *S = dyn_cast<SelectInst>(&I))
        return S->getCondition()->getType()->isIntegerTy(1) &&
               isScalarVmTy(S->getType());
    if (const auto *L = dyn_cast<LoadInst>(&I))
        return !L->isAtomic() && isPtrAS0(L->getPointerOperandType()) &&
               accessBytes(L->getType()).has_value();
    if (const auto *St = dyn_cast<StoreInst>(&I))
        return !St->isAtomic() && isPtrAS0(St->getPointerOperandType()) &&
               accessBytes(St->getValueOperand()->getType()).has_value();
    if (const auto *G = dyn_cast<GetElementPtrInst>(&I)) {
        if (!isPtrAS0(G->getType()) ||
            !isPtrAS0(G->getPointerOperandType()))
            return false;
        for (auto GTI = gep_type_begin(G), GTE = gep_type_end(G); GTI != GTE;
             ++GTI) {
            if (StructType *STy = GTI.getStructTypeOrNull()) {
                (void)STy;
                continue; // constant field index, handled at lift time
            }
            if (DL.getTypeAllocSize(GTI.getIndexedType()).isScalable())
                return false;
        }
        return true;
    }
    if (const auto *Fr = dyn_cast<FreezeInst>(&I))
        return isScalarVmTy(Fr->getType());
    if (const auto *CB = dyn_cast<CallBase>(&I))
        return isSkippableIntrinsic(*CB) || isLowerableIntrinsic(*CB) ||
               liftableCall(*CB, AllowProtectionCalls,
                            /*AllowInlineAsm=*/AllowProtectionCalls);
    return false;
}

bool isEligible(Function &F, const VirtualizationParams &Params) {
    if (F.isDeclaration() || !candidateFunctionAllowed(F, Params) ||
        F.hasPersonalityFn() || ir::usesFuncletEH(F))
        return false;
    if (Params.max_instructions == 0 || Params.max_registers == 0)
        return false;
    if (!classifySignature(F))
        return false;
    if (!generatedFunction(F) && loopLikelyHot(F))
        return false;
    if (F.size() > kMaxLiftBlocks)
        return false;

    const DataLayout &DL = F.getParent()->getDataLayout();
    const BasicBlock &Entry = F.getEntryBlock();
    const bool AllowProtectionCalls =
        Params.include_protection_helpers && generatedProtectionFunction(F);
    std::uint32_t Instructions = 0;
    // Coarse pre-estimate of the post-demotion register arena (every value used
    // across blocks or by a PHI becomes a stack slot).  Reject if it cannot fit
    // alongside the args, so we never demote a function we must then reject.
    std::uint32_t ArgsAndArena = static_cast<std::uint32_t>(F.arg_size());
    for (const BasicBlock &BB : F) {
        if (!supportedTerminator(*BB.getTerminator()))
            return false;
        for (const Instruction &I : BB) {
            if (I.isTerminator())
                continue;
            if (!liftableInstruction(I, Entry, DL, AllowProtectionCalls))
                return false;
            if (++Instructions > kMaxLiftInstructions)
                return false;
            if (isa<PHINode>(I) || isa<AllocaInst>(&I) ||
                I.isUsedOutsideOfBlock(&BB))
                ++ArgsAndArena;
        }
    }
    // The args and the demotion arena take fixed registers below the per-block
    // scratch base; if they alone cannot fit, the function is hopeless and must
    // be rejected before we demote it.  (Scratch-register overflow inside a
    // block is handled later by a graceful build bail-out.)
    if (ArgsAndArena >= std::min<std::uint32_t>(Params.max_registers, 256))
        return false;
    return true;
}

void prepareFunction(Function &F) {
    // PHI demotion writes incoming values into predecessor terminators; a
    // critical edge would route a write down the wrong path, so split first.
    SplitAllCriticalEdges(F);
    ir::demoteToStack(F);
}

// ---------------------------------------------------------------------------
// Lifter: walks the de-SSA'd function and emits the canonical-64 bytecode.
// ---------------------------------------------------------------------------

class Lifter {
public:
    Lifter(Function &F, const VirtualizationParams &Params)
        : F_(F), Params_(Params), DL_(F.getParent()->getDataLayout()) {}

    std::optional<Program> run();

private:
    Function &F_;
    const VirtualizationParams &Params_;
    const DataLayout &DL_;
    Program P_;
    DenseMap<const Value *, std::uint8_t> Fixed_; // args + alloca addresses
    DenseMap<const Value *, std::uint8_t> Local_; // per-block scratch / consts
    DenseMap<Constant *, std::uint32_t> PointerConstantIds_;
    std::uint32_t Base_ = 0;
    std::uint32_t LocalNext_ = 0;
    std::uint32_t MaxReg_ = 0;
    DenseMap<const BasicBlock *, std::uint32_t> BlockStart_;

    struct Fixup {
        std::uint32_t op_index = 0;
        const BasicBlock *taken = nullptr;
        const BasicBlock *not_taken = nullptr; // null => static
        std::uint32_t not_taken_static = 0;
    };
    std::vector<Fixup> Fixups_;

    std::uint32_t regLimit() const {
        return std::min<std::uint32_t>(Params_.max_registers, 256);
    }

    std::optional<std::uint8_t> newLocalReg() {
        if (LocalNext_ >= regLimit())
            return std::nullopt;
        auto R = static_cast<std::uint8_t>(LocalNext_++);
        MaxReg_ = std::max(MaxReg_, LocalNext_);
        return R;
    }

    bool emit(const VmInstr &I) {
        if (P_.code.size() >= Params_.max_instructions)
            return false;
        P_.code.push_back(I);
        return true;
    }

    std::optional<std::uint8_t> materializeImm(std::uint64_t Imm,
                                               unsigned Width) {
        auto R = newLocalReg();
        if (!R)
            return std::nullopt;
        if (!emit({VmOp::Const, *R, 0, 0, Imm & widthMask(Width)}))
            return std::nullopt;
        return R;
    }

    std::uint32_t pointerConstantId(Constant *C) {
        auto It = PointerConstantIds_.find(C);
        if (It != PointerConstantIds_.end())
            return It->second;
        const auto Id = static_cast<std::uint32_t>(P_.pointer_constants.size());
        PointerConstantIds_[C] = Id;
        P_.pointer_constants.push_back(C);
        return Id;
    }

    std::optional<std::uint8_t> materializePointerConstant(Constant *C) {
        if (!isPtrAS0(C->getType()))
            return std::nullopt;
        auto R = newLocalReg();
        if (!R)
            return std::nullopt;
        if (!emit({VmOp::PtrConst, *R, 0, 0, pointerConstantId(C)}))
            return std::nullopt;
        return R;
    }

    std::optional<std::uint8_t> materialize(Value *V) {
        if (auto It = Fixed_.find(V); It != Fixed_.end())
            return It->second;
        if (auto It = Local_.find(V); It != Local_.end())
            return It->second;
        if (auto *CI = dyn_cast<ConstantInt>(V)) {
            if (CI->getBitWidth() > 64)
                return std::nullopt;
            auto R = materializeImm(CI->getZExtValue(), CI->getBitWidth());
            if (R)
                Local_[V] = *R;
            return R;
        }
        if (isa<ConstantPointerNull>(V) || isa<UndefValue>(V)) {
            auto R = materializeImm(0, 64);
            if (R)
                Local_[V] = *R;
            return R;
        }
        if (auto *C = dyn_cast<Constant>(V)) {
            auto R = materializePointerConstant(C);
            if (R)
                Local_[V] = *R;
            return R;
        }
        return std::nullopt;
    }

    // Sign-extend a canonical-W value to a full signed 64-bit value.
    std::optional<std::uint8_t> sext64(std::uint8_t Reg, unsigned Width) {
        if (Width >= 64)
            return Reg;
        auto D = newLocalReg();
        if (!D)
            return std::nullopt;
        if (!emit({VmOp::Sext, *D, Reg, 0, Width}))
            return std::nullopt;
        return D;
    }

    // Re-canonicalize a value to width W (zero the bits at/above W).
    std::optional<std::uint8_t> maskTo(std::uint8_t Reg, unsigned Width) {
        if (Width >= 64)
            return Reg;
        auto M = materializeImm(widthMask(Width), 64);
        if (!M)
            return std::nullopt;
        auto D = newLocalReg();
        if (!D)
            return std::nullopt;
        if (!emit({VmOp::And, *D, Reg, *M, 0}))
            return std::nullopt;
        return D;
    }

    std::optional<std::uint8_t> emitRaw(VmOp Op, std::uint8_t L,
                                        std::uint8_t R) {
        auto D = newLocalReg();
        if (!D)
            return std::nullopt;
        if (!emit({Op, *D, L, R, 0}))
            return std::nullopt;
        return D;
    }

    // reg & constant.
    std::optional<std::uint8_t> andConst(std::uint8_t Reg, std::uint64_t Mask) {
        auto M = materializeImm(Mask, 64);
        if (!M)
            return std::nullopt;
        return emitRaw(VmOp::And, Reg, *M);
    }

    // constant - reg.
    std::optional<std::uint8_t> subFrom(std::uint64_t K, std::uint8_t Reg) {
        auto KK = materializeImm(K, 64);
        if (!KK)
            return std::nullopt;
        return emitRaw(VmOp::Sub, *KK, Reg);
    }

    // dst = cond ? T : Fv  (cond is a canonical i1 register).
    std::optional<std::uint8_t> emitSelect(std::uint8_t Cond, std::uint8_t T,
                                           std::uint8_t Fv) {
        auto D = newLocalReg();
        if (!D)
            return std::nullopt;
        if (!emit({VmOp::Select, *D, Cond, T, Fv}))
            return std::nullopt;
        return D;
    }

    bool liftBinary(BinaryOperator &BO);
    bool liftICmp(ICmpInst &C);
    bool liftCast(Instruction &I);
    bool liftSelect(SelectInst &S);
    bool liftLoad(LoadInst &L);
    bool liftStore(StoreInst &St);
    bool liftGep(GetElementPtrInst &G);
    bool liftIntrinsic(IntrinsicInst &II);
    bool liftCall(CallInst &CI);
    bool liftInstruction(Instruction &I);
    bool liftTerminator(Instruction &T);
    bool liftBlock(BasicBlock &BB);
    void patchFixups();
};

bool Lifter::liftBinary(BinaryOperator &BO) {
    const unsigned W = BO.getType()->getIntegerBitWidth();
    VmOp Op = *binaryOpcode(BO);
    auto L = materialize(BO.getOperand(0));
    auto R = materialize(BO.getOperand(1));
    if (!L || !R)
        return false;
    const bool Signed =
        Op == VmOp::AShr || Op == VmOp::SDiv || Op == VmOp::SRem;
    if (Signed && W < 64) {
        L = sext64(*L, W);
        if (Op != VmOp::AShr) // shift count stays canonical
            R = sext64(*R, W);
        if (!L || !R)
            return false;
    }
    auto D = emitRaw(Op, *L, *R);
    if (!D)
        return false;
    if (needsResultMask(Op) && W < 64) {
        D = maskTo(*D, W);
        if (!D)
            return false;
    }
    Local_[&BO] = *D;
    return true;
}

bool Lifter::liftICmp(ICmpInst &C) {
    auto Op = icmpOpcode(C.getPredicate());
    if (!Op)
        return false;
    Type *OpTy = C.getOperand(0)->getType();
    const unsigned W = OpTy->isPointerTy() ? 64 : OpTy->getIntegerBitWidth();
    auto L = materialize(C.getOperand(0));
    auto R = materialize(C.getOperand(1));
    if (!L || !R)
        return false;
    if (isSignedPredicate(C.getPredicate()) && W < 64) {
        L = sext64(*L, W);
        R = sext64(*R, W);
        if (!L || !R)
            return false;
    }
    auto D = emitRaw(*Op, *L, *R); // handler zero-extends the i1 to canonical
    if (!D)
        return false;
    Local_[&C] = *D;
    return true;
}

bool Lifter::liftCast(Instruction &I) {
    auto Src = materialize(I.getOperand(0));
    if (!Src)
        return false;
    if (isa<ZExtInst>(I) || isa<IntToPtrInst>(I)) {
        Local_[&I] = *Src; // canonical-W reinterpreted as wider / as address
        return true;
    }
    if (isa<TruncInst>(I)) {
        auto D = maskTo(*Src, I.getType()->getIntegerBitWidth());
        if (!D)
            return false;
        Local_[&I] = *D;
        return true;
    }
    if (isa<PtrToIntInst>(I)) {
        auto D = maskTo(*Src, I.getType()->getIntegerBitWidth());
        if (!D)
            return false;
        Local_[&I] = *D;
        return true;
    }
    // SExt iW -> iV
    const unsigned SrcW = I.getOperand(0)->getType()->getIntegerBitWidth();
    const unsigned DstW = I.getType()->getIntegerBitWidth();
    auto T = sext64(*Src, SrcW);
    if (!T)
        return false;
    if (DstW < 64) {
        T = maskTo(*T, DstW);
        if (!T)
            return false;
    }
    Local_[&I] = *T;
    return true;
}

bool Lifter::liftSelect(SelectInst &S) {
    auto C = materialize(S.getCondition());
    auto T = materialize(S.getTrueValue());
    auto Fv = materialize(S.getFalseValue());
    if (!C || !T || !Fv)
        return false;
    auto D = newLocalReg();
    if (!D)
        return false;
    if (!emit({VmOp::Select, *D, *C, *T, *Fv}))
        return false;
    Local_[&S] = *D;
    return true;
}

bool Lifter::liftLoad(LoadInst &L) {
    auto Addr = materialize(L.getPointerOperand());
    if (!Addr)
        return false;
    auto Bytes = accessBytes(L.getType());
    if (!Bytes)
        return false;
    auto D = newLocalReg();
    if (!D)
        return false;
    if (!emit({loadOpForBytes(*Bytes), *D, *Addr, 0, 0}))
        return false;
    Local_[&L] = *D;
    return true;
}

bool Lifter::liftStore(StoreInst &St) {
    auto Addr = materialize(St.getPointerOperand());
    auto Val = materialize(St.getValueOperand());
    if (!Addr || !Val)
        return false;
    auto Bytes = accessBytes(St.getValueOperand()->getType());
    if (!Bytes)
        return false;
    return emit({storeOpForBytes(*Bytes), 0, *Addr, *Val, 0});
}

bool Lifter::liftGep(GetElementPtrInst &G) {
    auto Acc = materialize(G.getPointerOperand());
    if (!Acc)
        return false;
    std::int64_t ConstOff = 0;
    auto GTI = gep_type_begin(G);
    for (unsigned I = 1, E = G.getNumOperands(); I < E; ++I, ++GTI) {
        Value *Idx = G.getOperand(I);
        if (StructType *STy = GTI.getStructTypeOrNull()) {
            auto *CI = dyn_cast<ConstantInt>(Idx);
            if (!CI)
                return false;
            ConstOff += static_cast<std::int64_t>(
                DL_.getStructLayout(STy)->getElementOffset(
                    static_cast<unsigned>(CI->getZExtValue())));
            continue;
        }
        TypeSize TS = DL_.getTypeAllocSize(GTI.getIndexedType());
        if (TS.isScalable())
            return false;
        const std::uint64_t Stride = TS.getFixedValue();
        if (auto *CI = dyn_cast<ConstantInt>(Idx)) {
            ConstOff += CI->getSExtValue() * static_cast<std::int64_t>(Stride);
            continue;
        }
        const unsigned IdxW = Idx->getType()->getIntegerBitWidth();
        auto IdxReg = materialize(Idx);
        if (!IdxReg)
            return false;
        auto Sx = sext64(*IdxReg, IdxW);
        if (!Sx)
            return false;
        auto StrideReg = materializeImm(Stride, 64);
        if (!StrideReg)
            return false;
        auto Term = emitRaw(VmOp::Mul, *Sx, *StrideReg);
        if (!Term)
            return false;
        auto Next = emitRaw(VmOp::Add, *Acc, *Term);
        if (!Next)
            return false;
        Acc = Next;
    }
    if (ConstOff != 0) {
        auto OffReg = materializeImm(static_cast<std::uint64_t>(ConstOff), 64);
        if (!OffReg)
            return false;
        auto Next = emitRaw(VmOp::Add, *Acc, *OffReg);
        if (!Next)
            return false;
        Acc = Next;
    }
    Local_[&G] = *Acc;
    return true;
}

// Expand a pure scalar intrinsic into existing VM ops.  All width handling is
// explicit; results are canonical-W like every other lifted value.
bool Lifter::liftIntrinsic(IntrinsicInst &II) {
    const unsigned W = II.getType()->getIntegerBitWidth();
    const Intrinsic::ID Id = II.getIntrinsicID();

    if (Id == Intrinsic::smax || Id == Intrinsic::smin ||
        Id == Intrinsic::umax || Id == Intrinsic::umin) {
        auto A = materialize(II.getArgOperand(0));
        auto B = materialize(II.getArgOperand(1));
        if (!A || !B)
            return false;
        const bool Signed = Id == Intrinsic::smax || Id == Intrinsic::smin;
        std::optional<std::uint8_t> Cmp;
        if (Signed) {
            auto SA = sext64(*A, W);
            auto SB = sext64(*B, W);
            if (!SA || !SB)
                return false;
            const VmOp P = (Id == Intrinsic::smax) ? VmOp::ICmpSGT
                                                   : VmOp::ICmpSLT;
            Cmp = emitRaw(P, *SA, *SB);
        } else {
            const VmOp P = (Id == Intrinsic::umax) ? VmOp::ICmpUGT
                                                   : VmOp::ICmpULT;
            Cmp = emitRaw(P, *A, *B);
        }
        if (!Cmp)
            return false;
        auto D = emitSelect(*Cmp, *A, *B); // cmp ? A : B
        if (!D)
            return false;
        Local_[&II] = *D;
        return true;
    }

    if (Id == Intrinsic::abs) {
        auto A = materialize(II.getArgOperand(0));
        if (!A)
            return false;
        auto SA = sext64(*A, W);
        auto Zero = materializeImm(0, 64);
        if (!SA || !Zero)
            return false;
        auto Cmp = emitRaw(VmOp::ICmpSLT, *SA, *Zero); // A <s 0
        auto NegRaw = emitRaw(VmOp::Sub, *Zero, *A);   // 0 - A
        if (!Cmp || !NegRaw)
            return false;
        auto Neg = maskTo(*NegRaw, W);
        if (!Neg)
            return false;
        auto D = emitSelect(*Cmp, *Neg, *A); // A<0 ? -A : A
        if (!D)
            return false;
        Local_[&II] = *D;
        return true;
    }

    // Funnel shifts: fshl(a,b,c) = top W bits of ((a:b) << (c mod W));
    // fshr(a,b,c) = low W bits of ((a:b) >> (c mod W)).  W is a power of two,
    // so `mod = c & (W-1)`.  The mod==0 case is selected explicitly to avoid a
    // 64-bit shift-by-64 (poison) when W==64.
    const bool Left = Id == Intrinsic::fshl;
    auto A = materialize(II.getArgOperand(0));
    auto B = materialize(II.getArgOperand(1));
    auto C = materialize(II.getArgOperand(2));
    if (!A || !B || !C)
        return false;
    auto Mod = andConst(*C, W - 1);
    auto Zero = materializeImm(0, 64);
    if (!Mod || !Zero)
        return false;
    auto IsZero = emitRaw(VmOp::ICmpEQ, *Mod, *Zero);
    if (!IsZero)
        return false;

    std::optional<std::uint8_t> Res;
    if (Left) {
        auto P1s = emitRaw(VmOp::Shl, *A, *Mod);
        auto Rsh = subFrom(W, *Mod); // W - mod
        if (!P1s || !Rsh)
            return false;
        auto P1 = maskTo(*P1s, W);
        auto P2raw = emitRaw(VmOp::LShr, *B, *Rsh);
        if (!P1 || !P2raw)
            return false;
        auto P2 = emitSelect(*IsZero, *Zero, *P2raw); // mod==0 -> 0
        if (!P2)
            return false;
        auto Or = emitRaw(VmOp::Or, *P1, *P2);
        if (!Or)
            return false;
        Res = maskTo(*Or, W);
    } else {
        auto P2 = emitRaw(VmOp::LShr, *B, *Mod); // b >> mod
        auto Lsh = subFrom(W, *Mod);             // W - mod
        if (!P2 || !Lsh)
            return false;
        auto P1s = emitRaw(VmOp::Shl, *A, *Lsh);
        if (!P1s)
            return false;
        auto P1raw = maskTo(*P1s, W);
        if (!P1raw)
            return false;
        auto P1 = emitSelect(*IsZero, *Zero, *P1raw); // mod==0 -> 0
        if (!P1)
            return false;
        auto Or = emitRaw(VmOp::Or, *P1, *P2);
        if (!Or)
            return false;
        Res = maskTo(*Or, W);
    }
    if (!Res)
        return false;
    Local_[&II] = *Res;
    return true;
}

// Record a call as a dedicated call site; the bytecode instruction only carries
// the call index (its handler bakes callee/args/result).
bool Lifter::liftCall(CallInst &CI) {
    const bool AllowProtectionCalls =
        Params_.include_protection_helpers && generatedProtectionFunction(F_);
    if (!AllowProtectionCalls)
        return false;
    if (P_.calls.size() >= 200) // bound: one dispatch handler id per call site
        return false;
    CallSite CS;
    CS.fn_ty = CI.getFunctionType();
    CS.cc = CI.getCallingConv();
    if (CI.isInlineAsm()) {
        CS.direct = CI.getCalledOperand();
    } else if (Function *Callee = CI.getCalledFunction()) {
        CS.direct = Callee;
    } else {
        auto Reg = materialize(CI.getCalledOperand());
        if (!Reg)
            return false;
        CS.indirect = true;
        CS.callee_reg = *Reg;
    }
    for (Value *Arg : CI.args()) {
        auto R = materialize(Arg);
        if (!R)
            return false;
        CS.args.push_back(*R);
    }
    if (!CI.getType()->isVoidTy()) {
        auto D = newLocalReg();
        if (!D)
            return false;
        CS.has_result = true;
        CS.result_reg = *D;
        Local_[&CI] = *D;
    }
    const std::uint32_t Idx = static_cast<std::uint32_t>(P_.calls.size());
    P_.calls.push_back(std::move(CS));
    return emit({VmOp::Call, 0, 0, 0, Idx}); // imm = call index (handler select)
}

bool Lifter::liftInstruction(Instruction &I) {
    if (isa<AllocaInst>(&I))
        return true; // arena slot already assigned in Fixed_
    if (auto *II = dyn_cast<IntrinsicInst>(&I)) {
        if (isLowerableIntrinsic(*II))
            return liftIntrinsic(*II);
        return isSkippableIntrinsic(*II); // skip; never a value source
    }
    if (auto *CI = dyn_cast<CallInst>(&I)) {
        if (isSkippableIntrinsic(*CI))
            return true;
        return liftCall(*CI);
    }
    if (auto *CB = dyn_cast<CallBase>(&I))
        return isSkippableIntrinsic(*CB); // invoke/callbr: skip-list only
    if (auto *BO = dyn_cast<BinaryOperator>(&I))
        return liftBinary(*BO);
    if (auto *C = dyn_cast<ICmpInst>(&I))
        return liftICmp(*C);
    if (isa<CastInst>(&I))
        return liftCast(I);
    if (auto *S = dyn_cast<SelectInst>(&I))
        return liftSelect(*S);
    if (auto *L = dyn_cast<LoadInst>(&I))
        return liftLoad(*L);
    if (auto *St = dyn_cast<StoreInst>(&I))
        return liftStore(*St);
    if (auto *G = dyn_cast<GetElementPtrInst>(&I))
        return liftGep(*G);
    if (auto *Fr = dyn_cast<FreezeInst>(&I)) {
        auto Src = materialize(Fr->getOperand(0));
        if (!Src)
            return false;
        Local_[Fr] = *Src;
        return true;
    }
    return false;
}

bool Lifter::liftTerminator(Instruction &T) {
    if (auto *RI = dyn_cast<ReturnInst>(&T)) {
        if (P_.ret_kind == RetKind::Void)
            return emit({VmOp::Ret, 0, 0, 0, 0});
        auto R = materialize(RI->getReturnValue());
        if (!R)
            return false;
        return emit({VmOp::Ret, 0, *R, 0, 0});
    }
    if (auto *BI = dyn_cast<BranchInst>(&T)) {
        if (BI->isUnconditional()) {
            auto Idx = static_cast<std::uint32_t>(P_.code.size());
            if (!emit({VmOp::Jmp, 0, 0, 0, 0}))
                return false;
            Fixups_.push_back({Idx, BI->getSuccessor(0), nullptr, 0});
            return true;
        }
        auto Cond = materialize(BI->getCondition());
        if (!Cond)
            return false;
        auto Idx = static_cast<std::uint32_t>(P_.code.size());
        if (!emit({VmOp::BrCond, *Cond, 0, 0, 0}))
            return false;
        Fixups_.push_back(
            {Idx, BI->getSuccessor(0), BI->getSuccessor(1), 0});
        return true;
    }
    if (auto *SI = dyn_cast<SwitchInst>(&T)) {
        Type *CondTy = SI->getCondition()->getType();
        const unsigned W = CondTy->getIntegerBitWidth();
        (void)W;
        auto Val = materialize(SI->getCondition());
        if (!Val)
            return false;
        for (auto Case : SI->cases()) {
            auto CReg = materialize(Case.getCaseValue());
            if (!CReg)
                return false;
            auto Eq = emitRaw(VmOp::ICmpEQ, *Val, *CReg);
            if (!Eq)
                return false;
            auto Idx = static_cast<std::uint32_t>(P_.code.size());
            if (!emit({VmOp::BrCond, *Eq, 0, 0, 0}))
                return false;
            Fixups_.push_back(
                {Idx, Case.getCaseSuccessor(), nullptr,
                 (Idx + 1) * kInstrStride});
        }
        auto Idx = static_cast<std::uint32_t>(P_.code.size());
        if (!emit({VmOp::Jmp, 0, 0, 0, 0}))
            return false;
        Fixups_.push_back({Idx, SI->getDefaultDest(), nullptr, 0});
        return true;
    }
    if (isa<UnreachableInst>(&T)) {
        // Never reached in defined executions; contain it as a self-loop so the
        // dispatcher always has a valid target.
        auto Idx = static_cast<std::uint32_t>(P_.code.size());
        return emit({VmOp::Jmp, 0, 0, 0, Idx * kInstrStride});
    }
    return false;
}

bool Lifter::liftBlock(BasicBlock &BB) {
    for (Instruction &I : BB) {
        if (I.isTerminator())
            return liftTerminator(I);
        if (!liftInstruction(I))
            return false;
    }
    return false; // a block must end in a terminator
}

void Lifter::patchFixups() {
    for (const Fixup &Fx : Fixups_) {
        VmInstr &Inst = P_.code[Fx.op_index];
        const std::uint64_t Taken =
            static_cast<std::uint64_t>(BlockStart_[Fx.taken]) * kInstrStride;
        if (Inst.op == VmOp::Jmp) {
            Inst.imm = Taken;
            continue;
        }
        const std::uint64_t NotTaken =
            Fx.not_taken
                ? static_cast<std::uint64_t>(BlockStart_[Fx.not_taken]) *
                      kInstrStride
                : Fx.not_taken_static;
        Inst.imm = (Taken & 0xFFFFFFFFULL) | (NotTaken << 32);
    }
}

std::optional<Program> Lifter::run() {
    P_.source = &F_;
    if (auto RK = classifySignature(F_))
        P_.ret_kind = *RK;
    else
        return std::nullopt;

    std::uint32_t Next = 0;
    const std::uint32_t Limit = regLimit();
    for (Argument &Arg : F_.args()) {
        if (Next >= Limit)
            return std::nullopt;
        Fixed_[&Arg] = static_cast<std::uint8_t>(Next++);
    }
    P_.num_args = Next;

    BasicBlock &Entry = F_.getEntryBlock();
    for (Instruction &I : Entry) {
        auto *AI = dyn_cast<AllocaInst>(&I);
        if (!AI)
            continue;
        if (Next >= Limit)
            return std::nullopt;
        auto *Count = cast<ConstantInt>(AI->getArraySize());
        AllocaSpec Spec;
        Spec.type = AI->getAllocatedType();
        Spec.num_elements = Count->getZExtValue();
        Spec.align = AI->getAlign();
        Spec.reg = static_cast<std::uint8_t>(Next++);
        Fixed_[AI] = Spec.reg;
        P_.allocas.push_back(Spec);
    }

    Base_ = Next;
    MaxReg_ = Next;
    if (Base_ >= Limit)
        return std::nullopt;

    for (BasicBlock &BB : F_) {
        Local_.clear();
        LocalNext_ = Base_;
        BlockStart_[&BB] = static_cast<std::uint32_t>(P_.code.size());
        if (!liftBlock(BB))
            return std::nullopt;
    }

    patchFixups();
    if (P_.code.empty())
        return std::nullopt;
    P_.reg_count = std::max<std::uint32_t>(MaxReg_, 1);
    return P_;
}

// ---------------------------------------------------------------------------
// Bytecode encoding (unchanged binary contract) and helper construction.
// ---------------------------------------------------------------------------

void shuffleSpecs(std::vector<HandlerSpec> &Specs, ir::IRRandom &Rng) {
    for (std::size_t I = Specs.size(); I > 1; --I) {
        const std::size_t J = Rng.range(static_cast<std::uint32_t>(I));
        std::swap(Specs[I - 1], Specs[J]);
    }
}

HandlerLayout makeLayout(ir::IRRandom &Rng, std::uint32_t NumCalls) {
    HandlerLayout Layout;
    Layout.specs = {
        {VmOp::Const, 0, "const"},  {VmOp::Ret, 0, "ret"},
        {VmOp::Add, 0, "add.a"},    {VmOp::Add, 1, "add.b"},
        {VmOp::Sub, 0, "sub.a"},    {VmOp::Sub, 1, "sub.b"},
        {VmOp::Xor, 0, "xor.a"},    {VmOp::Xor, 1, "xor.b"},
        {VmOp::And, 0, "and.a"},    {VmOp::And, 1, "and.b"},
        {VmOp::Or, 0, "or.a"},      {VmOp::Or, 1, "or.b"},
        {VmOp::Mul, 0, "mul.a"},    {VmOp::Mul, 1, "mul.b"},
        {VmOp::Shl, 0, "shl.a"},    {VmOp::Shl, 1, "shl.b"},
        {VmOp::LShr, 0, "lshr.a"},  {VmOp::LShr, 1, "lshr.b"},
        {VmOp::AShr, 0, "ashr.a"},  {VmOp::AShr, 1, "ashr.b"},
        {VmOp::UDiv, 0, "udiv.a"},  {VmOp::UDiv, 1, "udiv.b"},
        {VmOp::SDiv, 0, "sdiv.a"},  {VmOp::SDiv, 1, "sdiv.b"},
        {VmOp::URem, 0, "urem.a"},  {VmOp::URem, 1, "urem.b"},
        {VmOp::SRem, 0, "srem.a"},  {VmOp::SRem, 1, "srem.b"},
        {VmOp::ICmpEQ, 0, "icmp.eq"},   {VmOp::ICmpNE, 0, "icmp.ne"},
        {VmOp::ICmpULT, 0, "icmp.ult"}, {VmOp::ICmpULE, 0, "icmp.ule"},
        {VmOp::ICmpUGT, 0, "icmp.ugt"}, {VmOp::ICmpUGE, 0, "icmp.uge"},
        {VmOp::ICmpSLT, 0, "icmp.slt"}, {VmOp::ICmpSLE, 0, "icmp.sle"},
        {VmOp::ICmpSGT, 0, "icmp.sgt"}, {VmOp::ICmpSGE, 0, "icmp.sge"},
        {VmOp::Select, 0, "select"},
        {VmOp::Jmp, 0, "jmp.a"},    {VmOp::Jmp, 1, "jmp.b"},
        {VmOp::BrCond, 0, "br.a"},  {VmOp::BrCond, 1, "br.b"},
        {VmOp::Sext, 0, "sext.a"},  {VmOp::Sext, 1, "sext.b"},
        {VmOp::Load8, 0, "load8"},  {VmOp::Load16, 0, "load16"},
        {VmOp::Load32, 0, "load32"}, {VmOp::Load64, 0, "load64"},
        {VmOp::Store8, 0, "store8"}, {VmOp::Store16, 0, "store16"},
        {VmOp::Store32, 0, "store32"}, {VmOp::Store64, 0, "store64"},
        {VmOp::PtrConst, 0, "ptrconst"},
    };
    shuffleSpecs(Layout.specs, Rng);
    // Each call site gets its own handler, appended in order AFTER the shuffle
    // so the call-index -> handler-id mapping is stable (encoder and builder
    // must agree).  variant carries the call index.
    for (std::uint32_t I = 0; I < NumCalls; ++I)
        Layout.specs.push_back(
            {VmOp::Call, static_cast<std::uint8_t>(I),
             std::string("call.") + std::to_string(I)});
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
        // A call selects its dedicated handler by index (imm); every other op
        // picks one of its interchangeable handler variants at random.
        const std::uint8_t Handler =
            Instr.op == VmOp::Call
                ? Ids[static_cast<std::size_t>(Instr.imm)]
                : Ids[Rng.range(static_cast<std::uint32_t>(Ids.size()))];
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

// Decode the 8-byte immediate exactly: the lifter stores already-canonical
// values (constants masked to their width, branch targets as raw byte offsets),
// so no post-decode width masking is applied here.
Value *emitDecodeImm(Builder &B, GlobalVariable *Bytecode, Value *Pc,
                     const Encoding &Enc) {
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
    return B.CreateXor(Acc, Salt, "morok.vm.imm.dec");
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

// Pure 64-bit arithmetic.  All width normalization is already in the bytecode,
// so handlers never mask or sign-extend implicitly.  Shift counts are masked to
// <64 (a valid refinement of an out-of-range/poison shift).
Value *emitBinary(Builder &B, VmOp Op, std::uint8_t Variant, Value *L, Value *R,
                  Value *Pc) {
    auto *I64 = B.getInt64Ty();
    Value *Shift = B.CreateAnd(R, ConstantInt::get(I64, 63), "morok.vm.sh.amt");
    Value *Out = nullptr;
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
        Out = B.CreateShl(L, Shift,
                          Variant == 0 ? "morok.vm.shl" : "morok.vm.shl.alt");
        break;
    case VmOp::LShr:
        Out = B.CreateLShr(
            L, Shift, Variant == 0 ? "morok.vm.lshr" : "morok.vm.lshr.alt");
        break;
    case VmOp::AShr:
        Out = B.CreateAShr(
            L, Shift, Variant == 0 ? "morok.vm.ashr" : "morok.vm.ashr.alt");
        break;
    case VmOp::UDiv:
        Out = B.CreateUDiv(
            L, R, Variant == 0 ? "morok.vm.udiv" : "morok.vm.udiv.alt");
        break;
    case VmOp::SDiv:
        Out = B.CreateSDiv(
            L, R, Variant == 0 ? "morok.vm.sdiv" : "morok.vm.sdiv.alt");
        break;
    case VmOp::URem:
        Out = B.CreateURem(
            L, R, Variant == 0 ? "morok.vm.urem" : "morok.vm.urem.alt");
        break;
    case VmOp::SRem:
        Out = B.CreateSRem(
            L, R, Variant == 0 ? "morok.vm.srem" : "morok.vm.srem.alt");
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
        Out = B.CreateZExt(B.CreateICmpSLT(L, R, "morok.vm.icmp.slt"), I64,
                           "morok.vm.icmp.zext");
        break;
    case VmOp::ICmpSLE:
        Out = B.CreateZExt(B.CreateICmpSLE(L, R, "morok.vm.icmp.sle"), I64,
                           "morok.vm.icmp.zext");
        break;
    case VmOp::ICmpSGT:
        Out = B.CreateZExt(B.CreateICmpSGT(L, R, "morok.vm.icmp.sgt"), I64,
                           "morok.vm.icmp.zext");
        break;
    case VmOp::ICmpSGE:
        Out = B.CreateZExt(B.CreateICmpSGE(L, R, "morok.vm.icmp.sge"), I64,
                           "morok.vm.icmp.zext");
        break;
    default:
        Out = ConstantInt::get(I64, 0);
        break;
    }
    if (Variant != 0 &&
        (Op == VmOp::Mul || Op == VmOp::UDiv || Op == VmOp::SDiv ||
         Op == VmOp::URem || Op == VmOp::SRem)) {
        Value *PcWide = B.CreateZExt(Pc, I64, "morok.vm.poly.pc");
        Value *Zero = B.CreateXor(PcWide, PcWide, "morok.vm.poly.zero");
        Out = B.CreateXor(Out, Zero, "morok.vm.poly.keep");
    }
    return Out;
}

void advancePc(Builder &B, AllocaInst *PcSlot, BasicBlock *Dispatch) {
    auto *I32 = B.getInt32Ty();
    Value *Pc = B.CreateLoad(I32, PcSlot, "morok.vm.pc.cur");
    Value *Next = B.CreateAdd(Pc, ConstantInt::get(I32, kInstrStride),
                              "morok.vm.pc.next");
    B.CreateStore(Next, PcSlot);
    B.CreateBr(Dispatch);
}

void setPc(Builder &B, AllocaInst *PcSlot, Value *NewPc, BasicBlock *Dispatch) {
    B.CreateStore(NewPc, PcSlot);
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

GlobalVariable *createPointerTable(Module &M, ArrayRef<Constant *> Pointers,
                                   StringRef SourceName) {
    if (Pointers.empty())
        return nullptr;
    LLVMContext &Ctx = M.getContext();
    auto *PtrTy = PointerType::getUnqual(Ctx);
    auto *ArrTy = ArrayType::get(PtrTy, Pointers.size());
    SmallVector<Constant *, 16> Entries;
    Entries.reserve(Pointers.size());
    for (Constant *Ptr : Pointers)
        Entries.push_back(ConstantExpr::getPointerCast(Ptr, PtrTy));
    auto *GV = new GlobalVariable(
        M, ArrTy, /*isConstant=*/true, GlobalValue::PrivateLinkage,
        ConstantArray::get(ArrTy, Entries),
        std::string("morok.vm.ptrs.") + SourceName.str());
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    GV->setAlignment(Align(8));
    return GV;
}

// Load/store a fixed-width access against an address register.
Value *emitMemLoad(Builder &B, Value *Addr, unsigned Bytes) {
    auto *Ptr = B.CreateIntToPtr(Addr, PointerType::getUnqual(B.getContext()),
                                 "morok.vm.mem.ptr");
    Type *Ty = B.getIntNTy(Bytes * 8);
    auto *Ld = B.CreateLoad(Ty, Ptr, "morok.vm.mem.val");
    Ld->setVolatile(true);
    Ld->setAlignment(Align(1));
    return B.CreateZExt(Ld, B.getInt64Ty(), "morok.vm.mem.zext");
}

void emitMemStore(Builder &B, Value *Addr, Value *Val, unsigned Bytes) {
    auto *Ptr = B.CreateIntToPtr(Addr, PointerType::getUnqual(B.getContext()),
                                 "morok.vm.mem.ptr");
    Value *Narrow =
        Bytes == 8 ? Val
                   : B.CreateTrunc(Val, B.getIntNTy(Bytes * 8),
                                   "morok.vm.mem.trunc");
    auto *St = B.CreateStore(Narrow, Ptr);
    St->setVolatile(true);
    St->setAlignment(Align(1));
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
    for (const HandlerSpec &Spec : Layout.specs)
        Handlers.push_back(BasicBlock::Create(
            Ctx, std::string("morok.vm.h.") + Spec.name, Helper));

    GlobalVariable *Targets =
        createTargetTable(M, Helper, Handlers, Src->getName());
    GlobalVariable *PointerTable =
        createPointerTable(M, ArrayRef<Constant *>(P.pointer_constants),
                           Src->getName());

    Builder EB(Entry);
    AllocaInst *Regs = EB.CreateAlloca(RegsTy, nullptr, "morok.vm.regs");
    Regs->setAlignment(Align(8));
    AllocaInst *PcSlot = EB.CreateAlloca(I32, nullptr, "morok.vm.pc");
    PcSlot->setAlignment(Align(4));
    EB.CreateStore(ConstantInt::get(I32, 0), PcSlot);

    std::uint32_t ArgIndex = 0;
    for (Argument &Arg : Helper->args()) {
        Value *Wide = nullptr;
        if (Arg.getType()->isPointerTy())
            Wide = EB.CreatePtrToInt(&Arg, I64, "morok.vm.arg.ptr");
        else {
            auto *ArgTy = cast<IntegerType>(Arg.getType());
            Wide = ArgTy->getBitWidth() < 64
                       ? EB.CreateZExt(&Arg, I64, "morok.vm.arg")
                       : static_cast<Value *>(&Arg);
        }
        storeReg(EB, Regs, RegsTy, ConstantInt::get(I32, ArgIndex), Wide);
        ++ArgIndex;
    }
    // Recreate the source/demoted allocas as a VM-private stack arena: the
    // helper is a separate function (the source body is deleted by the wrapper
    // rewrite), so the demoted slots must live here.
    for (const AllocaSpec &Spec : P.allocas) {
        Value *Count =
            Spec.num_elements == 1
                ? nullptr
                : static_cast<Value *>(ConstantInt::get(I64, Spec.num_elements));
        auto *Slot = EB.CreateAlloca(Spec.type, Count, "morok.vm.arena");
        Slot->setAlignment(Spec.align);
        storeReg(EB, Regs, RegsTy, ConstantInt::get(I32, Spec.reg),
                 EB.CreatePtrToInt(Slot, I64, "morok.vm.arena.addr"));
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

        switch (Spec.op) {
        case VmOp::Const: {
            Value *Dst = emitDecodeReg(B, Bytecode, CurPc, 1, Enc);
            Value *Imm = emitDecodeImm(B, Bytecode, CurPc, Enc);
            storeReg(B, Regs, RegsTy, Dst, Imm);
            advancePc(B, PcSlot, Dispatch);
            continue;
        }
        case VmOp::Ret: {
            if (P.ret_kind == RetKind::Void) {
                B.CreateRetVoid();
                continue;
            }
            Value *RetIdx = emitDecodeReg(B, Bytecode, CurPc, 2, Enc);
            Value *Ret = loadReg(B, Regs, RegsTy, RetIdx);
            Type *RetTy = Src->getReturnType();
            if (P.ret_kind == RetKind::Ptr)
                B.CreateRet(B.CreateIntToPtr(Ret, RetTy, "morok.vm.ret.ptr"));
            else if (RetTy->getIntegerBitWidth() < 64)
                B.CreateRet(
                    B.CreateTrunc(Ret, RetTy, "morok.vm.ret.trunc"));
            else
                B.CreateRet(Ret);
            continue;
        }
        case VmOp::Select: {
            Value *Dst = emitDecodeReg(B, Bytecode, CurPc, 1, Enc);
            Value *CondIdx = emitDecodeReg(B, Bytecode, CurPc, 2, Enc);
            Value *TrueIdx = emitDecodeReg(B, Bytecode, CurPc, 3, Enc);
            Value *FalseIdx = B.CreateTrunc(
                emitDecodeImm(B, Bytecode, CurPc, Enc), I32,
                "morok.vm.select.false.idx");
            Value *Cond = loadReg(B, Regs, RegsTy, CondIdx);
            Value *TrueVal = loadReg(B, Regs, RegsTy, TrueIdx);
            Value *FalseVal = loadReg(B, Regs, RegsTy, FalseIdx);
            Value *TakeTrue = B.CreateICmpNE(
                Cond, ConstantInt::get(I64, 0), "morok.vm.select.cond");
            storeReg(B, Regs, RegsTy, Dst,
                     B.CreateSelect(TakeTrue, TrueVal, FalseVal,
                                    "morok.vm.select"));
            advancePc(B, PcSlot, Dispatch);
            continue;
        }
        case VmOp::Jmp: {
            Value *JmpTarget =
                B.CreateTrunc(emitDecodeImm(B, Bytecode, CurPc, Enc), I32,
                              "morok.vm.jmp.target");
            if (Spec.variant != 0) {
                Value *Zero =
                    B.CreateXor(JmpTarget, JmpTarget, "morok.vm.jmp.zero");
                JmpTarget = B.CreateAdd(JmpTarget, Zero, "morok.vm.jmp.keep");
            }
            setPc(B, PcSlot, JmpTarget, Dispatch);
            continue;
        }
        case VmOp::BrCond: {
            Value *CondIdx = emitDecodeReg(B, Bytecode, CurPc, 1, Enc);
            Value *Packed = emitDecodeImm(B, Bytecode, CurPc, Enc);
            Value *Taken =
                B.CreateTrunc(Packed, I32, "morok.vm.br.taken");
            Value *NotTaken = B.CreateTrunc(
                B.CreateLShr(Packed, ConstantInt::get(I64, 32)), I32,
                "morok.vm.br.nottaken");
            Value *Cond = loadReg(B, Regs, RegsTy, CondIdx);
            Value *Take = B.CreateICmpNE(Cond, ConstantInt::get(I64, 0),
                                         "morok.vm.br.cond");
            if (Spec.variant != 0) {
                Value *Zero = B.CreateXor(Taken, Taken, "morok.vm.br.zero");
                Taken = B.CreateAdd(Taken, Zero, "morok.vm.br.keep");
            }
            Value *Next =
                B.CreateSelect(Take, Taken, NotTaken, "morok.vm.br.next");
            setPc(B, PcSlot, Next, Dispatch);
            continue;
        }
        case VmOp::Sext: {
            Value *Dst = emitDecodeReg(B, Bytecode, CurPc, 1, Enc);
            Value *SextSrc = loadReg(B, Regs, RegsTy,
                                     emitDecodeReg(B, Bytecode, CurPc, 2, Enc));
            Value *W = emitDecodeImm(B, Bytecode, CurPc, Enc);
            Value *Sh = B.CreateAnd(
                B.CreateSub(ConstantInt::get(I64, 64), W, "morok.vm.sext.sh"),
                ConstantInt::get(I64, 63), "morok.vm.sext.sh.m");
            Value *Res = B.CreateAShr(
                B.CreateShl(SextSrc, Sh, "morok.vm.sext.shl"), Sh,
                "morok.vm.sext.ashr");
            if (Spec.variant != 0) {
                Value *Zero = B.CreateXor(W, W, "morok.vm.sext.zero");
                Res = B.CreateXor(Res, Zero, "morok.vm.sext.keep");
            }
            storeReg(B, Regs, RegsTy, Dst, Res);
            advancePc(B, PcSlot, Dispatch);
            continue;
        }
        case VmOp::Load8:
        case VmOp::Load16:
        case VmOp::Load32:
        case VmOp::Load64: {
            const unsigned Bytes = Spec.op == VmOp::Load8    ? 1
                                   : Spec.op == VmOp::Load16 ? 2
                                   : Spec.op == VmOp::Load32 ? 4
                                                             : 8;
            Value *Dst = emitDecodeReg(B, Bytecode, CurPc, 1, Enc);
            Value *Addr = loadReg(B, Regs, RegsTy,
                                  emitDecodeReg(B, Bytecode, CurPc, 2, Enc));
            storeReg(B, Regs, RegsTy, Dst, emitMemLoad(B, Addr, Bytes));
            advancePc(B, PcSlot, Dispatch);
            continue;
        }
        case VmOp::Store8:
        case VmOp::Store16:
        case VmOp::Store32:
        case VmOp::Store64: {
            const unsigned Bytes = Spec.op == VmOp::Store8    ? 1
                                   : Spec.op == VmOp::Store16 ? 2
                                   : Spec.op == VmOp::Store32 ? 4
                                                              : 8;
            Value *Addr = loadReg(B, Regs, RegsTy,
                                  emitDecodeReg(B, Bytecode, CurPc, 2, Enc));
            Value *Val = loadReg(B, Regs, RegsTy,
                                 emitDecodeReg(B, Bytecode, CurPc, 3, Enc));
            emitMemStore(B, Addr, Val, Bytes);
            advancePc(B, PcSlot, Dispatch);
            continue;
        }
        case VmOp::PtrConst: {
            Value *Dst = emitDecodeReg(B, Bytecode, CurPc, 1, Enc);
            Value *Idx =
                B.CreateTrunc(emitDecodeImm(B, Bytecode, CurPc, Enc), I32,
                              "morok.vm.ptr.idx");
            Value *Ptr = ConstantPointerNull::get(PtrTy);
            if (PointerTable) {
                auto *PtrTableTy = cast<ArrayType>(PointerTable->getValueType());
                Value *PtrSlot = B.CreateInBoundsGEP(
                    PtrTableTy, PointerTable,
                    {ConstantInt::get(I32, 0), Idx}, "morok.vm.ptr.slot");
                Ptr = B.CreateLoad(PtrTy, PtrSlot, "morok.vm.ptr.load");
            }
            storeReg(B, Regs, RegsTy, Dst,
                     B.CreatePtrToInt(Ptr, I64, "morok.vm.ptr.addr"));
            advancePc(B, PcSlot, Dispatch);
            continue;
        }
        case VmOp::Call: {
            // Per-call-site handler: callee, signature, argument registers and
            // result register are all fixed at lift time and baked in here, so
            // the bytecode instruction needs no operands.
            const CallSite &CS = P.calls[Spec.variant];
            SmallVector<Value *, 8> Args;
            for (std::uint32_t A = 0; A < CS.fn_ty->getNumParams(); ++A) {
                Value *Raw = loadReg(B, Regs, RegsTy,
                                     ConstantInt::get(I32, CS.args[A]));
                Type *PT = CS.fn_ty->getParamType(A);
                if (PT->isPointerTy())
                    Args.push_back(
                        B.CreateIntToPtr(Raw, PT, "morok.vm.call.arg"));
                else if (PT->getIntegerBitWidth() < 64)
                    Args.push_back(
                        B.CreateTrunc(Raw, PT, "morok.vm.call.arg"));
                else
                    Args.push_back(Raw);
            }
            Value *Callee =
                CS.indirect
                    ? B.CreateIntToPtr(
                          loadReg(B, Regs, RegsTy,
                                  ConstantInt::get(I32, CS.callee_reg)),
                          PtrTy, "morok.vm.call.fp")
                    : CS.direct;
            CallInst *Call = B.CreateCall(
                CS.fn_ty, Callee, Args,
                CS.fn_ty->getReturnType()->isVoidTy() ? "" : "morok.vm.call.r");
            Call->setCallingConv(CS.cc);
            if (CS.has_result) {
                Type *RT = CS.fn_ty->getReturnType();
                Value *Res =
                    RT->isPointerTy()
                        ? B.CreatePtrToInt(Call, I64, "morok.vm.call.res")
                        : (RT->getIntegerBitWidth() < 64
                               ? B.CreateZExt(Call, I64, "morok.vm.call.res")
                               : static_cast<Value *>(Call));
                storeReg(B, Regs, RegsTy, ConstantInt::get(I32, CS.result_reg),
                         Res);
            }
            advancePc(B, PcSlot, Dispatch);
            continue;
        }
        default:
            break;
        }

        // Generic binary / comparison handler.
        Value *Dst = emitDecodeReg(B, Bytecode, CurPc, 1, Enc);
        Value *LIdx = emitDecodeReg(B, Bytecode, CurPc, 2, Enc);
        Value *RIdx = emitDecodeReg(B, Bytecode, CurPc, 3, Enc);
        Value *L = loadReg(B, Regs, RegsTy, LIdx);
        Value *R = loadReg(B, Regs, RegsTy, RIdx);
        Value *Out = emitBinary(B, Spec.op, Spec.variant, L, R, CurPc);
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
    const bool Void = F.getReturnType()->isVoidTy();
    CallInst *Call = B.CreateCall(Helper->getFunctionType(), Helper, Args,
                                  Void ? "" : "morok.vm.call");
    Call->setCallingConv(Helper->getCallingConv());
    if (Void)
        B.CreateRetVoid();
    else
        B.CreateRet(Call);
}

bool materializeProgram(Module &M, Program &P, ir::IRRandom &Rng) {
    HandlerLayout Layout =
        makeLayout(Rng, static_cast<std::uint32_t>(P.calls.size()));
    Encoding Enc = makeEncoding(Rng);
    std::vector<std::uint8_t> Bytes = encodeBytecode(P, Layout, Enc, Rng);
    GlobalVariable *Bytecode = createBytecode(M, Bytes, P.source->getName());
    Function *Helper = buildHelper(M, P, Bytecode, Layout, Enc);
    rewriteAsWrapper(*P.source, Helper);
    invalidateCallerEffects(*P.source);
    return true;
}

bool liftOne(Function &F, const VirtualizationParams &Params,
             ir::IRRandom &Rng) {
    if (!isEligible(F, Params))
        return false;
    prepareFunction(F);
    Lifter L(F, Params);
    std::optional<Program> P = L.run();
    if (!P)
        return false;
    return materializeProgram(*F.getParent(), *P, Rng);
}

} // namespace

bool virtualizationWillLift(Function &F, const VirtualizationParams &Params) {
    return Params.probability != 0 && Params.max_functions != 0 &&
           isEligible(F, Params);
}

bool virtualizeFunction(Function &F, const VirtualizationParams &Params,
                        ir::IRRandom &Rng) {
    if (Params.probability == 0 || Params.max_functions == 0 ||
        !Rng.chance(Params.probability))
        return false;
    return liftOne(F, Params, Rng);
}

bool virtualizeModule(Module &M, const VirtualizationParams &Params,
                      ir::IRRandom &Rng) {
    if (Params.probability == 0 || Params.max_functions == 0 ||
        Params.max_instructions == 0 || Params.max_registers == 0)
        return false;

    // Snapshot candidate functions before any mutation: materializing a helper
    // inserts new functions into `M`, which would invalidate a live range-for
    // over the module.
    SmallVector<Function *, 32> Worklist;
    for (Function &F : M)
        if (!F.isDeclaration() && candidateFunctionAllowed(F, Params))
            Worklist.push_back(&F);

    bool Changed = false;
    std::uint32_t Lifted = 0;
    for (Function *F : Worklist) {
        if (Lifted >= Params.max_functions)
            break;
        if (!Rng.chance(Params.probability))
            continue;
        if (liftOne(*F, Params, Rng)) {
            Changed = true;
            ++Lifted;
        }
    }
    return Changed;
}

PreservedAnalyses VirtualizationPass::run(Module &M, ModuleAnalysisManager &) {
    ir::IRRandom Rng(engine_);
    return virtualizeModule(M, params_, Rng) ? PreservedAnalyses::none()
                                             : PreservedAnalyses::all();
}

} // namespace morok::passes
