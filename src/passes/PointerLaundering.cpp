// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/PointerLaundering.cpp
//
// Pointer/integer laundering targets the decompiler value layer: pointer
// operands cross an integer boundary and return through a computed byte GEP,
// while integer SSA values round-trip through a vector byte view.  Both
// rewrites preserve the bit pattern but poison simple alias/type propagation.

#include "morok/passes/PointerLaundering.hpp"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"

#include <cstdint>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr std::size_t kMaxPointerLaunderTargets = 128;
constexpr std::size_t kMaxIntegerLaunderTargets = 128;

struct PointerTarget {
    Instruction *user = nullptr;
    unsigned operandIndex = 0;
    Value *pointer = nullptr;
};

struct IntegerLaunderResult {
    Value *replacement = nullptr;
    SmallVector<Instruction *, 4> generated;
};

bool canRoundTripPointer(const DataLayout &DL, Type *ptrTy) {
    auto *PT = dyn_cast<PointerType>(ptrTy);
    if (!PT)
        return false;
    const unsigned as = PT->getAddressSpace();
    return !DL.isNonIntegralAddressSpace(as) &&
           !DL.mustNotIntroducePtrToInt(as) && !DL.mustNotIntroduceIntToPtr(as);
}

bool isPassGenerated(const Value *V) {
    if (const auto *I = dyn_cast<Instruction>(V))
        return I->getName().starts_with("morok.ptr") ||
               I->getName().starts_with("morok.int");
    return false;
}

void addPointerOperand(const DataLayout &DL, Instruction &I, unsigned index,
                       std::vector<PointerTarget> &targets) {
    if (targets.size() >= kMaxPointerLaunderTargets)
        return;
    Value *ptr = I.getOperand(index);
    if (isPassGenerated(ptr))
        return;
    if (canRoundTripPointer(DL, ptr->getType()))
        targets.push_back(PointerTarget{&I, index, ptr});
}

void collectPointerTargets(Function &F, const DataLayout &DL,
                           std::vector<PointerTarget> &targets) {
    for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
            if (targets.size() >= kMaxPointerLaunderTargets)
                break;
            if (auto *LI = dyn_cast<LoadInst>(&I)) {
                addPointerOperand(DL, I, LI->getPointerOperandIndex(), targets);
                continue;
            }
            if (auto *SI = dyn_cast<StoreInst>(&I)) {
                addPointerOperand(DL, I, SI->getPointerOperandIndex(), targets);
                continue;
            }
            if (auto *GEP = dyn_cast<GetElementPtrInst>(&I)) {
                addPointerOperand(DL, I, GEP->getPointerOperandIndex(),
                                  targets);
                continue;
            }
            if (auto *ARMW = dyn_cast<AtomicRMWInst>(&I)) {
                addPointerOperand(DL, I, ARMW->getPointerOperandIndex(),
                                  targets);
                continue;
            }
            if (auto *ACX = dyn_cast<AtomicCmpXchgInst>(&I)) {
                addPointerOperand(DL, I, ACX->getPointerOperandIndex(),
                                  targets);
                continue;
            }
            if (auto *MI = dyn_cast<MemIntrinsic>(&I)) {
                addPointerOperand(DL, I, MI->getRawDestUse().getOperandNo(),
                                  targets);
                if (auto *MT = dyn_cast<MemTransferInst>(MI))
                    addPointerOperand(
                        DL, I, MT->getRawSourceUse().getOperandNo(), targets);
                continue;
            }
        }
        if (targets.size() >= kMaxPointerLaunderTargets)
            break;
    }
}

bool canLaunderInteger(const Instruction &I) {
    if (I.isTerminator() || isa<PHINode>(I) || isa<AllocaInst>(I) ||
        isa<LandingPadInst>(I) || isa<IntrinsicInst>(I))
        return false;
    if (isPassGenerated(&I))
        return false;

    auto *Ty = dyn_cast<IntegerType>(I.getType());
    if (!Ty)
        return false;
    const unsigned bits = Ty->getBitWidth();
    return bits >= 8 && bits <= 1024 && bits % 8 == 0 && I.getNextNode();
}

void collectIntegerTargets(Function &F, std::vector<Instruction *> &targets) {
    for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
            if (targets.size() >= kMaxIntegerLaunderTargets)
                break;
            if (canLaunderInteger(I))
                targets.push_back(&I);
        }
        if (targets.size() >= kMaxIntegerLaunderTargets)
            break;
    }
}

ConstantInt *randomConstant(IntegerType *Ty, ir::IRRandom &rng) {
    return rng.constInt(Ty);
}

Value *volatileKey(Module &M, IRBuilder<NoFolder> &B, IntegerType *Ty,
                   ir::IRRandom &rng, const Twine &name) {
    auto *GV = new GlobalVariable(M, Ty, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage,
                                  randomConstant(Ty, rng), "morok.ptr.key");
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    GV->setAlignment(Align(8));
    return B.CreateLoad(Ty, GV, /*isVolatile=*/true, name);
}

Value *launderPointer(Module &M, const DataLayout &DL, Instruction &user,
                      Value *ptr, ir::IRRandom &rng) {
    auto *PtrTy = cast<PointerType>(ptr->getType());
    const unsigned as = PtrTy->getAddressSpace();
    auto *IntPtrTy = DL.getIntPtrType(M.getContext(), as);
    IRBuilder<NoFolder> B(&user);

    Value *bits = B.CreatePtrToInt(ptr, IntPtrTy, "morok.ptr.bits");
    Value *key = volatileKey(M, B, IntPtrTy, rng, "morok.ptr.key.load");
    Value *mixed = B.CreateXor(bits, key, "morok.ptr.mix");
    Value *raw = B.CreateXor(mixed, key, "morok.ptr.raw");
    Value *round = B.CreateIntToPtr(raw, PtrTy, "morok.ptr.round");

    Value *seed = volatileKey(M, B, IntPtrTy, rng, "morok.ptr.zero.seed");
    Value *zero = B.CreateSub(seed, seed, "morok.ptr.zero");
    return B.CreateGEP(B.getInt8Ty(), round, zero, "morok.ptr.gep");
}

IntegerLaunderResult launderInteger(Instruction &I) {
    auto *Ty = cast<IntegerType>(I.getType());
    const unsigned lanes = Ty->getBitWidth() / 8;
    auto *VecTy = FixedVectorType::get(Type::getInt8Ty(I.getContext()), lanes);

    IRBuilder<NoFolder> B(I.getNextNode());
    Value *bytes = B.CreateBitCast(&I, VecTy, "morok.int.bytes");

    SmallVector<int, 16> mask;
    mask.reserve(lanes);
    for (unsigned i = 0; i < lanes; ++i)
        mask.push_back(static_cast<int>(i));
    Value *shuffled = B.CreateShuffleVector(bytes, PoisonValue::get(VecTy),
                                            mask, "morok.int.shuffle");
    Value *back = B.CreateBitCast(shuffled, Ty, "morok.int.value");

    IntegerLaunderResult result;
    result.replacement = back;
    result.generated.push_back(cast<Instruction>(bytes));
    result.generated.push_back(cast<Instruction>(shuffled));
    result.generated.push_back(cast<Instruction>(back));
    return result;
}

void replaceIntegerUses(Instruction &I, const IntegerLaunderResult &result) {
    SmallPtrSet<const User *, 4> generated;
    for (Instruction *generatedInst : result.generated)
        generated.insert(generatedInst);

    I.replaceUsesWithIf(result.replacement, [&](Use &U) {
        return !generated.contains(U.getUser());
    });
}

} // namespace

bool pointerLaunderFunction(Function &F, const PointerLaunderParams &params,
                            ir::IRRandom &rng) {
    if (F.isDeclaration())
        return false;

    Module *M = F.getParent();
    if (!M)
        return false;
    const DataLayout &DL = M->getDataLayout();

    std::vector<PointerTarget> pointerTargets;
    std::vector<Instruction *> integerTargets;
    if (params.pointer_probability > 0)
        collectPointerTargets(F, DL, pointerTargets);
    if (params.integer_probability > 0)
        collectIntegerTargets(F, integerTargets);

    bool changed = false;

    for (const PointerTarget &target : pointerTargets) {
        if (!rng.chance(params.pointer_probability))
            continue;
        Value *replacement =
            launderPointer(*M, DL, *target.user, target.pointer, rng);
        target.user->setOperand(target.operandIndex, replacement);
        changed = true;
    }

    for (Instruction *I : integerTargets) {
        if (!rng.chance(params.integer_probability))
            continue;
        IntegerLaunderResult replacement = launderInteger(*I);
        replaceIntegerUses(*I, replacement);
        changed = true;
    }

    return changed;
}

PreservedAnalyses PointerLaunderingPass::run(Function &F,
                                             FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return pointerLaunderFunction(F, params_, rng) ? PreservedAnalyses::none()
                                                   : PreservedAnalyses::all();
}

} // namespace morok::passes
