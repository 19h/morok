// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/ShamirShare.cpp
//
// Dominator-deposited Shamir sharing for integer literals.  Each selected
// literal is split byte-wise in GF(2^8); entry-block deposits publish k shares
// into volatile cells, and the use-site reconstructs from those cells with
// constant Lagrange basis coefficients.

#include "morok/passes/ShamirShare.hpp"

#include "morok/core/Galois8.hpp"
#include "morok/core/ShamirGf256.hpp"

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"

#include <algorithm>
#include <cstdint>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

using Builder = IRBuilder<NoFolder>;

bool eligibleWidth(unsigned Bits) {
    return Bits >= 1 && Bits <= 64;
}

bool isRewritableUser(const Instruction &I) {
    return isa<BinaryOperator>(I) || isa<ICmpInst>(I) ||
           isa<SelectInst>(I) || isa<CastInst>(I) || isa<ReturnInst>(I);
}

bool safeCallArgs(const CallBase &CB) {
    if (CB.isInlineAsm() || CB.hasOperandBundles() || CB.isMustTailCall())
        return false;
    if (Function *Callee = CB.getCalledFunction())
        if (Callee->isIntrinsic())
            return false;
    return true;
}

std::uint8_t lagrangeBasisAtZero(ArrayRef<core::shamir::Share> Shares,
                                 std::size_t J) {
    const std::uint8_t Xj = Shares[J].first;
    std::uint8_t Num = 1;
    std::uint8_t Den = 1;
    for (std::size_t M = 0; M < Shares.size(); ++M) {
        if (M == J)
            continue;
        const std::uint8_t Xm = Shares[M].first;
        Num = core::gf8::mul(Num, Xm);
        Den = core::gf8::mul(Den, static_cast<std::uint8_t>(Xj ^ Xm));
    }
    return core::gf8::mul(Num, core::gf8::inv(Den));
}

Function *getOrCreateGf8Mul(Module &M) {
    if (Function *Existing = M.getFunction("morok.gf8mul"))
        return Existing;

    LLVMContext &Ctx = M.getContext();
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *FT = FunctionType::get(I8, {I8, I8}, false);
    auto *F =
        Function::Create(FT, GlobalValue::InternalLinkage, "morok.gf8mul", &M);
    F->addFnAttr(Attribute::AlwaysInline);
    F->setDSOLocal(true);

    BasicBlock *BB = BasicBlock::Create(Ctx, "entry", F);
    Builder B(BB);
    Value *A = F->getArg(0);
    Value *Bv = F->getArg(1);
    Value *Zero = ConstantInt::get(I8, 0);
    Value *R = Zero;
    for (int I = 0; I < 8; ++I) {
        Value *BitSet =
            B.CreateICmpNE(B.CreateAnd(Bv, ConstantInt::get(I8, 1)), Zero);
        R = B.CreateXor(R, B.CreateSelect(BitSet, A, Zero),
                        "morok.gf8mul.acc");
        Value *HiSet =
            B.CreateICmpNE(B.CreateAnd(A, ConstantInt::get(I8, 0x80)), Zero);
        Value *Shifted = B.CreateShl(A, ConstantInt::get(I8, 1));
        A = B.CreateXor(
            Shifted,
            B.CreateSelect(HiSet,
                           ConstantInt::get(I8, core::gf8::kReductionPoly),
                           Zero),
            "morok.gf8mul.xtime");
        Bv = B.CreateLShr(Bv, ConstantInt::get(I8, 1));
    }
    B.CreateRet(R);
    return F;
}

GlobalVariable *createShareGlobal(Module &M, std::uint8_t ShareValue) {
    auto *I8 = Type::getInt8Ty(M.getContext());
    auto *GV = new GlobalVariable(
        M, I8, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I8, ShareValue), "morok.shamir.share");
    GV->setDSOLocal(true);
    GV->setAlignment(Align(1));
    return GV;
}

GlobalVariable *createCellGlobal(Module &M) {
    auto *I8 = Type::getInt8Ty(M.getContext());
    auto *GV = new GlobalVariable(
        M, I8, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I8, 0), "morok.shamir.cell");
    GV->setDSOLocal(true);
    GV->setAlignment(Align(1));
    return GV;
}

Value *loadShare(Builder &B, GlobalVariable *GV) {
    auto *LI = B.CreateLoad(B.getInt8Ty(), GV, "morok.shamir.share.load");
    LI->setVolatile(true);
    LI->setAlignment(Align(1));
    return LI;
}

GlobalVariable *depositShare(Function &F, Module &M, std::uint8_t ShareValue) {
    GlobalVariable *Share = createShareGlobal(M, ShareValue);
    GlobalVariable *Cell = createCellGlobal(M);
    Builder B(&*F.getEntryBlock().getFirstInsertionPt());
    Value *Loaded = loadShare(B, Share);
    auto *Store = B.CreateStore(Loaded, Cell);
    Store->setVolatile(true);
    Store->setAlignment(Align(1));
    return Cell;
}

Value *loadCell(Builder &B, GlobalVariable *GV) {
    auto *LI = B.CreateLoad(B.getInt8Ty(), GV, "morok.shamir.cell.load");
    LI->setVolatile(true);
    LI->setAlignment(Align(1));
    return LI;
}

Value *reconstructByte(Function &F, Module &M, Builder &B, Function *Gf8Mul,
                       std::uint8_t Secret, std::uint32_t Threshold,
                       std::uint32_t Shares, ir::IRRandom &Rng) {
    auto AllShares = core::shamir::split(Secret, Threshold, Shares, Rng.engine());
    const std::uint32_t K =
        std::min<std::uint32_t>(Threshold, static_cast<std::uint32_t>(
                                               AllShares.size()));
    SmallVector<core::shamir::Share, 8> Used;
    for (std::uint32_t I = 0; I < K; ++I)
        Used.push_back(AllShares[I]);

    Value *Acc = nullptr;
    for (std::uint32_t I = 0; I < K; ++I) {
        GlobalVariable *Cell = depositShare(F, M, Used[I].second);
        Value *Share = loadCell(B, Cell);
        const std::uint8_t Basis = lagrangeBasisAtZero(Used, I);
        Value *Term = B.CreateCall(Gf8Mul->getFunctionType(), Gf8Mul,
                                   {Share, ConstantInt::get(B.getInt8Ty(),
                                                            Basis)},
                                   "morok.shamir.term");
        Acc = Acc ? B.CreateXor(Acc, Term, "morok.shamir.byte") : Term;
    }
    return Acc ? Acc : ConstantInt::get(B.getInt8Ty(), Secret);
}

Value *reconstructInteger(Module &M, Instruction &User, ConstantInt *C,
                          std::uint32_t Threshold, std::uint32_t Shares,
                          ir::IRRandom &Rng) {
    auto *Ty = cast<IntegerType>(C->getType());
    const unsigned Bits = Ty->getBitWidth();
    const unsigned Bytes = (Bits + 7u) / 8u;
    auto *WorkTy = Bytes == 1 ? Type::getInt8Ty(M.getContext())
                              : IntegerType::get(M.getContext(), Bytes * 8u);
    const std::uint64_t Raw = C->getZExtValue();

    Builder B(&User);
    Function *Gf8Mul = getOrCreateGf8Mul(M);
    Value *Wide = nullptr;
    for (unsigned Byte = 0; Byte < Bytes; ++Byte) {
        const auto Secret =
            static_cast<std::uint8_t>((Raw >> (Byte * 8u)) & 0xFFu);
        Value *Part8 =
            reconstructByte(*User.getFunction(), M, B, Gf8Mul, Secret,
                            Threshold, Shares, Rng);
        Value *Part = Bytes == 1 ? Part8
                                 : B.CreateZExt(Part8, WorkTy,
                                                "morok.shamir.value.byte");
        if (Byte != 0)
            Part = B.CreateShl(Part, ConstantInt::get(WorkTy, Byte * 8u),
                               "morok.shamir.value.shift");
        Wide = Wide ? B.CreateOr(Wide, Part, "morok.shamir.value") : Part;
    }
    if (!Wide)
        return C;
    if (Wide->getType() == Ty)
        return Wide;
    return B.CreateTrunc(Wide, Ty, "morok.shamir.value.trunc");
}

} // namespace

bool shamirShareFunction(Function &F, const ShamirShareParams &Params,
                         ir::IRRandom &Rng) {
    if (F.isDeclaration() || F.getName().starts_with("morok.") ||
        Params.probability == 0 || Params.max_secrets == 0)
        return false;

    Module &M = *F.getParent();
    const std::uint32_t Threshold =
        std::max<std::uint32_t>(Params.threshold, core::shamir::kMinThreshold);
    const std::uint32_t Shares = std::clamp<std::uint32_t>(
        Params.shares, Threshold, core::shamir::kMaxShares);

    struct Target {
        Instruction *user = nullptr;
        unsigned index = 0;
        ConstantInt *value = nullptr;
    };
    std::vector<Target> Targets;
    for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
            if (auto *CB = dyn_cast<CallBase>(&I)) {
                if (!safeCallArgs(*CB))
                    continue;
                for (unsigned Op = 0; Op < CB->arg_size(); ++Op) {
                    auto *C = dyn_cast<ConstantInt>(CB->getArgOperand(Op));
                    if (!C)
                        continue;
                    if (eligibleWidth(C->getType()->getIntegerBitWidth()))
                        Targets.push_back({&I, Op, C});
                }
            } else {
                if (!isRewritableUser(I))
                    continue;
                for (unsigned Op = 0; Op < I.getNumOperands(); ++Op) {
                    auto *C = dyn_cast<ConstantInt>(I.getOperand(Op));
                    if (!C)
                        continue;
                    if (eligibleWidth(C->getType()->getIntegerBitWidth()))
                        Targets.push_back({&I, Op, C});
                }
            }
        }
    }
    if (Targets.empty())
        return false;

    bool Changed = false;
    std::uint32_t Count = 0;
    for (const Target &T : Targets) {
        if (Count >= Params.max_secrets)
            break;
        if (!Rng.chance(Params.probability))
            continue;
        Value *Replacement =
            reconstructInteger(M, *T.user, T.value, Threshold, Shares, Rng);
        T.user->setOperand(T.index, Replacement);
        ++Count;
        Changed = true;
    }
    return Changed;
}

PreservedAnalyses ShamirSharePass::run(Function &F,
                                       FunctionAnalysisManager &) {
    ir::IRRandom Rng(engine_);
    return shamirShareFunction(F, params_, Rng) ? PreservedAnalyses::none()
                                                : PreservedAnalyses::all();
}

} // namespace morok::passes
