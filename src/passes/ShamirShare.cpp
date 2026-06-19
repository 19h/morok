// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/ShamirShare.cpp
//
// Dominator-deposited Shamir sharing for scalar integer/FP literals.  Each
// selected literal is split byte-wise in GF(2^8); entry-block deposits publish
// k shares into volatile cells, and the use-site reconstructs from those cells
// with constant Lagrange basis coefficients.  Floating literals are shared by
// raw bit pattern and bitcast back exactly.

#include "morok/passes/ShamirShare.hpp"

#include "morok/core/Galois8.hpp"
#include "morok/core/ShamirGf256.hpp"
#include "morok/ir/InstUtil.hpp"

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

using Builder = IRBuilder<NoFolder>;

bool eligibleWidth(unsigned Bits) {
    return Bits >= 1 && Bits <= 64;
}

bool supportedFloatType(Type *Ty) {
    return Ty->isHalfTy() || Ty->isBFloatTy() || Ty->isFloatTy() ||
           Ty->isDoubleTy();
}

bool isRewritableUser(const Instruction &I) {
    return isa<BinaryOperator>(I) || isa<ICmpInst>(I) || isa<FCmpInst>(I) ||
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

bool eligibleConstant(Constant *C) {
    if (auto *CI = dyn_cast<ConstantInt>(C))
        return eligibleWidth(CI->getType()->getIntegerBitWidth());
    auto *CFP = dyn_cast<ConstantFP>(C);
    if (!CFP || !supportedFloatType(CFP->getType()))
        return false;
    return eligibleWidth(CFP->getValueAPF().bitcastToAPInt().getBitWidth());
}

Constant *eligibleStoreValue(StoreInst &SI) {
    auto *C = dyn_cast<Constant>(SI.getValueOperand());
    if (!C || !eligibleConstant(C))
        return nullptr;
    return C;
}

ConstantInt *eligibleBranchCondition(BranchInst &BI) {
    if (!BI.isConditional())
        return nullptr;
    auto *C = dyn_cast<ConstantInt>(BI.getCondition());
    if (!C || !eligibleWidth(C->getType()->getIntegerBitWidth()))
        return nullptr;
    return C;
}

ConstantInt *eligibleSwitchCondition(SwitchInst &SI) {
    auto *C = dyn_cast<ConstantInt>(SI.getCondition());
    if (!C || !eligibleWidth(C->getType()->getIntegerBitWidth()))
        return nullptr;
    return C;
}

bool eligiblePhiIncoming(PHINode &PN, unsigned Incoming) {
    auto *C = dyn_cast<Constant>(PN.getIncomingValue(Incoming));
    if (!C || !eligibleConstant(C))
        return false;
    BasicBlock *Pred = PN.getIncomingBlock(Incoming);
    Instruction *Term = Pred ? Pred->getTerminator() : nullptr;
    if (!Term || Term->getNumSuccessors() == 0)
        return false;
    return Term->getNumSuccessors() == 1 || isa<BranchInst>(Term) ||
           isa<SwitchInst>(Term);
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

struct EncodedConstant {
    IntegerType *carrier_ty = nullptr;
    Type *result_ty = nullptr;
    std::uint64_t raw = 0;
};

std::optional<EncodedConstant> encodeConstant(Constant *C) {
    if (auto *CI = dyn_cast<ConstantInt>(C)) {
        auto *Ty = cast<IntegerType>(CI->getType());
        if (!eligibleWidth(Ty->getBitWidth()))
            return std::nullopt;
        return EncodedConstant{Ty, Ty, CI->getZExtValue()};
    }

    auto *CFP = dyn_cast<ConstantFP>(C);
    if (!CFP || !supportedFloatType(CFP->getType()))
        return std::nullopt;
    APInt Bits = CFP->getValueAPF().bitcastToAPInt();
    if (!eligibleWidth(Bits.getBitWidth()))
        return std::nullopt;
    auto *CarrierTy = IntegerType::get(C->getContext(), Bits.getBitWidth());
    return EncodedConstant{CarrierTy, C->getType(), Bits.getZExtValue()};
}

Value *reconstructConstant(Module &M, Instruction &User, Constant *C,
                           std::uint32_t Threshold, std::uint32_t Shares,
                           ir::IRRandom &Rng) {
    std::optional<EncodedConstant> Enc = encodeConstant(C);
    if (!Enc)
        return C;
    auto *Ty = Enc->carrier_ty;
    const unsigned Bits = Ty->getBitWidth();
    const unsigned Bytes = (Bits + 7u) / 8u;
    auto *WorkTy = Bytes == 1 ? Type::getInt8Ty(M.getContext())
                              : IntegerType::get(M.getContext(), Bytes * 8u);

    Builder B(&User);
    Function *Gf8Mul = getOrCreateGf8Mul(M);
    Value *Wide = nullptr;
    for (unsigned Byte = 0; Byte < Bytes; ++Byte) {
        const auto Secret =
            static_cast<std::uint8_t>((Enc->raw >> (Byte * 8u)) & 0xFFu);
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
        return Enc->result_ty == Ty
                   ? Wide
                   : B.CreateBitCast(Wide, Enc->result_ty,
                                     "morok.shamir.value.fp");
    Value *Narrow = B.CreateTrunc(Wide, Ty, "morok.shamir.value.trunc");
    if (Enc->result_ty == Ty)
        return Narrow;
    return B.CreateBitCast(Narrow, Enc->result_ty, "morok.shamir.value.fp");
}

} // namespace

bool shamirShareFunction(Function &F, const ShamirShareParams &Params,
                         ir::IRRandom &Rng) {
    if (F.isDeclaration() || F.getName().starts_with("morok.") ||
        Params.probability == 0 || Params.max_secrets == 0)
        return false;
    // Reconstruction splices plain calls to morok.gf8mul at the selected user
    // sites (including store-value literals).  Calls inside Windows funclet-EH
    // blocks need a ["funclet"(token)] operand bundle or the verifier rejects
    // them, so skip funclet-EH functions, mirroring the sibling passes.  No-op
    // on Itanium (macOS/Linux).
    if (ir::usesFuncletEH(F))
        return false;

    Module &M = *F.getParent();
    const std::uint32_t Threshold =
        std::max<std::uint32_t>(Params.threshold, core::shamir::kMinThreshold);
    const std::uint32_t Shares = std::clamp<std::uint32_t>(
        Params.shares, Threshold, core::shamir::kMaxShares);

    struct Target {
        Instruction *user = nullptr;
        unsigned index = 0;
        Constant *value = nullptr;
        bool phi_incoming = false;
        BasicBlock *incoming_block = nullptr;
    };
    std::vector<Target> Targets;
    for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
            if (auto *PN = dyn_cast<PHINode>(&I)) {
                for (unsigned Op = 0; Op < PN->getNumIncomingValues(); ++Op) {
                    if (!eligiblePhiIncoming(*PN, Op))
                        continue;
                    Targets.push_back(
                        {&I, Op, cast<Constant>(PN->getIncomingValue(Op)),
                         true, PN->getIncomingBlock(Op)});
                }
            } else if (auto *CB = dyn_cast<CallBase>(&I)) {
                if (!safeCallArgs(*CB))
                    continue;
                for (unsigned Op = 0; Op < CB->arg_size(); ++Op) {
                    auto *C = dyn_cast<Constant>(CB->getArgOperand(Op));
                    if (!C)
                        continue;
                    if (eligibleConstant(C))
                        Targets.push_back({&I, Op, C});
                }
            } else if (auto *SI = dyn_cast<StoreInst>(&I)) {
                if (auto *C = eligibleStoreValue(*SI))
                    Targets.push_back({&I, 0, C});
            } else if (auto *BI = dyn_cast<BranchInst>(&I)) {
                if (auto *C = eligibleBranchCondition(*BI))
                    Targets.push_back({&I, 0, C});
            } else if (auto *SW = dyn_cast<SwitchInst>(&I)) {
                if (auto *C = eligibleSwitchCondition(*SW))
                    Targets.push_back({&I, 0, C});
            } else {
                if (!isRewritableUser(I))
                    continue;
                for (unsigned Op = 0; Op < I.getNumOperands(); ++Op) {
                    auto *C = dyn_cast<Constant>(I.getOperand(Op));
                    if (!C)
                        continue;
                    if (eligibleConstant(C))
                        Targets.push_back({&I, Op, C});
                }
            }
        }
    }
    if (Targets.empty())
        return false;

    bool Changed = false;
    std::uint32_t Count = 0;
    std::map<std::pair<BasicBlock *, BasicBlock *>, BasicBlock *> SplitEdges;
    auto insertionPoint = [&](const Target &T) -> Instruction * {
        if (!T.phi_incoming)
            return T.user;
        auto *PN = cast<PHINode>(T.user);
        BasicBlock *Succ = PN->getParent();
        BasicBlock *Pred = T.incoming_block;
        auto Key = std::make_pair(Pred, Succ);
        auto It = SplitEdges.find(Key);
        if (It != SplitEdges.end())
            return It->second->getTerminator();

        Instruction *Term = Pred ? Pred->getTerminator() : nullptr;
        if (!Term)
            return nullptr;
        if (Term->getNumSuccessors() == 1)
            return Term;
        BasicBlock *Edge =
            SplitEdge(Pred, Succ, nullptr, nullptr, nullptr,
                      "morok.shamir.phi.edge");
        if (!Edge)
            return nullptr;
        SplitEdges[Key] = Edge;
        return Edge->getTerminator();
    };

    for (const Target &T : Targets) {
        if (Count >= Params.max_secrets)
            break;
        if (!Rng.chance(Params.probability))
            continue;
        Instruction *InsertBefore = insertionPoint(T);
        if (!InsertBefore)
            continue;
        Value *Replacement =
            reconstructConstant(M, *InsertBefore, T.value, Threshold, Shares,
                                Rng);
        if (T.phi_incoming) {
            auto *PN = cast<PHINode>(T.user);
            BasicBlock *Incoming = T.incoming_block;
            auto It = SplitEdges.find(std::make_pair(Incoming, PN->getParent()));
            if (It != SplitEdges.end())
                Incoming = It->second;
            const int IncomingIndex = PN->getBasicBlockIndex(Incoming);
            if (IncomingIndex < 0)
                continue;
            PN->setIncomingValue(static_cast<unsigned>(IncomingIndex),
                                 Replacement);
        } else {
            T.user->setOperand(T.index, Replacement);
        }
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
