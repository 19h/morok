// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/SelfChecksumConstants.cpp
//
// IR-stage self-checksum-fused constants.  Final native code-region hashes need
// post-link sizing, so this pass emits the data-flow shape and runtime hash
// stub over a private IR-owned region plus a patchable live-code window length.
// The hash result feeds values directly: there is no branch, trap, or separable
// check to NOP.  If the hashed data diverges from the expected value, selected
// constants reconstruct to corrupted values.

#include "morok/passes/SelfChecksumConstants.hpp"

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
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

using Builder = IRBuilder<NoFolder>;

constexpr std::uint64_t kPostlinkMagic = 0x4D4F524F4B534331ULL; // MOROKSC1

struct Target {
    Instruction *user = nullptr;
    unsigned index = 0;
    Constant *value = nullptr;
    bool phi_incoming = false;
    BasicBlock *incoming_block = nullptr;
};

struct EncodedConstant {
    IntegerType *carrier_ty = nullptr;
    Type *result_ty = nullptr;
    std::uint64_t raw = 0;
};

struct Runtime {
    Function *diff = nullptr;
    GlobalVariable *region = nullptr;
    GlobalVariable *expected = nullptr;
    GlobalVariable *code_size = nullptr;
    std::uint64_t expected_hash = 0;
    std::uint64_t seed = 0;
};

bool generatedFunction(const Function &F) {
    return F.getName().starts_with("morok.");
}

bool eligibleWidth(unsigned Bits) {
    return Bits >= 1 && Bits <= 64;
}

std::uint64_t widthMask(unsigned Bits) {
    return Bits >= 64 ? ~0ULL : ((1ULL << Bits) - 1ULL);
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

bool supportedFloatType(Type *Ty) {
    return Ty->isHalfTy() || Ty->isBFloatTy() || Ty->isFloatTy() ||
           Ty->isDoubleTy();
}

std::optional<EncodedConstant> encodeConstant(Constant *C) {
    if (!C)
        return std::nullopt;

    if (auto *CI = dyn_cast<ConstantInt>(C)) {
        auto *Ty = dyn_cast<IntegerType>(CI->getType());
        if (!Ty || !eligibleWidth(Ty->getBitWidth()))
            return std::nullopt;
        return EncodedConstant{Ty, Ty, CI->getZExtValue()};
    }

    auto *CFP = dyn_cast<ConstantFP>(C);
    if (!CFP || !supportedFloatType(CFP->getType()))
        return std::nullopt;

    APInt Bits = CFP->getValueAPF().bitcastToAPInt();
    if (!eligibleWidth(Bits.getBitWidth()))
        return std::nullopt;

    return EncodedConstant{IntegerType::get(C->getContext(), Bits.getBitWidth()),
                           C->getType(), Bits.getZExtValue()};
}

bool eligibleConstant(Constant *C) { return encodeConstant(C).has_value(); }

Constant *eligibleStoreValue(StoreInst &SI) {
    auto *C = dyn_cast<Constant>(SI.getValueOperand());
    if (!eligibleConstant(C))
        return nullptr;
    return C;
}

ConstantInt *eligibleBranchCondition(BranchInst &BI) {
    if (!BI.isConditional())
        return nullptr;
    auto *C = dyn_cast<ConstantInt>(BI.getCondition());
    if (!C)
        return nullptr;
    auto *Ty = dyn_cast<IntegerType>(C->getType());
    if (!Ty || !eligibleWidth(Ty->getBitWidth()))
        return nullptr;
    return C;
}

ConstantInt *eligibleSwitchCondition(SwitchInst &SI) {
    auto *C = dyn_cast<ConstantInt>(SI.getCondition());
    if (!C)
        return nullptr;
    auto *Ty = dyn_cast<IntegerType>(C->getType());
    if (!Ty || !eligibleWidth(Ty->getBitWidth()))
        return nullptr;
    return C;
}

bool eligiblePhiIncoming(PHINode &PN, unsigned Incoming) {
    auto *C = dyn_cast<Constant>(PN.getIncomingValue(Incoming));
    if (!eligibleConstant(C))
        return false;
    BasicBlock *Pred = PN.getIncomingBlock(Incoming);
    Instruction *Term = Pred ? Pred->getTerminator() : nullptr;
    if (!Term || Term->getNumSuccessors() == 0)
        return false;
    return Term->getNumSuccessors() == 1 || isa<BranchInst>(Term) ||
           isa<SwitchInst>(Term);
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

Value *emitHashStep(Builder &B, Value *H, Value *Byte) {
    auto *I64 = B.getInt64Ty();
    Value *Wide = B.CreateZExt(Byte, I64, "morok.sc.hash.byte");
    Value *X = B.CreateXor(H, Wide, "morok.sc.hash.mix");
    X = B.CreateMul(X, ConstantInt::get(I64, 0xff51afd7ed558ccdULL),
                    "morok.sc.hash.mix");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 32)),
                    "morok.sc.hash.mix");
    X = B.CreateMul(X, ConstantInt::get(I64, 0xc4ceb9fe1a85ec53ULL),
                    "morok.sc.hash.mix");
    return B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 29)),
                       "morok.sc.hash.mix");
}

std::vector<std::uint8_t> randomRegion(std::uint32_t Size, ir::IRRandom &Rng) {
    std::vector<std::uint8_t> Bytes;
    Bytes.reserve(Size);
    for (std::uint32_t I = 0; I < Size; ++I)
        Bytes.push_back(static_cast<std::uint8_t>(Rng.next()));
    return Bytes;
}

std::string suffixFor(Function &F) { return F.getName().str(); }

std::vector<Target> collectTargets(Function &F) {
    std::vector<Target> Targets;
    for (BasicBlock &BB : F)
        for (Instruction &I : BB) {
            if (auto *PN = dyn_cast<PHINode>(&I)) {
                for (unsigned Op = 0; Op < PN->getNumIncomingValues(); ++Op) {
                    if (!eligiblePhiIncoming(*PN, Op))
                        continue;
                    Targets.push_back({&I, Op,
                                       cast<Constant>(PN->getIncomingValue(Op)),
                                       true, PN->getIncomingBlock(Op)});
                }
            } else if (auto *CB = dyn_cast<CallBase>(&I)) {
                if (!safeCallArgs(*CB))
                    continue;
                for (unsigned Op = 0; Op < CB->arg_size(); ++Op) {
                    auto *C = dyn_cast<Constant>(CB->getArgOperand(Op));
                    if (!eligibleConstant(C))
                        continue;
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
                    if (!eligibleConstant(C))
                        continue;
                    Targets.push_back({&I, Op, C});
                }
            }
        }
    return Targets;
}

void shuffleTargets(std::vector<Target> &Targets, ir::IRRandom &Rng) {
    for (std::size_t I = Targets.size(); I > 1; --I) {
        const std::size_t J = Rng.range(static_cast<std::uint32_t>(I));
        std::swap(Targets[I - 1], Targets[J]);
    }
}

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
        (Twine("morok.sc.region.") + Suffix).str());
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
        (Twine("morok.sc.expected.") + Suffix).str());
    Expected->setAlignment(Align(8));
    return Expected;
}

GlobalVariable *createCodeSize(Module &M, StringRef Suffix) {
    auto *I32 = Type::getInt32Ty(M.getContext());
    auto *CodeSize = new GlobalVariable(
        M, I32, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I32, 0),
        (Twine("morok.sc.code.size.") + Suffix).str());
    CodeSize->setAlignment(Align(4));
    return CodeSize;
}

GlobalVariable *
createPostlinkManifest(Module &M, Function &Target, StringRef Suffix,
                       GlobalVariable *Region, GlobalVariable *Expected,
                       GlobalVariable *CodeSize, std::uint32_t RegionSize,
                       std::uint64_t Seed, std::uint64_t ExpectedHash) {
    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *PtrTy = PointerType::getUnqual(Ctx);
    auto *ManifestTy = StructType::get(
        Ctx, {I64, I32, PtrTy, PtrTy, I32, I64, I64, PtrTy, PtrTy});
    auto *Init = ConstantStruct::get(
        ManifestTy,
        {ConstantInt::get(I64, kPostlinkMagic), ConstantInt::get(I32, 2),
         Region, Expected, ConstantInt::get(I32, RegionSize),
         ConstantInt::get(I64, Seed), ConstantInt::get(I64, ExpectedHash),
         &Target, CodeSize});
    auto *Manifest = new GlobalVariable(
        M, ManifestTy, /*isConstant=*/true, GlobalValue::PrivateLinkage, Init,
        (Twine("morok.postlink.sc.") + Suffix).str());
    Manifest->setUnnamedAddr(GlobalValue::UnnamedAddr::None);
    Manifest->setAlignment(Align(8));
    appendToCompilerUsed(M, {Manifest});
    return Manifest;
}

Value *regionPtr(Builder &B, GlobalVariable *Region, Value *Idx) {
    auto *I32 = B.getInt32Ty();
    auto *ArrTy = cast<ArrayType>(Region->getValueType());
    return B.CreateInBoundsGEP(ArrTy, Region, {ConstantInt::get(I32, 0), Idx},
                               "morok.sc.region.ptr");
}

Value *codePtr(Builder &B, Function *Target, Value *Idx) {
    auto *I64 = B.getInt64Ty();
    Value *Base = B.CreatePtrToInt(Target, I64, "morok.sc.code.base");
    Value *Offset = B.CreateZExt(Idx, I64, "morok.sc.code.offset");
    Value *Addr = B.CreateAdd(Base, Offset, "morok.sc.code.addr");
    return B.CreateIntToPtr(Addr, PointerType::getUnqual(B.getContext()),
                            "morok.sc.code.ptr");
}

Function *createDiffFunction(Module &M, StringRef Suffix,
                             GlobalVariable *Region, GlobalVariable *Expected,
                             GlobalVariable *CodeSize, Function *Target,
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
                                (Twine("morok.sc.diff.") + Suffix).str(), &M);
    addRuntimeAttrs(Fn);

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    BasicBlock *Loop = BasicBlock::Create(Ctx, "hash", Fn);
    BasicBlock *CodeCheck = BasicBlock::Create(Ctx, "code.check", Fn);
    BasicBlock *CodeLoop = BasicBlock::Create(Ctx, "code.hash", Fn);
    BasicBlock *Exit = BasicBlock::Create(Ctx, "exit", Fn);

    Builder EB(Entry);
    EB.CreateBr(Loop);

    Builder LB(Loop);
    PHINode *I = LB.CreatePHI(I32, 2, "morok.sc.hash.i");
    PHINode *H = LB.CreatePHI(I64, 2, "morok.sc.hash");
    I->addIncoming(ConstantInt::get(I32, 0), Entry);
    H->addIncoming(ConstantInt::get(I64, Seed), Entry);
    auto *Byte =
        LB.CreateLoad(I8, regionPtr(LB, Region, I), "morok.sc.region.byte");
    Byte->setVolatile(true);
    Byte->setAlignment(Align(1));
    Value *NextH = emitHashStep(LB, H, Byte);
    Value *NextI =
        LB.CreateAdd(I, ConstantInt::get(I32, 1), "morok.sc.hash.next");
    I->addIncoming(NextI, Loop);
    H->addIncoming(NextH, Loop);
    Value *Done = LB.CreateICmpEQ(NextI, ConstantInt::get(I32, Size),
                                  "morok.sc.hash.done");
    LB.CreateCondBr(Done, CodeCheck, Loop);

    Builder CB(CodeCheck);
    auto *CodeSizeLoad =
        CB.CreateLoad(I32, CodeSize, "morok.sc.code.size.load");
    CodeSizeLoad->setVolatile(true);
    CodeSizeLoad->setAlignment(Align(4));
    Value *HasCode =
        CB.CreateICmpNE(CodeSizeLoad, ConstantInt::get(I32, 0),
                        "morok.sc.code.has");
    CB.CreateCondBr(HasCode, CodeLoop, Exit);

    Builder KB(CodeLoop);
    PHINode *CI = KB.CreatePHI(I32, 2, "morok.sc.code.i");
    PHINode *CH = KB.CreatePHI(I64, 2, "morok.sc.code.hash");
    CI->addIncoming(ConstantInt::get(I32, 0), CodeCheck);
    CH->addIncoming(NextH, CodeCheck);
    auto *CodeByte =
        KB.CreateLoad(I8, codePtr(KB, Target, CI), "morok.sc.code.byte");
    CodeByte->setVolatile(true);
    CodeByte->setAlignment(Align(1));
    Value *NextCH = emitHashStep(KB, CH, CodeByte);
    Value *NextCI =
        KB.CreateAdd(CI, ConstantInt::get(I32, 1), "morok.sc.code.next");
    CI->addIncoming(NextCI, CodeLoop);
    CH->addIncoming(NextCH, CodeLoop);
    Value *CodeDone =
        KB.CreateICmpEQ(NextCI, CodeSizeLoad, "morok.sc.code.done");
    KB.CreateCondBr(CodeDone, Exit, CodeLoop);

    Builder XB(Exit);
    PHINode *FinalH = XB.CreatePHI(I64, 2, "morok.sc.final.hash");
    FinalH->addIncoming(NextH, CodeCheck);
    FinalH->addIncoming(NextCH, CodeLoop);
    auto *ExpectedLoad = XB.CreateLoad(I64, Expected, "morok.sc.expected.load");
    ExpectedLoad->setVolatile(true);
    ExpectedLoad->setAlignment(Align(8));
    Value *Diff = XB.CreateXor(FinalH, ExpectedLoad, "morok.sc.diff");
    XB.CreateRet(Diff);
    return Fn;
}

Runtime createRuntime(Function &F, const SelfChecksumParams &Params,
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
    R.seed = Seed;
    R.region = createRegion(M, Suffix, Bytes);
    R.expected = createExpected(M, Suffix, R.expected_hash);
    R.code_size = createCodeSize(M, Suffix);
    createPostlinkManifest(M, F, Suffix, R.region, R.expected, R.code_size,
                           RegionSize, R.seed, R.expected_hash);
    R.diff = createDiffFunction(M, Suffix, R.region, R.expected, R.code_size,
                                &F, Seed);
    return R;
}

GlobalVariable *createMask(Module &M, Function &F, IntegerType *Ty,
                           std::uint64_t Mask) {
    const unsigned Bytes = (Ty->getBitWidth() + 7u) / 8u;
    auto *GV = new GlobalVariable(
        M, Ty, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(Ty, Mask),
        (Twine("morok.sc.mask.") + suffixFor(F)).str());
    GV->setAlignment(Align(Bytes));
    return GV;
}

Value *emitFusedConstant(Function &F, Runtime &R, Instruction &User,
                         Constant *C, ir::IRRandom &Rng) {
    auto Encoded = encodeConstant(C);
    if (!Encoded)
        return C;

    Module &M = *F.getParent();
    auto *Ty = Encoded->carrier_ty;
    const unsigned Bits = Ty->getBitWidth();
    const std::uint64_t MaskLimit = widthMask(Bits);
    const std::uint64_t Original = Encoded->raw & MaskLimit;
    const std::uint64_t Mask = Rng.next() & MaskLimit;
    const std::uint64_t Enc = (Original ^ Mask) & MaskLimit;

    GlobalVariable *MaskGV = createMask(M, F, Ty, Mask);

    Builder B(&User);
    auto *Diff64 = B.CreateCall(R.diff->getFunctionType(), R.diff, {},
                                "morok.sc.diff.call");
    Value *Diff = Diff64;
    if (Bits < 64)
        Diff = B.CreateTrunc(Diff64, Ty, "morok.sc.diff.trunc");
    auto *MaskLoad = B.CreateLoad(Ty, MaskGV, "morok.sc.mask.load");
    MaskLoad->setVolatile(true);
    MaskLoad->setAlignment(MaskGV->getAlign().valueOrOne());
    Value *Base =
        B.CreateXor(ConstantInt::get(Ty, Enc), MaskLoad, "morok.sc.base");
    Value *Raw = B.CreateXor(Base, Diff, "morok.sc.const");
    if (Encoded->result_ty == Ty)
        return Raw;
    return B.CreateBitCast(Raw, Encoded->result_ty, "morok.sc.const.fp");
}

} // namespace

bool selfChecksumConstantsFunction(Function &F,
                                   const SelfChecksumParams &Params,
                                   ir::IRRandom &Rng) {
    if (F.isDeclaration() || generatedFunction(F) || Params.probability == 0 ||
        Params.max_constants == 0 || Params.region_bytes == 0)
        return false;

    const std::string DiffName = "morok.sc.diff." + suffixFor(F);
    if (F.getParent()->getFunction(DiffName))
        return false;

    std::vector<Target> Targets = collectTargets(F);
    if (Targets.empty())
        return false;
    shuffleTargets(Targets, Rng);

    SmallVector<Target, 16> Selected;
    for (const Target &T : Targets) {
        if (Selected.size() >= Params.max_constants)
            break;
        if (!Rng.chance(Params.probability))
            continue;
        Selected.push_back(T);
    }
    if (Selected.empty())
        return false;

    Runtime R = createRuntime(F, Params, Rng);
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
                      "morok.sc.phi.edge");
        if (!Edge)
            return nullptr;
        SplitEdges[Key] = Edge;
        return Edge->getTerminator();
    };

    for (const Target &T : Selected) {
        Instruction *InsertBefore = insertionPoint(T);
        if (!InsertBefore)
            continue;
        Value *Repl = emitFusedConstant(F, R, *InsertBefore, T.value, Rng);
        if (T.phi_incoming) {
            auto *PN = cast<PHINode>(T.user);
            BasicBlock *Incoming = T.incoming_block;
            auto It = SplitEdges.find(std::make_pair(Incoming, PN->getParent()));
            if (It != SplitEdges.end())
                Incoming = It->second;
            const int IncomingIndex = PN->getBasicBlockIndex(Incoming);
            if (IncomingIndex < 0)
                continue;
            PN->setIncomingValue(static_cast<unsigned>(IncomingIndex), Repl);
        } else {
            T.user->setOperand(T.index, Repl);
        }
    }

    relaxMemoryAttrs(F);
    invalidateCallerEffects(F);
    return true;
}

PreservedAnalyses SelfChecksumConstantsPass::run(Function &F,
                                                 FunctionAnalysisManager &) {
    ir::IRRandom Rng(engine_);
    return selfChecksumConstantsFunction(F, params_, Rng)
               ? PreservedAnalyses::none()
               : PreservedAnalyses::all();
}

} // namespace morok::passes
