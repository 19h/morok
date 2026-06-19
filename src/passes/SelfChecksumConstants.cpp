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

// Fixed post-link manifest sentinel. Keep this non-printable: readable product
// markers in emitted binaries become cheap static-analysis anchors.
constexpr std::uint64_t kPostlinkMagic = 0xA7D13C5E9000C3B2ULL;

// Unsealed sentinel for the post-link code-window length.  A *non-zero*
// initializer is mandatory here: a zero-initialized mutable global lands in
// BSS/NOBITS, which has no file offset for the post-link sealer to patch, so
// the window length can never be written and native code never enters the diff
// (issues/6.md).  A non-zero initializer forces the global into a file-backed
// data section.  The sealer overwrites this with the real native code length;
// until then the runtime treats the sentinel as "unsealed" and skips the
// code-byte hash so unsealed dev/test builds still behave correctly.
constexpr std::uint32_t kUnsealedCodeSize = 0xFFFFFFFFu;

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
    GlobalVariable *heartbeat_crypto = nullptr;
    GlobalVariable *antidbg_seal = nullptr;
    std::uint64_t antidbg_seal_s0 = 0;
    std::uint64_t expected_hash = 0;
    std::uint64_t seed = 0;
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

SmallPtrSet<BasicBlock *, 32> naturalLoopBlocks(Function &F) {
    DominatorTree DT(F);
    SmallPtrSet<BasicBlock *, 32> Blocks;
    for (BasicBlock &BB : F) {
        for (BasicBlock *Succ : successors(&BB)) {
            if (!DT.dominates(Succ, &BB))
                continue;

            Blocks.insert(Succ);
            SmallVector<BasicBlock *, 16> Worklist;
            if (&BB != Succ && Blocks.insert(&BB).second)
                Worklist.push_back(&BB);

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

std::vector<Target> collectTargets(Function &F) {
    std::vector<Target> Targets;
    SmallPtrSet<BasicBlock *, 32> LoopBlocks = naturalLoopBlocks(F);
    for (BasicBlock &BB : F) {
        if (LoopBlocks.contains(&BB))
            continue;
        for (Instruction &I : BB) {
            if (auto *PN = dyn_cast<PHINode>(&I)) {
                for (unsigned Op = 0; Op < PN->getNumIncomingValues(); ++Op) {
                    if (!eligiblePhiIncoming(*PN, Op))
                        continue;
                    if (LoopBlocks.contains(PN->getIncomingBlock(Op)))
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
        ConstantInt::get(I32, kUnsealedCodeSize),
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
                             GlobalVariable *HeartbeatCrypto,
                             GlobalVariable *AntidbgSeal,
                             std::uint64_t AntidbgSealS0, std::uint64_t Seed) {
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
    // The code-byte hash runs only once the post-link sealer has replaced the
    // unsealed sentinel with a concrete native window length.  Treat both 0 and
    // the sentinel as "unsealed" so the data-only diff stays identity (== 0) and
    // unsealed builds behave correctly; sealed builds fold real code bytes in.
    Value *NonZero = CB.CreateICmpNE(CodeSizeLoad, ConstantInt::get(I32, 0),
                                     "morok.sc.code.nz");
    Value *Sealed =
        CB.CreateICmpNE(CodeSizeLoad, ConstantInt::get(I32, kUnsealedCodeSize),
                        "morok.sc.code.sealed");
    Value *HasCode = CB.CreateAnd(NonZero, Sealed, "morok.sc.code.has");
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
    if (HeartbeatCrypto) {
        auto *Crypto =
            XB.CreateLoad(I64, HeartbeatCrypto, "morok.sc.watchdog.crypto");
        Crypto->setVolatile(true);
        Crypto->setAlignment(Align(8));
        Diff = XB.CreateXor(Diff, Crypto, "morok.sc.crypto.diff");
    }
    if (AntidbgSeal) {
        // seal == S0 on a clean run -> (seal ^ S0) == 0 contribution; any tripped
        // anti-debug detector (or one an attacker forced) makes it nonzero, which
        // poisons this function's fused constants.  Binds anti-debug to the verdict.
        auto *Seal = XB.CreateLoad(I64, AntidbgSeal, "morok.sc.antidbg.seal");
        Seal->setVolatile(true);
        Seal->setAlignment(Align(8));
        Value *SealDelta = XB.CreateXor(
            Seal, ConstantInt::get(I64, AntidbgSealS0), "morok.sc.antidbg.delta");
        Diff = XB.CreateXor(Diff, SealDelta, "morok.sc.antidbg.diff");
    }
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
    R.heartbeat_crypto =
        M.getGlobalVariable("morok.watchdog.crypto", /*AllowInternal=*/true);
    // The anti-debug seal holds S0 on a clean run; the diff cancels it to 0
    // unless a detector tripped at runtime.  This pass may run BEFORE the
    // anti-debug pass that folds into the seal, so create it here if absent
    // (getOrInsert) — the anti-debug pass then shares the same global.  S0 is
    // read back from the initializer so the cancellation constant always matches.
    R.antidbg_seal =
        M.getGlobalVariable("morok.antidbg.seal", /*AllowInternal=*/true);
    if (!R.antidbg_seal) {
        auto *I64Ty = Type::getInt64Ty(M.getContext());
        R.antidbg_seal = new GlobalVariable(
            M, I64Ty, /*isConstant=*/false, GlobalValue::PrivateLinkage,
            ConstantInt::get(I64Ty, Rng.next()), "morok.antidbg.seal");
        R.antidbg_seal->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
        R.antidbg_seal->setAlignment(Align(8));
    }
    if (R.antidbg_seal->hasInitializer())
        if (auto *CI = dyn_cast<ConstantInt>(R.antidbg_seal->getInitializer()))
            R.antidbg_seal_s0 = CI->getZExtValue();
    createPostlinkManifest(M, F, Suffix, R.region, R.expected, R.code_size,
                           RegionSize, R.seed, R.expected_hash);
    R.diff = createDiffFunction(M, Suffix, R.region, R.expected, R.code_size,
                                &F, R.heartbeat_crypto, R.antidbg_seal,
                                R.antidbg_seal_s0, Seed);
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

// Fold the sealed, code-dependent diff into non-constant return values too —
// including the first integer field of an aggregate (struct) return.  Constant
// returns are already covered by collectTargets; this closes the gap for
// computed and struct-typed verdicts a function hands back by value (e.g. a
// license result), so a code patch corrupts the *returned* value, not only the
// constants the function uses internally.  On an intact + sealed binary the
// diff is zero and the return is byte-for-byte unchanged.
void poisonReturns(Function &F, Runtime &R, const SelfChecksumParams &Params,
                   ir::IRRandom &Rng) {
    SmallVector<ReturnInst *, 8> Returns;
    for (BasicBlock &BB : F) {
        auto *RI = dyn_cast<ReturnInst>(BB.getTerminator());
        if (!RI || RI->getNumOperands() != 1 || ir::isMustTailReturn(*RI))
            continue;
        if (isa<Constant>(RI->getOperand(0)))
            continue; // already handled as a constant target
        Returns.push_back(RI);
    }

    for (ReturnInst *RI : Returns) {
        if (!Rng.chance(Params.probability))
            continue;
        Value *RetVal = RI->getOperand(0);
        Type *Ty = RetVal->getType();

        // Resolve which integer slot to poison BEFORE emitting the diff call so
        // an unusable return type never leaves a dead checker behind.
        IntegerType *IT = dyn_cast<IntegerType>(Ty);
        int StructIdx = -1;
        if (!IT) {
            if (auto *ST = dyn_cast<StructType>(Ty)) {
                for (unsigned Idx = 0; Idx < ST->getNumElements(); ++Idx) {
                    auto *FT = dyn_cast<IntegerType>(ST->getElementType(Idx));
                    if (FT && FT->getBitWidth() <= 64) {
                        IT = FT;
                        StructIdx = static_cast<int>(Idx);
                        break;
                    }
                }
            }
        }
        if (!IT || IT->getBitWidth() > 64)
            continue;

        Builder B(RI);
        auto *Diff64 = B.CreateCall(R.diff->getFunctionType(), R.diff, {},
                                    "morok.sc.ret.diff");
        Value *D = IT->getBitWidth() < 64
                       ? B.CreateTrunc(Diff64, IT, "morok.sc.ret.trunc")
                       : static_cast<Value *>(Diff64);
        if (StructIdx < 0) {
            RI->setOperand(0, B.CreateXor(RetVal, D, "morok.sc.ret.val"));
        } else {
            Value *Field = B.CreateExtractValue(
                RetVal, {static_cast<unsigned>(StructIdx)}, "morok.sc.ret.field");
            Value *Mixed = B.CreateXor(Field, D, "morok.sc.ret.val");
            RI->setOperand(0, B.CreateInsertValue(
                                  RetVal, Mixed,
                                  {static_cast<unsigned>(StructIdx)},
                                  "morok.sc.ret.struct"));
        }
    }
}

} // namespace

bool selfChecksumConstantsFunction(Function &F,
                                   const SelfChecksumParams &Params,
                                   ir::IRRandom &Rng) {
    if (F.isDeclaration() || generatedFunction(F) || Params.probability == 0 ||
        Params.max_constants == 0 || Params.region_bytes == 0)
        return false;
    if (directlyRecursive(F))
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

    poisonReturns(F, R, Params, Rng);

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
