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
#include "morok/passes/CodeRegionKdf.hpp"
#include "morok/passes/RuntimeSeal.hpp"

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
#include "llvm/Support/AtomicOrdering.h"
#include "llvm/Support/MathExtras.h"
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
    GlobalVariable *runtime_seal = nullptr;
    GlobalVariable *external_proof_seal = nullptr;
    GlobalVariable *tracer_seal = nullptr;
    GlobalVariable *anti_analysis_poison = nullptr;
    std::uint64_t runtime_seal_s0 = 0;
    std::uint64_t external_proof_s0 = 0;
    std::uint64_t tracer_s0 = 0;
    std::uint64_t expected_hash = 0;
    std::uint64_t seed = 0;
};

struct ActivationDiffCache {
    AllocaInst *encoded = nullptr;
    Function *direct_provider = nullptr;
    std::uint64_t mask = 0;
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
        ConstantInt::get(I32, code_region_kdf::kUnsealedCodeSize),
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

Function *createDiffFunction(Module &M, StringRef Suffix,
                             GlobalVariable *Region, GlobalVariable *Expected,
                             GlobalVariable *CodeSize, Function *Target,
                             GlobalVariable *HeartbeatCrypto,
                             GlobalVariable *AntidbgSeal,
                             std::uint64_t AntidbgSealS0,
                             GlobalVariable *ExternalProofSeal,
                             std::uint64_t ExternalProofS0,
                             GlobalVariable *TracerSeal,
                             std::uint64_t TracerS0,
                             GlobalVariable *AntiAnalysisPoison,
                             std::uint64_t Seed, bool FailClosed) {
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
    Value *NextH = code_region_kdf::emitHashStep(LB, H, Byte,
                                                 "morok.sc.hash");
    Value *NextI =
        LB.CreateAdd(I, ConstantInt::get(I32, 1), "morok.sc.hash.next");
    I->addIncoming(NextI, Loop);
    H->addIncoming(NextH, Loop);
    Value *Done = LB.CreateICmpEQ(NextI, ConstantInt::get(I32, Size),
                                  "morok.sc.hash.done");
    LB.CreateCondBr(Done, CodeCheck, Loop);

    Builder CB(CodeCheck);
    code_region_kdf::SealedCodeHash CodeHash =
        code_region_kdf::emitSealedCodeHash(CB, CodeCheck, CodeLoop, Exit,
                                            Target, CodeSize, NextH, NextH,
                                            "morok.sc", "morok.sc.final.hash",
                                            FailClosed);

    Builder XB(Exit);
    PHINode *FinalH = CodeHash.final_hash;
    auto *ExpectedLoad = XB.CreateLoad(I64, Expected, "morok.sc.expected.load");
    ExpectedLoad->setVolatile(true);
    ExpectedLoad->setAlignment(Align(8));
    Value *Diff = XB.CreateXor(FinalH, ExpectedLoad, "morok.sc.diff");
    if (HeartbeatCrypto) {
        auto *Crypto =
            XB.CreateLoad(I64, HeartbeatCrypto, "morok.sc.watchdog.crypto");
        Crypto->setVolatile(true);
        Crypto->setAtomic(AtomicOrdering::Monotonic);
        Crypto->setAlignment(Align(8));
        Diff = XB.CreateXor(Diff, Crypto, "morok.sc.crypto.diff");
    }
    if (AntidbgSeal) {
        Value *SealDelta = runtime_seal::emitDelta(
            XB, AntidbgSeal, AntidbgSealS0, "morok.sc.runtime_seal");
        Value *SealKey = runtime_seal::emitKdf64(
            XB, SealDelta, Seed ^ 0xD1F2C3A497586B0EULL,
            "morok.sc.runtime_seal.kdf");
        Diff = XB.CreateXor(Diff, SealKey, "morok.sc.runtime_seal.diff");
    }
    if (ExternalProofSeal) {
        Value *ProofDelta = runtime_seal::emitDelta(
            XB, ExternalProofSeal, ExternalProofS0, "morok.sc.external_proof");
        Value *ProofKey = runtime_seal::emitKdf64(
            XB, ProofDelta, Seed ^ 0xA529B72F1D3C4E8BULL,
            "morok.sc.external_proof.kdf");
        Diff = XB.CreateXor(Diff, ProofKey, "morok.sc.external_proof.diff");
    }
    if (TracerSeal) {
        Value *TracerDelta = runtime_seal::emitDelta(
            XB, TracerSeal, TracerS0, "morok.sc.tracer");
        Value *TracerKey = runtime_seal::emitKdf64(
            XB, TracerDelta, Seed ^ 0xC8735F2D9E164AB1ULL,
            "morok.sc.tracer.kdf");
        Diff = XB.CreateXor(Diff, TracerKey, "morok.sc.tracer.diff");
    }
    if (AntiAnalysisPoison) {
        auto *Poison =
            XB.CreateLoad(I64, AntiAnalysisPoison, "morok.sc.antianalysis.poison");
        Poison->setVolatile(true);
        Poison->setAlignment(Align(8));
        Diff = XB.CreateXor(Diff, Poison, "morok.sc.antianalysis.diff");
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
        code_region_kdf::hashBytes(
            ArrayRef<std::uint8_t>(Bytes.data(), Bytes.size()), Seed);
    R.seed = Seed;
    R.region = createRegion(M, Suffix, Bytes);
    R.expected = createExpected(M, Suffix, R.expected_hash);
    R.code_size = createCodeSize(M, Suffix);
    R.heartbeat_crypto =
        M.getGlobalVariable("morok.watchdog.crypto", /*AllowInternal=*/true);
    R.runtime_seal =
        runtime_seal::getChannel(M, runtime_seal::kAntiDebugChannel, Rng);
    R.runtime_seal_s0 = runtime_seal::initialValue(R.runtime_seal);
    R.external_proof_seal =
        runtime_seal::findChannel(M, runtime_seal::kExternalProofChannel);
    R.external_proof_s0 = runtime_seal::initialValue(R.external_proof_seal);
    R.tracer_seal = runtime_seal::findChannel(M, runtime_seal::kTracerChannel);
    R.tracer_s0 = runtime_seal::initialValue(R.tracer_seal);
    R.anti_analysis_poison =
        M.getGlobalVariable("morok.antianalysis.poison", /*AllowInternal=*/true);
    createPostlinkManifest(M, F, Suffix, R.region, R.expected, R.code_size,
                           RegionSize, R.seed, R.expected_hash);
    R.diff = createDiffFunction(M, Suffix, R.region, R.expected, R.code_size,
                                &F, R.heartbeat_crypto, R.runtime_seal,
                                R.runtime_seal_s0, R.external_proof_seal,
                                R.external_proof_s0, R.tracer_seal,
                                R.tracer_s0, R.anti_analysis_poison, Seed,
                                Params.fail_closed_on_unsealed);
    return R;
}

GlobalVariable *createMask(Module &M, Function &F, IntegerType *Ty,
                           std::uint64_t Mask) {
    // The storage byte count of an odd-width integer (e.g. i17 -> 3, i40 -> 5)
    // is not a valid llvm::Align, which requires a nonzero power of two and
    // otherwise asserts ("Alignment is not a power of 2") in assertions-enabled
    // builds.  This private mask is a plain XOR pad with no real alignment
    // requirement, so round the byte count up to the next power of two; natural
    // widths (i8/i16/i32/i64) are unchanged.
    const unsigned Bytes = (Ty->getBitWidth() + 7u) / 8u;
    const std::uint64_t MaskAlign = llvm::PowerOf2Ceil(Bytes);
    auto *GV = new GlobalVariable(
        M, Ty, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(Ty, Mask),
        (Twine("morok.sc.mask.") + suffixFor(F)).str());
    GV->setAlignment(Align(MaskAlign));
    return GV;
}

GlobalVariable *createI64CacheGlobal(Module &M, StringRef Name) {
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *GV = new GlobalVariable(M, I64, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage,
                                  ConstantInt::get(I64, 0), Name);
    GV->setAlignment(Align(8));
    return GV;
}

GlobalVariable *createI8CacheGlobal(Module &M, StringRef Name) {
    auto *I8 = Type::getInt8Ty(M.getContext());
    auto *GV = new GlobalVariable(M, I8, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage,
                                  ConstantInt::get(I8, 0), Name);
    GV->setAlignment(Align(1));
    return GV;
}

Value *zextOrTruncI64(Builder &B, Value *V) {
    auto *I64 = B.getInt64Ty();
    if (V->getType() == I64)
        return V;
    if (V->getType()->isIntegerTy())
        return B.CreateZExtOrTrunc(V, I64);
    return B.CreatePtrToInt(V, I64);
}

Value *mixCacheKey(Builder &B, Value *Key, Value *Word, std::uint64_t Salt,
                   const Twine &Name) {
    auto *I64 = B.getInt64Ty();
    Word = zextOrTruncI64(B, Word);
    Key = B.CreateXor(Key, Word, Name + ".xor");
    Key = B.CreateAdd(Key, ConstantInt::get(I64, Salt), Name + ".add");
    Key = B.CreateXor(Key, B.CreateLShr(Key, ConstantInt::get(I64, 33)),
                      Name + ".fold33");
    Key = B.CreateMul(Key, ConstantInt::get(I64, 0xff51afd7ed558ccdULL),
                      Name + ".mul0");
    Key = B.CreateXor(Key, B.CreateLShr(Key, ConstantInt::get(I64, 29)),
                      Name + ".fold29");
    Key = B.CreateMul(Key, ConstantInt::get(I64, 0xc4ceb9fe1a85ec53ULL),
                      Name + ".mul1");
    return B.CreateXor(Key, B.CreateLShr(Key, ConstantInt::get(I64, 32)),
                       Name + ".fold32");
}

Value *emitStaticCacheKey(Builder &B, Runtime &R, std::uint64_t Seed,
                          StringRef Prefix) {
    auto *I64 = B.getInt64Ty();
    Value *Key = ConstantInt::get(I64, Seed ^ R.seed ^ 0x9C15D37B4A7C159EULL);
    if (R.code_size) {
        auto *CodeSize =
            B.CreateLoad(B.getInt32Ty(), R.code_size,
                         Twine(Prefix) + ".code_size");
        CodeSize->setVolatile(true);
        CodeSize->setAlignment(Align(4));
        Key = mixCacheKey(B, Key, CodeSize, Seed ^ 0x61C8864680B583EBULL,
                          Twine(Prefix) + ".code_size.mix");
    }
    if (R.heartbeat_crypto) {
        auto *Crypto =
            B.CreateLoad(I64, R.heartbeat_crypto, Twine(Prefix) + ".watchdog");
        Crypto->setVolatile(true);
        Crypto->setAtomic(AtomicOrdering::Monotonic);
        Crypto->setAlignment(Align(8));
        Key = mixCacheKey(B, Key, Crypto, Seed ^ 0xD6E8FEB86659FD93ULL,
                          Twine(Prefix) + ".watchdog.mix");
    }
    if (R.runtime_seal) {
        Value *Delta = runtime_seal::emitDelta(
            B, R.runtime_seal, R.runtime_seal_s0,
            Twine(Prefix) + ".runtime_seal");
        Key = mixCacheKey(B, Key, Delta, Seed ^ 0xD1F2C3A497586B0EULL,
                          Twine(Prefix) + ".runtime_seal.mix");
    }
    if (R.external_proof_seal) {
        Value *Delta = runtime_seal::emitDelta(
            B, R.external_proof_seal, R.external_proof_s0,
            Twine(Prefix) + ".external_proof");
        Key = mixCacheKey(B, Key, Delta, Seed ^ 0xA529B72F1D3C4E8BULL,
                          Twine(Prefix) + ".external_proof.mix");
    }
    if (R.tracer_seal) {
        Value *Delta = runtime_seal::emitDelta(
            B, R.tracer_seal, R.tracer_s0, Twine(Prefix) + ".tracer");
        Key = mixCacheKey(B, Key, Delta, Seed ^ 0xC8735F2D9E164AB1ULL,
                          Twine(Prefix) + ".tracer.mix");
    }
    if (R.anti_analysis_poison) {
        auto *Poison =
            B.CreateLoad(I64, R.anti_analysis_poison,
                         Twine(Prefix) + ".poison");
        Poison->setVolatile(true);
        Poison->setAlignment(Align(8));
        Key = mixCacheKey(B, Key, Poison, Seed ^ 0xBADC0FFEE0DDF00DULL,
                          Twine(Prefix) + ".poison.mix");
    }
    return Key;
}

Function *createStaticDiffCacheFunction(Module &M, StringRef Suffix, Runtime &R,
                                        std::uint64_t Mask,
                                        std::uint64_t KeySeed) {
    LLVMContext &Ctx = M.getContext();
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);

    auto *ValueGV = createI64CacheGlobal(
        M, (Twine("morok.sc.cache.value.") + Suffix).str());
    auto *KeyGV = createI64CacheGlobal(
        M, (Twine("morok.sc.cache.key.") + Suffix).str());
    auto *ReadyGV = createI8CacheGlobal(
        M, (Twine("morok.sc.cache.ready.") + Suffix).str());

    auto *Fn = Function::Create(FunctionType::get(I64, false),
                                GlobalValue::InternalLinkage,
                                (Twine("morok.sc.cache.") + Suffix).str(), &M);
    addRuntimeAttrs(Fn);

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    BasicBlock *Cached = BasicBlock::Create(Ctx, "cached", Fn);
    BasicBlock *Fill = BasicBlock::Create(Ctx, "fill", Fn);
    BasicBlock *Exit = BasicBlock::Create(Ctx, "exit", Fn);

    Builder EB(Entry);
    Value *CurrentKey = emitStaticCacheKey(EB, R, KeySeed, "morok.sc.cache.key");
    auto *Ready = EB.CreateLoad(I8, ReadyGV, "morok.sc.cache.ready.load");
    Ready->setAtomic(AtomicOrdering::Acquire);
    Ready->setAlignment(Align(1));
    auto *StoredKey = EB.CreateLoad(I64, KeyGV, "morok.sc.cache.key.load");
    StoredKey->setAtomic(AtomicOrdering::Monotonic);
    StoredKey->setAlignment(Align(8));
    Value *ReadySet =
        EB.CreateICmpNE(Ready, ConstantInt::get(I8, 0), "morok.sc.cache.ready");
    Value *KeyMatches =
        EB.CreateICmpEQ(StoredKey, CurrentKey, "morok.sc.cache.key.ok");
    Value *UseCached =
        EB.CreateAnd(ReadySet, KeyMatches, "morok.sc.cache.use");
    EB.CreateCondBr(UseCached, Cached, Fill);

    Builder CB(Cached);
    auto *CachedValue =
        CB.CreateLoad(I64, ValueGV, "morok.sc.cache.value.load");
    CachedValue->setAtomic(AtomicOrdering::Monotonic);
    CachedValue->setAlignment(Align(8));
    CB.CreateBr(Exit);

    Builder FB(Fill);
    Value *Diff64 = FB.CreateCall(R.diff->getFunctionType(), R.diff, {},
                                  "morok.sc.cache.diff");
    Value *Encoded =
        FB.CreateXor(Diff64, FB.getInt64(Mask), "morok.sc.cache.value.enc");
    auto *ValueStore = FB.CreateStore(Encoded, ValueGV);
    ValueStore->setAtomic(AtomicOrdering::Monotonic);
    ValueStore->setAlignment(Align(8));
    auto *KeyStore = FB.CreateStore(CurrentKey, KeyGV);
    KeyStore->setAtomic(AtomicOrdering::Monotonic);
    KeyStore->setAlignment(Align(8));
    auto *ReadyStore = FB.CreateStore(ConstantInt::get(I8, 1), ReadyGV);
    ReadyStore->setAtomic(AtomicOrdering::Release);
    ReadyStore->setAlignment(Align(1));
    FB.CreateBr(Exit);

    Builder XB(Exit);
    PHINode *EncodedDiff = XB.CreatePHI(I64, 2, "morok.sc.cache.value");
    EncodedDiff->addIncoming(CachedValue, Cached);
    EncodedDiff->addIncoming(Encoded, Fill);
    Value *Diff =
        XB.CreateXor(EncodedDiff, XB.getInt64(Mask), "morok.sc.cache.diff.raw");
    XB.CreateRet(Diff);
    return Fn;
}

ActivationDiffCache createActivationDiffCache(Function &F, Function *Provider,
                                              StringRef CallName,
                                              ir::IRRandom &Rng) {
    BasicBlock &Entry = F.getEntryBlock();
    auto IP = Entry.getFirstInsertionPt();
    Instruction *InsertBefore =
        IP == Entry.end() ? Entry.getTerminator() : &*IP;
    Builder B(InsertBefore);
    auto *I64 = B.getInt64Ty();

    ActivationDiffCache Cache;
    Cache.direct_provider = Provider;
    Cache.mask = Rng.next();
    Cache.encoded = B.CreateAlloca(I64, nullptr, "morok.sc.diff.cache");
    Cache.encoded->setAlignment(Align(8));

    Value *Diff64 =
        B.CreateCall(Provider->getFunctionType(), Provider, {}, CallName);
    Value *Encoded =
        B.CreateXor(Diff64, B.getInt64(Cache.mask), "morok.sc.diff.cache.enc");
    auto *Store = B.CreateStore(Encoded, Cache.encoded);
    Store->setVolatile(true);
    Store->setAlignment(Align(8));
    return Cache;
}

Value *emitCachedDiff64(Builder &B, const ActivationDiffCache &Cache,
                        StringRef Name) {
    if (!Cache.encoded)
        return B.CreateCall(Cache.direct_provider->getFunctionType(),
                            Cache.direct_provider, {}, Name);
    auto *Load = B.CreateLoad(B.getInt64Ty(), Cache.encoded,
                              "morok.sc.diff.cache.load");
    Load->setVolatile(true);
    Load->setAlignment(Align(8));
    return B.CreateXor(Load, B.getInt64(Cache.mask), Name);
}

Value *emitFusedConstant(Function &F, Instruction &User,
                         Constant *C, const ActivationDiffCache &Cache,
                         ir::IRRandom &Rng) {
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
    Value *Diff64 =
        emitCachedDiff64(B, Cache,
                         Cache.encoded ? "morok.sc.diff.cached"
                                       : "morok.sc.diff.call");
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
void poisonReturns(Function &F, const SelfChecksumParams &Params,
                   const ActivationDiffCache &Cache,
                   ir::IRRandom &Rng,
                   const SmallPtrSetImpl<const ReturnInst *> &AlreadyFused) {
    SmallVector<ReturnInst *, 8> Returns;
    for (BasicBlock &BB : F) {
        auto *RI = dyn_cast<ReturnInst>(BB.getTerminator());
        if (!RI || RI->getNumOperands() != 1 || ir::isMustTailReturn(*RI))
            continue;
        if (isa<Constant>(RI->getOperand(0)))
            continue; // still a constant: handled (or skipped) as a const target
        // A return whose constant operand was just fused by emitFusedConstant is
        // no longer a Constant but already carries the seal-dependent diff.
        // Folding the same deterministic diff again here would XOR it twice and
        // cancel the tamper corruption (`(orig^diff)^diff == orig`), silently
        // disabling the self-check on constant verdict returns.  Skip them.
        if (AlreadyFused.contains(RI))
            continue;
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
        Value *Diff64 = emitCachedDiff64(B, Cache, "morok.sc.ret.diff");
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
    // This pass rewrites arbitrary user sites (including store-value literals).
    // Keep skipping Windows funclet-EH functions so those rewrites do not create
    // verifier-sensitive IR inside catch/cleanup funclets.
    if (ir::usesFuncletEH(F))
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
    Function *DiffProvider = R.diff;
    StringRef DiffProviderCallName = "morok.sc.diff.call";
    if (Params.diff_cache == SelfChecksumDiffCacheMode::Static) {
        DiffProvider = createStaticDiffCacheFunction(
            *F.getParent(), suffixFor(F), R, Rng.next(), Rng.next());
        DiffProviderCallName = "morok.sc.cache.call";
    }
    ActivationDiffCache Cache;
    if (Params.diff_cache == SelfChecksumDiffCacheMode::Direct) {
        Cache.direct_provider = DiffProvider;
    } else {
        Cache = createActivationDiffCache(F, DiffProvider, DiffProviderCallName,
                                          Rng);
    }
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

    // Track constant returns fused below so poisonReturns does not fold the same
    // deterministic diff into them a second time (which would cancel out).
    SmallPtrSet<const ReturnInst *, 8> FusedReturns;
    for (const Target &T : Selected) {
        Instruction *InsertBefore = insertionPoint(T);
        if (!InsertBefore)
            continue;
        Value *Repl =
            emitFusedConstant(F, *InsertBefore, T.value, Cache, Rng);
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
            if (auto *RI = dyn_cast<ReturnInst>(T.user))
                FusedReturns.insert(RI);
        }
    }

    poisonReturns(F, Params, Cache, Rng, FusedReturns);

    relaxMemoryAttrs(F);
    invalidateCallerEffects(F);
    return true;
}

bool bindLeafHelpersToSeal(Module &M, ir::IRRandom &Rng) {
    GlobalVariable *Seal =
        runtime_seal::findChannel(M, runtime_seal::kAntiDebugChannel);
    if (!Seal || !Seal->hasInitializer())
        return false;
    const std::uint64_t S0 = runtime_seal::initialValue(Seal);

    // A function is already seal-bound if its body calls a self-checksum diff
    // function (poisonReturns folds the seal-dependent diff into its returns) —
    // folding again would XOR the seal twice and cancel it.
    auto isSelfChecked = [](Function &F) {
        for (Instruction &I : instructions(F))
            if (auto *CB = dyn_cast<CallBase>(&I))
                if (Function *C = CB->getCalledFunction())
                    if (C->getName().starts_with("morok.sc.diff") ||
                        C->getName().starts_with("morok.sc.cache"))
                        return true;
        return false;
    };
    // Restrict to the validation cluster: helpers called by a self-checksum'd or
    // virtualized function.  This binds exactly the reused seal helpers (l1/g*/…)
    // without touching unrelated leaves across the module.
    auto inValidationCluster = [&](Function &F) {
        for (User *U : F.users())
            if (auto *CB = dyn_cast<CallBase>(U))
                if (Function *Caller = CB->getFunction())
                    if (Caller->getName().starts_with("morok.vm.") ||
                        isSelfChecked(*Caller))
                        return true;
        return false;
    };

    bool Changed = false;
    for (Function &F : M) {
        if (F.isDeclaration() || F.isVarArg())
            continue;
        if (F.getName().starts_with("morok.") || F.getName() == "main")
            continue;
        if (!F.getReturnType()->isIntegerTy())
            continue;
        if (isSelfChecked(F) || !inValidationCluster(F))
            continue;
        for (BasicBlock &BB : F) {
            auto *RI = dyn_cast<ReturnInst>(BB.getTerminator());
            if (!RI || !RI->getReturnValue() ||
                !RI->getReturnValue()->getType()->isIntegerTy())
                continue;
            // A musttail return must be `ret <call-result>` with nothing between
            // the call and the ret; folding the seal into its operand would insert
            // ops there and break the backend's tail-call lowering.  Leave such
            // returns alone (other returns in the function are still bound).
            if (auto *CI = dyn_cast<CallInst>(RI->getReturnValue()))
                if (CI->isMustTailCall())
                    continue;
            IRBuilder<> B(RI);
            Value *RV = RI->getReturnValue();
            Value *Delta =
                runtime_seal::emitDelta(B, Seal, S0, "morok.helper.seal");
            Value *Key = runtime_seal::emitKdf64(
                B, Delta, Rng.next(), "morok.helper.seal.kdf");
            Value *KeyT = B.CreateZExtOrTrunc(Key, RV->getType());
            RI->setOperand(0, B.CreateXor(RV, KeyT, "morok.helper.bound"));
            Changed = true;
        }
    }
    return Changed;
}

PreservedAnalyses SelfChecksumConstantsPass::run(Function &F,
                                                 FunctionAnalysisManager &) {
    ir::IRRandom Rng(engine_);
    return selfChecksumConstantsFunction(F, params_, Rng)
               ? PreservedAnalyses::none()
               : PreservedAnalyses::all();
}

} // namespace morok::passes
