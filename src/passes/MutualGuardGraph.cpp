// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/MutualGuardGraph.cpp
//
// IR-stage mutual guard graph.  Final native code-region checksums need
// post-link sizing, so this pass emits many private IR-owned checksum regions
// plus mutable expected-hash globals that a post-link rewriter can replace.
// Each checker validates its own region and peer expected hashes; the graph's
// combined diff is fused into return values as data, not a trap or branch.

#include "morok/passes/MutualGuardGraph.hpp"

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
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

using Builder = IRBuilder<NoFolder>;

constexpr std::uint64_t kPostlinkMagic = 0x4D4F524F4B4D4731ULL; // MOROKMG1

struct NodeRuntime {
    GlobalVariable *region = nullptr;
    GlobalVariable *expected = nullptr;
    Function *checker = nullptr;
    std::uint64_t expected_hash = 0;
    std::uint64_t seed = 0;
};

struct GraphRuntime {
    Function *diff = nullptr;
    std::vector<NodeRuntime> nodes;
};

bool generatedFunction(const Function &F) {
    return F.getName().starts_with("morok.");
}

std::string suffixFor(Function &F) { return F.getName().str(); }

bool eligibleReturn(ReturnInst *RI) {
    if (!RI || RI->getNumOperands() == 0)
        return false;
    auto *Ty = dyn_cast<IntegerType>(RI->getOperand(0)->getType());
    return Ty && Ty->getBitWidth() <= 64;
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
    Value *Wide = B.CreateZExt(Byte, I64, "morok.mg.hash.byte");
    Value *X = B.CreateXor(H, Wide, "morok.mg.hash.mix");
    X = B.CreateMul(X, ConstantInt::get(I64, 0xff51afd7ed558ccdULL),
                    "morok.mg.hash.mix");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 32)),
                    "morok.mg.hash.mix");
    X = B.CreateMul(X, ConstantInt::get(I64, 0xc4ceb9fe1a85ec53ULL),
                    "morok.mg.hash.mix");
    return B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 29)),
                       "morok.mg.hash.mix");
}

Value *rotl64(Builder &B, Value *V, unsigned Amount, const Twine &Name) {
    auto *I64 = B.getInt64Ty();
    const unsigned Sh = (Amount % 63u) + 1u;
    Value *L = B.CreateShl(V, ConstantInt::get(I64, Sh), Name + ".lo");
    Value *R = B.CreateLShr(V, ConstantInt::get(I64, 64u - Sh), Name + ".hi");
    return B.CreateOr(L, R, Name);
}

std::vector<std::uint8_t> randomRegion(std::uint32_t Size, ir::IRRandom &Rng) {
    std::vector<std::uint8_t> Bytes;
    Bytes.reserve(Size);
    for (std::uint32_t I = 0; I < Size; ++I)
        Bytes.push_back(static_cast<std::uint8_t>(Rng.next()));
    return Bytes;
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

void shuffleReturns(std::vector<ReturnInst *> &Returns, ir::IRRandom &Rng) {
    for (std::size_t I = Returns.size(); I > 1; --I) {
        const std::size_t J = Rng.range(static_cast<std::uint32_t>(I));
        std::swap(Returns[I - 1], Returns[J]);
    }
}

GlobalVariable *createRegion(Module &M, StringRef Suffix, std::uint32_t Index,
                             ArrayRef<std::uint8_t> Bytes) {
    LLVMContext &Ctx = M.getContext();
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *ArrTy = ArrayType::get(I8, Bytes.size());
    auto *Region = new GlobalVariable(
        M, ArrTy, /*isConstant=*/true, GlobalValue::PrivateLinkage,
        ConstantDataArray::get(Ctx, Bytes),
        (Twine("morok.mg.region.") + Suffix + "." + Twine(Index)).str());
    Region->setUnnamedAddr(GlobalValue::UnnamedAddr::None);
    Region->setAlignment(Align(1));
    return Region;
}

GlobalVariable *createExpected(Module &M, StringRef Suffix, std::uint32_t Index,
                               std::uint64_t ExpectedHash) {
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *Expected = new GlobalVariable(
        M, I64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I64, ExpectedHash),
        (Twine("morok.mg.expected.") + Suffix + "." + Twine(Index)).str());
    Expected->setAlignment(Align(8));
    return Expected;
}

Value *regionPtr(Builder &B, GlobalVariable *Region, Value *Idx) {
    auto *I32 = B.getInt32Ty();
    auto *ArrTy = cast<ArrayType>(Region->getValueType());
    return B.CreateInBoundsGEP(ArrTy, Region, {ConstantInt::get(I32, 0), Idx},
                               "morok.mg.region.ptr");
}

LoadInst *volatileExpectedLoad(Builder &B, GlobalVariable *Expected,
                               const Twine &Name) {
    auto *I64 = B.getInt64Ty();
    auto *Load = B.CreateLoad(I64, Expected, Name);
    Load->setVolatile(true);
    Load->setAlignment(Align(8));
    return Load;
}

Value *peerDiff(Builder &B, GlobalVariable *Expected,
                std::uint64_t ExpectedHash, const Twine &Name) {
    auto *I64 = B.getInt64Ty();
    Value *Loaded = volatileExpectedLoad(B, Expected, Name + ".load");
    return B.CreateXor(Loaded, ConstantInt::get(I64, ExpectedHash), Name);
}

Function *createNodeFunction(Module &M, StringRef Suffix, std::uint32_t Index,
                             ArrayRef<NodeRuntime> Nodes) {
    LLVMContext &Ctx = M.getContext();
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    const NodeRuntime &Self = Nodes[Index];
    const auto *ArrTy = cast<ArrayType>(Self.region->getValueType());
    const std::uint32_t Size =
        static_cast<std::uint32_t>(ArrTy->getNumElements());
    const std::uint32_t Count = static_cast<std::uint32_t>(Nodes.size());
    const std::uint32_t Prev = (Index + Count - 1u) % Count;
    const std::uint32_t Next = (Index + 1u) % Count;

    auto *Fn = Function::Create(
        FunctionType::get(I64, false), GlobalValue::InternalLinkage,
        (Twine("morok.mg.node.") + Suffix + "." + Twine(Index)).str(), &M);
    addRuntimeAttrs(Fn);

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    BasicBlock *Loop = BasicBlock::Create(Ctx, "hash", Fn);
    BasicBlock *Exit = BasicBlock::Create(Ctx, "exit", Fn);

    Builder EB(Entry);
    EB.CreateBr(Loop);

    Builder LB(Loop);
    PHINode *I = LB.CreatePHI(I32, 2, "morok.mg.hash.i");
    PHINode *H = LB.CreatePHI(I64, 2, "morok.mg.hash");
    I->addIncoming(ConstantInt::get(I32, 0), Entry);
    H->addIncoming(ConstantInt::get(I64, Self.seed), Entry);
    auto *Byte = LB.CreateLoad(I8, regionPtr(LB, Self.region, I),
                               "morok.mg.region.byte");
    Byte->setVolatile(true);
    Byte->setAlignment(Align(1));
    Value *NextH = emitHashStep(LB, H, Byte);
    Value *NextI =
        LB.CreateAdd(I, ConstantInt::get(I32, 1), "morok.mg.hash.next");
    I->addIncoming(NextI, Loop);
    H->addIncoming(NextH, Loop);
    Value *Done = LB.CreateICmpEQ(NextI, ConstantInt::get(I32, Size),
                                  "morok.mg.hash.done");
    LB.CreateCondBr(Done, Exit, Loop);

    Builder XB(Exit);
    Value *OwnLoaded =
        volatileExpectedLoad(XB, Self.expected, "morok.mg.expected.load");
    Value *OwnDiff = XB.CreateXor(NextH, OwnLoaded, "morok.mg.node.diff");
    Value *PrevDiff = peerDiff(XB, Nodes[Prev].expected,
                               Nodes[Prev].expected_hash, "morok.mg.peer.prev");
    Value *NextDiff = peerDiff(XB, Nodes[Next].expected,
                               Nodes[Next].expected_hash, "morok.mg.peer.next");
    Value *Acc = XB.CreateXor(OwnDiff, PrevDiff, "morok.mg.node.diff");
    Acc = XB.CreateXor(Acc, NextDiff, "morok.mg.node.diff");
    Value *Rot = rotl64(XB, Acc, 9u + Index * 7u, "morok.mg.node.diff.rot");
    Value *Mul = XB.CreateMul(
        Acc, ConstantInt::get(I64, 0x9e3779b97f4a7c15ULL + Index * 0x101u),
        "morok.mg.node.diff.mul");
    XB.CreateRet(XB.CreateXor(Mul, Rot, "morok.mg.node.diff"));
    return Fn;
}

Function *createDiffFunction(Module &M, StringRef Suffix,
                             ArrayRef<NodeRuntime> Nodes) {
    LLVMContext &Ctx = M.getContext();
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *Fn = Function::Create(FunctionType::get(I64, false),
                                GlobalValue::InternalLinkage,
                                (Twine("morok.mg.diff.") + Suffix).str(), &M);
    addRuntimeAttrs(Fn);

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    Builder B(Entry);
    Value *Acc = ConstantInt::get(I64, 0);
    for (std::uint32_t I = 0, E = static_cast<std::uint32_t>(Nodes.size());
         I != E; ++I) {
        Function *Node = Nodes[I].checker;
        Value *D = B.CreateCall(Node->getFunctionType(), Node, {},
                                "morok.mg.node.call");
        Value *Rot = rotl64(B, D, 13u + I * 5u, "morok.mg.diff.rot");
        Value *Mix = B.CreateXor(D, Rot, "morok.mg.diff");
        Mix = B.CreateMul(
            Mix, ConstantInt::get(I64, 0xbf58476d1ce4e5b9ULL + I * 0x211u),
            "morok.mg.diff");
        Acc = B.CreateXor(Acc, Mix, "morok.mg.diff");
    }
    B.CreateRet(Acc);
    return Fn;
}

GlobalVariable *createPostlinkManifest(Module &M, StringRef Suffix,
                                       ArrayRef<NodeRuntime> Nodes,
                                       std::uint32_t RegionSize) {
    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *PtrTy = PointerType::getUnqual(Ctx);
    auto *NodeTy = StructType::get(Ctx, {PtrTy, PtrTy, I64, I64});
    SmallVector<Constant *, 16> NodeRecords;
    NodeRecords.reserve(Nodes.size());
    for (const NodeRuntime &Node : Nodes) {
        NodeRecords.push_back(ConstantStruct::get(
            NodeTy,
            {Node.region, Node.expected, ConstantInt::get(I64, Node.seed),
             ConstantInt::get(I64, Node.expected_hash)}));
    }
    auto *NodesTy = ArrayType::get(NodeTy, NodeRecords.size());
    auto *ManifestTy = StructType::get(Ctx, {I64, I32, I32, I32, NodesTy});
    auto *Init = ConstantStruct::get(
        ManifestTy,
        {ConstantInt::get(I64, kPostlinkMagic), ConstantInt::get(I32, 1),
         ConstantInt::get(I32, Nodes.size()), ConstantInt::get(I32, RegionSize),
         ConstantArray::get(NodesTy, NodeRecords)});
    auto *Manifest = new GlobalVariable(
        M, ManifestTy, /*isConstant=*/true, GlobalValue::PrivateLinkage, Init,
        (Twine("morok.postlink.mg.") + Suffix).str());
    Manifest->setUnnamedAddr(GlobalValue::UnnamedAddr::None);
    Manifest->setAlignment(Align(8));
    appendToCompilerUsed(M, {Manifest});
    return Manifest;
}

GraphRuntime createGraph(Function &F, const MutualGuardGraphParams &Params,
                         ir::IRRandom &Rng) {
    Module &M = *F.getParent();
    const std::string Suffix = suffixFor(F);
    const std::uint32_t Count = std::clamp<std::uint32_t>(Params.nodes, 2, 16);
    const std::uint32_t RegionSize =
        std::clamp<std::uint32_t>(Params.region_bytes, 8, 1024);

    GraphRuntime G;
    G.nodes.reserve(Count);
    for (std::uint32_t I = 0; I != Count; ++I) {
        NodeRuntime Node;
        Node.seed = Rng.next();
        std::vector<std::uint8_t> Bytes = randomRegion(RegionSize, Rng);
        Node.expected_hash = hashBytes(
            ArrayRef<std::uint8_t>(Bytes.data(), Bytes.size()), Node.seed);
        Node.region = createRegion(
            M, Suffix, I, ArrayRef<std::uint8_t>(Bytes.data(), Bytes.size()));
        Node.expected = createExpected(M, Suffix, I, Node.expected_hash);
        G.nodes.push_back(Node);
    }

    for (std::uint32_t I = 0; I != Count; ++I)
        G.nodes[I].checker =
            createNodeFunction(M, Suffix, I, ArrayRef<NodeRuntime>(G.nodes));
    createPostlinkManifest(M, Suffix, ArrayRef<NodeRuntime>(G.nodes),
                           RegionSize);
    G.diff = createDiffFunction(M, Suffix, ArrayRef<NodeRuntime>(G.nodes));
    return G;
}

Value *emitPoisonedReturn(ReturnInst *RI, Function *Diff) {
    Value *RetVal = RI->getOperand(0);
    auto *Ty = cast<IntegerType>(RetVal->getType());
    Builder B(RI);
    Value *GraphDiff =
        B.CreateCall(Diff->getFunctionType(), Diff, {}, "morok.mg.diff.call");
    Value *Narrow = GraphDiff;
    if (Ty->getBitWidth() < 64)
        Narrow = B.CreateTrunc(GraphDiff, Ty, "morok.mg.diff.trunc");
    return B.CreateXor(RetVal, Narrow, "morok.mg.value");
}

} // namespace

bool mutualGuardGraphFunction(Function &F, const MutualGuardGraphParams &Params,
                              ir::IRRandom &Rng) {
    if (F.isDeclaration() || generatedFunction(F) || Params.probability == 0 ||
        Params.nodes < 2 || Params.region_bytes == 0 || Params.max_returns == 0)
        return false;

    const std::string DiffName = "morok.mg.diff." + suffixFor(F);
    if (F.getParent()->getFunction(DiffName))
        return false;

    std::vector<ReturnInst *> Returns;
    for (BasicBlock &BB : F)
        if (eligibleReturn(dyn_cast<ReturnInst>(BB.getTerminator())))
            Returns.push_back(cast<ReturnInst>(BB.getTerminator()));
    if (Returns.empty())
        return false;
    shuffleReturns(Returns, Rng);

    SmallVector<ReturnInst *, 8> Selected;
    for (ReturnInst *RI : Returns) {
        if (Selected.size() >= Params.max_returns)
            break;
        if (!Rng.chance(Params.probability))
            continue;
        Selected.push_back(RI);
    }
    if (Selected.empty())
        return false;

    GraphRuntime G = createGraph(F, Params, Rng);
    for (ReturnInst *RI : Selected)
        RI->setOperand(0, emitPoisonedReturn(RI, G.diff));

    relaxMemoryAttrs(F);
    invalidateCallerEffects(F);
    return true;
}

PreservedAnalyses MutualGuardGraphPass::run(Function &F,
                                            FunctionAnalysisManager &) {
    ir::IRRandom Rng(engine_);
    return mutualGuardGraphFunction(F, params_, Rng) ? PreservedAnalyses::none()
                                                     : PreservedAnalyses::all();
}

} // namespace morok::passes
