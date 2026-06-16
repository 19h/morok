// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/AdversarialFunctionMerging.cpp
//
// IR-stage adversarial function merging + scalar outlining.  The pass keeps
// original function symbols intact but moves selected same-signature bodies
// behind one shared noinline selector dispatcher.  Selected scalar expression
// fragments inside the cloned implementations are outlined into shared helpers,
// perturbing function boundaries and call-graph similarity without changing
// behaviour.

#include "morok/passes/AdversarialFunctionMerging.hpp"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/IR/ValueMap.h"
#include "llvm/Support/ModRef.h"
#include "llvm/Transforms/Utils/Cloning.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr std::uint64_t kCloneInstLimit = 1500;
constexpr std::uint64_t kCloneBlockLimit = 160;

using Builder = IRBuilder<NoFolder>;

struct SignatureGroup {
    FunctionType *type = nullptr;
    CallingConv::ID calling_conv = CallingConv::C;
    std::vector<Function *> functions;
};

struct MergedFunction {
    Function *original = nullptr;
    Function *impl = nullptr;
    std::uint32_t selector = 0;
};

struct OutlineKey {
    unsigned opcode = 0;
    unsigned bits = 0;
};

struct OutlineHelper {
    OutlineKey key;
    Function *helper = nullptr;
};

bool generatedFunction(const Function &F) {
    return F.getName().starts_with("morok.");
}

bool hasExistingAfm(const Module &M) {
    for (const Function &F : M)
        if (F.getName().starts_with("morok.afm."))
            return true;
    for (const GlobalVariable &GV : M.globals())
        if (GV.getName().starts_with("morok.afm."))
            return true;
    return false;
}

bool supportedOpcode(unsigned Opcode) {
    switch (Opcode) {
    case Instruction::Add:
    case Instruction::Sub:
    case Instruction::Mul:
    case Instruction::And:
    case Instruction::Or:
    case Instruction::Xor:
        return true;
    default:
        return false;
    }
}

StringRef opcodeName(unsigned Opcode) {
    switch (Opcode) {
    case Instruction::Add:
        return "add";
    case Instruction::Sub:
        return "sub";
    case Instruction::Mul:
        return "mul";
    case Instruction::And:
        return "and";
    case Instruction::Or:
        return "or";
    case Instruction::Xor:
        return "xor";
    default:
        return "op";
    }
}

bool hasBlockAddressUser(const Function &F) {
    for (const User *U : F.users())
        if (isa<BlockAddress>(U))
            return true;
    return false;
}

std::uint64_t instructionCount(const Function &F) {
    std::uint64_t Count = 0;
    for (const BasicBlock &BB : F)
        Count += BB.size();
    return Count;
}

bool withinCloneBudget(const Function &F) {
    return instructionCount(F) <= kCloneInstLimit &&
           F.size() <= kCloneBlockLimit;
}

bool eligibleFunction(Function &F) {
    if (F.isDeclaration() || F.isIntrinsic() || F.isVarArg())
        return false;
    if (generatedFunction(F))
        return false;
    if (hasBlockAddressUser(F))
        return false;
    if (F.hasAvailableExternallyLinkage() || F.hasFnAttribute(Attribute::Naked))
        return false;
    if (!withinCloneBudget(F))
        return false;
    if (F.hasFnAttribute(Attribute::NoReturn) || F.hasPersonalityFn())
        return false;
    if (!F.getFunctionType()->getReturnType()->isFirstClassType() &&
        !F.getFunctionType()->getReturnType()->isVoidTy())
        return false;
    for (Argument &A : F.args()) {
        if (!A.getType()->isFirstClassType())
            return false;
        // ABI / structural parameter attributes that the selector-dispatcher
        // indirection cannot faithfully forward.  Merging such functions would
        // silently miscompile (byval/sret) or fail the verifier (swifterror).
        if (A.hasAttribute(Attribute::ByVal) ||
            A.hasAttribute(Attribute::StructRet) ||
            A.hasAttribute(Attribute::SwiftError) ||
            A.hasAttribute(Attribute::SwiftSelf) ||
            A.hasAttribute(Attribute::SwiftAsync) ||
            A.hasAttribute(Attribute::InAlloca) ||
            A.hasAttribute(Attribute::Preallocated) ||
            A.hasAttribute(Attribute::Nest))
            return false;
    }
    return true;
}

bool eligibleOutline(BinaryOperator &BO) {
    if (!supportedOpcode(BO.getOpcode()))
        return false;
    if (BO.getName().starts_with("morok.afm."))
        return false;
    auto *Ty = dyn_cast<IntegerType>(BO.getType());
    if (!Ty || Ty->getBitWidth() == 0 || Ty->getBitWidth() > 64)
        return false;
    return !BO.hasPoisonGeneratingFlags();
}

void addNoInlineBarrier(Function *F) {
    F->removeFnAttr(Attribute::AlwaysInline);
    F->addFnAttr(Attribute::NoInline);
}

void addGeneratedAttrs(Function *F) {
    addNoInlineBarrier(F);
    F->addFnAttr(Attribute::OptimizeNone);
    F->setMemoryEffects(MemoryEffects::unknown());
    F->removeFnAttr(Attribute::NoSync);
}

void relaxFunctionEffects(Function &F) {
    F.setMemoryEffects(MemoryEffects::unknown());
    F.removeFnAttr(Attribute::NoSync);
    F.removeFnAttr(Attribute::NoRecurse);
    F.removeFnAttr(Attribute::ReadNone);
    F.removeFnAttr(Attribute::ReadOnly);
    F.removeFnAttr(Attribute::WillReturn);
}

void shuffleFunctions(std::vector<Function *> &Functions, ir::IRRandom &Rng) {
    for (std::size_t I = Functions.size(); I > 1; --I) {
        const std::size_t J = Rng.range(static_cast<std::uint32_t>(I));
        std::swap(Functions[I - 1], Functions[J]);
    }
}

void shuffleGroups(std::vector<SignatureGroup> &Groups, ir::IRRandom &Rng) {
    for (std::size_t I = Groups.size(); I > 1; --I) {
        const std::size_t J = Rng.range(static_cast<std::uint32_t>(I));
        std::swap(Groups[I - 1], Groups[J]);
    }
}

void shuffleOutlines(std::vector<BinaryOperator *> &Ops, ir::IRRandom &Rng) {
    for (std::size_t I = Ops.size(); I > 1; --I) {
        const std::size_t J = Rng.range(static_cast<std::uint32_t>(I));
        std::swap(Ops[I - 1], Ops[J]);
    }
}

std::vector<SignatureGroup> collectGroups(Module &M) {
    std::vector<SignatureGroup> Groups;
    for (Function &F : M) {
        if (!eligibleFunction(F))
            continue;
        auto It = std::find_if(Groups.begin(), Groups.end(),
                               [&](const SignatureGroup &G) {
                                   return G.type == F.getFunctionType() &&
                                          G.calling_conv == F.getCallingConv();
                               });
        if (It == Groups.end()) {
            SignatureGroup G;
            G.type = F.getFunctionType();
            G.calling_conv = F.getCallingConv();
            G.functions.push_back(&F);
            Groups.push_back(std::move(G));
        } else {
            It->functions.push_back(&F);
        }
    }

    Groups.erase(std::remove_if(Groups.begin(), Groups.end(),
                                [](const SignatureGroup &G) {
                                    return G.functions.size() < 2;
                                }),
                 Groups.end());
    return Groups;
}

Function *cloneToImpl(Function &F, Module &M) {
    auto *Impl =
        Function::Create(F.getFunctionType(), GlobalValue::InternalLinkage,
                         (Twine("morok.afm.impl.") + F.getName()).str(), &M);
    Impl->copyAttributesFrom(&F);
    Impl->setLinkage(GlobalValue::InternalLinkage);
    Impl->setVisibility(GlobalValue::DefaultVisibility);
    Impl->setDSOLocal(true);
    Impl->setComdat(nullptr);
    Impl->setCallingConv(F.getCallingConv());
    addGeneratedAttrs(Impl);

    ValueToValueMapTy VMap;
    auto Dest = Impl->arg_begin();
    for (Argument &A : F.args()) {
        Dest->setName(A.getName());
        VMap[&A] = &*Dest++;
    }

    SmallVector<ReturnInst *, 8> Returns;
    CloneFunctionInto(Impl, &F, VMap, CloneFunctionChangeType::LocalChangesOnly,
                      Returns);
    Impl->setLinkage(GlobalValue::InternalLinkage);
    Impl->setVisibility(GlobalValue::DefaultVisibility);
    Impl->setDSOLocal(true);
    Impl->setComdat(nullptr);
    addGeneratedAttrs(Impl);
    return Impl;
}

GlobalVariable *createI32Global(Module &M, const Twine &Name,
                                std::uint32_t Value) {
    auto *I32 = Type::getInt32Ty(M.getContext());
    auto *GV = new GlobalVariable(M, I32, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage,
                                  ConstantInt::get(I32, Value), Name.str());
    GV->setAlignment(Align(4));
    GV->setDSOLocal(true);
    return GV;
}

Value *hiddenSelector(Builder &B, Module &M, Function &F,
                      std::uint32_t Selector, ir::IRRandom &Rng) {
    const std::uint32_t Key = static_cast<std::uint32_t>(Rng.next());
    GlobalVariable *Encoded = createI32Global(
        M, Twine("morok.afm.selector.") + F.getName(), Selector ^ Key);
    GlobalVariable *KeyGV =
        createI32Global(M, Twine("morok.afm.key.") + F.getName(), Key);

    auto *I32 = Type::getInt32Ty(M.getContext());
    auto *EncLoad = B.CreateLoad(I32, Encoded, "morok.afm.selector.enc");
    EncLoad->setVolatile(true);
    EncLoad->setAlignment(Align(4));
    auto *KeyLoad = B.CreateLoad(I32, KeyGV, "morok.afm.selector.key");
    KeyLoad->setVolatile(true);
    KeyLoad->setAlignment(Align(4));
    return B.CreateXor(EncLoad, KeyLoad, "morok.afm.selector");
}

Function *createDispatcher(Module &M, const SignatureGroup &Group,
                           ArrayRef<MergedFunction> Merged,
                           std::uint32_t GroupIndex) {
    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);

    std::vector<Type *> Params;
    Params.push_back(I32);
    for (Type *Param : Group.type->params())
        Params.push_back(Param);

    auto *DispatchTy =
        FunctionType::get(Group.type->getReturnType(), Params, false);
    auto *Dispatch = Function::Create(
        DispatchTy, GlobalValue::InternalLinkage,
        (Twine("morok.afm.dispatch.") + Twine(GroupIndex)).str(), &M);
    Dispatch->setCallingConv(Group.calling_conv);
    Dispatch->setDSOLocal(true);
    addGeneratedAttrs(Dispatch);

    auto AI = Dispatch->arg_begin();
    Value *Selector = &*AI++;
    Selector->setName("selector");
    std::vector<Value *> Args;
    Args.reserve(Group.type->getNumParams());
    for (Argument &A : llvm::make_range(AI, Dispatch->arg_end())) {
        A.setName("arg");
        Args.push_back(&A);
    }

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Dispatch);
    BasicBlock *Default = BasicBlock::Create(Ctx, "invalid", Dispatch);
    Builder B(Entry);
    auto *Switch =
        B.CreateSwitch(Selector, Default, static_cast<unsigned>(Merged.size()));

    for (const MergedFunction &MF : Merged) {
        BasicBlock *Case = BasicBlock::Create(
            Ctx, (Twine("case.") + MF.original->getName()).str(), Dispatch);
        Switch->addCase(ConstantInt::get(I32, MF.selector), Case);
        B.SetInsertPoint(Case);
        CallInst *Call = B.CreateCall(MF.impl->getFunctionType(), MF.impl, Args,
                                      "morok.afm.impl.call");
        Call->setCallingConv(MF.impl->getCallingConv());
        if (Group.type->getReturnType()->isVoidTy())
            B.CreateRetVoid();
        else
            B.CreateRet(Call);
    }

    B.SetInsertPoint(Default);
    B.CreateUnreachable();
    return Dispatch;
}

void rewriteOriginalAsWrapper(MergedFunction &MF, Function *Dispatch, Module &M,
                              ir::IRRandom &Rng) {
    Function &F = *MF.original;
    F.deleteBody();
    addNoInlineBarrier(&F);
    relaxFunctionEffects(F);

    BasicBlock *Entry = BasicBlock::Create(M.getContext(), "entry", &F);
    Builder B(Entry);
    std::vector<Value *> Args;
    Args.reserve(F.arg_size() + 1u);
    Args.push_back(hiddenSelector(B, M, F, MF.selector, Rng));
    for (Argument &A : F.args())
        Args.push_back(&A);

    CallInst *Call = B.CreateCall(Dispatch->getFunctionType(), Dispatch, Args,
                                  "morok.afm.dispatch.call");
    Call->setCallingConv(Dispatch->getCallingConv());
    if (F.getReturnType()->isVoidTy())
        B.CreateRetVoid();
    else
        B.CreateRet(Call);
}

GlobalVariable *createOutlineKey(Module &M, const OutlineKey &Key,
                                 ir::IRRandom &Rng) {
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *GV = new GlobalVariable(
        M, I64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I64, Rng.next()),
        (Twine("morok.afm.key.outline.") + opcodeName(Key.opcode) + ".i" +
         Twine(Key.bits))
            .str());
    GV->setAlignment(Align(8));
    GV->setDSOLocal(true);
    return GV;
}

Value *castZero(Builder &B, Value *Zero64, IntegerType *Ty) {
    auto *I64 = B.getInt64Ty();
    if (Ty == I64)
        return Zero64;
    if (Ty->getBitWidth() < 64)
        return B.CreateTrunc(Zero64, Ty, "morok.afm.outline.zero");
    return B.CreateZExt(Zero64, Ty, "morok.afm.outline.zero");
}

Function *createOutlineHelper(Module &M, const OutlineKey &Key,
                              ir::IRRandom &Rng) {
    LLVMContext &Ctx = M.getContext();
    auto *Ty = IntegerType::get(Ctx, Key.bits);
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *FT = FunctionType::get(Ty, {Ty, Ty}, false);
    auto *Fn =
        Function::Create(FT, GlobalValue::InternalLinkage,
                         (Twine("morok.afm.outline.") + opcodeName(Key.opcode) +
                          ".i" + Twine(Key.bits))
                             .str(),
                         &M);
    Fn->setDSOLocal(true);
    addGeneratedAttrs(Fn);

    GlobalVariable *KeyGV = createOutlineKey(M, Key, Rng);

    auto AI = Fn->arg_begin();
    Value *L = &*AI++;
    L->setName("lhs");
    Value *R = &*AI++;
    R->setName("rhs");

    Builder B(BasicBlock::Create(Ctx, "entry", Fn));
    Value *Base = B.CreateBinOp(static_cast<Instruction::BinaryOps>(Key.opcode),
                                L, R, "morok.afm.outline.base");
    auto *A = B.CreateLoad(I64, KeyGV, "morok.afm.outline.key.a");
    A->setVolatile(true);
    A->setAlignment(Align(8));
    auto *Bv = B.CreateLoad(I64, KeyGV, "morok.afm.outline.key.b");
    Bv->setVolatile(true);
    Bv->setAlignment(Align(8));
    Value *Zero64 = B.CreateXor(A, Bv, "morok.afm.outline.zero64");
    Value *Zero = castZero(B, Zero64, Ty);
    B.CreateRet(B.CreateXor(Base, Zero, "morok.afm.outline.value"));
    return Fn;
}

Function *getOutlineHelper(Module &M, std::vector<OutlineHelper> &Helpers,
                           const OutlineKey &Key, ir::IRRandom &Rng) {
    for (const OutlineHelper &H : Helpers)
        if (H.key.opcode == Key.opcode && H.key.bits == Key.bits)
            return H.helper;
    Function *Helper = createOutlineHelper(M, Key, Rng);
    Helpers.push_back({Key, Helper});
    return Helper;
}

bool outlineFragments(Module &M, ArrayRef<Function *> ImplFunctions,
                      const AdversarialMergeParams &Params, ir::IRRandom &Rng) {
    if (Params.outline_probability == 0 || Params.max_outlines == 0)
        return false;

    std::vector<BinaryOperator *> Targets;
    for (Function *Impl : ImplFunctions)
        for (Instruction &I : instructions(*Impl))
            if (auto *BO = dyn_cast<BinaryOperator>(&I))
                if (eligibleOutline(*BO))
                    Targets.push_back(BO);
    if (Targets.empty())
        return false;
    shuffleOutlines(Targets, Rng);

    std::vector<OutlineHelper> Helpers;
    std::uint32_t Outlined = 0;
    for (BinaryOperator *BO : Targets) {
        if (Outlined >= Params.max_outlines)
            break;
        if (!Rng.chance(Params.outline_probability))
            continue;
        auto *Ty = cast<IntegerType>(BO->getType());
        OutlineKey Key{BO->getOpcode(), Ty->getBitWidth()};
        Function *Helper = getOutlineHelper(M, Helpers, Key, Rng);

        Builder B(BO);
        CallInst *Call = B.CreateCall(Helper->getFunctionType(), Helper,
                                      {BO->getOperand(0), BO->getOperand(1)},
                                      "morok.afm.outline.value");
        BO->replaceAllUsesWith(Call);
        BO->eraseFromParent();
        ++Outlined;
    }

    for (Function *Impl : ImplFunctions)
        relaxFunctionEffects(*Impl);
    return Outlined != 0;
}

SmallVector<Function *, 8> impls(ArrayRef<MergedFunction> Merged) {
    SmallVector<Function *, 8> Out;
    for (const MergedFunction &MF : Merged)
        Out.push_back(MF.impl);
    return Out;
}

bool mergeGroup(Module &M, SignatureGroup &Group,
                const AdversarialMergeParams &Params, ir::IRRandom &Rng,
                std::uint32_t GroupIndex) {
    shuffleFunctions(Group.functions, Rng);

    std::vector<Function *> Selected;
    const std::uint32_t MaxFns =
        std::clamp<std::uint32_t>(Params.max_functions, 2, 16);
    for (Function *F : Group.functions) {
        if (Selected.size() >= MaxFns)
            break;
        if (!Rng.chance(Params.probability))
            continue;
        Selected.push_back(F);
    }
    if (Selected.size() < 2)
        return false;

    SmallVector<MergedFunction, 8> Merged;
    std::uint32_t Selector = 1;
    for (Function *F : Selected)
        Merged.push_back({F, cloneToImpl(*F, M), Selector++});

    SmallVector<Function *, 8> ImplFunctions = impls(Merged);
    outlineFragments(M, ArrayRef<Function *>(ImplFunctions), Params, Rng);

    Function *Dispatch = createDispatcher(
        M, Group, ArrayRef<MergedFunction>(Merged), GroupIndex);
    for (MergedFunction &MF : Merged)
        rewriteOriginalAsWrapper(MF, Dispatch, M, Rng);
    return true;
}

} // namespace

bool adversarialFunctionMergingModule(Module &M,
                                      const AdversarialMergeParams &Params,
                                      ir::IRRandom &Rng) {
    if (Params.probability == 0 || Params.max_groups == 0 ||
        Params.max_functions < 2 || hasExistingAfm(M))
        return false;

    std::vector<SignatureGroup> Groups = collectGroups(M);
    if (Groups.empty())
        return false;
    shuffleGroups(Groups, Rng);

    bool Changed = false;
    std::uint32_t ChangedGroups = 0;
    for (SignatureGroup &Group : Groups) {
        if (ChangedGroups >= Params.max_groups)
            break;
        if (!mergeGroup(M, Group, Params, Rng, ChangedGroups))
            continue;
        ++ChangedGroups;
        Changed = true;
    }
    return Changed;
}

PreservedAnalyses AdversarialFunctionMergingPass::run(Module &M,
                                                      ModuleAnalysisManager &) {
    ir::IRRandom Rng(engine_);
    return adversarialFunctionMergingModule(M, params_, Rng)
               ? PreservedAnalyses::none()
               : PreservedAnalyses::all();
}

} // namespace morok::passes
