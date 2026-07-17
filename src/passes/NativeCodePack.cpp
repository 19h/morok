// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.

#include "morok/passes/NativeCodePack.hpp"

#include "morok/ir/Annotations.hpp"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/TargetParser/Triple.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr StringLiteral kBodySection(".morok.npack.text");
constexpr StringLiteral kStubSection(".text.morok.npack.stub");
constexpr StringLiteral kOpenSymbol("__morok_npack_open");

SmallPtrSet<Function *, 16> collectEarlyFunctions(Module &M) {
    SmallPtrSet<Function *, 16> Out;
    for (StringRef Name : {"llvm.global_ctors", "llvm.global_dtors"}) {
        GlobalVariable *GV = M.getGlobalVariable(Name);
        if (!GV || !GV->hasInitializer())
            continue;
        auto *Array = dyn_cast<ConstantArray>(GV->getInitializer());
        if (!Array)
            continue;
        for (Value *Op : Array->operands()) {
            auto *Entry = dyn_cast<ConstantStruct>(Op);
            if (!Entry || Entry->getNumOperands() < 2)
                continue;
            if (auto *F = dyn_cast<Function>(
                    Entry->getOperand(1)->stripPointerCasts()))
                Out.insert(F);
        }
    }
    return Out;
}

bool hasBlockAddressUse(const Function &F) {
    for (const User *U : F.users())
        if (isa<BlockAddress>(U))
            return true;
    return false;
}

bool hasUnsupportedAbi(const Function &F) {
    if (F.isVarArg() || F.getReturnType()->isTokenTy())
        return true;
    if (F.hasFnAttribute(Attribute::Naked) ||
        F.hasFnAttribute(Attribute::ReturnsTwice) ||
        F.hasFnAttribute(Attribute::Builtin) ||
        F.hasFnAttribute("interrupt") || F.hasFnAttribute("presplitcoroutine"))
        return true;
    for (const Argument &A : F.args())
        if (A.getType()->isTokenTy() || A.hasAttribute(Attribute::SwiftError))
            return true;
    return hasBlockAddressUse(F);
}

bool eligible(Function &F, const NativeCodePackParams &P,
              const SmallPtrSetImpl<Function *> &Early,
              bool HasSchedulerMarks) {
    if (F.isDeclaration() || F.isIntrinsic() || F.hasAvailableExternallyLinkage() ||
        F.empty() || Early.contains(&F))
        return false;
    if (F.getName() == kOpenSymbol ||
        F.getName().starts_with("__morok_npack_") ||
        F.getName().starts_with("morok.npack."))
        return false;
    if (ir::hasAnnotation(F, "nonativepack"))
        return false;
    const bool Forced = ir::hasAnnotation(F, "nativepack");
    // The scheduler marks source functions after its per-function wave.  Late
    // decoy/metadata passes deliberately emit plausible non-morok symbol names,
    // so a name-prefix test alone would mistake those generated helpers for
    // user code and wrap unsupported synthetic ABIs.
    if (!Forced && !P.protect_generated &&
        ((HasSchedulerMarks && !F.hasFnAttribute("morok.reached")) ||
         F.getName().starts_with("morok.")))
        return false;
    if (!Forced && !F.getSection().empty())
        return false;
    if (hasUnsupportedAbi(F))
        return false;
    return Forced || F.getInstructionCount() >= P.min_instructions;
}

void stripInvalidMemoryAttributes(Function &F) {
    F.removeFnAttr(Attribute::Memory);
    F.removeFnAttr(Attribute::NoSync);
    F.removeFnAttr(Attribute::Speculatable);
    F.removeFnAttr(Attribute::NoRecurse);
}

struct StubInfo {
    Function *stub = nullptr;
    BasicBlock *ready = nullptr;
};

StubInfo makeStub(Module &M, Function &Body, StringRef PublicName,
                  GlobalValue::LinkageTypes Linkage,
                  GlobalValue::VisibilityTypes Visibility,
                  GlobalValue::DLLStorageClassTypes DllStorage,
                  bool DsoLocal, GlobalValue::UnnamedAddr Unnamed,
                  MaybeAlign Alignment, Comdat *OriginalComdat,
                  std::uint64_t Id) {
    Function *Stub = Function::Create(Body.getFunctionType(), Linkage,
                                      Body.getAddressSpace(), PublicName, &M);
    Stub->setCallingConv(Body.getCallingConv());
    Stub->setAttributes(Body.getAttributes());
    Stub->setVisibility(Visibility);
    Stub->setDLLStorageClass(DllStorage);
    Stub->setDSOLocal(DsoLocal);
    Stub->setUnnamedAddr(Unnamed);
    if (OriginalComdat)
        Stub->setComdat(OriginalComdat);
    if (Body.hasPartition())
        Stub->setPartition(Body.getPartition());
    for (unsigned Kind : {LLVMContext::MD_type, LLVMContext::MD_kcfi_type}) {
        SmallVector<MDNode *, 2> Nodes;
        Body.getMetadata(Kind, Nodes);
        for (MDNode *Node : Nodes)
            Stub->addMetadata(Kind, *Node);
    }
    Stub->setSection(kStubSection);
    if (Alignment)
        Stub->setAlignment(*Alignment);
    Stub->removeFnAttr(Attribute::AlwaysInline);
    Stub->addFnAttr(Attribute::NoInline);
    stripInvalidMemoryAttributes(*Stub);

    auto BodyArg = Body.arg_begin();
    for (Argument &A : Stub->args()) {
        A.setName(BodyArg->getName());
        ++BodyArg;
    }

    BasicBlock *Entry =
        BasicBlock::Create(M.getContext(), "morok.npack.entry", Stub);
    BasicBlock *Ready =
        BasicBlock::Create(M.getContext(), "morok.npack.ready", Stub);
    BasicBlock *Failed =
        BasicBlock::Create(M.getContext(), "morok.npack.failed", Stub);
    IRBuilder<> B(Entry);
    FunctionType *OpenTy = FunctionType::get(B.getInt32Ty(), false);
    FunctionCallee Open = M.getOrInsertFunction(kOpenSymbol, OpenTy);
    if (Function *OpenFn = dyn_cast<Function>(Open.getCallee())) {
        OpenFn->setVisibility(GlobalValue::HiddenVisibility);
        OpenFn->setDSOLocal(true);
    }
    CallInst *Status = B.CreateCall(Open, {}, "");
    Status->setDoesNotThrow();
    // Every entry site carries a distinct volatile equation.  Two volatile
    // reads prevent the optimizer from cancelling the guard into the uniform
    // `status == 0` signature, while the odd multiplier makes zero the sole
    // successful status in Z/(2^32).
    const std::uint32_t GuardValue = static_cast<std::uint32_t>(Id);
    const std::uint32_t Odd = static_cast<std::uint32_t>(Id >> 32) | 1u;
    auto *Guard = new GlobalVariable(
        M, B.getInt32Ty(), /*isConstant=*/false, GlobalValue::PrivateLinkage,
        B.getInt32(GuardValue), "morok.npack.guard." + std::to_string(Id));
    Guard->setAlignment(Align(4));
    LoadInst *Before = B.CreateLoad(B.getInt32Ty(), Guard);
    Before->setVolatile(true);
    Value *Encoded = B.CreateXor(B.CreateMul(Status, B.getInt32(Odd)), Before);
    LoadInst *After = B.CreateLoad(B.getInt32Ty(), Guard);
    After->setVolatile(true);
    B.CreateCondBr(B.CreateICmpEQ(Encoded, After), Ready, Failed);

    B.SetInsertPoint(Failed);
    Function *Trap = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::trap);
    B.CreateCall(Trap);
    B.CreateUnreachable();
    return {Stub, Ready};
}

bool wrapFunction(Module &M, Function &F, std::uint64_t Id) {
    const std::string PublicName = F.getName().str();
    const auto Linkage = F.getLinkage();
    const auto Visibility = F.getVisibility();
    const auto DllStorage = F.getDLLStorageClass();
    const bool DsoLocal = F.isDSOLocal();
    const auto Unnamed = F.getUnnamedAddr();
    const MaybeAlign Alignment = F.getAlign();
    Comdat *OriginalComdat = F.getComdat();

    F.setName("morok.npack.body." + std::to_string(Id));
    const StubInfo Info = makeStub(M, F, PublicName, Linkage, Visibility,
                                   DllStorage, DsoLocal, Unnamed, Alignment,
                                   OriginalComdat, Id);
    Function *Stub = Info.stub;

    F.replaceAllUsesWith(Stub);
    // Create the implementation call only after RAUW so it remains the one
    // direct plaintext-to-ciphertext edge.  The sole unterminated block is the
    // ready path established by makeStub().
    BasicBlock *Ready = Info.ready;
    if (!Ready)
        return false;
    SmallVector<Value *, 16> Args;
    for (Argument &A : Stub->args())
        Args.push_back(&A);
    IRBuilder<> B(Ready);
    CallInst *BodyCall = B.CreateCall(F.getFunctionType(), &F, Args);
    BodyCall->setCallingConv(F.getCallingConv());
    BodyCall->setAttributes(F.getAttributes());
    BodyCall->setTailCallKind(CallInst::TCK_Tail);
    if (F.doesNotReturn())
        B.CreateUnreachable();
    else if (F.getReturnType()->isVoidTy())
        B.CreateRetVoid();
    else
        B.CreateRet(BodyCall);

    F.setLinkage(GlobalValue::PrivateLinkage);
    F.setVisibility(GlobalValue::DefaultVisibility);
    F.setDLLStorageClass(GlobalValue::DefaultStorageClass);
    F.setDSOLocal(true);
    F.setUnnamedAddr(GlobalValue::UnnamedAddr::None);
    F.setComdat(nullptr);
    F.setSection(kBodySection);
    F.removeFnAttr(Attribute::AlwaysInline);
    F.addFnAttr(Attribute::NoInline);
    stripInvalidMemoryAttributes(F);
    return true;
}

} // namespace

bool nativeCodePackModule(Module &M, const NativeCodePackParams &P,
                          ir::IRRandom &Rng) {
    if (!P.enabled || P.probability == 0 || P.max_functions == 0)
        return false;

    const Triple TT(M.getTargetTriple());
    if (!TT.isOSLinux() || !TT.isArch64Bit()) {
        M.getContext().emitError(
            "Morok native_code_pack supports Linux ELF64 targets only");
        return false;
    }

    ir::materializeAnnotations(M);
    const SmallPtrSet<Function *, 16> Early = collectEarlyFunctions(M);
    const bool HasSchedulerMarks =
        std::any_of(M.begin(), M.end(), [](const Function &F) {
            return F.hasFnAttribute("morok.reached");
        });
    std::vector<Function *> Candidates;
    for (Function &F : M)
        if (eligible(F, P, Early, HasSchedulerMarks))
            Candidates.push_back(&F);

    for (std::size_t I = Candidates.size(); I > 1; --I)
        std::swap(Candidates[I - 1],
                  Candidates[Rng.range(static_cast<std::uint32_t>(I))]);

    bool Changed = false;
    std::uint32_t Packed = 0;
    for (Function *F : Candidates) {
        if (Packed >= P.max_functions)
            break;
        const bool Forced = ir::hasAnnotation(*F, "nativepack");
        if (!Forced && !Rng.chance(P.probability))
            continue;
        if (wrapFunction(M, *F, Rng.next())) {
            ++Packed;
            Changed = true;
        }
    }
    return Changed;
}

PreservedAnalyses NativeCodePackPass::run(Module &M,
                                          ModuleAnalysisManager &) {
    ir::IRRandom Rng(engine_);
    return nativeCodePackModule(M, params_, Rng)
               ? PreservedAnalyses::none()
               : PreservedAnalyses::all();
}

} // namespace morok::passes
