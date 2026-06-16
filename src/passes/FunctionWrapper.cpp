// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/FunctionWrapper.cpp
//
// Direct calls and invokes are wrapped: intrinsics, inline asm, operand-bundle
// call sites, `callbr`, and `musttail` calls are left alone.  Variadic callees
// get a site-specific non-variadic wrapper matching the concrete argument list.

#include "morok/passes/FunctionWrapper.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <algorithm>
#include <cstdint>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr std::uint32_t kMaxWrappersPerModule = 256;

bool wrappable(CallBase *cb) {
    if (!isa<CallInst>(cb) && !isa<InvokeInst>(cb))
        return false;
    if (cb->isInlineAsm() || cb->hasOperandBundles())
        return false;
    if (auto *ci = dyn_cast<CallInst>(cb))
        if (ci->isMustTailCall())
            return false;
    Function *callee = cb->getCalledFunction();
    if (!callee || callee->isIntrinsic())
        return false;
    if (callee->getName().starts_with("morok."))
        return false;
    return true;
}

FunctionType *wrapperTypeFor(CallBase &cb) {
    Function *callee = cb.getCalledFunction();
    FunctionType *calleeTy = callee->getFunctionType();
    if (!calleeTy->isVarArg())
        return calleeTy;

    std::vector<Type *> params;
    params.reserve(cb.arg_size());
    for (Use &arg : cb.args())
        params.push_back(arg->getType());
    return FunctionType::get(calleeTy->getReturnType(), params,
                             /*isVarArg=*/false);
}

// Build an internal forwarder with either the callee's exact signature or, for
// variadic callees, the concrete argument list used by this call site.
Function *makeForwarder(Module &M, CallBase &cb) {
    Function *callee = cb.getCalledFunction();
    FunctionType *calleeTy = callee->getFunctionType();
    FunctionType *wrapTy = wrapperTypeFor(cb);
    auto *wrap =
        Function::Create(wrapTy, GlobalValue::InternalLinkage, "morok.wrap", &M);
    wrap->setCallingConv(cb.getCallingConv());
    // Carry the call site's parameter/return/function attributes onto both the
    // forwarder declaration and the forwarded call, so ABI attributes
    // (byval/sret/swifterror/align/...) survive the extra indirection instead
    // of being silently dropped.
    const AttributeList AL = cb.getAttributes();
    wrap->setAttributes(AL);

    IRBuilder<> B(BasicBlock::Create(M.getContext(), "entry", wrap));
    std::vector<Value *> args;
    args.reserve(wrap->arg_size());
    for (Argument &a : wrap->args())
        args.push_back(&a);
    CallInst *fwd = B.CreateCall(calleeTy, callee, args);
    fwd->setCallingConv(cb.getCallingConv());
    fwd->setAttributes(AL);
    if (!calleeTy->isVarArg())
        fwd->setTailCall();
    if (calleeTy->getReturnType()->isVoidTy())
        B.CreateRetVoid();
    else
        B.CreateRet(fwd);
    return wrap;
}

} // namespace

bool functionWrapModule(Module &M, const FuncWrapParams &params,
                        ir::IRRandom &rng) {
    if (params.probability == 0 || params.max_wrappers == 0)
        return false;

    const std::uint32_t MaxWrappers =
        std::min(params.max_wrappers, kMaxWrappersPerModule);
    const std::uint32_t times = params.times ? params.times : 1;
    bool changed = false;
    std::uint32_t wrappers = 0;

    for (std::uint32_t round = 0; round < times; ++round) {
        if (wrappers >= MaxWrappers)
            return changed;
        const std::uint32_t Remaining = MaxWrappers - wrappers;
        std::vector<CallBase *> targets;
        targets.reserve(Remaining);
        for (Function &F : M) {
            if (targets.size() >= Remaining)
                break;
            if (F.isDeclaration() || F.getName().starts_with("morok."))
                continue;
            for (Instruction &inst : instructions(F)) {
                if (targets.size() >= Remaining)
                    break;
                if (auto *cb = dyn_cast<CallBase>(&inst))
                    if (wrappable(cb))
                        if (rng.chance(params.probability))
                            targets.push_back(cb);
            }
        }

        for (CallBase *cb : targets) {
            Function *forwarder = makeForwarder(M, *cb);
            cb->setCalledFunction(forwarder);
            ++wrappers;
            changed = true;
        }
    }
    return changed;
}

PreservedAnalyses FunctionWrapperPass::run(Module &M, ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return functionWrapModule(M, params_, rng) ? PreservedAnalyses::none()
                                               : PreservedAnalyses::all();
}

} // namespace morok::passes
