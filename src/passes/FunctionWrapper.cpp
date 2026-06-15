// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/passes/FunctionWrapper.cpp
//
// Only ordinary direct calls are wrapped: variadic callees, intrinsics, inline
// asm, operand-bundle calls, and `musttail` calls are left alone, so the
// forwarder always has a well-defined, type-identical signature.

#include "morok/passes/FunctionWrapper.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

bool wrappable(CallInst *ci) {
    if (ci->isInlineAsm() || ci->hasOperandBundles())
        return false;
    if (ci->isMustTailCall())
        return false;
    Function *callee = ci->getCalledFunction();
    if (!callee || callee->isIntrinsic() || callee->isVarArg())
        return false;
    if (callee->getName().starts_with("morok."))
        return false;
    return true;
}

// Build an internal forwarder with the callee's exact signature.
Function *makeForwarder(Module &M, Function *callee) {
    FunctionType *ft = callee->getFunctionType();
    auto *wrap =
        Function::Create(ft, GlobalValue::InternalLinkage, "morok.wrap", &M);
    wrap->setCallingConv(callee->getCallingConv());

    IRBuilder<> B(BasicBlock::Create(M.getContext(), "entry", wrap));
    std::vector<Value *> args;
    args.reserve(wrap->arg_size());
    for (Argument &a : wrap->args())
        args.push_back(&a);
    CallInst *fwd = B.CreateCall(ft, callee, args);
    fwd->setCallingConv(callee->getCallingConv());
    fwd->setTailCall();
    if (ft->getReturnType()->isVoidTy())
        B.CreateRetVoid();
    else
        B.CreateRet(fwd);
    return wrap;
}

} // namespace

bool functionWrapModule(Module &M, const FuncWrapParams &params,
                        ir::IRRandom &rng) {
    const std::uint32_t times = params.times ? params.times : 1;
    bool changed = false;

    for (std::uint32_t round = 0; round < times; ++round) {
        std::vector<CallInst *> targets;
        for (Function &F : M) {
            if (F.isDeclaration() || F.getName().starts_with("morok."))
                continue;
            for (Instruction &inst : instructions(F))
                if (auto *ci = dyn_cast<CallInst>(&inst))
                    if (wrappable(ci))
                        targets.push_back(ci);
        }

        for (CallInst *ci : targets) {
            if (!rng.chance(params.probability))
                continue;
            Function *forwarder = makeForwarder(M, ci->getCalledFunction());
            ci->setCalledFunction(forwarder);
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
