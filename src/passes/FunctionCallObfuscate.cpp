// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/FunctionCallObfuscate.cpp
//
// Each eligible direct call to an external function `f(args)` becomes
//   p = dlsym(RTLD_DEFAULT, "f"); p(args)
// so the static import/call edge to `f` disappears.  Only declared (external)
// symbols are redirected — locally-defined functions stay direct, since dlsym
// would not resolve them.

#include "morok/passes/FunctionCallObfuscate.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/TargetParser/Triple.h"

#include <algorithm>
#include <cstdint>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr std::uint32_t kMaxCallsPerModule = 256;

bool eligible(CallInst *ci) {
    if (ci->isInlineAsm() || ci->hasOperandBundles() || ci->isMustTailCall())
        return false;
    Function *callee = ci->getCalledFunction();
    if (!callee || !callee->isDeclaration() || callee->isIntrinsic())
        return false;
    if (callee->getName().starts_with("llvm.") ||
        callee->getName().starts_with("morok.") || callee->getName() == "dlsym")
        return false;
    return true;
}

} // namespace

bool functionCallObfuscateModule(Module &M, const FcoParams &params,
                                 ir::IRRandom &rng) {
    if (params.probability == 0 || params.max_calls == 0)
        return false;

    const std::uint32_t Limit = std::min(params.max_calls, kMaxCallsPerModule);

    std::vector<CallInst *> targets;
    targets.reserve(Limit);
    for (Function &F : M) {
        if (targets.size() >= Limit)
            break;
        if (F.isDeclaration() || F.getName().starts_with("morok."))
            continue;
        for (Instruction &inst : instructions(F)) {
            if (targets.size() >= Limit)
                break;
            if (auto *ci = dyn_cast<CallInst>(&inst))
                if (eligible(ci))
                    if (rng.chance(params.probability))
                        targets.push_back(ci);
        }
    }
    if (targets.empty())
        return false;

    LLVMContext &ctx = M.getContext();
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);
    const Triple tt(M.getTargetTriple());
    const int rtldDefaultVal = tt.isOSDarwin() ? -2 : 0; // RTLD_DEFAULT

    FunctionCallee dlsym = M.getOrInsertFunction(
        "dlsym", FunctionType::get(ptr, {ptr, ptr}, false));

    bool changed = false;
    for (CallInst *ci : targets) {
        Function *callee = ci->getCalledFunction();

        IRBuilder<> B(ci);
        Constant *name = B.CreateGlobalString(callee->getName(), "morok.sym");
        Value *rtld =
            B.CreateIntToPtr(ConstantInt::getSigned(i64, rtldDefaultVal), ptr);
        Value *resolved = B.CreateCall(dlsym, {rtld, name});

        std::vector<Value *> args(ci->arg_begin(), ci->arg_end());
        CallInst *indirect =
            B.CreateCall(callee->getFunctionType(), resolved, args);
        indirect->setCallingConv(ci->getCallingConv());
        indirect->setAttributes(ci->getAttributes());

        ci->replaceAllUsesWith(indirect);
        ci->eraseFromParent();
        changed = true;
    }
    return changed;
}

PreservedAnalyses FunctionCallObfuscatePass::run(Module &M,
                                                 ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return functionCallObfuscateModule(M, params_, rng)
               ? PreservedAnalyses::none()
               : PreservedAnalyses::all();
}

} // namespace morok::passes
