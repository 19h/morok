// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/passes/AntiAnalysis.cpp
//
// Each pass injects a startup constructor (or inspects metadata).  The injected
// code is inert in an un-instrumented run, so program behaviour is unchanged.

#include "morok/passes/AntiAnalysis.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

namespace morok::passes {

namespace {

Function *makeCtorShell(Module &M, const char *name) {
    auto *fn = Function::Create(
        FunctionType::get(Type::getVoidTy(M.getContext()), false),
        GlobalValue::InternalLinkage, name, &M);
    BasicBlock::Create(M.getContext(), "entry", fn);
    return fn;
}

} // namespace

bool antiDebuggingModule(Module &M) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);
    const Triple tt(M.getTargetTriple());

    // ptrace request that denies attachment: PT_DENY_ATTACH (31) on Darwin,
    // PTRACE_TRACEME (0) elsewhere — both make subsequent attaches fail.
    const int request = tt.isOSDarwin() ? 31 : 0;

    FunctionCallee ptrace = M.getOrInsertFunction(
        "ptrace", FunctionType::get(i32, {i32, i32, ptr, i32}, false));

    Function *ctor = makeCtorShell(M, "morok.antidbg");
    IRBuilder<> B(&ctor->getEntryBlock());
    B.CreateCall(
        ptrace, {ConstantInt::getSigned(i32, request), ConstantInt::get(i32, 0),
                 ConstantPointerNull::get(ptr), ConstantInt::get(i32, 0)});
    B.CreateRetVoid();
    appendToGlobalCtors(M, ctor, 0);
    return true;
}

bool antiHookingModule(Module &M) {
    LLVMContext &ctx = M.getContext();
    auto *i32 = Type::getInt32Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);

    // Detect a resident function-hooking framework: if its entry point
    // resolves, the process is being instrumented — bail out.
    FunctionCallee dlsym = M.getOrInsertFunction(
        "dlsym", FunctionType::get(ptr, {ptr, ptr}, false));
    FunctionCallee exitFn = M.getOrInsertFunction(
        "exit", FunctionType::get(Type::getVoidTy(ctx), {i32}, false));

    Function *ctor = makeCtorShell(M, "morok.antihook");
    IRBuilder<> B(&ctor->getEntryBlock());
    Constant *sym = B.CreateGlobalString("MSHookFunction", "morok.hooksym");
    // RTLD_DEFAULT == (void*)-2; build it at pointer width so inttoptr does not
    // zero-extend a 32-bit value into the wrong handle.
    auto *i64 = Type::getInt64Ty(ctx);
    Value *rtldDefault = B.CreateIntToPtr(ConstantInt::getSigned(i64, -2), ptr);
    Value *found = B.CreateCall(dlsym, {rtldDefault, sym});
    Value *hooked = B.CreateICmpNE(found, ConstantPointerNull::get(ptr));

    auto *bail = BasicBlock::Create(ctx, "bail", ctor);
    auto *cont = BasicBlock::Create(ctx, "cont", ctor);
    B.CreateCondBr(hooked, bail, cont);

    IRBuilder<> BB(bail);
    BB.CreateCall(exitFn, {ConstantInt::get(i32, 1)});
    BB.CreateUnreachable();

    IRBuilder<> CB(cont);
    CB.CreateRetVoid();
    appendToGlobalCtors(M, ctor, 0);
    return true;
}

bool antiClassDumpModule(Module &M) {
    // Objective-C metadata lives in __objc_* sections / OBJC_* globals.  Only
    // act when such metadata exists; plain C/C++ modules have none, so this is
    // a safe no-op there.
    bool hasObjC = false;
    for (GlobalVariable &gv : M.globals()) {
        StringRef sec = gv.getSection();
        if (gv.getName().starts_with("OBJC_") || sec.contains("__objc")) {
            hasObjC = true;
            break;
        }
    }
    if (!hasObjC)
        return false;

    // Scramble the names of private Objective-C metadata globals so class-dump
    // style tools cannot recover symbol names from the metadata.
    bool changed = false;
    for (GlobalVariable &gv : M.globals()) {
        if (gv.hasLocalLinkage() && gv.getName().starts_with("OBJC_")) {
            gv.setName("morok.objc");
            changed = true;
        }
    }
    return changed;
}

PreservedAnalyses AntiDebuggingPass::run(Module &M, ModuleAnalysisManager &) {
    return antiDebuggingModule(M) ? PreservedAnalyses::none()
                                  : PreservedAnalyses::all();
}
PreservedAnalyses AntiHookingPass::run(Module &M, ModuleAnalysisManager &) {
    return antiHookingModule(M) ? PreservedAnalyses::none()
                                : PreservedAnalyses::all();
}
PreservedAnalyses AntiClassDumpPass::run(Module &M, ModuleAnalysisManager &) {
    return antiClassDumpModule(M) ? PreservedAnalyses::none()
                                  : PreservedAnalyses::all();
}

} // namespace morok::passes
