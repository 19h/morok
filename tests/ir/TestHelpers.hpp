// SPDX-License-Identifier: MIT
//
// Shared test helpers for IR-level pass tests.
//
// General-purpose predicates and counters used across multiple test files.
// Domain-specific helpers (anti-debug, seal enforcement, etc.) stay in their
// respective test files.

#ifndef MOROK_TESTS_IR_TEST_HELPERS_HPP
#define MOROK_TESTS_IR_TEST_HELPERS_HPP

#include "doctest.h"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Twine.h"
#include "llvm/AsmParser/Parser.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace morok::test {

// ---------------------------------------------------------------------------
// IR parsing
// ---------------------------------------------------------------------------

inline std::unique_ptr<llvm::Module> parse(llvm::LLVMContext &ctx,
                                           const char *ir) {
    llvm::SMDiagnostic err;
    auto m = llvm::parseAssemblyString(ir, err, ctx);
    REQUIRE(m != nullptr);
    return m;
}

// ---------------------------------------------------------------------------
// Instruction counting
// ---------------------------------------------------------------------------

inline std::size_t countBinops(llvm::Function &F) {
    std::size_t n = 0;
    for (llvm::Instruction &I : llvm::instructions(F))
        if (llvm::isa<llvm::BinaryOperator>(&I))
            ++n;
    return n;
}

inline std::size_t countNamedAllocas(llvm::Function &F,
                                     llvm::StringRef prefix) {
    std::size_t n = 0;
    for (llvm::Instruction &I : llvm::instructions(F))
        if (auto *ai = llvm::dyn_cast<llvm::AllocaInst>(&I))
            if (ai->getName().starts_with(prefix))
                ++n;
    return n;
}

inline std::size_t countNamedAllocas(llvm::Module &M, llvm::StringRef prefix) {
    std::size_t n = 0;
    for (llvm::Function &F : M)
        if (!F.isDeclaration())
            n += countNamedAllocas(F, prefix);
    return n;
}

inline std::size_t countNamedAllocas(llvm::BasicBlock &BB,
                                     llvm::StringRef prefix) {
    std::size_t n = 0;
    for (llvm::Instruction &I : BB)
        if (auto *AI = llvm::dyn_cast<llvm::AllocaInst>(&I))
            if (AI->getName().starts_with(prefix))
                ++n;
    return n;
}

inline std::uint64_t maxStaticAllocaArrayBytes(llvm::Function &F,
                                               llvm::StringRef prefix) {
    std::uint64_t maxBytes = 0;
    for (llvm::Instruction &I : llvm::instructions(F)) {
        auto *AI = llvm::dyn_cast<llvm::AllocaInst>(&I);
        if (!AI || !AI->getName().starts_with(prefix))
            continue;
        auto *AT = llvm::dyn_cast<llvm::ArrayType>(AI->getAllocatedType());
        if (!AT || !AT->getElementType()->isIntegerTy(8))
            continue;
        maxBytes = std::max(maxBytes, AT->getNumElements());
    }
    return maxBytes;
}

inline std::uint64_t maxStaticAllocaArrayElements(llvm::Function &F,
                                                  llvm::StringRef prefix) {
    std::uint64_t maxElements = 0;
    for (llvm::Instruction &I : llvm::instructions(F)) {
        auto *AI = llvm::dyn_cast<llvm::AllocaInst>(&I);
        if (!AI || !AI->getName().starts_with(prefix))
            continue;
        auto *AT = llvm::dyn_cast<llvm::ArrayType>(AI->getAllocatedType());
        if (!AT)
            continue;
        maxElements = std::max(maxElements, AT->getNumElements());
    }
    return maxElements;
}

inline std::size_t countNamedInstructions(llvm::Function &F,
                                          llvm::StringRef prefix) {
    std::size_t n = 0;
    for (llvm::Instruction &I : llvm::instructions(F))
        if (I.getName().starts_with(prefix))
            ++n;
    return n;
}

inline std::size_t countNamedInstructions(llvm::Module &M,
                                          llvm::StringRef prefix) {
    std::size_t n = 0;
    for (llvm::Function &F : M)
        if (!F.isDeclaration())
            n += countNamedInstructions(F, prefix);
    return n;
}

inline std::size_t countPhis(llvm::Function &F) {
    std::size_t n = 0;
    for (llvm::BasicBlock &BB : F)
        for (llvm::Instruction &I : BB)
            if (llvm::isa<llvm::PHINode>(&I))
                ++n;
            else
                break; // PHIs are always at the start of a block
    return n;
}

inline std::size_t countOpcode(llvm::Module &M, unsigned opcode) {
    std::size_t n = 0;
    for (llvm::Function &F : M)
        for (llvm::Instruction &I : llvm::instructions(F))
            if (I.getOpcode() == opcode)
                ++n;
    return n;
}

inline std::size_t countGlobals(llvm::Module &M, llvm::StringRef prefix) {
    std::size_t n = 0;
    for (llvm::GlobalVariable &G : M.globals())
        if (G.getName().starts_with(prefix))
            ++n;
    return n;
}

inline std::size_t countFunctions(llvm::Module &M, llvm::StringRef prefix) {
    std::size_t n = 0;
    for (llvm::Function &F : M)
        if (F.getName().starts_with(prefix))
            ++n;
    return n;
}

inline std::size_t countAliases(llvm::Module &M) {
    std::size_t n = 0;
    for (auto &A : M.aliases())
        (void)A, ++n;
    return n;
}

inline std::size_t countCallsTo(llvm::Function &F, llvm::StringRef name) {
    std::size_t n = 0;
    for (llvm::Instruction &I : llvm::instructions(F))
        if (auto *CI = llvm::dyn_cast<llvm::CallInst>(&I))
            if (CI->getCalledFunction() &&
                CI->getCalledFunction()->getName() == name)
                ++n;
    return n;
}

inline std::size_t countCallsToPrefix(llvm::Function &F,
                                      llvm::StringRef prefix) {
    std::size_t n = 0;
    for (llvm::Instruction &I : llvm::instructions(F))
        if (auto *CI = llvm::dyn_cast<llvm::CallInst>(&I))
            if (CI->getCalledFunction() &&
                CI->getCalledFunction()->getName().starts_with(prefix))
                ++n;
    return n;
}

inline std::size_t countCallsTo(llvm::BasicBlock &BB, llvm::StringRef name) {
    std::size_t n = 0;
    for (llvm::Instruction &I : BB)
        if (auto *CI = llvm::dyn_cast<llvm::CallInst>(&I))
            if (CI->getCalledFunction() &&
                CI->getCalledFunction()->getName() == name)
                ++n;
    return n;
}

inline std::size_t countCallsThroughOperand(llvm::Function &F,
                                            const llvm::Value *Target) {
    std::size_t n = 0;
    for (llvm::Instruction &I : llvm::instructions(F))
        if (auto *CI = llvm::dyn_cast<llvm::CallInst>(&I))
            if (CI->getCalledOperand() == Target)
                ++n;
    return n;
}

// ---------------------------------------------------------------------------
// Instruction lookup and predicates
// ---------------------------------------------------------------------------

inline llvm::Instruction *findNamedInstruction(llvm::Function &F,
                                               llvm::StringRef name) {
    for (llvm::Instruction &I : llvm::instructions(F))
        if (I.getName() == name)
            return &I;
    return nullptr;
}

inline bool namedInstructionPrecedes(llvm::Function &F,
                                     llvm::StringRef firstPrefix,
                                     llvm::StringRef secondPrefix) {
    bool sawFirst = false;
    for (llvm::Instruction &I : llvm::instructions(F)) {
        if (I.getName().starts_with(firstPrefix))
            sawFirst = true;
        if (I.getName().starts_with(secondPrefix))
            return sawFirst;
    }
    return false;
}

inline bool namedConditionBranchesTo(llvm::Function &F,
                                     llvm::StringRef conditionPrefix,
                                     llvm::StringRef trueSuccessorPrefix) {
    for (llvm::BasicBlock &BB : F) {
        auto *BI = llvm::dyn_cast<llvm::BranchInst>(BB.getTerminator());
        if (!BI || !BI->isConditional())
            continue;
        llvm::Value *Cond = BI->getCondition();
        if (Cond->hasName() && Cond->getName().starts_with(conditionPrefix) &&
            BI->getSuccessor(0)->getName().starts_with(trueSuccessorPrefix))
            return true;
    }
    return false;
}

inline bool hasNamedInstructionContaining(llvm::Function &F,
                                         llvm::StringRef needle) {
    for (llvm::Instruction &I : llvm::instructions(F))
        if (I.getName().contains(needle))
            return true;
    return false;
}

inline bool namedCallHasConstantArg(llvm::Function &F, llvm::StringRef name,
                                    unsigned arg, std::uint64_t expected) {
    auto *CI =
        llvm::dyn_cast_or_null<llvm::CallInst>(findNamedInstruction(F, name));
    if (!CI || arg >= CI->arg_size())
        return false;
    auto *C = llvm::dyn_cast<llvm::ConstantInt>(CI->getArgOperand(arg));
    return C && C->getZExtValue() == expected;
}

inline bool instructionHasConstantOperand(llvm::Instruction *I,
                                          std::uint64_t Expected) {
    if (!I)
        return false;
    for (llvm::Value *Op : I->operands())
        if (auto *CI = llvm::dyn_cast<llvm::ConstantInt>(Op))
            if (CI->getZExtValue() == Expected)
                return true;
    return false;
}

// Byte offset of a gepI8-emitted `getelementptr i8, ptr Base, ip <off>` named
// `name`. Returns -1 if the instruction is missing or not a constant-offset
// i8 GEP.
inline long long namedGepByteOffset(llvm::Function &F, llvm::StringRef name) {
    auto *GEP = llvm::dyn_cast_or_null<llvm::GetElementPtrInst>(
        findNamedInstruction(F, name));
    if (!GEP || GEP->getNumOperands() != 2)
        return -1;
    auto *Idx = llvm::dyn_cast<llvm::ConstantInt>(GEP->getOperand(1));
    if (!Idx)
        return -1;
    return static_cast<long long>(Idx->getZExtValue());
}

inline bool valueFeedsNamedInstruction(llvm::Value *Root,
                                       llvm::StringRef prefix) {
    llvm::SmallVector<llvm::Value *, 16> worklist;
    llvm::SmallPtrSet<llvm::Value *, 32> seen;
    worklist.push_back(Root);
    seen.insert(Root);
    while (!worklist.empty()) {
        llvm::Value *cur = worklist.pop_back_val();
        for (llvm::User *U : cur->users()) {
            if (auto *I = llvm::dyn_cast<llvm::Instruction>(U)) {
                if (I->getName().starts_with(prefix))
                    return true;
            }
            llvm::Value *V = U;
            if (seen.insert(V).second)
                worklist.push_back(V);
        }
    }
    return false;
}

inline bool constantReferencesGlobal(const llvm::Constant *C,
                                     const llvm::GlobalValue *GV) {
    for (unsigned i = 0; i < C->getNumOperands(); ++i) {
        auto *Op = llvm::dyn_cast<llvm::Constant>(C->getOperand(i));
        if (!Op)
            continue;
        if (Op == GV)
            return true;
        if (constantReferencesGlobal(Op, GV))
            return true;
    }
    return false;
}

inline bool hasReadableByteString(llvm::Module &M, llvm::StringRef needle) {
    for (llvm::GlobalVariable &G : M.globals()) {
        if (!G.hasInitializer())
            continue;
        auto *CDA = llvm::dyn_cast<llvm::ConstantDataArray>(G.getInitializer());
        if (!CDA)
            continue;
        if (CDA->isCString() && CDA->getAsCString().contains(needle))
            return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Module verification
// ---------------------------------------------------------------------------

inline bool verifyModule(llvm::Module &M) {
    return llvm::verifyModule(M, &llvm::errs());
}

} // namespace morok::test

#endif // MOROK_TESTS_IR_TEST_HELPERS_HPP
