// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/passes/ChaosStateMachine.cpp
//
// The emitted `step` IR reproduces morok::core::chaos::step bit-for-bit, so the
// compile-time correction constants (core::chaos::correction) telescope
// exactly:
//   next = step(current) XOR (step(current_id) XOR successor_id) ==
//   successor_id.

#include "morok/passes/ChaosStateMachine.hpp"

#include "morok/core/LogisticMap.hpp"
#include "morok/ir/ControlFlowFlattener.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"

using namespace llvm;

namespace morok::passes {

namespace {

// Emit the logistic-map step in Q16 fixed point — identical arithmetic to
// morok::core::chaos::step.  Input/output are i32.
Value *emitStep(IRBuilder<> &B, Value *x) {
    auto *i32 = B.getInt32Ty();
    auto *i64 = B.getInt64Ty();
    namespace chaos = core::chaos;

    Value *xc = B.CreateAnd(x, ConstantInt::get(i32, 0xFFFF));
    Value *isZero = B.CreateICmpEQ(xc, ConstantInt::get(i32, 0));
    xc = B.CreateSelect(isZero, ConstantInt::get(i32, chaos::kInputGuard), xc);
    Value *xc64 = B.CreateZExt(xc, i64);
    Value *inv = B.CreateSub(ConstantInt::get(i64, chaos::kOne), xc64);
    Value *prod = B.CreateMul(xc64, inv);
    Value *scaled = B.CreateMul(prod, ConstantInt::get(i64, chaos::kRScaled));
    Value *shifted = B.CreateLShr(scaled, ConstantInt::get(i64, 30));
    Value *next = B.CreateTrunc(shifted, i32);
    Value *isZero2 = B.CreateICmpEQ(next, ConstantInt::get(i32, 0));
    return B.CreateSelect(isZero2, ConstantInt::get(i32, chaos::kOutputGuard),
                          next);
}

} // namespace

bool chaosStateMachineFunction(Function &F, ir::IRRandom &rng) {
    return ir::flattenControlFlow(
        F, rng,
        [](IRBuilder<> &B, AllocaInst *stateVar, std::uint32_t currentId,
           const ir::SuccessorIds &s) -> Value * {
            auto *i32 = B.getInt32Ty();
            Value *cur = B.CreateLoad(i32, stateVar, "csm.cur");
            Value *stepped = emitStep(B, cur);
            // Pick the correction for the taken edge, then telescope:
            //   next = step(cur) XOR (step(currentId) XOR targetId) ==
            //   targetId.
            Value *corr = ConstantInt::get(
                i32, core::chaos::correction(currentId, s.defaultId));
            for (auto it = s.arms.rbegin(); it != s.arms.rend(); ++it)
                corr = B.CreateSelect(
                    it->condition,
                    ConstantInt::get(
                        i32, core::chaos::correction(currentId, it->targetId)),
                    corr);
            return B.CreateXor(stepped, corr);
        });
}

PreservedAnalyses ChaosStateMachinePass::run(Function &F,
                                             FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return chaosStateMachineFunction(F, rng) ? PreservedAnalyses::none()
                                             : PreservedAnalyses::all();
}

} // namespace morok::passes
