// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/ChaosStateMachine.cpp
//
// The emitted `step` IR reproduces the selected pure core generator bit-for-bit,
// so the compile-time correction constants telescope exactly:
//   next = step(current) XOR (step(current_id) XOR successor_id) ==
//   successor_id.

#include "morok/passes/ChaosStateMachine.hpp"

#include "morok/core/LogisticMap.hpp"
#include "morok/core/TFunction.hpp"
#include "morok/ir/ControlFlowFlattener.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"

using namespace llvm;

namespace morok::passes {

namespace {

// Emit the logistic-map step in Q16 fixed point — identical arithmetic to
// morok::core::chaos::step.  Input/output are i32.
Value *emitStepLogistic(IRBuilder<> &B, Value *x) {
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

Value *emitStepTFunction(IRBuilder<> &B, Value *x, std::uint64_t C) {
    auto *i32 = B.getInt32Ty();
    Value *mul = B.CreateMul(x, x, "csm.tf.mul");
    Value *orC =
        B.CreateOr(mul, ConstantInt::get(i32, static_cast<std::uint32_t>(C)),
                   "csm.tf.or");
    return B.CreateAdd(x, orC, "csm.tf.next");
}

std::uint64_t validTFunctionConstant(const CsmParams &Params,
                                     ir::IRRandom &Rng) {
    if (Params.tf_const != 0 &&
        core::tfunc::isSingleCycleConstant(Params.tf_const))
        return Params.tf_const;
    return (Rng.next() & ~std::uint64_t{7}) | (Rng.chance(50) ? 5u : 7u);
}

} // namespace

bool chaosStateMachineFunction(Function &F, const CsmParams &Params,
                               ir::IRRandom &rng) {
    (void)Params.warmup;
    (void)Params.nested_dispatch;
    const std::uint64_t TfConst = validTFunctionConstant(Params, rng);

    return ir::flattenControlFlow(
        F, rng,
        [Params, TfConst](IRBuilder<> &B, AllocaInst *stateVar,
                          std::uint32_t currentId,
                          const ir::SuccessorIds &s) -> Value * {
            auto *i32 = B.getInt32Ty();
            Value *cur = B.CreateLoad(i32, stateVar, "csm.cur");
            const bool UseTFunction =
                Params.generator == CsmGenerator::TFunction;
            Value *stepped = UseTFunction ? emitStepTFunction(B, cur, TfConst)
                                          : emitStepLogistic(B, cur);
            // Pick the correction for the taken edge, then telescope:
            //   next = step(cur) XOR (step(currentId) XOR targetId) ==
            //   targetId.
            auto Correction = [&](std::uint32_t TargetId) -> std::uint32_t {
                if (UseTFunction)
                    return static_cast<std::uint32_t>(
                        core::tfunc::correction(currentId, TargetId, 32,
                                                TfConst));
                return core::chaos::correction(currentId, TargetId);
            };
            Value *corr = ConstantInt::get(i32, Correction(s.defaultId));
            for (auto it = s.arms.rbegin(); it != s.arms.rend(); ++it)
                corr = B.CreateSelect(
                    it->condition, ConstantInt::get(i32, Correction(it->targetId)),
                    corr);
            return B.CreateXor(stepped, corr);
        });
}

bool chaosStateMachineFunction(Function &F, ir::IRRandom &rng) {
    return chaosStateMachineFunction(F, {}, rng);
}

PreservedAnalyses ChaosStateMachinePass::run(Function &F,
                                             FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return chaosStateMachineFunction(F, params_, rng) ? PreservedAnalyses::none()
                                                      : PreservedAnalyses::all();
}

} // namespace morok::passes
