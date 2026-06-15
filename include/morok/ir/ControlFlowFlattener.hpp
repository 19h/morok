// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/ir/ControlFlowFlattener.hpp — reusable CFG-flattening engine.
//
// Collapses a function into a switch dispatcher driven by a state variable, and
// rewrites each block to compute and store its successor state before looping
// back.  *How* the next state is computed is delegated to a callback, so the
// same engine powers plain flattening (store the successor's id directly) and
// the chaos state machine (route the state through the logistic map).  SSA
// values that cross blocks are demoted to stack afterwards, making the rewiring
// sound.

#ifndef MOROK_IR_CONTROL_FLOW_FLATTENER_HPP
#define MOROK_IR_CONTROL_FLOW_FLATTENER_HPP

#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/IRBuilder.h"

#include <cstdint>
#include <functional>
#include <vector>

namespace llvm {
class AllocaInst;
class Function;
class Value;
} // namespace llvm

namespace morok::ir {

/// One guarded successor: when `condition` is true, the block transfers to the
/// block whose state id is `targetId`.  Arms are evaluated in order.
struct SuccessorArm {
    llvm::Value *condition; ///< i1 guard
    std::uint32_t targetId; ///< destination state id
};

/// The resolved successors for a block being rewritten.  Models unconditional
/// branches (no arms), conditional branches (one arm), and switches (one arm
/// per case); `defaultId` is the fall-through / default destination.
struct SuccessorIds {
    std::vector<SuccessorArm> arms;
    std::uint32_t defaultId = 0;
};

/// Computes the i32 value to store as the next state.  `B` is positioned before
/// the block's original terminator; `stateVar` holds the current state;
/// `currentId` is this block's own state id.
using NextStateFn = std::function<llvm::Value *(
    llvm::IRBuilder<> &B, llvm::AllocaInst *stateVar, std::uint32_t currentId,
    const SuccessorIds &succ)>;

/// Flatten `F` using `nextState` to drive transitions.  Returns false (leaving
/// `F` unchanged) for functions with fewer than two blocks or containing
/// exception-handling / indirect terminators.
bool flattenControlFlow(llvm::Function &F, IRRandom &rng,
                        const NextStateFn &nextState);

} // namespace morok::ir

#endif // MOROK_IR_CONTROL_FLOW_FLATTENER_HPP
