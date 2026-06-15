// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/ir/Reg2Mem.hpp — demote cross-block SSA values to stack slots.
//
// Control-flow obfuscations (flattening, the chaos state machine) rewire the
// CFG in ways that violate SSA dominance for values that live across blocks.
// Running this first — demoting every value that escapes its defining block,
// and every PHI, to an alloca — makes those rewrites sound: afterwards no
// register value crosses a block boundary, so the dispatcher can route blocks
// in any order.

#ifndef MOROK_IR_REG2MEM_HPP
#define MOROK_IR_REG2MEM_HPP

namespace llvm {
class Function;
} // namespace llvm

namespace morok::ir {

/// Demote all escaping registers and PHIs in `F` to stack slots, leaving the
/// function in a form where no SSA value lives across a basic-block boundary.
void demoteToStack(llvm::Function &F);

} // namespace morok::ir

#endif // MOROK_IR_REG2MEM_HPP
