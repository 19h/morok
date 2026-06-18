// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/ir/SymbolCloak.hpp — inline, per-site decryption of C symbol names.
//
// Several passes resolve imports dynamically (`dlsym`/anti-hook).  Emitting the
// symbol as a readable string is the single worst leak: a decompiler annotates
// the call with the import name.  `emitCloakedSymbol` instead recovers the name
// at the call site from per-site ciphertext, keyed on a runtime-opaque module
// seed, using one of several keystream generators chosen per site — so the name
// never appears in the binary and cracking one site does not crack the rest.

#ifndef MOROK_IR_SYMBOL_CLOAK_HPP
#define MOROK_IR_SYMBOL_CLOAK_HPP

#include "llvm/ADT/StringRef.h"

#include <cstdint>

namespace llvm {
class GlobalVariable;
class IRBuilderBase;
class Module;
class Value;
} // namespace llvm

namespace morok::ir {

class IRRandom;

/// Number of distinct keystream generators `keystreamValue`/`emitKeystream`
/// can produce (selected by `variant`).
constexpr unsigned kKeystreamVariants = 3;

/// Pass-time keystream value for position `j`, given the runtime key `k0`, the
/// odd multiplier `mul`, and the generator `variant` (< kKeystreamVariants).
/// Pure 64-bit wraparound arithmetic with an exact IR analogue (emitKeystream),
/// so ciphertext built with this is recovered byte-for-byte by the emitted IR.
std::uint64_t keystreamValue(unsigned variant, std::uint64_t k0,
                             std::uint32_t j, std::uint64_t mul);

/// Emit the i64 keystream value for position `j` from the runtime key `K0` —
/// the exact IR mirror of keystreamValue.
llvm::Value *emitKeystream(llvm::IRBuilderBase &B, unsigned variant,
                           llvm::Value *K0, std::uint32_t j, std::uint64_t mul);

/// Like emitKeystream but with a runtime byte index `JVal` (an i64 Value),
/// for loop-based decryptors over long buffers.  Equivalent to
/// `keystreamValue(variant, K0, JVal, mul)`.
llvm::Value *emitKeystreamDynamic(llvm::IRBuilderBase &B, unsigned variant,
                                  llvm::Value *K0, llvm::Value *JVal,
                                  std::uint64_t mul);

/// Emit an i64 that is zero at runtime but opaque to ordinary microcode
/// constant folding.  The value is tied to a stack address through a private
/// noinline helper call, so intraprocedural decompiler passes cannot reduce
/// dependent byte stores to constants just by reading globals and replaying
/// arithmetic.
llvm::Value *emitRuntimeOpaqueZero(llvm::IRBuilderBase &B, llvm::Module &M,
                                   std::uint64_t salt, llvm::StringRef prefix);

/// The shared per-module runtime key: a private *mutable* i64 global holding a
/// random value, meant to be read with a volatile load (so the optimizer cannot
/// fold keystream-derived values back to plaintext).  Created on first use.
llvm::GlobalVariable *cloakSeed(llvm::Module &M, IRRandom &rng);

/// Emit, at `B`'s current insertion point, an inline per-site decryption of the
/// C symbol name `symbol` into a fresh stack buffer, and return an `i8*` to the
/// recovered NUL-terminated string.  No readable copy of `symbol` exists in the
/// artifact: each call site carries its own ciphertext (a private
/// `morok.cloak.c` byte global) and its own unrolled keystream — one of several
/// generators, XOR- or ADD-combined, chosen per site — keyed on `k0 = (volatile
/// load of the mutable module seed `morok.cloak.seed`) ^ siteKey`.  The
/// volatile load is opaque to the optimizer, so the cipher never folds back to
/// text.
llvm::Value *emitCloakedSymbol(llvm::IRBuilderBase &B, llvm::Module &M,
                               llvm::StringRef symbol, IRRandom &rng);

} // namespace morok::ir

#endif // MOROK_IR_SYMBOL_CLOAK_HPP
