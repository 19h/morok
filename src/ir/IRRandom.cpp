// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/ir/IRRandom.cpp

#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"

namespace morok::ir {

llvm::ConstantInt *IRRandom::constInt(llvm::IntegerType *ty) {
    // APInt of the type's exact width, filled from the engine word by word.
    const unsigned bits = ty->getBitWidth();
    llvm::APInt value(bits, 0);
    for (unsigned filled = 0; filled < bits; filled += 64) {
        llvm::APInt word(bits, engine_());
        value |= word.shl(filled);
    }
    return llvm::ConstantInt::get(ty->getContext(), value);
}

} // namespace morok::ir
