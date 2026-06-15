// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/ir/IRRandom.hpp — bridges the pure PRNG to LLVM IR construction.
//
// Passes draw randomness from a single shared xoshiro256++ engine (seeded once
// per run for reproducibility) and frequently need random ConstantInts of a
// given width.  This thin adaptor keeps the engine reference and the LLVM glue
// in one place so the passes stay focused on their transformation.

#ifndef MOROK_IR_IRRANDOM_HPP
#define MOROK_IR_IRRANDOM_HPP

#include "morok/core/Random.hpp"
#include "morok/core/Xoshiro256.hpp"

#include <cstdint>

namespace llvm {
class ConstantInt;
class IntegerType;
} // namespace llvm

namespace morok::ir {

/// Adaptor over a shared PRNG engine providing IR-friendly random helpers.
class IRRandom {
public:
    explicit IRRandom(core::Xoshiro256pp &engine) noexcept : engine_(engine) {}

    /// Raw 64-bit draw.
    std::uint64_t next() noexcept { return engine_(); }

    /// Uniform value in [0, bound).
    std::uint32_t range(std::uint32_t bound) noexcept {
        return core::boundedU32(engine_, bound);
    }

    /// True with probability `percent` (0..100).
    bool chance(std::uint32_t percent) noexcept {
        return core::chance(engine_, percent);
    }

    /// A random ConstantInt of the given integer type (full-width random
    /// value).
    llvm::ConstantInt *constInt(llvm::IntegerType *ty);

    /// The underlying engine (for code that needs the raw generator).
    core::Xoshiro256pp &engine() noexcept { return engine_; }

private:
    core::Xoshiro256pp &engine_;
};

} // namespace morok::ir

#endif // MOROK_IR_IRRANDOM_HPP
