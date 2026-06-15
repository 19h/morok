// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Morok — modular LLVM IR obfuscator.  Clean-room rewrite.
//
// morok/ir/Annotations.hpp — per-function obfuscation opt-in/opt-out.
//
// Source code can steer the obfuscator per function with
//     __attribute__((annotate("sub")))    // force a pass on
//     __attribute__((annotate("nosub")))  // force a pass off
// The Clang front end lowers these into `llvm.global.annotations`;
// `materializeAnnotations` copies them onto each function as private metadata,
// and `shouldObfuscate` consults that metadata, letting an explicit annotation
// override the pass's default decision.

#ifndef MOROK_IR_ANNOTATIONS_HPP
#define MOROK_IR_ANNOTATIONS_HPP

#include "llvm/ADT/StringRef.h"

namespace llvm {
class Function;
class Module;
} // namespace llvm

namespace morok::ir {

/// Copy `llvm.global.annotations` entries onto their functions as metadata.
/// Call once per module before consulting `shouldObfuscate`.
void materializeAnnotations(llvm::Module &M);

/// True if function `F` carries the given obfuscation annotation.
bool hasAnnotation(const llvm::Function &F, llvm::StringRef annotation);

/// Attach an obfuscation annotation to `F` (idempotent).
void addAnnotation(llvm::Function &F, llvm::StringRef annotation);

/// Decide whether pass `attr` should run on `F`.
///
/// Declarations are never obfuscated.  An explicit `no<attr>` annotation forces
/// false; an explicit `<attr>` annotation forces true; otherwise the pass's
/// `defaultEnabled` decision is used.
bool shouldObfuscate(const llvm::Function &F, llvm::StringRef attr,
                     bool defaultEnabled);

} // namespace morok::ir

#endif // MOROK_IR_ANNOTATIONS_HPP
