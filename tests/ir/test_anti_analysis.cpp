// SPDX-License-Identifier: MIT
//
// Tests for AntiAnalysis — startup debugger-denial, anti-hook prologue checks,
// and timing/trap self-defence oracles injected as module constructors.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/AntiAnalysis.hpp"
#include "morok/passes/RuntimeSeal.hpp"

#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;
using namespace morok::test;

namespace {

// A minimal, target-agnostic module.  With no `target triple`, the pass takes
// its portable "unknown OS" path, so its behaviour here is identical on every
// CI host (the impl only ever inspects the module triple, never the host).
const char *kSimpleModule = R"ir(
define i32 @main(i32 %x) {
entry:
  %y = add i32 %x, 7
  ret i32 %y
}
)ir";

// Explicit x86_64 Linux target.  Because the pass branches on the *module*
// triple (not the host), pinning it here keeps emission deterministic and
// identical across linux/macOS/windows CI runners.
const char *kLinuxModule = R"ir(
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

define i32 @compute(i32 %a, i32 %b) {
entry:
  %s = add i32 %a, %b
  %p = mul i32 %s, %a
  ret i32 %p
}

define i32 @main() {
entry:
  %r = call i32 @compute(i32 3, i32 4)
  ret i32 %r
}
)ir";

// A Linux target on an architecture the trap oracle does not support, so
// trapOracleModule bails out (returns false) before mutating anything.
const char *kUnsupportedTrapModule = R"ir(
target triple = "riscv64-unknown-linux-gnu"

define i32 @main() {
entry:
  ret i32 0
}
)ir";

const char *kDeclOnlyModule = R"ir(
declare void @external()
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

// Total number of top-level functions + global variables — a simple, robustly
// deterministic proxy for "the module grew".
std::size_t moduleEntityCount(llvm::Module &M) {
    std::size_t n = 0;
    for (const auto &F : M) {
        (void)F;
        ++n;
    }
    for (const auto &G : M.globals()) {
        (void)G;
        ++n;
    }
    return n;
}

std::string printModule(llvm::Module &M) {
    std::string text;
    llvm::raw_string_ostream os(text);
    M.print(os, nullptr);
    os.flush();
    return text;
}

} // namespace

TEST_CASE("antiDebuggingModule grows the module and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kSimpleModule);

    const std::size_t before = moduleEntityCount(*M);
    CHECK(morok::passes::antiDebuggingModule(*M));
    const std::size_t after = moduleEntityCount(*M);

    CHECK(after > before);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("antiDebuggingModule emits the antidbg ctor, state, seal and ctor list") {
    LLVMContext ctx;
    auto M = parse(ctx, kSimpleModule);

    CHECK(morok::passes::antiDebuggingModule(*M));

    // Internal-linkage constructor shell (makeCtorShell names it "morok.antidbg").
    Function *ctor = M->getFunction("morok.antidbg");
    REQUIRE(ctor != nullptr);
    CHECK(ctor->hasInternalLinkage());

    // Private i64 hidden-state global folded by the detectors.
    CHECK(M->getGlobalVariable("morok.antidbg.state", /*AllowInternal=*/true) !=
          nullptr);

    // The verdict-bound anti_debug seal channel must exist.
    CHECK(morok::passes::runtime_seal::findChannel(
              *M, morok::passes::runtime_seal::kAntiDebugChannel) != nullptr);

    // The ctor is registered so it runs at process startup.
    CHECK(M->getGlobalVariable("llvm.global_ctors") != nullptr);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("antiDebuggingModule runs on an explicit linux target and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kLinuxModule);

    const std::size_t before = moduleEntityCount(*M);
    auto rng = makeRng(0xADB1);
    CHECK(morok::passes::antiDebuggingModule(*M, rng));
    const std::size_t after = moduleEntityCount(*M);

    CHECK(after > before);
    CHECK(morok::passes::runtime_seal::findChannel(
              *M, morok::passes::runtime_seal::kAntiDebugChannel) != nullptr);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("antiDebuggingModule is deterministic for a fixed seed") {
    LLVMContext ctx;
    auto M1 = parse(ctx, kSimpleModule);
    auto M2 = parse(ctx, kSimpleModule);

    // The single-arg overload uses a self-contained engine with a fixed seed,
    // so identical input must yield byte-identical output.
    CHECK(morok::passes::antiDebuggingModule(*M1));
    CHECK(morok::passes::antiDebuggingModule(*M2));

    CHECK(printModule(*M1) == printModule(*M2));
    CHECK_FALSE(verifyModule(*M1));
    CHECK_FALSE(verifyModule(*M2));
}

TEST_CASE("antiDebuggingModule is safe on a declaration-only module") {
    LLVMContext ctx;
    auto M = parse(ctx, kDeclOnlyModule);

    // No defined functions — the pass must not crash and must still fire.
    CHECK(morok::passes::antiDebuggingModule(*M));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("antiHookingModule fires, cloaks its probe symbol and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kLinuxModule);

    const std::size_t before = moduleEntityCount(*M);
    auto rng = makeRng(0xA400C);
    CHECK(morok::passes::antiHookingModule(*M, rng));
    const std::size_t after = moduleEntityCount(*M);

    CHECK(after > before);

    Function *ctor = M->getFunction("morok.antihook");
    REQUIRE(ctor != nullptr);
    CHECK(ctor->hasInternalLinkage());

    // The anti_hook seal channel is created up front.
    CHECK(morok::passes::runtime_seal::findChannel(
              *M, morok::passes::runtime_seal::kAntiHookChannel) != nullptr);

    // The probed framework symbol is cloaked inline — never a readable string.
    CHECK_FALSE(hasReadableByteString(*M, "MSHookFunction"));

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("timingOracleModule installs a timing constructor and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kLinuxModule);

    const std::size_t before = moduleEntityCount(*M);
    auto rng = makeRng(0x71301);
    CHECK(morok::passes::timingOracleModule(*M, rng));
    const std::size_t after = moduleEntityCount(*M);

    CHECK(after > before);

    CHECK(M->getFunction("morok.timing") != nullptr);
    CHECK(M->getGlobalVariable("morok.timing.state", /*AllowInternal=*/true) !=
          nullptr);
    // The oracle folds into the shared anti_debug seal channel.
    CHECK(morok::passes::runtime_seal::findChannel(
              *M, morok::passes::runtime_seal::kAntiDebugChannel) != nullptr);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("trapOracleModule fires on a supported target and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kLinuxModule);

    const std::size_t before = moduleEntityCount(*M);
    auto rng = makeRng(0x77A91);
    CHECK(morok::passes::trapOracleModule(*M, rng));
    const std::size_t after = moduleEntityCount(*M);

    CHECK(after > before);

    CHECK(M->getFunction("morok.trap") != nullptr);
    CHECK(M->getGlobalVariable("morok.trap.state", /*AllowInternal=*/true) !=
          nullptr);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("trapOracleModule is a no-op on an unsupported target") {
    LLVMContext ctx;
    auto M = parse(ctx, kUnsupportedTrapModule);

    const std::size_t before = moduleEntityCount(*M);
    auto rng = makeRng(0x51105);
    // riscv64 has no supported sigaction layout, so the oracle bails out early.
    CHECK_FALSE(morok::passes::trapOracleModule(*M, rng));
    const std::size_t after = moduleEntityCount(*M);

    CHECK(after == before);
    CHECK_FALSE(verifyModule(*M));
}
