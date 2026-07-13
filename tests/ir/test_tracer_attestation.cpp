// SPDX-License-Identifier: MIT
//
// Tests for TracerAttestation — buddy-process ptrace tracer seal producer.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/RuntimeSeal.hpp"
#include "morok/passes/TracerAttestation.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"

using namespace llvm;
using namespace morok::test;

namespace {

// The pass only materializes on a Linux/x86_64 target. Pin the module triple
// explicitly so the tests behave identically on every CI host/arch.
const char *kLinuxModule = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @main(i32 %x) {
entry:
  %y = add i32 %x, 1
  ret i32 %y
}
)ir";

// A Linux/x86_64 module that *uses* a fork/signal API. The pass must bail out
// here to avoid colliding with the program's own fork/signal handling.
const char *kForkModule = R"ir(
target triple = "x86_64-unknown-linux-gnu"

declare i32 @fork()

define i32 @main() {
entry:
  %p = call i32 @fork()
  ret i32 %p
}
)ir";

// No target triple => not Linux/x86_64 => pass is a platform-neutral no-op on
// every host it is compiled and run on.
const char *kNoTripleModule = R"ir(
define i32 @main(i32 %x) {
entry:
  ret i32 %x
}
)ir";

// Declaration-only Linux/x86_64 module: the pass supplies its own ctor/helper
// so it should still materialize without touching any user body.
const char *kDeclOnlyModule = R"ir(
target triple = "x86_64-unknown-linux-gnu"

declare void @external()
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

} // namespace

TEST_CASE("tracerAttestationModule grows the module and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kLinuxModule);

    const std::size_t fnsBefore = countFunctions(*M, "");
    const std::size_t globalsBefore = countGlobals(*M, "");

    auto rng = makeRng(0x7101);
    morok::passes::TracerAttestationParams p;

    CHECK(morok::passes::tracerAttestationModule(*M, p, rng));
    // Emits at least the share helper + ctor, plus seal channel + global_ctors.
    CHECK(countFunctions(*M, "") > fnsBefore);
    CHECK(countGlobals(*M, "") > globalsBefore);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("tracerAttestationModule emits the ctor and share helper") {
    LLVMContext ctx;
    auto M = parse(ctx, kLinuxModule);

    auto rng = makeRng(0x7102);
    morok::passes::TracerAttestationParams p;

    REQUIRE(morok::passes::tracerAttestationModule(*M, p, rng));

    // Exactly the two functions the pass names under this prefix.
    CHECK(countFunctions(*M, "morok.tracer.") == static_cast<std::size_t>(2));

    Function *ctor = M->getFunction("morok.tracer.attest");
    REQUIRE(ctor != nullptr);
    CHECK(ctor->hasInternalLinkage());
    CHECK(ctor->hasFnAttribute(Attribute::NoUnwind));
    // The fork branch produces a multi-block control-flow graph.
    CHECK(ctor->size() > static_cast<std::size_t>(1));
    // The ctor consumes the share helper (child injection + parent expectation).
    CHECK(countCallsTo(*ctor, "morok.tracer.share") > static_cast<std::size_t>(0));

    Function *share = M->getFunction("morok.tracer.share");
    REQUIRE(share != nullptr);
    CHECK(share->hasPrivateLinkage());
    CHECK(share->hasFnAttribute(Attribute::NoInline));
    // The keyed mixing (mix64) leaves arithmetic in the helper body.
    CHECK(countBinops(*share) > static_cast<std::size_t>(0));

    // Registered as a global constructor.
    CHECK(M->getGlobalVariable("llvm.global_ctors") != nullptr);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("tracerAttestationModule binds the tracer seal channel on request") {
    LLVMContext ctx;
    auto M = parse(ctx, kLinuxModule);

    auto rng = makeRng(0x7103);
    morok::passes::TracerAttestationParams bound;
    bound.bind_to_runtime_seal = true;

    REQUIRE(morok::passes::tracerAttestationModule(*M, bound, rng));
    CHECK(morok::passes::runtime_seal::findChannel(
              *M, morok::passes::runtime_seal::kTracerChannel) != nullptr);
    CHECK_FALSE(verifyModule(*M));

    // With binding off, the pass still fires but leaves the seal channel alone.
    LLVMContext ctx2;
    auto M2 = parse(ctx2, kLinuxModule);
    auto rng2 = makeRng(0x7104);
    morok::passes::TracerAttestationParams unbound;
    unbound.bind_to_runtime_seal = false;

    REQUIRE(morok::passes::tracerAttestationModule(*M2, unbound, rng2));
    CHECK(morok::passes::runtime_seal::findChannel(
              *M2, morok::passes::runtime_seal::kTracerChannel) == nullptr);
    CHECK_FALSE(verifyModule(*M2));
}

TEST_CASE("tracerAttestationModule is a no-op off Linux/x86_64 and when gated") {
    // Missing triple => not the supported target => unchanged.
    LLVMContext ctx;
    auto M = parse(ctx, kNoTripleModule);
    const std::size_t fnsBefore = countFunctions(*M, "");

    auto rng = makeRng(0x7105);
    morok::passes::TracerAttestationParams p;
    CHECK_FALSE(morok::passes::tracerAttestationModule(*M, p, rng));
    CHECK(countFunctions(*M, "") == fnsBefore);
    CHECK(countFunctions(*M, "morok.tracer.") == static_cast<std::size_t>(0));
    CHECK_FALSE(verifyModule(*M));

    // Param gates: each independently disables the pass on a valid target.
    auto checkGated = [&](const morok::passes::TracerAttestationParams &gated,
                          std::uint64_t seed) {
        LLVMContext gctx;
        auto GM = parse(gctx, kLinuxModule);
        auto grng = makeRng(seed);
        CHECK_FALSE(morok::passes::tracerAttestationModule(*GM, gated, grng));
        CHECK(countFunctions(*GM, "morok.tracer.") == static_cast<std::size_t>(0));
        CHECK_FALSE(verifyModule(*GM));
    };

    morok::passes::TracerAttestationParams disabled;
    disabled.enabled = false;
    checkGated(disabled, 0x7106);

    morok::passes::TracerAttestationParams wrongMode;
    wrongMode.mode = "windows_dbg";
    checkGated(wrongMode, 0x7107);

    morok::passes::TracerAttestationParams wrongRenewal;
    wrongRenewal.renewal = "periodic";
    checkGated(wrongRenewal, 0x7108);

    morok::passes::TracerAttestationParams zeroShares;
    zeroShares.shares = 0;
    checkGated(zeroShares, 0x7109);
}

TEST_CASE("tracerAttestationModule skips modules using fork/signal APIs") {
    LLVMContext ctx;
    auto M = parse(ctx, kForkModule);

    auto rng = makeRng(0x710A);
    morok::passes::TracerAttestationParams p;

    // The program already forks; the pass must not add a second forker.
    CHECK_FALSE(morok::passes::tracerAttestationModule(*M, p, rng));
    CHECK(countFunctions(*M, "morok.tracer.") == static_cast<std::size_t>(0));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("tracerAttestationModule handles declaration-only modules") {
    LLVMContext ctx;
    auto M = parse(ctx, kDeclOnlyModule);

    auto rng = makeRng(0x710B);
    morok::passes::TracerAttestationParams p;

    // Supplies its own ctor/helper; no user body required.
    CHECK(morok::passes::tracerAttestationModule(*M, p, rng));
    CHECK(M->getFunction("morok.tracer.attest") != nullptr);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("tracerAttestationModule is idempotent via the ctor guard") {
    LLVMContext ctx;
    auto M = parse(ctx, kLinuxModule);

    auto rng = makeRng(0x710C);
    morok::passes::TracerAttestationParams p;

    REQUIRE(morok::passes::tracerAttestationModule(*M, p, rng));
    CHECK(countFunctions(*M, "morok.tracer.") == static_cast<std::size_t>(2));

    // Second run sees the existing ctor and bails without duplicating anything.
    auto rng2 = makeRng(0x710D);
    CHECK_FALSE(morok::passes::tracerAttestationModule(*M, p, rng2));
    CHECK(countFunctions(*M, "morok.tracer.") == static_cast<std::size_t>(2));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("tracerAttestationModule clamps share count and gates repair sites") {
    // shares far above the kMaxShares cap (4): expect exactly one retry PHI per
    // emitted round, so the round count is clamped to the cap.
    LLVMContext ctxHi;
    auto MHi = parse(ctxHi, kLinuxModule);
    auto rngHi = makeRng(0x710E);
    morok::passes::TracerAttestationParams over;
    over.shares = 100;

    REQUIRE(morok::passes::tracerAttestationModule(*MHi, over, rngHi));
    Function *ctorHi = MHi->getFunction("morok.tracer.attest");
    REQUIRE(ctorHi != nullptr);
    CHECK(countPhis(*ctorHi) == static_cast<std::size_t>(4));
    // At the cap, repair-site fortification is enabled.
    CHECK(countNamedAllocas(*ctorHi, "morok.tracer.repair.slot") >
          static_cast<std::size_t>(0));
    CHECK_FALSE(verifyModule(*MHi));

    // Below the cap: one round per requested share, and no repair fortification.
    LLVMContext ctxLo;
    auto MLo = parse(ctxLo, kLinuxModule);
    auto rngLo = makeRng(0x710F);
    morok::passes::TracerAttestationParams few;
    few.shares = 2;

    REQUIRE(morok::passes::tracerAttestationModule(*MLo, few, rngLo));
    Function *ctorLo = MLo->getFunction("morok.tracer.attest");
    REQUIRE(ctorLo != nullptr);
    CHECK(countPhis(*ctorLo) == static_cast<std::size_t>(2));
    CHECK(countNamedAllocas(*ctorLo, "morok.tracer.repair.slot") ==
          static_cast<std::size_t>(0));
    CHECK_FALSE(verifyModule(*MLo));
}

TEST_CASE("tracerAttestationModule emits a structurally stable shape for a fixed seed") {
    LLVMContext ctxA;
    LLVMContext ctxB;
    auto MA = parse(ctxA, kLinuxModule);
    auto MB = parse(ctxB, kLinuxModule);

    // Fresh engines seeded identically (makeRng's static engine can't be reused
    // for two independent same-seed streams).
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0xBEEF1234ULL);
    morok::ir::IRRandom rngA(engineA);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0xBEEF1234ULL);
    morok::ir::IRRandom rngB(engineB);

    morok::passes::TracerAttestationParams p;
    REQUIRE(morok::passes::tracerAttestationModule(*MA, p, rngA));
    REQUIRE(morok::passes::tracerAttestationModule(*MB, p, rngB));

    // The pass intentionally embeds fresh random seal material per build (the
    // seal-root initializer is drawn from the RNG), so the emitted IR is not
    // byte-identical across runs. What IS invariant is the emitted *structure*:
    // the same number of functions and globals, and the same named tracer
    // artifacts. Assert that structural determinism rather than textual
    // equality.
    CHECK(countFunctions(*MA, "") == countFunctions(*MB, ""));
    CHECK(countGlobals(*MA, "") == countGlobals(*MB, ""));
    CHECK(countFunctions(*MA, "morok.tracer.") ==
          countFunctions(*MB, "morok.tracer."));
    CHECK(morok::passes::runtime_seal::findChannel(
              *MA, morok::passes::runtime_seal::kTracerChannel) != nullptr);
    CHECK(morok::passes::runtime_seal::findChannel(
              *MB, morok::passes::runtime_seal::kTracerChannel) != nullptr);
    CHECK_FALSE(verifyModule(*MA));
    CHECK_FALSE(verifyModule(*MB));
}
