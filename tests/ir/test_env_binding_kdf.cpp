// SPDX-License-Identifier: MIT
//
// Tests for EnvBindingKdf — host identity folded into the RuntimeSeal
// env_binding channel via feed/finish helpers and a startup collector.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/EnvBindingKdf.hpp"
#include "morok/passes/RuntimeSeal.hpp"

#include "llvm/IR/Attributes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// Minimal module with no target triple: Triple("") is not OS-Linux, so the
// syscall-backed host collector is skipped and the platform-neutral
// finish-only fallback is emitted instead. Deterministic on every CI host.
const char *kNeutralModule = R"ir(
define i32 @main(i32 %x) {
entry:
  ret i32 %x
}
)ir";

// Explicit Linux triple in the IR text (not the host triple) exercises the
// syscall host collector deterministically regardless of where the test runs.
const char *kLinuxModule = R"ir(
target triple = "x86_64-unknown-linux-gnu"
define i32 @main() {
entry:
  ret i32 0
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

std::string printModule(Module &M) {
    std::string text;
    raw_string_ostream os(text);
    M.print(os, nullptr);
    os.flush();
    return text;
}

} // namespace

TEST_CASE("envBindingKdfModule grows the module and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kNeutralModule);

    CHECK(countFunctions(*M, "morok.envbind.") == 0u);
    CHECK(countGlobals(*M, "morok.envbind.") == 0u);

    auto rng = makeRng(0xE0B1);
    morok::passes::EnvBindingKdfParams params;
    CHECK(morok::passes::envBindingKdfModule(*M, params, rng));

    // feed + finish helpers and the finish-only collector ctor.
    CHECK(countFunctions(*M, "morok.envbind.") == 3u);
    // accum + mask + done state globals.
    CHECK(countGlobals(*M, "morok.envbind.") == 3u);
    CHECK(M->getGlobalVariable("morok.envbind.accum", true) != nullptr);
    CHECK(M->getGlobalVariable("morok.envbind.mask", true) != nullptr);
    CHECK(M->getGlobalVariable("morok.envbind.done", true) != nullptr);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("envBindingKdfModule disabled is an inert no-op") {
    LLVMContext ctx;
    auto M = parse(ctx, kNeutralModule);

    const std::string before = printModule(*M);

    auto rng = makeRng(0xE0B2);
    morok::passes::EnvBindingKdfParams params;
    params.enabled = false;
    CHECK_FALSE(morok::passes::envBindingKdfModule(*M, params, rng));

    // Nothing emitted, IR byte-identical, module still valid.
    CHECK(countFunctions(*M, "morok.envbind.") == 0u);
    CHECK(countGlobals(*M, "morok.envbind.") == 0u);
    CHECK(printModule(*M) == before);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("envBindingKdfModule tolerates a declaration-only module") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare void @external()
)ir");

    auto rng = makeRng(0xE0B3);
    morok::passes::EnvBindingKdfParams params;
    // The helpers are module-level, so the pass still fires with no defined
    // user function present; it must not crash and must verify.
    CHECK(morok::passes::envBindingKdfModule(*M, params, rng));
    CHECK(M->getFunction("morok.envbind.feed") != nullptr);
    CHECK(M->getFunction("morok.envbind.finish") != nullptr);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("envBindingKdfModule is deterministic for a fixed seed and input") {
    LLVMContext ctx;
    auto Ma = parse(ctx, kNeutralModule);
    auto Mb = parse(ctx, kNeutralModule);

    // Two freshly-seeded engines with the same seed produce identical streams.
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0xD00D1234);
    morok::ir::IRRandom rngA(engineA);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0xD00D1234);
    morok::ir::IRRandom rngB(engineB);

    morok::passes::EnvBindingKdfParams params;
    params.expected_digest = "0x1122334455667788";
    CHECK(morok::passes::envBindingKdfModule(*Ma, params, rngA));
    CHECK(morok::passes::envBindingKdfModule(*Mb, params, rngB));

    CHECK(printModule(*Ma) == printModule(*Mb));
    CHECK_FALSE(verifyModule(*Ma));
    CHECK_FALSE(verifyModule(*Mb));
}

TEST_CASE("envBindingKdfModule is idempotent on a second run") {
    LLVMContext ctx;
    auto M = parse(ctx, kNeutralModule);

    auto rng1 = makeRng(0xE0B4);
    morok::passes::EnvBindingKdfParams params;
    CHECK(morok::passes::envBindingKdfModule(*M, params, rng1));
    CHECK_FALSE(verifyModule(*M));

    // Every helper/global/ctor already exists, so nothing is re-emitted.
    auto rng2 = makeRng(0xE0B5);
    CHECK_FALSE(morok::passes::envBindingKdfModule(*M, params, rng2));
    CHECK(countFunctions(*M, "morok.envbind.") == 3u);
    CHECK(countGlobals(*M, "morok.envbind.") == 3u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("envBindingKdfModule emits external feed/finish helpers with attrs") {
    LLVMContext ctx;
    auto M = parse(ctx, kNeutralModule);

    auto rng = makeRng(0xE0B6);
    morok::passes::EnvBindingKdfParams params;
    CHECK(morok::passes::envBindingKdfModule(*M, params, rng));

    Function *Feed = M->getFunction("morok.envbind.feed");
    Function *Finish = M->getFunction("morok.envbind.finish");
    REQUIRE(Feed != nullptr);
    REQUIRE(Finish != nullptr);
    CHECK(Feed->hasExternalLinkage());
    CHECK(Finish->hasExternalLinkage());
    CHECK(Feed->hasFnAttribute(Attribute::NoInline));
    CHECK(Feed->hasFnAttribute(Attribute::NoUnwind));
    CHECK(Finish->hasFnAttribute(Attribute::NoInline));
    CHECK(Finish->hasFnAttribute(Attribute::NoUnwind));
    CHECK_FALSE(Feed->empty());
    CHECK_FALSE(Finish->empty());

    // The feed loop reads each identity byte with a volatile i8 load.
    bool feedLoadsIdentityByte = false;
    for (Instruction &I : instructions(*Feed))
        if (auto *LI = dyn_cast<LoadInst>(&I))
            feedLoadsIdentityByte |=
                LI->isVolatile() &&
                LI->getName() == "morok.envbind.feed.byte";
    CHECK(feedLoadsIdentityByte);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("envBindingKdfModule binds the env_binding seal channel and opts out") {
    LLVMContext ctx;
    auto Bound = parse(ctx, kNeutralModule);
    auto Free = parse(ctx, kNeutralModule);

    auto rngBound = makeRng(0xE0B7);
    morok::passes::EnvBindingKdfParams boundParams;
    boundParams.bind_to_runtime_seal = true;
    CHECK(morok::passes::envBindingKdfModule(*Bound, boundParams, rngBound));

    // Seal-bound: env_binding channel exists and finish folds a word into it.
    CHECK(morok::passes::runtime_seal::findChannel(
              *Bound, morok::passes::runtime_seal::kEnvBindingChannel) !=
          nullptr);
    Function *BoundFinish = Bound->getFunction("morok.envbind.finish");
    REQUIRE(BoundFinish != nullptr);
    CHECK(countNamedInstructions(*BoundFinish,
                                 "morok.envbind.finish.seal.next") == 1u);
    // Seal-bound emits the finish-only collector ctor on this neutral triple.
    CHECK(Bound->getFunction("morok.envbind.collect") != nullptr);
    CHECK_FALSE(verifyModule(*Bound));

    auto rngFree = makeRng(0xE0B8);
    morok::passes::EnvBindingKdfParams freeParams;
    freeParams.bind_to_runtime_seal = false;
    CHECK(morok::passes::envBindingKdfModule(*Free, freeParams, rngFree));

    // Seal opt-out: no channel, no seal fold, no collector emitted.
    CHECK(morok::passes::runtime_seal::findChannel(
              *Free, morok::passes::runtime_seal::kEnvBindingChannel) ==
          nullptr);
    Function *FreeFinish = Free->getFunction("morok.envbind.finish");
    REQUIRE(FreeFinish != nullptr);
    CHECK(countNamedInstructions(*FreeFinish,
                                 "morok.envbind.finish.seal.next") == 0u);
    CHECK(Free->getFunction("morok.envbind.collect") == nullptr);
    CHECK_FALSE(verifyModule(*Free));
}

TEST_CASE("envBindingKdfModule obfuscates identity paths in the Linux collector") {
    LLVMContext ctx;
    auto M = parse(ctx, kLinuxModule);

    auto rng = makeRng(0xE0B9);
    morok::passes::EnvBindingKdfParams params;
    params.expected_digest = "0x1122334455667788";
    CHECK(morok::passes::envBindingKdfModule(*M, params, rng));

    // The Linux host collector feeds several identity factors then finishes.
    Function *Ctor = M->getFunction("morok.envbind.collect");
    REQUIRE(Ctor != nullptr);
    CHECK(countCallsTo(*Ctor, "morok.envbind.feed") >= 4u);
    CHECK(countCallsTo(*Ctor, "morok.envbind.finish") == 1u);
    CHECK(M->getGlobalVariable("llvm.global_ctors", true) != nullptr);

    // Factor paths are XOR-masked byte-by-byte, never present in plaintext.
    CHECK_FALSE(hasReadableByteString(*M, "/etc/machine-id"));
    CHECK_FALSE(hasReadableByteString(*M, "/sys/class/dmi"));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("envBindingKdfModule finish computes a ctpop factor gate") {
    LLVMContext ctx;
    auto M = parse(ctx, kNeutralModule);

    auto rng = makeRng(0xE0BA);
    morok::passes::EnvBindingKdfParams params;
    params.min_factors = 2;
    CHECK(morok::passes::envBindingKdfModule(*M, params, rng));

    Function *Finish = M->getFunction("morok.envbind.finish");
    REQUIRE(Finish != nullptr);

    // ctpop over the factor mask gates the expected-digest contribution vs the
    // deliberately-nonzero "missing" contribution.
    CHECK(countCallsToPrefix(*Finish, "llvm.ctpop") == 1u);
    CHECK(countNamedInstructions(*Finish, "morok.envbind.factor.count") == 1u);
    CHECK(countNamedInstructions(*Finish, "morok.envbind.enough_factors") ==
          1u);
    CHECK(countNamedInstructions(*Finish,
                                 "morok.envbind.finish.expected.diff") == 1u);
    CHECK(countNamedInstructions(*Finish,
                                 "morok.envbind.finish.missing.nonzero") == 1u);
    CHECK(countNamedInstructions(*Finish, "morok.envbind.finish.contribution") ==
          1u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("envBindingKdfModule tags helpers no_vm when virtualization disabled") {
    LLVMContext ctx;
    auto Virtualized = parse(ctx, kNeutralModule);
    auto Plain = parse(ctx, kNeutralModule);

    auto rngV = makeRng(0xE0BB);
    morok::passes::EnvBindingKdfParams vParams;
    vParams.virtualize_helpers = true;
    CHECK(morok::passes::envBindingKdfModule(*Virtualized, vParams, rngV));

    Function *VFeed = Virtualized->getFunction("morok.envbind.feed");
    Function *VFinish = Virtualized->getFunction("morok.envbind.finish");
    REQUIRE(VFeed != nullptr);
    REQUIRE(VFinish != nullptr);
    CHECK_FALSE(VFeed->hasFnAttribute("morok.envbind.no_vm"));
    CHECK_FALSE(VFinish->hasFnAttribute("morok.envbind.no_vm"));
    CHECK_FALSE(verifyModule(*Virtualized));

    auto rngP = makeRng(0xE0BC);
    morok::passes::EnvBindingKdfParams pParams;
    pParams.virtualize_helpers = false;
    CHECK(morok::passes::envBindingKdfModule(*Plain, pParams, rngP));

    Function *PFeed = Plain->getFunction("morok.envbind.feed");
    Function *PFinish = Plain->getFunction("morok.envbind.finish");
    REQUIRE(PFeed != nullptr);
    REQUIRE(PFinish != nullptr);
    CHECK(PFeed->hasFnAttribute("morok.envbind.no_vm"));
    CHECK(PFinish->hasFnAttribute("morok.envbind.no_vm"));
    CHECK_FALSE(verifyModule(*Plain));
}
