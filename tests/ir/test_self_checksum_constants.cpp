// SPDX-License-Identifier: MIT
//
// Tests for SelfChecksumConstants — checksum-fused constants and seal-bound
// leaf helpers (a code patch corrupts reconstructed constants / returns).

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/RuntimeSeal.hpp"
#include "morok/passes/SelfChecksumConstants.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;
using namespace morok::test;

namespace {

// A function packed with eligible scalar-constant operands (binop literals, an
// icmp constant, and two select constants) plus a computed non-constant return.
// An explicit Linux triple keeps the code-region hash lowering platform-neutral
// for the verify-only checks below.
const char *kComputeModule = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @compute(i32 %x) {
entry:
  %a = add i32 %x, 12345
  %b = mul i32 %a, 6789
  %c = icmp sgt i32 %b, 100
  %d = select i1 %c, i32 42, i32 99
  ret i32 %d
}
)ir";

// helper() is a reused integer leaf called only by main(); once main() is
// self-checksummed, bindLeafHelpersToSeal should bind helper()'s return.
const char *kHelperModule = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @helper(i32 %x) {
entry:
  %r = add i32 %x, 7
  ret i32 %r
}

define i32 @main(i32 %x) {
entry:
  %a = add i32 %x, 12345
  %c = call i32 @helper(i32 %a)
  %b = icmp sgt i32 %c, 100
  %d = select i1 %b, i32 42, i32 99
  ret i32 %d
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

} // namespace

TEST_CASE("selfChecksumConstantsFunction grows the function and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kComputeModule);
    Function *F = M->getFunction("compute");
    REQUIRE(F != nullptr);

    const std::size_t binopsBefore = countBinops(*F);

    auto rng = makeRng(0x5C01);
    morok::passes::SelfChecksumParams p;
    CHECK(morok::passes::selfChecksumConstantsFunction(*F, p, rng));

    // A diff function and runtime globals were emitted, and the target function
    // gained XOR reconstruction ops.
    CHECK(countBinops(*F) > binopsBefore);
    CHECK(countFunctions(*M, "morok.sc.diff.") == std::size_t{1});
    CHECK(countGlobals(*M, "morok.sc.") > std::size_t{0});
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("selfChecksumConstantsFunction is a no-op at probability zero") {
    LLVMContext ctx;
    auto M = parse(ctx, kComputeModule);
    Function *F = M->getFunction("compute");
    REQUIRE(F != nullptr);

    auto rng = makeRng(0x5C02);
    morok::passes::SelfChecksumParams p;
    p.probability = 0;
    CHECK_FALSE(morok::passes::selfChecksumConstantsFunction(*F, p, rng));

    // Nothing emitted: no runtime infrastructure, module untouched.
    CHECK(countFunctions(*M, "morok.sc.diff.") == std::size_t{0});
    CHECK(countGlobals(*M, "morok.") == std::size_t{0});
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("selfChecksumConstantsFunction is safe on trivial and skipped inputs") {
    // Declaration: no body to rewrite.
    {
        LLVMContext ctx;
        auto M = parse(ctx, R"ir(
declare i32 @ext(i32)
)ir");
        Function *F = M->getFunction("ext");
        REQUIRE(F != nullptr);
        auto rng = makeRng(0x5C03);
        morok::passes::SelfChecksumParams p;
        CHECK_FALSE(morok::passes::selfChecksumConstantsFunction(*F, p, rng));
        CHECK_FALSE(verifyModule(*M));
    }

    // Generated (morok.*) function: explicitly skipped.
    {
        LLVMContext ctx;
        auto M = parse(ctx, R"ir(
define i32 @"morok.gen"(i32 %x) {
entry:
  %a = add i32 %x, 12345
  ret i32 %a
}
)ir");
        Function *F = M->getFunction("morok.gen");
        REQUIRE(F != nullptr);
        auto rng = makeRng(0x5C04);
        morok::passes::SelfChecksumParams p;
        CHECK_FALSE(morok::passes::selfChecksumConstantsFunction(*F, p, rng));
        CHECK_FALSE(verifyModule(*M));
    }

    // No eligible constant operand: passthrough identity function.
    {
        LLVMContext ctx;
        auto M = parse(ctx, R"ir(
define i32 @idfn(i32 %x) {
entry:
  ret i32 %x
}
)ir");
        Function *F = M->getFunction("idfn");
        REQUIRE(F != nullptr);
        auto rng = makeRng(0x5C05);
        morok::passes::SelfChecksumParams p;
        CHECK_FALSE(morok::passes::selfChecksumConstantsFunction(*F, p, rng));
        CHECK_FALSE(verifyModule(*M));
    }
}

TEST_CASE("selfChecksumConstantsFunction is deterministic for equal seed and input") {
    LLVMContext ctxFirst;
    LLVMContext ctxSecond;
    auto MFirst = parse(ctxFirst, kComputeModule);
    auto MSecond = parse(ctxSecond, kComputeModule);

    morok::passes::SelfChecksumParams p;

    auto engineFirst = morok::core::Xoshiro256pp::fromSeed(0x2026u);
    morok::ir::IRRandom rngFirst(engineFirst);
    CHECK(morok::passes::selfChecksumConstantsFunction(
        *MFirst->getFunction("compute"), p, rngFirst));

    auto engineSecond = morok::core::Xoshiro256pp::fromSeed(0x2026u);
    morok::ir::IRRandom rngSecond(engineSecond);
    CHECK(morok::passes::selfChecksumConstantsFunction(
        *MSecond->getFunction("compute"), p, rngSecond));

    std::string textFirst;
    raw_string_ostream osFirst(textFirst);
    MFirst->print(osFirst, nullptr);
    osFirst.flush();

    std::string textSecond;
    raw_string_ostream osSecond(textSecond);
    MSecond->print(osSecond, nullptr);
    osSecond.flush();

    CHECK(textFirst == textSecond);
    CHECK_FALSE(verifyModule(*MFirst));
    CHECK_FALSE(verifyModule(*MSecond));
}

TEST_CASE("selfChecksumConstantsFunction emits the runtime globals and seal channel") {
    LLVMContext ctx;
    auto M = parse(ctx, kComputeModule);
    Function *F = M->getFunction("compute");
    REQUIRE(F != nullptr);

    auto rng = makeRng(0x5C06);
    morok::passes::SelfChecksumParams p;
    CHECK(morok::passes::selfChecksumConstantsFunction(*F, p, rng));

    // The private hashed region, expected-hash slot, patchable code-size slot,
    // compiler-used post-link manifest, and at least one XOR mask.
    CHECK(countGlobals(*M, "morok.sc.region.") == std::size_t{1});
    CHECK(countGlobals(*M, "morok.sc.expected.") == std::size_t{1});
    CHECK(countGlobals(*M, "morok.sc.code.size.") == std::size_t{1});
    CHECK(countGlobals(*M, "morok.postlink.sc.") == std::size_t{1});
    CHECK(countGlobals(*M, "morok.sc.mask.") > std::size_t{0});

    // The pass binds the diff to the anti-debug runtime seal channel.
    auto *Seal = morok::passes::runtime_seal::findChannel(
        *M, morok::passes::runtime_seal::kAntiDebugChannel);
    CHECK(Seal != nullptr);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("selfChecksumConstantsFunction fuses constants with xor and a diff call") {
    LLVMContext ctx;
    auto M = parse(ctx, kComputeModule);
    Function *F = M->getFunction("compute");
    REQUIRE(F != nullptr);

    auto rng = makeRng(0x5C07);
    morok::passes::SelfChecksumParams p; // default Activation cache mode
    CHECK(morok::passes::selfChecksumConstantsFunction(*F, p, rng));

    // Activation cache: one cached-diff alloca in the target, a call into the
    // diff function, and XOR ops reconstructing the fused constants.
    CHECK(countNamedAllocas(*F, "morok.sc.diff.cache") == std::size_t{1});
    CHECK(countCallsToPrefix(*F, "morok.sc.diff") >= std::size_t{1});
    CHECK(countOpcode(*M, static_cast<unsigned>(Instruction::Xor)) >
          std::size_t{0});
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("selfChecksumConstantsFunction respects the max_constants cap") {
    LLVMContext ctx;
    auto M = parse(ctx, kComputeModule);
    Function *F = M->getFunction("compute");
    REQUIRE(F != nullptr);

    auto rng = makeRng(0x5C08);
    morok::passes::SelfChecksumParams p;
    p.max_constants = 1; // at most one fused constant => at most one XOR mask

    CHECK(morok::passes::selfChecksumConstantsFunction(*F, p, rng));
    CHECK(countGlobals(*M, "morok.sc.mask.") == std::size_t{1});
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("selfChecksumConstantsFunction Static cache mode emits a cache stub") {
    LLVMContext ctx;
    auto M = parse(ctx, kComputeModule);
    Function *F = M->getFunction("compute");
    REQUIRE(F != nullptr);

    auto rng = makeRng(0x5C09);
    morok::passes::SelfChecksumParams p;
    p.diff_cache = morok::passes::SelfChecksumDiffCacheMode::Static;

    CHECK(morok::passes::selfChecksumConstantsFunction(*F, p, rng));

    // Static mode adds a memoizing cache function plus its value/key/ready slots
    // in front of the raw diff function.
    CHECK(countFunctions(*M, "morok.sc.cache.") == std::size_t{1});
    CHECK(countFunctions(*M, "morok.sc.diff.") == std::size_t{1});
    CHECK(countGlobals(*M, "morok.sc.cache.value.") == std::size_t{1});
    CHECK(countGlobals(*M, "morok.sc.cache.key.") == std::size_t{1});
    CHECK(countGlobals(*M, "morok.sc.cache.ready.") == std::size_t{1});
    CHECK(countCallsToPrefix(*F, "morok.sc.cache") >= std::size_t{1});
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("bindLeafHelpersToSeal binds reused helper returns to the seal") {
    LLVMContext ctx;
    auto M = parse(ctx, kHelperModule);
    Function *Main = M->getFunction("main");
    Function *Helper = M->getFunction("helper");
    REQUIRE(Main != nullptr);
    REQUIRE(Helper != nullptr);

    // Self-checksum main() first: this creates the seal channel and makes main()
    // a self-checked caller so helper() counts as a validation-cluster leaf.
    auto rngSc = makeRng(0x5C0A);
    morok::passes::SelfChecksumParams p;
    CHECK(morok::passes::selfChecksumConstantsFunction(*Main, p, rngSc));

    const std::size_t helperBinopsBefore = countBinops(*Helper);

    auto rngBind = makeRng(0x5C0B);
    CHECK(morok::passes::bindLeafHelpersToSeal(*M, rngBind));

    // The helper return is now folded with a seal-derived key.
    CHECK(countNamedInstructions(*Helper, "morok.helper.bound") >=
          std::size_t{1});
    CHECK(countBinops(*Helper) > helperBinopsBefore);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("bindLeafHelpersToSeal is a no-op without a seal channel") {
    LLVMContext ctx;
    auto M = parse(ctx, kHelperModule);

    // No self-checksum pass has run, so the anti-debug seal channel is absent.
    REQUIRE(morok::passes::runtime_seal::findChannel(
                *M, morok::passes::runtime_seal::kAntiDebugChannel) == nullptr);

    auto rng = makeRng(0x5C0C);
    CHECK_FALSE(morok::passes::bindLeafHelpersToSeal(*M, rng));
    CHECK(countNamedInstructions(*M, "morok.helper.bound") == std::size_t{0});
    CHECK_FALSE(verifyModule(*M));
}
