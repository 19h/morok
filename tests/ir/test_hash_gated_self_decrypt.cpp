// SPDX-License-Identifier: MIT
//
// Tests for HashGatedSelfDecrypt — wraps VM bytecode payloads in an outer
// encrypted layer with a hash-gated lazy decryptor, a moving/rotating layout,
// and a matching re-seal on helper return.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/HashGatedSelfDecrypt.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// A VM bytecode payload plus its matching `morok.vm.<suffix>.exec` helper —
// the exact shape collectPayloads() looks for. The plaintext "SECRET_BYTECODE"
// lets us assert that the outer-encryption step scrubs the readable bytes.
const char *kVmPayload = R"ir(
@morok.vm.bytecode.f0 = constant [16 x i8] c"SECRET_BYTECODE\00"

define i32 @morok.vm.f0.exec(i32 %x) {
entry:
  %r = add i32 %x, 7
  ret i32 %r
}
)ir";

// Three independent payloads for exercising the max_payloads cap.
const char *kThreeVmPayloads = R"ir(
@morok.vm.bytecode.f0 = constant [16 x i8] c"AAAAAAAAAAAAAAAA"
@morok.vm.bytecode.f1 = constant [16 x i8] c"BBBBBBBBBBBBBBBB"
@morok.vm.bytecode.f2 = constant [16 x i8] c"CCCCCCCCCCCCCCCC"

define i32 @morok.vm.f0.exec(i32 %x) {
entry:
  ret i32 %x
}
define i32 @morok.vm.f1.exec(i32 %x) {
entry:
  ret i32 %x
}
define i32 @morok.vm.f2.exec(i32 %x) {
entry:
  ret i32 %x
}
)ir";

// No bytecode global at all — nothing for the pass to wrap.
const char *kPlainModule = R"ir(
define i32 @main(i32 %x) {
entry:
  ret i32 %x
}
)ir";

// A bytecode global whose helper is only a declaration: collectPayloads must
// reject it (Helper->isDeclaration()).
const char *kDeclHelperModule = R"ir(
@morok.vm.bytecode.g0 = constant [8 x i8] c"ZZZZZZZZ"
declare i32 @morok.vm.g0.exec(i32)
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

} // namespace

TEST_CASE("hashGatedSelfDecryptModule wraps a VM payload and grows the module") {
    LLVMContext ctx;
    auto M = parse(ctx, kVmPayload);

    const std::size_t fnsBefore = countFunctions(*M, "");
    const std::size_t globalsBefore = countGlobals(*M, "");

    auto rng = makeRng(0xC0DE01);
    morok::passes::HashGatedSelfDecryptParams p;
    CHECK(morok::passes::hashGatedSelfDecryptModule(*M, p, rng));

    // Grew in both functions (ensure + seal + intrinsic decl) and globals.
    CHECK(countFunctions(*M, "") > fnsBefore);
    CHECK(countGlobals(*M, "") > globalsBefore);

    // Exactly one ensure + one seal function, seven sdb state globals.
    CHECK(countFunctions(*M, "morok.sdb.") == 2u);
    CHECK(countGlobals(*M, "morok.sdb.") == 7u);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("hashGatedSelfDecryptModule emits the per-payload seal-state globals") {
    LLVMContext ctx;
    auto M = parse(ctx, kVmPayload);

    auto rng = makeRng(0xC0DE02);
    morok::passes::HashGatedSelfDecryptParams p;
    REQUIRE(morok::passes::hashGatedSelfDecryptModule(*M, p, rng));

    // Every named channel wrapPayload() creates for suffix "f0".
    CHECK(M->getNamedGlobal("morok.sdb.ready.f0") != nullptr);
    CHECK(M->getNamedGlobal("morok.sdb.bound.f0") != nullptr);
    CHECK(M->getNamedGlobal("morok.sdb.bound.hash.f0") != nullptr);
    CHECK(M->getNamedGlobal("morok.sdb.bound.keymask.f0") != nullptr);
    CHECK(M->getNamedGlobal("morok.sdb.move.rot.f0") != nullptr);
    CHECK(M->getNamedGlobal("morok.sdb.move.epoch.f0") != nullptr);
    CHECK(M->getNamedGlobal("morok.sdb.poison.f0") != nullptr);

    CHECK(M->getFunction("morok.sdb.ensure.f0") != nullptr);
    CHECK(M->getFunction("morok.sdb.seal.f0") != nullptr);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("hashGatedSelfDecryptModule makes the bytecode mutable and scrubs plaintext") {
    LLVMContext ctx;
    auto M = parse(ctx, kVmPayload);

    // Sanity: the plaintext is readable before the pass runs.
    CHECK(hasReadableByteString(*M, "SECRET"));

    auto rng = makeRng(0xC0DE03);
    morok::passes::HashGatedSelfDecryptParams p;
    REQUIRE(morok::passes::hashGatedSelfDecryptModule(*M, p, rng));

    // makeMutablePayload() flips the global to non-constant and rewrites it
    // with the outer-encrypted (rotated) bytes.
    GlobalVariable *Bytecode = M->getNamedGlobal("morok.vm.bytecode.f0");
    REQUIRE(Bytecode != nullptr);
    CHECK_FALSE(Bytecode->isConstant());
    CHECK_FALSE(hasReadableByteString(*M, "SECRET"));

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("hashGatedSelfDecryptModule wires ensure and seal into the helper") {
    LLVMContext ctx;
    auto M = parse(ctx, kVmPayload);

    auto rng = makeRng(0xC0DE04);
    morok::passes::HashGatedSelfDecryptParams p;
    REQUIRE(morok::passes::hashGatedSelfDecryptModule(*M, p, rng));

    Function *Helper = M->getFunction("morok.vm.f0.exec");
    REQUIRE(Helper != nullptr);

    // insertEnsureCall() + insertSealCalls(): the single-return helper gains
    // exactly one call to each generated runtime function.
    CHECK(countCallsTo(*Helper, "morok.sdb.ensure.f0") == 1u);
    CHECK(countCallsTo(*Helper, "morok.sdb.seal.f0") == 1u);
    CHECK(countCallsToPrefix(*Helper, "morok.sdb.") == 2u);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("hashGatedSelfDecryptModule emits the hash-gate and lock machinery") {
    LLVMContext ctx;
    auto M = parse(ctx, kVmPayload);

    auto rng = makeRng(0xC0DE05);
    morok::passes::HashGatedSelfDecryptParams p;
    REQUIRE(morok::passes::hashGatedSelfDecryptModule(*M, p, rng));

    // The ready-word claim/retain/release protocol uses cmpxchg.
    CHECK(countOpcode(*M, static_cast<unsigned>(Instruction::AtomicCmpXchg)) >
          0u);

    // The ensure decryptor is a real loop: it carries PHI nodes.
    Function *Ensure = M->getFunction("morok.sdb.ensure.f0");
    REQUIRE(Ensure != nullptr);
    CHECK(countPhis(*Ensure) > 0u);

    // emitEnvironmentZero() always folds in the cycle counter (triple-neutral).
    CHECK(M->getFunction("llvm.readcyclecounter") != nullptr);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("hashGatedSelfDecryptModule respects the max_payloads cap") {
    LLVMContext ctx;
    auto M = parse(ctx, kThreeVmPayloads);

    auto rng = makeRng(0xC0DE06);
    morok::passes::HashGatedSelfDecryptParams p;
    p.max_payloads = 2;
    p.probability = 100; // wrap every payload we reach, until the cap trips
    REQUIRE(morok::passes::hashGatedSelfDecryptModule(*M, p, rng));

    // Only two of the three payloads may be wrapped.
    CHECK(countFunctions(*M, "morok.sdb.ensure.") == 2u);
    CHECK(countFunctions(*M, "morok.sdb.seal.") == 2u);
    CHECK(countGlobals(*M, "morok.sdb.") == 14u); // 7 state globals x 2

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("hashGatedSelfDecryptModule is a no-op when probability is zero") {
    LLVMContext ctx;
    auto M = parse(ctx, kVmPayload);

    auto rng = makeRng(0xC0DE07);
    morok::passes::HashGatedSelfDecryptParams p;
    p.probability = 0;

    CHECK_FALSE(morok::passes::hashGatedSelfDecryptModule(*M, p, rng));
    CHECK(countGlobals(*M, "morok.sdb.") == 0u);
    CHECK(countFunctions(*M, "morok.sdb.") == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("hashGatedSelfDecryptModule skips modules without wrappable payloads") {
    // No bytecode global at all.
    {
        LLVMContext ctx;
        auto M = parse(ctx, kPlainModule);
        auto rng = makeRng(0xC0DE08);
        morok::passes::HashGatedSelfDecryptParams p;
        CHECK_FALSE(morok::passes::hashGatedSelfDecryptModule(*M, p, rng));
        CHECK(countGlobals(*M, "morok.sdb.") == 0u);
        CHECK_FALSE(verifyModule(*M));
    }

    // Bytecode present, but its helper is only a declaration.
    {
        LLVMContext ctx;
        auto M = parse(ctx, kDeclHelperModule);
        auto rng = makeRng(0xC0DE09);
        morok::passes::HashGatedSelfDecryptParams p;
        CHECK_FALSE(morok::passes::hashGatedSelfDecryptModule(*M, p, rng));
        CHECK(countGlobals(*M, "morok.sdb.") == 0u);
        CHECK_FALSE(verifyModule(*M));
    }
}

TEST_CASE("hashGatedSelfDecryptModule is idempotent on an already-wrapped module") {
    LLVMContext ctx;
    auto M = parse(ctx, kVmPayload);

    morok::passes::HashGatedSelfDecryptParams p;
    auto rngFirst = makeRng(0xC0DE0A);
    REQUIRE(morok::passes::hashGatedSelfDecryptModule(*M, p, rngFirst));
    const std::size_t globalsAfterFirst = countGlobals(*M, "morok.sdb.");

    // Second run: the existing morok.sdb.ensure.* function makes collectPayloads
    // skip the (now non-constant) payload, so nothing changes.
    auto rngSecond = makeRng(0xC0DE0B);
    CHECK_FALSE(morok::passes::hashGatedSelfDecryptModule(*M, p, rngSecond));
    CHECK(countGlobals(*M, "morok.sdb.") == globalsAfterFirst);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("hashGatedSelfDecryptModule is deterministic for a fixed seed") {
    LLVMContext ctx1;
    LLVMContext ctx2;
    auto M1 = parse(ctx1, kVmPayload);
    auto M2 = parse(ctx2, kVmPayload);

    // Two independent engines seeded identically must drive identical output.
    auto engine1 = morok::core::Xoshiro256pp::fromSeed(0x5EEDFACE);
    auto engine2 = morok::core::Xoshiro256pp::fromSeed(0x5EEDFACE);
    morok::ir::IRRandom rng1(engine1);
    morok::ir::IRRandom rng2(engine2);

    morok::passes::HashGatedSelfDecryptParams p;
    CHECK(morok::passes::hashGatedSelfDecryptModule(*M1, p, rng1));
    CHECK(morok::passes::hashGatedSelfDecryptModule(*M2, p, rng2));

    std::string text1;
    std::string text2;
    raw_string_ostream os1(text1);
    raw_string_ostream os2(text2);
    M1->print(os1, nullptr);
    M2->print(os2, nullptr);
    os1.flush();
    os2.flush();

    CHECK(text1 == text2);
    CHECK_FALSE(verifyModule(*M1));
    CHECK_FALSE(verifyModule(*M2));
}
