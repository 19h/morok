// SPDX-License-Identifier: MIT
//
// Tests for FunctionCallObfuscate — redirect direct calls to external
// (declared) functions through a cloaked runtime symbol resolution, erasing the
// static call/import edge.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/FunctionCallObfuscate.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;
using namespace morok::test;

namespace {

// No `target triple` is set on purpose: `useManualHashResolver` requires an
// explicit Linux/Darwin/Windows-x86_64 triple, so an empty triple forces the
// portable cloaked-`dlsym` fallback path on every CI host (linux-x86_64,
// linux-arm64, macOS-arm64, windows-x86_64).  The pass reads the module triple,
// never the host, so this behaves identically everywhere.
const char *kCallsExternal = R"ir(
declare i32 @secret_api_function(ptr)

define i32 @app(ptr %p) {
entry:
  %r = call i32 @secret_api_function(ptr %p)
  ret i32 %r
}
)ir";

// Only calls a locally-defined function: no eligible external call site.
const char *kNoExternalCall = R"ir(
define i32 @helper(i32 %x) {
entry:
  ret i32 %x
}

define i32 @app(i32 %x) {
entry:
  %r = call i32 @helper(i32 %x)
  ret i32 %r
}
)ir";

const char *kDeclOnly = R"ir(
declare void @external()
)ir";

const char *kTrivial = R"ir(
define i32 @app(i32 %x) {
entry:
  ret i32 %x
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

} // namespace

TEST_CASE("functionCallObfuscateModule redirects an external call and stays "
          "valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kCallsExternal);

    const std::size_t functionsBefore = countFunctions(*M, "");
    CHECK(countNamedInstructions(*M, "morok.") == 0);

    auto rng = makeRng(0xFC0001);
    morok::passes::FcoParams p;
    CHECK(morok::passes::functionCallObfuscateModule(*M, p, rng));

    // The rewrite grows the module: a `dlsym` declaration plus opaque-zero
    // helpers appear, and the call site gains resolution/decode scaffolding.
    CHECK(countFunctions(*M, "") > functionsBefore);
    CHECK(countNamedInstructions(*M, "morok.") > 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("functionCallObfuscateModule removes the direct external call edge") {
    LLVMContext ctx;
    auto M = parse(ctx, kCallsExternal);

    Function *app = M->getFunction("app");
    REQUIRE(app != nullptr);
    CHECK(countCallsTo(*app, "secret_api_function") == 1);

    auto rng = makeRng(0xFC0002);
    morok::passes::FcoParams p;
    CHECK(morok::passes::functionCallObfuscateModule(*M, p, rng));

    // The static call edge to the external symbol is gone; it is now an
    // indirect call through the resolved pointer.
    CHECK(countCallsTo(*app, "secret_api_function") == 0);

    // The dlsym fallback resolver is imported as a declaration.
    Function *dlsym = M->getFunction("dlsym");
    REQUIRE(dlsym != nullptr);
    CHECK(dlsym->isDeclaration());
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("functionCallObfuscateModule cloaks the symbol name") {
    LLVMContext ctx;
    auto M = parse(ctx, kCallsExternal);

    auto rng = makeRng(0xFC0003);
    morok::passes::FcoParams p;
    CHECK(morok::passes::functionCallObfuscateModule(*M, p, rng));

    // The symbol is recovered from per-site ciphertext globals, so the plaintext
    // API name never survives as a readable byte string in the artifact.
    CHECK(countGlobals(*M, "morok.cloak.") >= 1);
    CHECK_FALSE(hasReadableByteString(*M, "secret_api_function"));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("functionCallObfuscateModule emits the dlsym resolve/decode "
          "scaffold") {
    LLVMContext ctx;
    auto M = parse(ctx, kCallsExternal);

    auto rng = makeRng(0xFC0004);
    morok::passes::FcoParams p;
    CHECK(morok::passes::functionCallObfuscateModule(*M, p, rng));

    Function *app = M->getFunction("app");
    REQUIRE(app != nullptr);

    // A runtime dlsym lookup and a pointer encode/decode round-trip are emitted
    // at the call site: the cloaked-name stack buffer and the encoded-pointer
    // slot are both entry-block allocas.
    CHECK(countCallsTo(*app, "dlsym") >= 1);
    CHECK(countNamedAllocas(*app, "morok.cloak.buf") >= 1);
    CHECK(countNamedAllocas(*app, "morok.fco.ptr.slot") >= 1);
    CHECK(countNamedInstructions(*app, "morok.fco.ptr.") > 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("functionCallObfuscateModule with probability 0 is a no-op") {
    LLVMContext ctx;
    auto M = parse(ctx, kCallsExternal);

    const std::size_t functionsBefore = countFunctions(*M, "");

    auto rng = makeRng(0xFC0005);
    morok::passes::FcoParams p;
    p.probability = 0;
    CHECK_FALSE(morok::passes::functionCallObfuscateModule(*M, p, rng));

    Function *app = M->getFunction("app");
    REQUIRE(app != nullptr);
    CHECK(countCallsTo(*app, "secret_api_function") == 1);
    CHECK(countFunctions(*M, "") == functionsBefore);
    CHECK(countNamedInstructions(*M, "morok.") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("functionCallObfuscateModule with max_calls 0 is a no-op") {
    LLVMContext ctx;
    auto M = parse(ctx, kCallsExternal);

    auto rng = makeRng(0xFC0006);
    morok::passes::FcoParams p;
    p.max_calls = 0;
    CHECK_FALSE(morok::passes::functionCallObfuscateModule(*M, p, rng));

    Function *app = M->getFunction("app");
    REQUIRE(app != nullptr);
    CHECK(countCallsTo(*app, "secret_api_function") == 1);
    CHECK(countNamedInstructions(*M, "morok.") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("functionCallObfuscateModule leaves modules without external calls "
          "unchanged") {
    LLVMContext ctx;
    auto M = parse(ctx, kNoExternalCall);

    // The only call targets a locally-defined function (not a declaration), so
    // it is ineligible and nothing is rewritten.
    auto rng = makeRng(0xFC0007);
    morok::passes::FcoParams p;
    CHECK_FALSE(morok::passes::functionCallObfuscateModule(*M, p, rng));

    Function *app = M->getFunction("app");
    REQUIRE(app != nullptr);
    CHECK(countCallsTo(*app, "helper") == 1);
    CHECK(countNamedInstructions(*M, "morok.") == 0);
    CHECK(M->getFunction("dlsym") == nullptr);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("functionCallObfuscateModule is safe on declaration-only and trivial "
          "modules") {
    LLVMContext ctx;

    auto declOnly = parse(ctx, kDeclOnly);
    auto rngDecl = makeRng(0xFC0008);
    morok::passes::FcoParams pDecl;
    CHECK_FALSE(
        morok::passes::functionCallObfuscateModule(*declOnly, pDecl, rngDecl));
    CHECK_FALSE(verifyModule(*declOnly));

    auto trivial = parse(ctx, kTrivial);
    auto rngTriv = makeRng(0xFC0009);
    morok::passes::FcoParams pTriv;
    CHECK_FALSE(
        morok::passes::functionCallObfuscateModule(*trivial, pTriv, rngTriv));
    CHECK(countNamedInstructions(*trivial, "morok.") == 0);
    CHECK_FALSE(verifyModule(*trivial));
}

TEST_CASE("functionCallObfuscateModule is deterministic for a fixed seed") {
    LLVMContext ctx;
    auto M1 = parse(ctx, kCallsExternal);
    auto M2 = parse(ctx, kCallsExternal);

    // Two fresh engines seeded identically drive two independent runs over
    // identical input, so the emitted IR must be byte-for-byte identical.
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0xDEADBEEF);
    morok::ir::IRRandom rngA(engineA);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0xDEADBEEF);
    morok::ir::IRRandom rngB(engineB);

    morok::passes::FcoParams p;
    CHECK(morok::passes::functionCallObfuscateModule(*M1, p, rngA));
    CHECK(morok::passes::functionCallObfuscateModule(*M2, p, rngB));

    std::string text1;
    raw_string_ostream os1(text1);
    M1->print(os1, nullptr);
    std::string text2;
    raw_string_ostream os2(text2);
    M2->print(os2, nullptr);

    CHECK(text1 == text2);
    CHECK_FALSE(verifyModule(*M1));
    CHECK_FALSE(verifyModule(*M2));
}
