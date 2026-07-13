// SPDX-License-Identifier: MIT
//
// Tests for DecoyStrings — plausible honeypot logging strings/infrastructure.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/DecoyStrings.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// Representative module with two real, eligible functions.  No target triple is
// set on purpose: with an empty triple the pass's x86_64+Linux "isolated
// dispatch" branch is inactive on every CI host, so the behaviour is identical
// across linux-x86_64, linux-arm64, macOS-arm64 and windows-x86_64.
const char *kModule = R"ir(
define i32 @main(i32 %x) {
entry:
  %y = add i32 %x, 1
  ret i32 %y
}

define i32 @helper(i32 %a) {
entry:
  %b = mul i32 %a, 3
  ret i32 %b
}
)ir";

// Explicit triple pins the codegen path for the determinism test so the output
// does not vary with the host that runs the test binary.
const char *kModuleTriple = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @main(i32 %x) {
entry:
  %y = add i32 %x, 1
  ret i32 %y
}
)ir";

// Only declarations — no function body is eligible, so the pass must be a no-op.
const char *kDeclOnly = R"ir(
declare void @external()
declare i32 @printf(ptr, ...)
)ir";

// The only definition is optnone; the pass guards optnone functions out, so
// there are no eligible targets and the pass must be a no-op.
const char *kOptNoneOnly = R"ir(
define void @noopt() noinline optnone {
entry:
  ret void
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

} // namespace

TEST_CASE("decoyStringsModule grows the module and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kModule);

    auto rng = makeRng(0xD0C0);
    CHECK(morok::passes::decoyStringsModule(*M, rng));

    // Bogus logging infrastructure: exactly five log functions and five state
    // globals.
    CHECK(countFunctions(*M, "morok.dbglog.") == 5);
    CHECK(countGlobals(*M, "morok.dbglog.state.") == 5);

    // One decoy string global and one site function per decoy line.
    const std::size_t strCount = countGlobals(*M, "morok.decoy.str.");
    const std::size_t siteCount = countFunctions(*M, "morok.decoy.site.");
    CHECK(strCount >= 1);
    CHECK(siteCount == strCount);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("decoyStringsModule emits the bogus logging infrastructure") {
    LLVMContext ctx;
    auto M = parse(ctx, kModule);

    auto rng = makeRng(0xD0C1);
    CHECK(morok::passes::decoyStringsModule(*M, rng));

    // All five named diagnostics helpers must exist.
    CHECK(M->getFunction("morok.dbglog.event") != nullptr);
    CHECK(M->getFunction("morok.dbglog.trace") != nullptr);
    CHECK(M->getFunction("morok.dbglog.emit") != nullptr);
    CHECK(M->getFunction("morok.dbglog.notify") != nullptr);
    CHECK(M->getFunction("morok.dbglog.diagnostic") != nullptr);

    auto *ev = M->getFunction("morok.dbglog.event");
    REQUIRE(ev != nullptr);
    CHECK(ev->hasInternalLinkage());
    CHECK(ev->doesNotThrow());

    // The volatile state global backing the helpers is private.
    auto *st0 = M->getNamedGlobal("morok.dbglog.state.0");
    REQUIRE(st0 != nullptr);
    CHECK(st0->hasPrivateLinkage());

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("decoyStringsModule emits private constant plaintext decoy strings") {
    LLVMContext ctx;
    auto M = parse(ctx, kModule);

    auto rng = makeRng(0xD0C2);
    CHECK(morok::passes::decoyStringsModule(*M, rng));

    std::size_t strGlobals = 0;
    for (GlobalVariable &G : M->globals()) {
        if (!G.getName().starts_with("morok.decoy.str."))
            continue;
        ++strGlobals;
        // Decoys are read-only, private, and stored as plain C strings — they
        // are meant to be found and read, not decrypted.
        CHECK(G.isConstant());
        CHECK(G.hasPrivateLinkage());
        REQUIRE(G.hasInitializer());
        CHECK(dyn_cast<ConstantDataArray>(G.getInitializer()) != nullptr);
    }
    CHECK(strGlobals >= 1);

    // Every decoy theme references the fictional "sve" tool in plaintext.
    CHECK(hasReadableByteString(*M, "sve"));

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("decoyStringsModule site functions call a logging helper") {
    LLVMContext ctx;
    auto M = parse(ctx, kModule);

    auto rng = makeRng(0xD0C3);
    CHECK(morok::passes::decoyStringsModule(*M, rng));

    std::size_t siteFns = 0;
    for (Function &F : *M) {
        if (!F.getName().starts_with("morok.decoy.site."))
            continue;
        ++siteFns;
        // Each site helper makes exactly one call into the decoy log API.
        CHECK(countCallsToPrefix(F, "morok.dbglog.") == 1);
    }
    CHECK(siteFns >= 1);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("decoyStringsModule anchors infrastructure in llvm.used") {
    LLVMContext ctx;
    auto M = parse(ctx, kModule);

    auto rng = makeRng(0xD0C4);
    CHECK(morok::passes::decoyStringsModule(*M, rng));

    // appendToUsed / appendToCompilerUsed keep the decoy globals and helpers
    // alive against dead-code elimination.
    CHECK(M->getNamedGlobal("llvm.used") != nullptr);
    CHECK(M->getNamedGlobal("llvm.compiler.used") != nullptr);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("decoyStringsModule is a no-op on declaration-only modules") {
    LLVMContext ctx;
    auto M = parse(ctx, kDeclOnly);

    auto rng = makeRng(0xD0C5);
    // No function has a body, so there is nothing eligible to instrument.
    CHECK_FALSE(morok::passes::decoyStringsModule(*M, rng));

    // Nothing was added.
    CHECK(countFunctions(*M, "morok.") == 0);
    CHECK(countGlobals(*M, "morok.") == 0);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("decoyStringsModule skips optnone-only modules") {
    LLVMContext ctx;
    auto M = parse(ctx, kOptNoneOnly);

    auto rng = makeRng(0xD0C6);
    // The single definition is optnone and is guarded out; no eligible target.
    CHECK_FALSE(morok::passes::decoyStringsModule(*M, rng));

    CHECK(countFunctions(*M, "morok.") == 0);
    CHECK(countGlobals(*M, "morok.") == 0);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("decoyStringsModule is deterministic for identical seed and input") {
    LLVMContext ctx;
    auto M1 = parse(ctx, kModuleTriple);
    auto M2 = parse(ctx, kModuleTriple);

    // Use freshly seeded, independent engines so the streams are genuinely
    // identical (the shared makeRng engine keeps advancing across tests).
    auto engine1 = morok::core::Xoshiro256pp::fromSeed(0xBEEF1234);
    auto engine2 = morok::core::Xoshiro256pp::fromSeed(0xBEEF1234);
    morok::ir::IRRandom rng1(engine1);
    morok::ir::IRRandom rng2(engine2);

    const bool fired1 = morok::passes::decoyStringsModule(*M1, rng1);
    const bool fired2 = morok::passes::decoyStringsModule(*M2, rng2);
    CHECK(fired1);
    CHECK(fired2);

    std::string s1;
    std::string s2;
    raw_string_ostream os1(s1);
    raw_string_ostream os2(s2);
    M1->print(os1, nullptr);
    M2->print(os2, nullptr);
    os1.flush();
    os2.flush();

    CHECK(s1 == s2);

    CHECK_FALSE(verifyModule(*M1));
    CHECK_FALSE(verifyModule(*M2));
}
