// SPDX-License-Identifier: MIT
//
// Tests for StringEncryption — encrypt string literals at rest, bind the
// keystream seed to runtime seals, and inline constant-format libc calls.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/StringEncryption.hpp"

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// A private, read-only C string containing a readable plaintext secret, loaded
// (used) inside a single function so the pass has a concrete decrypt site.
const char *kSecretModule = R"ir(
target triple = "x86_64-unknown-linux-gnu"

@.secret = private unnamed_addr constant [7 x i8] c"S3cr3t\00"

define i32 @main() {
entry:
  %c = load i8, ptr @.secret
  %z = zext i8 %c to i32
  ret i32 %z
}
)ir";

// The secret's address escapes into static data (a global pointer), so the
// pass must fall back to an init-time constructor decryptor.
const char *kEscapeModule = R"ir(
target triple = "x86_64-unknown-linux-gnu"

@.secret = private unnamed_addr constant [7 x i8] c"S3cr3t\00"
@g_ptr = global ptr @.secret
)ir";

// A sensitive-output-label string ("Password:") — forced regardless of the
// per-string probability.
const char *kPasswordModule = R"ir(
target triple = "x86_64-unknown-linux-gnu"

@.pw = private unnamed_addr constant [13 x i8] c"Password: 42\00"

define i32 @check() {
entry:
  %c = load i8, ptr @.pw
  %z = zext i8 %c to i32
  ret i32 %z
}
)ir";

// An externally-visible (non-local) string constant is ineligible.
const char *kIneligibleModule = R"ir(
target triple = "x86_64-unknown-linux-gnu"

@pub = constant [7 x i8] c"S3cr3t\00"

declare void @ext()
)ir";

// A printf call over a constant format string with one %s argument.
const char *kPrintfModule = R"ir(
target triple = "x86_64-unknown-linux-gnu"

@.fmt = private unnamed_addr constant [4 x i8] c"%s\0A\00"

declare i32 @printf(ptr, ...)

define i32 @greet(ptr %name) {
entry:
  %r = call i32 (ptr, ...) @printf(ptr @.fmt, ptr %name)
  ret i32 %r
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

std::string moduleToText(Module &M) {
    std::string text;
    raw_string_ostream os(text);
    M.print(os, nullptr);
    os.flush();
    return text;
}

} // namespace

TEST_CASE("stringEncryptModule renders a plaintext global unreadable") {
    LLVMContext ctx;
    auto M = parse(ctx, kSecretModule);

    // The plaintext is present at rest before the pass runs.
    CHECK(hasReadableByteString(*M, "S3cr3t"));

    auto rng = makeRng(0x51A1);
    morok::passes::StrEncParams p;
    p.force_content = {"S3cr3t"}; // guarantee selection irrespective of RNG

    CHECK(morok::passes::stringEncryptModule(*M, p, rng));

    // The readable byte string no longer exists anywhere in the module.
    CHECK_FALSE(hasReadableByteString(*M, "S3cr3t"));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stringEncryptModule grows the module with seed provider and blob") {
    LLVMContext ctx;
    auto M = parse(ctx, kSecretModule);

    const std::size_t fnsBefore = countFunctions(*M, "");
    const std::size_t globalsBefore = countGlobals(*M, "");

    auto rng = makeRng(0x51A2);
    morok::passes::StrEncParams p;
    p.force_content = {"S3cr3t"};

    CHECK(morok::passes::stringEncryptModule(*M, p, rng));

    // The pass adds a runtime seed provider function and its private KDF blob,
    // plus a per-string decryptor and a once-state guard global.
    CHECK(countFunctions(*M, "") > fnsBefore);
    CHECK(countGlobals(*M, "") > globalsBefore);
    CHECK(M->getFunction("morok.str.seed") != nullptr);
    CHECK(countGlobals(*M, "morok.str.kdf.blob") >= 1);
    CHECK(countFunctions(*M, "morok.") >= 2);
    CHECK(countGlobals(*M, "morok.") >= 2);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stringEncryptModule with probability 0 leaves random strings alone") {
    LLVMContext ctx;
    auto M = parse(ctx, kSecretModule);

    auto rng = makeRng(0x51A3);
    morok::passes::StrEncParams p;
    p.probability = 0; // not forced and not sensitive => nothing to encrypt

    CHECK_FALSE(morok::passes::stringEncryptModule(*M, p, rng));

    // Nothing was queued, so the plaintext survives and no infra was emitted.
    CHECK(hasReadableByteString(*M, "S3cr3t"));
    CHECK(countFunctions(*M, "morok.") == 0);
    CHECK(M->getFunction("morok.str.seed") == nullptr);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stringEncryptModule forces sensitive-label strings at probability 0") {
    LLVMContext ctx;
    auto M = parse(ctx, kPasswordModule);

    CHECK(hasReadableByteString(*M, "Password:"));

    auto rng = makeRng(0x51A4);
    morok::passes::StrEncParams p;
    p.probability = 0; // "Password:" is force-selected despite probability 0

    CHECK(morok::passes::stringEncryptModule(*M, p, rng));

    CHECK_FALSE(hasReadableByteString(*M, "Password:"));
    CHECK(M->getFunction("morok.str.seed") != nullptr);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stringEncryptModule skips ineligible non-local globals") {
    LLVMContext ctx;
    auto M = parse(ctx, kIneligibleModule);

    auto rng = makeRng(0x51A5);
    morok::passes::StrEncParams p;
    p.force_content = {"S3cr3t"}; // still ineligible: external linkage

    CHECK_FALSE(morok::passes::stringEncryptModule(*M, p, rng));

    CHECK(hasReadableByteString(*M, "S3cr3t"));
    CHECK(countFunctions(*M, "morok.") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stringEncryptModule registers a constructor for escaping strings") {
    LLVMContext ctx;
    auto M = parse(ctx, kEscapeModule);

    auto rng = makeRng(0x51A6);
    morok::passes::StrEncParams p;
    p.force_content = {"S3cr3t"};

    CHECK(morok::passes::stringEncryptModule(*M, p, rng));

    // The address escapes into static data, so decryption runs from a global
    // constructor rather than a function-entry hook.
    CHECK(M->getFunction("morok.strdec") != nullptr);
    CHECK(M->getNamedGlobal("llvm.global_ctors") != nullptr);
    CHECK(countGlobals(*M, "morok.strg") >= 1);
    CHECK_FALSE(hasReadableByteString(*M, "S3cr3t"));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stringEncryptModule is deterministic for identical seed and input") {
    LLVMContext ctx1;
    LLVMContext ctx2;
    auto M1 = parse(ctx1, kEscapeModule);
    auto M2 = parse(ctx2, kEscapeModule);

    // Independent engines seeded identically (the shared static makeRng engine
    // cannot express this), so both runs consume the same PRNG stream.
    auto engine1 = morok::core::Xoshiro256pp::fromSeed(0xC0FFEE);
    auto engine2 = morok::core::Xoshiro256pp::fromSeed(0xC0FFEE);
    morok::ir::IRRandom rng1(engine1);
    morok::ir::IRRandom rng2(engine2);

    morok::passes::StrEncParams p;
    p.force_content = {"S3cr3t"};

    CHECK(morok::passes::stringEncryptModule(*M1, p, rng1));
    CHECK(morok::passes::stringEncryptModule(*M2, p, rng2));

    CHECK(moduleToText(*M1) == moduleToText(*M2));
    CHECK_FALSE(verifyModule(*M1));
    CHECK_FALSE(verifyModule(*M2));
}

TEST_CASE("stringEncryptModule inlineConstantFormatCalls rewrites a printf") {
    LLVMContext ctx;
    auto M = parse(ctx, kPrintfModule);

    CHECK(morok::passes::inlineConstantFormatCalls(*M));

    Function *greet = M->getFunction("greet");
    REQUIRE(greet != nullptr);

    // The libc printf call is replaced by a generated per-site printer helper.
    CHECK(countCallsTo(*greet, "printf") == 0);
    CHECK(countCallsToPrefix(*greet, "morok.print") >= 1);
    CHECK(countFunctions(*M, "morok.print") >= 1);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stringEncryptModule inlineConstantFormatCalls no-op without libc decls") {
    LLVMContext ctx;
    auto M = parse(ctx, kSecretModule); // no printf/sprintf/sscanf declarations

    CHECK_FALSE(morok::passes::inlineConstantFormatCalls(*M));
    CHECK(countFunctions(*M, "morok.") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stringEncryptModule bindStringSeedToSeal no-op without seal channels") {
    LLVMContext ctx;
    auto M = parse(ctx, kSecretModule);

    // Create the morok.str.seed provider so bindStringSeedToSeal exercises its
    // channel scan; with no seal channels present it must not change anything.
    auto rng = makeRng(0x51A7);
    morok::passes::StrEncParams p;
    p.force_content = {"S3cr3t"};
    CHECK(morok::passes::stringEncryptModule(*M, p, rng));
    REQUIRE(M->getFunction("morok.str.seed") != nullptr);

    auto sealRng = makeRng(0x51A8);
    CHECK_FALSE(morok::passes::bindStringSeedToSeal(*M, sealRng));
    CHECK_FALSE(verifyModule(*M));
}
