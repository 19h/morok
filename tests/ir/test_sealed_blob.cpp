// SPDX-License-Identifier: MIT
//
// Tests for SealedBlob — encrypt explicit byte-array globals at rest and
// rewrite their uses to materialize lazily through a per-blob accessor.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/RuntimeSeal.hpp"
#include "morok/passes/SealedBlob.hpp"

#include "llvm/IR/Attributes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;
using namespace morok::test;

namespace {

// A single sealed, used blob: a private constant i8 array selected by the
// "morok.sealed." name prefix, loaded from within a defined function.
const char *kSealedLoad = R"ir(
target triple = "x86_64-unknown-linux-gnu"

@morok.sealed.secret = private constant [8 x i8] c"\01\02\03\04\05\06\07\08"

define i8 @use() {
entry:
  %v = load i8, ptr @morok.sealed.secret
  ret i8 %v
}
)ir";

// A sealed blob whose plaintext is a readable, NUL-terminated C string.
const char *kSealedCString = R"ir(
target triple = "x86_64-unknown-linux-gnu"

@morok.sealed.msg = private constant [12 x i8] c"hello world\00"

define i8 @use() {
entry:
  %v = load i8, ptr @morok.sealed.msg
  ret i8 %v
}
)ir";

// Three sealed, used blobs to exercise the max_blobs cap.
const char *kThreeBlobs = R"ir(
target triple = "x86_64-unknown-linux-gnu"

@morok.sealed.a = private constant [4 x i8] c"aaaa"
@morok.sealed.b = private constant [4 x i8] c"bbbb"
@morok.sealed.c = private constant [4 x i8] c"cccc"

define i8 @use() {
entry:
  %va = load i8, ptr @morok.sealed.a
  %vb = load i8, ptr @morok.sealed.b
  %vc = load i8, ptr @morok.sealed.c
  %s1 = add i8 %va, %vb
  %s2 = add i8 %s1, %vc
  ret i8 %s2
}
)ir";

// A blob selected purely by section (bare ".morok.sealed", ELF-style), with a
// name that does NOT match the "morok.sealed." prefix.
const char *kSectionBlob = R"ir(
target triple = "x86_64-unknown-linux-gnu"

@rawblob = private constant [4 x i8] c"\01\02\03\04", section ".morok.sealed"

define i8 @use() {
entry:
  %v = load i8, ptr @rawblob
  ret i8 %v
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

} // namespace

TEST_CASE("sealedBlobModule seals a used blob and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kSealedLoad);

    const std::size_t beforeFns = countFunctions(*M, "");

    auto rng = makeRng(0xB001);
    morok::passes::SealedBlobParams p;
    CHECK(morok::passes::sealedBlobModule(*M, p, rng));

    // A new accessor function appears, and the storage global is renamed to the
    // cipher prefix.
    CHECK(countFunctions(*M, "") > beforeFns);
    CHECK(countFunctions(*M, "morok.sealed.open.") == 1u);
    CHECK(countGlobals(*M, "morok.sealed.cipher.") == 1u);

    // The accessor is emitted noinline / nounwind so it is not folded away.
    Function *Open = nullptr;
    for (Function &F : *M)
        if (F.getName().starts_with("morok.sealed.open."))
            Open = &F;
    REQUIRE(Open != nullptr);
    CHECK(Open->hasFnAttribute(Attribute::NoInline));
    CHECK(Open->hasFnAttribute(Attribute::NoUnwind));

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("sealedBlobModule scrubs the plaintext byte string") {
    LLVMContext ctx;
    auto M = parse(ctx, kSealedCString);

    // The readable plaintext is present before sealing.
    CHECK(hasReadableByteString(*M, "hello world"));

    auto rng = makeRng(0xB002);
    morok::passes::SealedBlobParams p;
    CHECK(morok::passes::sealedBlobModule(*M, p, rng));

    // After sealing, the ciphertext no longer exposes the plaintext.
    CHECK_FALSE(hasReadableByteString(*M, "hello world"));
    CHECK(countGlobals(*M, "morok.sealed.cipher.") == 1u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("sealedBlobModule rewrites uses through the accessor") {
    LLVMContext ctx;
    auto M = parse(ctx, kSealedLoad);

    auto rng = makeRng(0xB003);
    morok::passes::SealedBlobParams p; // zeroize_after_use defaults to true
    CHECK(morok::passes::sealedBlobModule(*M, p, rng));

    Function *F = M->getFunction("use");
    REQUIRE(F != nullptr);

    // The use site gains a local scratch alloca, an accessor call that fills it,
    // and a volatile scrub memset after the use.
    CHECK(countNamedAllocas(*F, "morok.sealed.local") == 1u);
    CHECK(countCallsToPrefix(*F, "morok.sealed.open.") == 1u);
    CHECK(countCallsToPrefix(*F, "llvm.memset") >= 1u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("sealedBlobModule respects the max_blobs cap") {
    LLVMContext ctx;
    auto M = parse(ctx, kThreeBlobs);

    auto rng = makeRng(0xB004);
    morok::passes::SealedBlobParams p;
    p.max_blobs = 2;
    CHECK(morok::passes::sealedBlobModule(*M, p, rng));

    // Only two of the three eligible blobs get accessors/ciphered storage.
    CHECK(countFunctions(*M, "morok.sealed.open.") == 2u);
    CHECK(countGlobals(*M, "morok.sealed.cipher.") == 2u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("sealedBlobModule selects via the .morok.sealed section") {
    LLVMContext ctx;
    auto M = parse(ctx, kSectionBlob);

    auto rng = makeRng(0xB005);
    morok::passes::SealedBlobParams p;
    CHECK(morok::passes::sealedBlobModule(*M, p, rng));

    // The section-selected global is sealed and renamed to the cipher prefix.
    CHECK(countGlobals(*M, "morok.sealed.cipher.") == 1u);
    CHECK(countGlobals(*M, "rawblob") == 0u);
    CHECK(countFunctions(*M, "morok.sealed.open.") == 1u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("sealedBlobModule runtime_keyed_magic wires anti_debug channel and "
          "tag sink") {
    LLVMContext ctx;
    auto M = parse(ctx, kSealedLoad);

    auto rng = makeRng(0xB006);
    morok::passes::SealedBlobParams p;
    p.runtime_keyed_magic = true;
    p.magic_bytes = 4;
    CHECK(morok::passes::sealedBlobModule(*M, p, rng));

    // Runtime-keyed magic provisions the anti_debug seal channel and a per-blob
    // tag sink global.
    auto *Seal = morok::passes::runtime_seal::findChannel(
        *M, morok::passes::runtime_seal::kAntiDebugChannel);
    CHECK(Seal != nullptr);
    CHECK(countGlobals(*M, "morok.sealed.tag.sink.") == 1u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("sealedBlobModule zeroize_after_use=false omits the scrub memset") {
    LLVMContext ctx;
    auto M = parse(ctx, kSealedLoad);

    auto rng = makeRng(0xB007);
    morok::passes::SealedBlobParams p;
    p.zeroize_after_use = false;
    CHECK(morok::passes::sealedBlobModule(*M, p, rng));

    Function *F = M->getFunction("use");
    REQUIRE(F != nullptr);

    // Still rewritten through the accessor, but no scrub memset is emitted.
    CHECK(countCallsToPrefix(*F, "morok.sealed.open.") == 1u);
    CHECK(countCallsToPrefix(*F, "llvm.memset") == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("sealedBlobModule is a no-op when disabled or non-eager") {
    LLVMContext ctx;

    SUBCASE("disabled returns false and leaves the module unchanged") {
        auto M = parse(ctx, kSealedLoad);
        auto rng = makeRng(0xB008);
        morok::passes::SealedBlobParams p;
        p.enabled = false;
        CHECK_FALSE(morok::passes::sealedBlobModule(*M, p, rng));
        CHECK(countFunctions(*M, "morok.sealed.open.") == 0u);
        CHECK(countGlobals(*M, "morok.sealed.cipher.") == 0u);
        CHECK_FALSE(verifyModule(*M));
    }

    SUBCASE("non-eager delivery returns false and leaves the module unchanged") {
        auto M = parse(ctx, kSealedLoad);
        auto rng = makeRng(0xB009);
        morok::passes::SealedBlobParams p;
        p.delivery = "lazy";
        CHECK_FALSE(morok::passes::sealedBlobModule(*M, p, rng));
        CHECK(countFunctions(*M, "morok.sealed.open.") == 0u);
        CHECK_FALSE(verifyModule(*M));
    }
}

TEST_CASE("sealedBlobModule ignores unselected, unused, and declaration inputs") {
    LLVMContext ctx;

    SUBCASE("plain (unselected) global is untouched") {
        auto M = parse(ctx, R"ir(
@plain = private constant [4 x i8] c"\01\02\03\04"
define i8 @f() {
entry:
  %v = load i8, ptr @plain
  ret i8 %v
}
)ir");
        auto rng = makeRng(0xB00A);
        morok::passes::SealedBlobParams p;
        CHECK_FALSE(morok::passes::sealedBlobModule(*M, p, rng));
        CHECK(countGlobals(*M, "morok.sealed.cipher.") == 0u);
        CHECK_FALSE(verifyModule(*M));
    }

    SUBCASE("selected-but-unused blob is skipped (no rewrite sites)") {
        auto M = parse(ctx, R"ir(
@morok.sealed.unused = private constant [4 x i8] c"\01\02\03\04"
define i8 @f() {
entry:
  ret i8 0
}
)ir");
        auto rng = makeRng(0xB00B);
        morok::passes::SealedBlobParams p;
        CHECK_FALSE(morok::passes::sealedBlobModule(*M, p, rng));
        CHECK(countGlobals(*M, "morok.sealed.cipher.") == 0u);
        CHECK_FALSE(verifyModule(*M));
    }

    SUBCASE("declaration-only module does not crash") {
        auto M = parse(ctx, R"ir(
declare void @external()
)ir");
        auto rng = makeRng(0xB00C);
        morok::passes::SealedBlobParams p;
        CHECK_FALSE(morok::passes::sealedBlobModule(*M, p, rng));
        CHECK_FALSE(verifyModule(*M));
    }
}

TEST_CASE("sealedBlobModule is deterministic for a fixed seed") {
    LLVMContext ctx;
    auto Ma = parse(ctx, kSealedLoad);
    auto Mb = parse(ctx, kSealedLoad);

    // Two independent engines seeded identically must drive identical output.
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0xD00D);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0xD00D);
    morok::ir::IRRandom rngA(engineA);
    morok::ir::IRRandom rngB(engineB);

    morok::passes::SealedBlobParams p;
    CHECK(morok::passes::sealedBlobModule(*Ma, p, rngA));
    CHECK(morok::passes::sealedBlobModule(*Mb, p, rngB));

    std::string textA;
    std::string textB;
    raw_string_ostream osA(textA);
    raw_string_ostream osB(textB);
    Ma->print(osA, nullptr);
    Mb->print(osB, nullptr);
    osA.flush();
    osB.flush();

    CHECK(textA == textB);
    CHECK_FALSE(verifyModule(*Ma));
    CHECK_FALSE(verifyModule(*Mb));
}
