// SPDX-License-Identifier: MIT
//
// Tests for MisleadingMetadata — false analysis anchors.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/MisleadingMetadata.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Verifier.h"

using namespace llvm;
using namespace morok::test;

namespace {

const char *kSimpleFn = R"ir(
define i32 @main(i32 %x) {
entry:
  %y = add i32 %x, 1
  ret i32 %y
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x5EED) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

} // namespace

TEST_CASE("misleadingMetadataModule plants decoy functions") {
    LLVMContext ctx;
    auto M = parse(ctx, kSimpleFn);

    auto rng = makeRng(0x5EED);
    CHECK(morok::passes::misleadingMetadataModule(*M, rng));

    std::vector<Function *> decoys;
    for (Function &F : *M) {
        if (F.getName() == "main")
            continue;
        decoys.push_back(&F);
    }
    CHECK(decoys.size() > 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("misleadingMetadataModule decoys have internal linkage") {
    LLVMContext ctx;
    auto M = parse(ctx, kSimpleFn);

    auto rng = makeRng(0x5EED1);
    CHECK(morok::passes::misleadingMetadataModule(*M, rng));

    for (Function &F : *M) {
        if (F.getName() == "main")
            continue;
        CHECK(F.hasInternalLinkage());
    }
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("misleadingMetadataModule decoys have OptimizeNone attribute") {
    LLVMContext ctx;
    auto M = parse(ctx, kSimpleFn);

    auto rng = makeRng(0x5EED2);
    CHECK(morok::passes::misleadingMetadataModule(*M, rng));

    for (Function &F : *M) {
        if (F.getName() == "main")
            continue;
        CHECK(F.hasFnAttribute(Attribute::OptimizeNone));
    }
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("misleadingMetadataModule anchors decoys in llvm.compiler.used") {
    LLVMContext ctx;
    auto M = parse(ctx, kSimpleFn);

    auto rng = makeRng(0x5EED3);
    CHECK(morok::passes::misleadingMetadataModule(*M, rng));

    GlobalVariable *Used = M->getGlobalVariable("llvm.compiler.used");
    REQUIRE(Used);
    REQUIRE(Used->hasInitializer());
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("misleadingMetadataModule creates debug metadata") {
    LLVMContext ctx;
    auto M = parse(ctx, kSimpleFn);

    auto rng = makeRng(0x5EED4);
    CHECK(morok::passes::misleadingMetadataModule(*M, rng));

    // Must have debug compile units
    CHECK(M->getNamedMetadata("llvm.dbg.cu") != nullptr);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("misleadingMetadataModule skips empty modules") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare void @external()
)ir");

    auto rng = makeRng(0x5EED5);
    // Should not crash on modules with no user-defined functions
    morok::passes::misleadingMetadataModule(*M, rng);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("misleadingMetadataModule produces different decoys with different seeds") {
    LLVMContext ctx;
    auto M1 = parse(ctx, kSimpleFn);
    auto M2 = parse(ctx, kSimpleFn);

    auto rng1 = makeRng(0xAAAA);
    auto rng2 = makeRng(0xBBBB);
    morok::passes::misleadingMetadataModule(*M1, rng1);
    morok::passes::misleadingMetadataModule(*M2, rng2);

    // Collect decoy names from each module
    std::vector<std::string> names1, names2;
    for (Function &F : *M1)
        if (F.getName() != "main")
            names1.push_back(F.getName().str());
    for (Function &F : *M2)
        if (F.getName() != "main")
            names2.push_back(F.getName().str());

    CHECK(names1.size() == names2.size());
    // At least some names should differ (RNG-driven)
    bool anyDiff = false;
    for (std::size_t i = 0; i < names1.size(); ++i)
        if (names1[i] != names2[i])
            anyDiff = true;
    CHECK(anyDiff);
}
