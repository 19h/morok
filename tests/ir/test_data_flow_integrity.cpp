// SPDX-License-Identifier: MIT
//
// Tests for DataFlowIntegrity — replaces narrow int ops/cmps with lookup tables
// decoded from a runtime integrity hash, entangling results with tamper diffs.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/DataFlowIntegrity.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// Four eligible straight-line i8 ops (add/xor/and/or) — all get selected under
// probability=100 up to the table cap.
const char *kNarrow = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i8 @narrow(i8 %a, i8 %b) {
entry:
  %x = add i8 %a, %b
  %y = xor i8 %x, %b
  %z = and i8 %y, %a
  %w = or  i8 %z, %a
  ret i8 %w
}
)ir";

// One uniquely named eligible op — used to observe erasure/replacement.
const char *kSingleOp = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i8 @single(i8 %a, i8 %b) {
entry:
  %uniquetarget = add i8 %a, %b
  ret i8 %uniquetarget
}
)ir";

// i32 ops: width > 16 => none are table-eligible.
const char *kWide = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @wide(i32 %a, i32 %b) {
entry:
  %p = add i32 %a, %b
  %q = mul i32 %p, %b
  %r = xor i32 %q, %a
  ret i32 %r
}
)ir";

// Trivial single-block function with no eligible ops.
const char *kTrivial = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i8 @trivial(i8 %x) {
entry:
  ret i8 %x
}
)ir";

// Empty (void) function.
const char *kEmpty = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define void @empty() {
entry:
  ret void
}
)ir";

// External declaration.
const char *kDecl = R"ir(
target triple = "x86_64-unknown-linux-gnu"

declare i8 @external(i8)
)ir";

// Directly recursive function with an otherwise-eligible op.
const char *kRecursive = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i8 @recur(i8 %a) {
entry:
  %x = add i8 %a, 1
  %r = call i8 @recur(i8 %x)
  ret i8 %r
}
)ir";

// A pass-generated function (morok. prefix) — must be skipped.
const char *kGenerated = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i8 @"morok.thing"(i8 %a, i8 %b) {
entry:
  %x = add i8 %a, %b
  ret i8 %x
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

std::size_t instructionTotal(Function &F) {
    std::size_t n = 0;
    for (Instruction &I : instructions(F)) {
        (void)I;
        ++n;
    }
    return n;
}

} // namespace

TEST_CASE("dataFlowIntegrityFunction grows the function and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kNarrow);
    Function *F = M->getFunction("narrow");
    REQUIRE(F);
    const std::size_t before = instructionTotal(*F);

    morok::passes::DataFlowIntegrityParams params{
        /*probability=*/100u, /*max_tables=*/4u, /*region_bytes=*/32u,
        /*decoy_state=*/false};
    auto rng = makeRng();
    CHECK(morok::passes::dataFlowIntegrityFunction(*F, params, rng));

    // The lookup expansion emits many instructions per replaced op.
    CHECK(instructionTotal(*F) > before);
    CHECK_FALSE(verifyModule(*M));

    // Runtime scaffolding: one region, one expected-hash global, one hash fn.
    CHECK(countGlobals(*M, "morok.dfi.region.") == 1);
    CHECK(countGlobals(*M, "morok.dfi.expected.") == 1);
    CHECK(countFunctions(*M, "morok.dfi.hash.") == 1);
    // Four eligible ops under a default cap of 4 => four tables.
    CHECK(countGlobals(*M, "morok.dfi.table.") == 4);
    // Every replaced op calls the integrity-hash function.
    CHECK(countCallsToPrefix(*F, "morok.dfi.hash.") == 4);
    // The decode seed is derived inline in the caller.
    CHECK(findNamedInstruction(*F, "morok.dfi.seed") != nullptr);

    // Without decoy entanglement the shared state global must not appear.
    CHECK(M->getGlobalVariable("morok.decoy.state", true) == nullptr);

    // The region hashed by the runtime stub matches the configured size.
    auto *region = M->getNamedGlobal("morok.dfi.region.narrow");
    REQUIRE(region != nullptr);
    auto *regionTy = dyn_cast<ArrayType>(region->getValueType());
    REQUIRE(regionTy != nullptr);
    CHECK(regionTy->getNumElements() == 32);
}

TEST_CASE("dataFlowIntegrityFunction respects probability=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kNarrow);
    Function *F = M->getFunction("narrow");
    REQUIRE(F);
    const std::size_t before = instructionTotal(*F);

    morok::passes::DataFlowIntegrityParams params{
        /*probability=*/0u, /*max_tables=*/4u, /*region_bytes=*/32u,
        /*decoy_state=*/false};
    auto rng = makeRng();
    CHECK_FALSE(morok::passes::dataFlowIntegrityFunction(*F, params, rng));

    CHECK(instructionTotal(*F) == before);
    CHECK(countGlobals(*M, "morok.dfi.") == 0);
    CHECK(countFunctions(*M, "morok.dfi.") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("dataFlowIntegrityFunction is safe on declarations, trivial and "
          "empty functions") {
    LLVMContext ctx;

    auto MDecl = parse(ctx, kDecl);
    Function *FDecl = MDecl->getFunction("external");
    REQUIRE(FDecl);
    auto rngDecl = makeRng();
    CHECK_FALSE(morok::passes::dataFlowIntegrityFunction(
        *FDecl, morok::passes::DataFlowIntegrityParams{}, rngDecl));
    CHECK_FALSE(verifyModule(*MDecl));

    auto MTriv = parse(ctx, kTrivial);
    Function *FTriv = MTriv->getFunction("trivial");
    REQUIRE(FTriv);
    auto rngTriv = makeRng();
    CHECK_FALSE(morok::passes::dataFlowIntegrityFunction(
        *FTriv, morok::passes::DataFlowIntegrityParams{}, rngTriv));
    CHECK(countGlobals(*MTriv, "morok.dfi.") == 0);
    CHECK_FALSE(verifyModule(*MTriv));

    auto MEmpty = parse(ctx, kEmpty);
    Function *FEmpty = MEmpty->getFunction("empty");
    REQUIRE(FEmpty);
    auto rngEmpty = makeRng();
    CHECK_FALSE(morok::passes::dataFlowIntegrityFunction(
        *FEmpty, morok::passes::DataFlowIntegrityParams{}, rngEmpty));
    CHECK_FALSE(verifyModule(*MEmpty));
}

TEST_CASE("dataFlowIntegrityFunction skips recursive and generated functions") {
    LLVMContext ctx;

    auto MRec = parse(ctx, kRecursive);
    Function *FRec = MRec->getFunction("recur");
    REQUIRE(FRec);
    auto rngRec = makeRng();
    // Directly recursive: bailed out even though it has an eligible op.
    CHECK_FALSE(morok::passes::dataFlowIntegrityFunction(
        *FRec, morok::passes::DataFlowIntegrityParams{}, rngRec));
    CHECK(countGlobals(*MRec, "morok.dfi.") == 0);
    CHECK_FALSE(verifyModule(*MRec));

    auto MGen = parse(ctx, kGenerated);
    Function *FGen = MGen->getFunction("morok.thing");
    REQUIRE(FGen);
    auto rngGen = makeRng();
    // morok.-prefixed functions are treated as pass-generated and skipped.
    CHECK_FALSE(morok::passes::dataFlowIntegrityFunction(
        *FGen, morok::passes::DataFlowIntegrityParams{}, rngGen));
    CHECK(countGlobals(*MGen, "morok.dfi.") == 0);
    CHECK_FALSE(verifyModule(*MGen));
}

TEST_CASE("dataFlowIntegrityFunction leaves ineligible wide-int functions "
          "unchanged") {
    LLVMContext ctx;
    auto M = parse(ctx, kWide);
    Function *F = M->getFunction("wide");
    REQUIRE(F);
    const std::size_t before = instructionTotal(*F);

    auto rng = makeRng();
    // i32 operations exceed the 16-bit table width, so nothing is eligible.
    CHECK_FALSE(morok::passes::dataFlowIntegrityFunction(
        *F, morok::passes::DataFlowIntegrityParams{}, rng));
    CHECK(instructionTotal(*F) == before);
    CHECK(countGlobals(*M, "morok.dfi.") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("dataFlowIntegrityFunction is deterministic for a fixed seed") {
    LLVMContext ctxFirst;
    LLVMContext ctxSecond;
    auto MFirst = parse(ctxFirst, kNarrow);
    auto MSecond = parse(ctxSecond, kNarrow);

    morok::passes::DataFlowIntegrityParams params{
        /*probability=*/100u, /*max_tables=*/1u, /*region_bytes=*/16u,
        /*decoy_state=*/false};

    auto engineFirst = morok::core::Xoshiro256pp::fromSeed(0x2026u);
    morok::ir::IRRandom rngFirst(engineFirst);
    CHECK(morok::passes::dataFlowIntegrityFunction(*MFirst->getFunction("narrow"),
                                                   params, rngFirst));

    auto engineSecond = morok::core::Xoshiro256pp::fromSeed(0x2026u);
    morok::ir::IRRandom rngSecond(engineSecond);
    CHECK(morok::passes::dataFlowIntegrityFunction(
        *MSecond->getFunction("narrow"), params, rngSecond));

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

TEST_CASE("dataFlowIntegrityFunction caps tables and clamps the region") {
    LLVMContext ctx;
    auto M = parse(ctx, kNarrow);
    Function *F = M->getFunction("narrow");
    REQUIRE(F);

    // Four eligible ops but a cap of two, and a region size below the floor.
    morok::passes::DataFlowIntegrityParams params{
        /*probability=*/100u, /*max_tables=*/2u, /*region_bytes=*/4u,
        /*decoy_state=*/false};
    auto rng = makeRng();
    CHECK(morok::passes::dataFlowIntegrityFunction(*F, params, rng));

    // Cap honored: at most max_tables tables and hash calls.
    CHECK(countGlobals(*M, "morok.dfi.table.") == 2);
    CHECK(countCallsToPrefix(*F, "morok.dfi.hash.") == 2);

    // region_bytes=4 is clamped up to the documented floor of 8.
    auto *region = M->getNamedGlobal("morok.dfi.region.narrow");
    REQUIRE(region != nullptr);
    auto *regionTy = dyn_cast<ArrayType>(region->getValueType());
    REQUIRE(regionTy != nullptr);
    CHECK(regionTy->getNumElements() == 8);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("dataFlowIntegrityFunction entangles lookups with decoy state") {
    LLVMContext ctx;
    auto M = parse(ctx, kNarrow);
    Function *F = M->getFunction("narrow");
    REQUIRE(F);

    morok::passes::DataFlowIntegrityParams params{
        /*probability=*/100u, /*max_tables=*/4u, /*region_bytes=*/32u,
        /*decoy_state=*/true};
    auto rng = makeRng();
    CHECK(morok::passes::dataFlowIntegrityFunction(*F, params, rng));

    // The shared coherent-decoy state global is get-or-created.
    CHECK(M->getGlobalVariable("morok.decoy.state", true) != nullptr);
    CHECK(countGlobals(*M, "morok.decoy.state") == 1);
    // Each lookup folds a volatile state load into the tamper diff.
    CHECK(findNamedInstruction(*F, "morok.dfi.decoy.state") != nullptr);
    CHECK(findNamedInstruction(*F, "morok.dfi.decoy.diff") != nullptr);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("dataFlowIntegrityFunction erases the original op and yields a table "
          "value") {
    LLVMContext ctx;
    auto M = parse(ctx, kSingleOp);
    Function *F = M->getFunction("single");
    REQUIRE(F);
    REQUIRE(findNamedInstruction(*F, "uniquetarget") != nullptr);

    morok::passes::DataFlowIntegrityParams params{
        /*probability=*/100u, /*max_tables=*/4u, /*region_bytes=*/32u,
        /*decoy_state=*/false};
    auto rng = makeRng();
    CHECK(morok::passes::dataFlowIntegrityFunction(*F, params, rng));

    // The original arithmetic op is gone, replaced by a decoded table value.
    CHECK(findNamedInstruction(*F, "uniquetarget") == nullptr);
    CHECK(findNamedInstruction(*F, "morok.dfi.value") != nullptr);
    CHECK(findNamedInstruction(*F, "morok.dfi.encoded") != nullptr);
    CHECK(countGlobals(*M, "morok.dfi.table.") == 1);
    CHECK_FALSE(verifyModule(*M));
}
