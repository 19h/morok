// SPDX-License-Identifier: MIT
//
// Tests for FunctionFission — outlines single-entry/single-exit regions of a
// function into fresh internal `morok.fission.*` callees (via CodeExtractor),
// so the original function shrinks and its logic scatters across smaller
// callees; the parts are internal, tagged `morok-fission-part`, and noinline.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/FunctionFission.hpp"

#include "llvm/IR/Attributes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// A function whose body carries one self-contained single-entry/single-exit
// diamond region {rh, rt, re, rj}: `entry` is a plain block (so the region's
// entry is NOT the function entry block), the join PHI lives *inside* the
// region, and the only live-out is %pv consumed by the tail.  This is the
// textbook CodeExtractor shape, so the region outlines cleanly.
const char *kWorker = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @worker(i32 %a, i32 %b) {
entry:
  %s = add i32 %a, %b
  br label %rh
rh:
  %c = icmp slt i32 %s, %b
  br i1 %c, label %rt, label %re
rt:
  %tv = add i32 %s, 1
  br label %rj
re:
  %ev = sub i32 %s, 1
  br label %rj
rj:
  %pv = phi i32 [ %tv, %rt ], [ %ev, %re ]
  br label %tail
tail:
  ret i32 %pv
}
)ir";

// Two sequential self-contained diamond regions after a plain entry: several
// eligible regions exist, which lets the per-function `max_splits` cap be
// exercised meaningfully.
const char *kMulti = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @multi(i32 %a, i32 %b) {
entry:
  %s = add i32 %a, %b
  br label %h0
h0:
  %c0 = icmp slt i32 %s, %b
  br i1 %c0, label %t0, label %e0
t0:
  %tv0 = add i32 %s, 1
  br label %j0
e0:
  %ev0 = sub i32 %s, 1
  br label %j0
j0:
  %pv0 = phi i32 [ %tv0, %t0 ], [ %ev0, %e0 ]
  br label %h1
h1:
  %c1 = icmp slt i32 %pv0, %a
  br i1 %c1, label %t1, label %e1
t1:
  %tv1 = mul i32 %pv0, 3
  br label %j1
e1:
  %ev1 = xor i32 %pv0, 7
  br label %j1
j1:
  %pv1 = phi i32 [ %tv1, %t1 ], [ %ev1, %e1 ]
  br label %tail
tail:
  ret i32 %pv1
}
)ir";

// Single-block function: there is no non-entry region to outline.
const char *kTrivial = R"ir(
define i32 @trivial(i32 %x) {
entry:
  %r = add i32 %x, 1
  ret i32 %r
}
)ir";

// Variadic function: functionEligible() rejects varargs outright, even though
// this body does contain an otherwise-outlineable diamond region.
const char *kVariadic = R"ir(
define i32 @variadic(i32 %n, ...) {
entry:
  %s = add i32 %n, 1
  br label %rh
rh:
  %c = icmp slt i32 %s, %n
  br i1 %c, label %rt, label %re
rt:
  %tv = add i32 %s, 1
  br label %rj
re:
  %ev = sub i32 %s, 1
  br label %rj
rj:
  %pv = phi i32 [ %tv, %rt ], [ %ev, %re ]
  ret i32 %pv
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

} // namespace

TEST_CASE("functionFissionModule outlines a region and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kWorker);
    Function *F = M->getFunction("worker");
    REQUIRE(F);

    const std::size_t blocksBefore = F->size();
    const std::size_t fnsBefore = countFunctions(*M, "");

    auto rng = makeRng(0x0f01);
    morok::passes::FunctionFissionParams params{/*probability=*/100u, /*max_splits=*/8u,
                                 /*min_region_blocks=*/2u,
                                 /*max_region_blocks=*/64u};
    CHECK(morok::passes::functionFissionModule(*M, params, rng));

    // A fresh internal callee was created, the module grew, and the original
    // function shrank (its region was replaced by a single call).
    CHECK(countFunctions(*M, "morok.fission") >= 1u);
    CHECK(countFunctions(*M, "") > fnsBefore);
    CHECK(F->size() < blocksBefore);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("functionFissionModule marks parts internal, tagged and noinline") {
    LLVMContext ctx;
    auto M = parse(ctx, kWorker);
    Function *F = M->getFunction("worker");
    REQUIRE(F);

    auto rng = makeRng(0x0f02);
    morok::passes::FunctionFissionParams params{/*probability=*/100u, /*max_splits=*/8u,
                                 /*min_region_blocks=*/2u,
                                 /*max_region_blocks=*/64u};
    REQUIRE(morok::passes::functionFissionModule(*M, params, rng));
    REQUIRE(countFunctions(*M, "morok.fission") >= 1u);

    std::size_t partsSeen = 0;
    for (Function &partFn : *M) {
        if (!partFn.getName().starts_with("morok.fission"))
            continue;
        ++partsSeen;
        CHECK(partFn.getLinkage() == GlobalValue::InternalLinkage);
        CHECK(partFn.hasFnAttribute(Attribute::NoInline));
        CHECK(partFn.hasFnAttribute("morok-fission-part"));
    }
    CHECK(partsSeen >= 1u);

    // The original function now calls into the outlined part.
    CHECK(countCallsToPrefix(*F, "morok.fission") >= 1u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("functionFissionModule respects probability=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kWorker);
    const std::size_t fnsBefore = countFunctions(*M, "");

    auto rng = makeRng(0x0f03);
    morok::passes::FunctionFissionParams params{/*probability=*/0u, /*max_splits=*/8u,
                                 /*min_region_blocks=*/2u,
                                 /*max_region_blocks=*/64u};
    CHECK_FALSE(morok::passes::functionFissionModule(*M, params, rng));
    CHECK(countFunctions(*M, "morok.fission") == 0u);
    CHECK(countFunctions(*M, "") == fnsBefore);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("functionFissionModule respects max_splits=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kWorker);
    const std::size_t fnsBefore = countFunctions(*M, "");

    auto rng = makeRng(0x0f04);
    morok::passes::FunctionFissionParams params{/*probability=*/100u, /*max_splits=*/0u,
                                 /*min_region_blocks=*/2u,
                                 /*max_region_blocks=*/64u};
    CHECK_FALSE(morok::passes::functionFissionModule(*M, params, rng));
    CHECK(countFunctions(*M, "morok.fission") == 0u);
    CHECK(countFunctions(*M, "") == fnsBefore);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("functionFissionModule is safe on declarations") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare i32 @external(i32)
)ir");
    const std::size_t fnsBefore = countFunctions(*M, "");

    auto rng = makeRng(0x0f05);
    morok::passes::FunctionFissionParams params{/*probability=*/100u, /*max_splits=*/8u,
                                 /*min_region_blocks=*/2u,
                                 /*max_region_blocks=*/64u};
    // A module of pure declarations has no eligible targets; no crash.
    CHECK_FALSE(morok::passes::functionFissionModule(*M, params, rng));
    CHECK(countFunctions(*M, "") == fnsBefore);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("functionFissionModule leaves trivial single-block functions alone") {
    LLVMContext ctx;
    auto M = parse(ctx, kTrivial);
    Function *F = M->getFunction("trivial");
    REQUIRE(F);
    const std::size_t blocksBefore = F->size();

    auto rng = makeRng(0x0f06);
    morok::passes::FunctionFissionParams params{/*probability=*/100u, /*max_splits=*/8u,
                                 /*min_region_blocks=*/2u,
                                 /*max_region_blocks=*/64u};
    // Eligible function but no non-entry region to outline.
    CHECK_FALSE(morok::passes::functionFissionModule(*M, params, rng));
    CHECK(countFunctions(*M, "morok.fission") == 0u);
    CHECK(F->size() == blocksBefore);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("functionFissionModule skips variadic functions") {
    LLVMContext ctx;
    auto M = parse(ctx, kVariadic);
    Function *F = M->getFunction("variadic");
    REQUIRE(F);
    const std::size_t blocksBefore = F->size();

    auto rng = makeRng(0x0f07);
    morok::passes::FunctionFissionParams params{/*probability=*/100u, /*max_splits=*/8u,
                                 /*min_region_blocks=*/2u,
                                 /*max_region_blocks=*/64u};
    // isVarArg() disqualifies the whole function, so nothing is outlined.
    CHECK_FALSE(morok::passes::functionFissionModule(*M, params, rng));
    CHECK(countFunctions(*M, "morok.fission") == 0u);
    CHECK(F->size() == blocksBefore);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("functionFissionModule caps outlined parts at max_splits") {
    LLVMContext ctx;
    auto M = parse(ctx, kMulti);
    Function *F = M->getFunction("multi");
    REQUIRE(F);

    auto rng = makeRng(0x0f08);
    // Several regions are eligible, but max_splits=1 permits exactly one.
    morok::passes::FunctionFissionParams params{/*probability=*/100u, /*max_splits=*/1u,
                                 /*min_region_blocks=*/2u,
                                 /*max_region_blocks=*/64u};
    CHECK(morok::passes::functionFissionModule(*M, params, rng));
    CHECK(countFunctions(*M, "morok.fission") == 1u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("functionFissionModule is deterministic for a fixed seed") {
    LLVMContext ctx;
    auto M1 = parse(ctx, kWorker);
    auto M2 = parse(ctx, kWorker);

    // Fresh, independent engines from the same seed must reproduce identical IR.
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0xF1551013);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0xF1551013);
    morok::ir::IRRandom rngA(engineA);
    morok::ir::IRRandom rngB(engineB);

    morok::passes::FunctionFissionParams params{/*probability=*/100u, /*max_splits=*/8u,
                                 /*min_region_blocks=*/2u,
                                 /*max_region_blocks=*/64u};
    CHECK(morok::passes::functionFissionModule(*M1, params, rngA));
    CHECK(morok::passes::functionFissionModule(*M2, params, rngB));

    auto printModule = [](Module &mod) {
        std::string text;
        raw_string_ostream os(text);
        mod.print(os, nullptr);
        os.flush();
        return text;
    };
    CHECK(printModule(*M1) == printModule(*M2));
    CHECK_FALSE(verifyModule(*M1));
    CHECK_FALSE(verifyModule(*M2));
}
