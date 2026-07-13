// SPDX-License-Identifier: MIT
//
// Tests for UniformPrimitiveLowering — lowers narrow arithmetic/comparisons to
// encrypted table loads (via the ArithmeticTables channel) and branch/switch
// terminators to blockaddress-table indirectbr dispatch, favoring loads, GEPs,
// selects and indirectbr over recognizable arithmetic and branch opcodes
// (morok::passes::uniformPrimitiveLowerFunction).

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/UniformPrimitiveLowering.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// A mixed function: six narrow (i8) operations feed a conditional branch and two
// unconditional branches into a phi-joined block.  The arithmetic is eligible
// for the table-lookup channel (i8 => Pair8, no constant operand required) and
// the three non-return terminators are eligible for the indirectbr channel.
// entry(cond br), then(uncond br) and else(uncond br) are the branch sites;
// join ends in a return and is not eligible.
const char *kMix = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i8 @mix(i8 %a, i8 %b) {
entry:
  %0 = add i8 %a, %b
  %1 = mul i8 %0, %b
  %2 = xor i8 %1, %a
  %c = icmp ult i8 %2, %a
  br i1 %c, label %then, label %else
then:
  %t = and i8 %2, %b
  br label %join
else:
  %e = or i8 %2, %a
  br label %join
join:
  %p = phi i8 [ %t, %then ], [ %e, %else ]
  ret i8 %p
}
)ir";

// No eligible arithmetic and only a return terminator: nothing for either
// channel to lower.
const char *kTrivial = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @trivial(i32 %x) {
entry:
  ret i32 %x
}
)ir";

// A declaration — no body to transform.
const char *kDecl = R"ir(
declare i32 @external(i32)
)ir";

// A function already living in the morok.* namespace — must be refused wholesale
// so the pass never rewrites its own output.
const char *kMorokNamed = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i8 @"morok.helper"(i8 %a, i8 %b) {
entry:
  %0 = add i8 %a, %b
  %c = icmp ult i8 %0, %a
  br i1 %c, label %hot, label %cold
hot:
  ret i8 %0
cold:
  ret i8 %a
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

std::size_t instructionCount(Function &Fn) {
    std::size_t n = 0;
    for (BasicBlock &BB : Fn)
        n += BB.size();
    return n;
}

} // namespace

TEST_CASE("uniformPrimitiveLowerFunction grows the function and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kMix);
    Function *F = M->getFunction("mix");
    REQUIRE(F);

    const std::size_t instsBefore = instructionCount(*F);
    REQUIRE(countGlobals(*M, "morok.uniform.table") == 0);
    REQUIRE(countGlobals(*M, "morok.tablearith.table") == 0);

    auto rng = makeRng(0x1337);
    // Both channels enabled and forced (probability 100 always fires).
    CHECK(morok::passes::uniformPrimitiveLowerFunction(
        *F, {/*op_probability=*/100, /*branch_probability=*/100,
             /*max_tables=*/8, /*max_branches=*/8},
        rng));

    // The body grew: arithmetic became call+load lookups and terminators became
    // select+GEP+load+indirectbr sequences.
    CHECK(instructionCount(*F) > instsBefore);
    // The arithmetic channel materialized encrypted tables + decoder functions.
    CHECK(countGlobals(*M, "morok.tablearith.table") >= 1);
    CHECK(countFunctions(*M, "morok.tablearith.ensure") >= 1);
    // The branch channel materialized a blockaddress dispatch table + indirectbr.
    CHECK(countGlobals(*M, "morok.uniform.table") >= 1);
    CHECK(countOpcode(*M, Instruction::IndirectBr) > 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("uniformPrimitiveLowerFunction lowers narrow arithmetic via the table "
          "channel only") {
    LLVMContext ctx;
    auto M = parse(ctx, kMix);
    Function *F = M->getFunction("mix");
    REQUIRE(F);

    auto rng = makeRng(0x2001);
    // Arithmetic channel on, branch channel off (branch_probability 0).
    CHECK(morok::passes::uniformPrimitiveLowerFunction(
        *F, {/*op_probability=*/100, /*branch_probability=*/0,
             /*max_tables=*/8, /*max_branches=*/8},
        rng));

    // Encrypted table + internal decoder + an ensure call are emitted.
    CHECK(countGlobals(*M, "morok.tablearith.table") >= 1);
    CHECK(countGlobals(*M, "morok.tablearith.ready") >= 1);
    CHECK(countFunctions(*M, "morok.tablearith.ensure") >= 1);
    CHECK(countCallsToPrefix(*F, "morok.tablearith.ensure") > 0);
    CHECK(countNamedInstructions(*F, "morok.tablearith") > 0);
    // The branch channel stayed inert: no dispatch table, no indirectbr.
    CHECK(countGlobals(*M, "morok.uniform.table") == 0);
    CHECK(countOpcode(*M, Instruction::IndirectBr) == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("uniformPrimitiveLowerFunction lowers branches into a shared "
          "indirectbr dispatch table") {
    LLVMContext ctx;
    auto M = parse(ctx, kMix);
    Function *F = M->getFunction("mix");
    REQUIRE(F);

    auto rng = makeRng(0x3003);
    // Branch channel on, arithmetic channel off (op_probability 0).
    CHECK(morok::passes::uniformPrimitiveLowerFunction(
        *F, {/*op_probability=*/0, /*branch_probability=*/100,
             /*max_tables=*/8, /*max_branches=*/8},
        rng));

    // All three eligible terminators share exactly one blockaddress table, but
    // each site becomes its own indirectbr.
    CHECK(countGlobals(*M, "morok.uniform.table") == 1);
    CHECK(countOpcode(*M, Instruction::IndirectBr) == 3);
    // Every direct branch opcode is gone from the module (join keeps its return;
    // no arithmetic decoders exist to reintroduce branches).
    CHECK(countOpcode(*M, Instruction::CondBr) == 0);
    CHECK(countOpcode(*M, Instruction::UncondBr) == 0);
    // The dispatch load and the conditional site's index-select are present.
    CHECK(findNamedInstruction(*F, "morok.uniform.target") != nullptr);
    CHECK(countNamedInstructions(*F, "morok.uniform.index") >= 1);
    // The arithmetic channel stayed inert.
    CHECK(countGlobals(*M, "morok.tablearith.table") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("uniformPrimitiveLowerFunction is a no-op when disabled by params") {
    LLVMContext ctx;

    SUBCASE("both probabilities zero") {
        auto M = parse(ctx, kMix);
        Function *F = M->getFunction("mix");
        REQUIRE(F);
        const std::size_t instsBefore = instructionCount(*F);

        auto rng = makeRng(0x4004);
        CHECK_FALSE(morok::passes::uniformPrimitiveLowerFunction(
            *F, {/*op_probability=*/0, /*branch_probability=*/0,
                 /*max_tables=*/8, /*max_branches=*/8},
            rng));

        CHECK(instructionCount(*F) == instsBefore);
        CHECK(countGlobals(*M, "morok.tablearith.table") == 0);
        CHECK(countGlobals(*M, "morok.uniform.table") == 0);
        CHECK_FALSE(verifyModule(*M));
    }

    SUBCASE("caps zero with probabilities forced") {
        auto M = parse(ctx, kMix);
        Function *F = M->getFunction("mix");
        REQUIRE(F);
        const std::size_t instsBefore = instructionCount(*F);

        auto rng = makeRng(0x5005);
        // max_tables gates the arithmetic channel; max_branches gates the branch
        // channel — both zero means neither fires despite probability 100.
        CHECK_FALSE(morok::passes::uniformPrimitiveLowerFunction(
            *F, {/*op_probability=*/100, /*branch_probability=*/100,
                 /*max_tables=*/0, /*max_branches=*/0},
            rng));

        CHECK(instructionCount(*F) == instsBefore);
        CHECK(countGlobals(*M, "morok.tablearith.table") == 0);
        CHECK(countGlobals(*M, "morok.uniform.table") == 0);
        CHECK_FALSE(verifyModule(*M));
    }
}

TEST_CASE("uniformPrimitiveLowerFunction skips declarations and morok.* "
          "functions") {
    LLVMContext ctx;

    auto Mdecl = parse(ctx, kDecl);
    Function *Ext = Mdecl->getFunction("external");
    REQUIRE(Ext);

    auto rngDecl = makeRng(0x6006);
    // A declaration has no body: refused without crashing.
    CHECK_FALSE(morok::passes::uniformPrimitiveLowerFunction(
        *Ext, {/*op_probability=*/100, /*branch_probability=*/100,
               /*max_tables=*/8, /*max_branches=*/8},
        rngDecl));
    CHECK_FALSE(verifyModule(*Mdecl));

    auto Mnamed = parse(ctx, kMorokNamed);
    Function *Helper = Mnamed->getFunction("morok.helper");
    REQUIRE(Helper);

    auto rngNamed = makeRng(0x7007);
    // A name already in the morok.* namespace is refused wholesale.
    CHECK_FALSE(morok::passes::uniformPrimitiveLowerFunction(
        *Helper, {/*op_probability=*/100, /*branch_probability=*/100,
                  /*max_tables=*/8, /*max_branches=*/8},
        rngNamed));
    CHECK(countGlobals(*Mnamed, "morok.tablearith.table") == 0);
    CHECK(countGlobals(*Mnamed, "morok.uniform.table") == 0);
    CHECK(countOpcode(*Mnamed, Instruction::IndirectBr) == 0);
    CHECK_FALSE(verifyModule(*Mnamed));
}

TEST_CASE("uniformPrimitiveLowerFunction is safe on a trivial single-block "
          "body") {
    LLVMContext ctx;
    auto M = parse(ctx, kTrivial);
    Function *F = M->getFunction("trivial");
    REQUIRE(F);
    const std::size_t instsBefore = instructionCount(*F);

    auto rng = makeRng(0x8008);
    // No eligible arithmetic and only a return terminator => no change, no crash.
    CHECK_FALSE(morok::passes::uniformPrimitiveLowerFunction(
        *F, {/*op_probability=*/100, /*branch_probability=*/100,
             /*max_tables=*/8, /*max_branches=*/8},
        rng));

    CHECK(instructionCount(*F) == instsBefore);
    CHECK(countGlobals(*M, "morok.tablearith.table") == 0);
    CHECK(countGlobals(*M, "morok.uniform.table") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("uniformPrimitiveLowerFunction is deterministic for a fixed seed") {
    LLVMContext ctxA;
    LLVMContext ctxB;
    auto MA = parse(ctxA, kMix);
    auto MB = parse(ctxB, kMix);
    REQUIRE(MA->getFunction("mix"));
    REQUIRE(MB->getFunction("mix"));

    // Two independent engines seeded identically must produce byte-identical IR,
    // including the encrypted table bytes and the blockaddress dispatch table.
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0xC0FFEE);
    morok::ir::IRRandom rngA(engineA);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0xC0FFEE);
    morok::ir::IRRandom rngB(engineB);

    const morok::passes::UniformLowerParams params{/*op_probability=*/100,
                                                   /*branch_probability=*/100,
                                                   /*max_tables=*/8,
                                                   /*max_branches=*/8};
    CHECK(morok::passes::uniformPrimitiveLowerFunction(*MA->getFunction("mix"),
                                                       params, rngA));
    CHECK(morok::passes::uniformPrimitiveLowerFunction(*MB->getFunction("mix"),
                                                       params, rngB));

    std::string textA;
    std::string textB;
    {
        raw_string_ostream osA(textA);
        MA->print(osA, nullptr);
    }
    {
        raw_string_ostream osB(textB);
        MB->print(osB, nullptr);
    }
    CHECK(textA == textB);
    CHECK_FALSE(verifyModule(*MA));
    CHECK_FALSE(verifyModule(*MB));
}

TEST_CASE("uniformPrimitiveLowerFunction honors the max_branches cap") {
    LLVMContext ctx;
    auto M = parse(ctx, kMix);
    Function *F = M->getFunction("mix");
    REQUIRE(F);

    auto rng = makeRng(0x9009);
    // Three terminators are eligible, but the cap limits the rewrite to a single
    // site (branch channel only, so no arithmetic tables interfere).
    CHECK(morok::passes::uniformPrimitiveLowerFunction(
        *F, {/*op_probability=*/0, /*branch_probability=*/100,
             /*max_tables=*/8, /*max_branches=*/1},
        rng));

    CHECK(countGlobals(*M, "morok.uniform.table") == 1);
    CHECK(countOpcode(*M, Instruction::IndirectBr) == 1);
    // Not everything was consumed: the two unconditional branches still remain.
    CHECK(countOpcode(*M, Instruction::UncondBr) > 0);
    CHECK_FALSE(verifyModule(*M));
}
