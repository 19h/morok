// SPDX-License-Identifier: MIT
//
// Tests for MicrocodeStress — sparse computed blockaddress/indirectbr jump-table
// stress that expands the CFG/alias surface without encoding source CFG edges.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/MicrocodeStress.hpp"

#include "llvm/IR/DerivedTypes.h"
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

// A firing-capable target: arch is x86_64 but the OS is *not* Linux, so the
// pass's linux-x86_64 backend guard (isLinuxX86_64Target) does not trip, and the
// x86_64 anti-disasm/analysis-bait inline-asm variants are emitted.  Kept in the
// IR text (not derived from the host) so the file behaves identically on every
// CI platform.
const char *kArithDarwin = R"ir(
target triple = "x86_64-apple-darwin"
define i32 @arith(i32 %a, i32 %b) {
entry:
  %0 = add i32 %a, %b
  %1 = mul i32 %a, %b
  %2 = xor i32 %0, %1
  %3 = sub i32 %2, %a
  ret i32 %3
}
)ir";

// Same body, but a linux-x86_64 triple: the pass must decline to transform.
const char *kArithLinuxX86 = R"ir(
target triple = "x86_64-unknown-linux-gnu"
define i32 @arith(i32 %a, i32 %b) {
entry:
  %0 = add i32 %a, %b
  %1 = mul i32 %a, %b
  %2 = xor i32 %0, %1
  %3 = sub i32 %2, %a
  ret i32 %3
}
)ir";

// Four blocks, each with a real (splittable) instruction, for the max_sites cap.
const char *kMultiDarwin = R"ir(
target triple = "x86_64-apple-darwin"
define i32 @multi(i32 %a, i32 %b) {
entry:
  %c = icmp slt i32 %a, %b
  br i1 %c, label %L1, label %L2
L1:
  %x = add i32 %a, 1
  br label %L3
L2:
  %y = sub i32 %b, 1
  br label %L3
L3:
  %z = phi i32 [ %x, %L1 ], [ %y, %L2 ]
  %w = mul i32 %z, 3
  ret i32 %w
}
)ir";

// A block whose only instruction is a terminator: no legal split point.
const char *kEmptyDarwin = R"ir(
target triple = "x86_64-apple-darwin"
define void @empty() {
entry:
  ret void
}
)ir";

// A function that looks Morok-generated: the pass must skip it.
const char *kGeneratedDarwin = R"ir(
target triple = "x86_64-apple-darwin"
define i32 @"morok.gen"(i32 %a) {
entry:
  %x = add i32 %a, 1
  ret i32 %x
}
)ir";

const char *kDecl = R"ir(
target triple = "x86_64-apple-darwin"
declare i32 @external(i32)
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

std::size_t countBlocksNamed(Function &F, StringRef prefix) {
    std::size_t n = 0;
    for (BasicBlock &BB : F)
        if (BB.getName().starts_with(prefix))
            ++n;
    return n;
}

std::string moduleToString(Module &M) {
    std::string text;
    raw_string_ostream os(text);
    M.print(os, nullptr);
    os.flush();
    return text;
}

} // namespace

TEST_CASE("microcodeStressFunction grows the function and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kArithDarwin);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = F->size();

    morok::passes::MicrocodeStressParams params;
    params.probability = 100u;
    params.max_sites = 1u;

    auto rng = makeRng();
    CHECK(morok::passes::microcodeStressFunction(*F, params, rng));
    CHECK(F->size() > before);
    // Backbone signals: the pass materialises its keyed seed, per-function
    // scratch, and at least one blockaddress dispatch table.
    CHECK(countGlobals(*M, "morok.micro.seed") == 1u);
    CHECK(countGlobals(*M, "morok.micro.table") >= 1u);
    CHECK(countNamedAllocas(*F, "morok.micro.scratch") == 1u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("microcodeStressFunction respects probability=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kArithDarwin);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = F->size();

    morok::passes::MicrocodeStressParams params;
    params.probability = 0u;

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::microcodeStressFunction(*F, params, rng));
    CHECK(F->size() == before);
    CHECK(countGlobals(*M, "morok.micro.seed") == 0u);
    CHECK(countGlobals(*M, "morok.micro.table") == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("microcodeStressFunction skips the linux-x86_64 target") {
    LLVMContext ctx;
    auto M = parse(ctx, kArithLinuxX86);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = F->size();

    morok::passes::MicrocodeStressParams params;
    params.probability = 100u;
    params.max_sites = 3u;

    auto rng = makeRng();
    // The backend guard declines the blockaddress/indirectbr transform here.
    CHECK_FALSE(morok::passes::microcodeStressFunction(*F, params, rng));
    CHECK(F->size() == before);
    CHECK(countGlobals(*M, "morok.micro.seed") == 0u);
    CHECK(countGlobals(*M, "morok.micro.table") == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("microcodeStressFunction skips declarations") {
    LLVMContext ctx;
    auto M = parse(ctx, kDecl);
    Function *F = M->getFunction("external");
    REQUIRE(F);

    morok::passes::MicrocodeStressParams params;
    params.probability = 100u;

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::microcodeStressFunction(*F, params, rng));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("microcodeStressFunction is safe on a terminator-only function") {
    LLVMContext ctx;
    auto M = parse(ctx, kEmptyDarwin);
    Function *F = M->getFunction("empty");
    REQUIRE(F);
    const std::size_t before = F->size();

    morok::passes::MicrocodeStressParams params;
    params.probability = 100u;
    params.max_sites = 3u;

    auto rng = makeRng();
    // No legal split point (the only instruction is the terminator) => no-op.
    CHECK_FALSE(morok::passes::microcodeStressFunction(*F, params, rng));
    CHECK(F->size() == before);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("microcodeStressFunction skips morok-generated functions") {
    LLVMContext ctx;
    auto M = parse(ctx, kGeneratedDarwin);
    Function *F = M->getFunction("morok.gen");
    REQUIRE(F);
    const std::size_t before = F->size();

    morok::passes::MicrocodeStressParams params;
    params.probability = 100u;
    params.max_sites = 3u;

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::microcodeStressFunction(*F, params, rng));
    CHECK(F->size() == before);
    CHECK(countGlobals(*M, "morok.micro.table") == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("microcodeStressFunction emits a blockaddress table and indirectbr") {
    LLVMContext ctx;
    auto M = parse(ctx, kArithDarwin);
    Function *F = M->getFunction("arith");
    REQUIRE(F);

    morok::passes::MicrocodeStressParams params;
    params.probability = 100u;
    params.max_sites = 1u;    // exactly one dispatch site
    params.table_entries = 30u; // deliberately not a power of two
    params.decoy_blocks = 8u;
    params.alias_stores = 2u;

    auto rng = makeRng();
    CHECK(morok::passes::microcodeStressFunction(*F, params, rng));

    // One site => one table, one indirectbr, and normalizedDecoys(8) decoys.
    CHECK(countGlobals(*M, "morok.micro.table") == 1u);
    CHECK(countOpcode(*M, static_cast<unsigned>(Instruction::IndirectBr)) == 1u);
    CHECK(countBlocksNamed(*F, "morok.micro.decoy") == 8u);

    // The table is a constant pointer array normalized to a power of two:
    // nextPow2(clamp(30, 9, 256)) == 32.
    GlobalVariable *table = nullptr;
    for (GlobalVariable &G : M->globals())
        if (G.getName().starts_with("morok.micro.table")) {
            table = &G;
            break;
        }
    REQUIRE(table);
    CHECK(table->isConstant());
    auto *arrTy = dyn_cast<ArrayType>(table->getValueType());
    REQUIRE(arrTy);
    CHECK(arrTy->getNumElements() == 32u);
    CHECK(arrTy->getElementType()->isPointerTy());

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("microcodeStressFunction plants an analysis-bait function") {
    LLVMContext ctx;
    auto M = parse(ctx, kArithDarwin);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    CHECK(countFunctions(*M, "morok.micro.analysis.bait") == 0u);

    morok::passes::MicrocodeStressParams params;
    params.probability = 100u;
    params.max_sites = 1u;

    auto rng = makeRng();
    CHECK(morok::passes::microcodeStressFunction(*F, params, rng));
    // x86_64 has a supported bait variant, so exactly one bait fn is created.
    CHECK(countFunctions(*M, "morok.micro.analysis.bait") == 1u);
    CHECK(M->getFunction("morok.micro.analysis.bait") != nullptr);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("microcodeStressFunction respects the max_sites cap") {
    LLVMContext ctx;
    auto M = parse(ctx, kMultiDarwin);
    Function *F = M->getFunction("multi");
    REQUIRE(F);

    morok::passes::MicrocodeStressParams params;
    params.probability = 100u; // every splittable block would fire...
    params.max_sites = 2u;     // ...but the site count is capped at 2.

    auto rng = makeRng();
    CHECK(morok::passes::microcodeStressFunction(*F, params, rng));
    // One table + one indirectbr per fired site; capped at max_sites.
    CHECK(countGlobals(*M, "morok.micro.table") == 2u);
    CHECK(countOpcode(*M, static_cast<unsigned>(Instruction::IndirectBr)) == 2u);
    CHECK(countGlobals(*M, "morok.micro.table") <= params.max_sites);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("microcodeStressFunction is deterministic for a fixed seed and input") {
    LLVMContext ctxA;
    LLVMContext ctxB;
    auto MA = parse(ctxA, kArithDarwin);
    auto MB = parse(ctxB, kArithDarwin);
    Function *FA = MA->getFunction("arith");
    Function *FB = MB->getFunction("arith");
    REQUIRE(FA);
    REQUIRE(FB);

    morok::passes::MicrocodeStressParams params;
    params.probability = 100u;
    params.max_sites = 3u;

    // Two freshly, identically seeded engines => identical transforms.
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0xD1CEu);
    morok::ir::IRRandom rngA(engineA);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0xD1CEu);
    morok::ir::IRRandom rngB(engineB);

    const bool firedA = morok::passes::microcodeStressFunction(*FA, params, rngA);
    const bool firedB = morok::passes::microcodeStressFunction(*FB, params, rngB);
    CHECK(firedA);
    CHECK(firedB);
    CHECK(moduleToString(*MA) == moduleToString(*MB));
    CHECK_FALSE(verifyModule(*MA));
    CHECK_FALSE(verifyModule(*MB));
}
