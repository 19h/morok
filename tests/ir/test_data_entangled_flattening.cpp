// SPDX-License-Identifier: MIT
//
// Tests for DataEntangledFlattening — control-flow flattening whose dispatcher
// state update is fused with live program values and routed through volatile
// shadow memory so the stored successor id is value-neutral but not trivially
// foldable.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/DataEntangledFlattening.hpp"

#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// Multi-block function with several live scalar integer values per block and an
// explicit target triple so nothing in the test depends on the host platform.
const char *kEntangle = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @entangle(i32 %a, i32 %b, i32 %n) {
entry:
  %c = icmp slt i32 %a, %b
  br i1 %c, label %then, label %else
then:
  %t0 = add i32 %a, %b
  %t1 = mul i32 %t0, %a
  %t2 = xor i32 %t1, %b
  br label %join
else:
  %e0 = sub i32 %b, %a
  %e1 = mul i32 %e0, %b
  br label %join
join:
  %p = phi i32 [ %t2, %then ], [ %e1, %else ]
  %q = add i32 %p, %n
  %r = icmp sgt i32 %q, 0
  br i1 %r, label %pos, label %neg
pos:
  %rp = add i32 %q, 1
  ret i32 %rp
neg:
  %rn = sub i32 %q, 1
  ret i32 %rn
}
)ir";

const char *kSingleBlock = R"ir(
define i32 @trivial(i32 %x) {
entry:
  %r = add i32 %x, 1
  ret i32 %r
}
)ir";

const char *kDeclaration = R"ir(
declare i32 @external(i32)
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

bool hasBlockNamed(Function &F, StringRef blockName) {
    for (BasicBlock &BB : F)
        if (BB.getName() == blockName)
            return true;
    return false;
}

std::size_t countVolatileStores(Function &F) {
    std::size_t n = 0;
    for (Instruction &I : instructions(F))
        if (auto *SI = dyn_cast<StoreInst>(&I))
            if (SI->isVolatile())
                ++n;
    return n;
}

std::size_t countVolatileLoads(Function &F) {
    std::size_t n = 0;
    for (Instruction &I : instructions(F))
        if (auto *LI = dyn_cast<LoadInst>(&I))
            if (LI->isVolatile())
                ++n;
    return n;
}

std::string printModule(Module &M) {
    std::string out;
    raw_string_ostream os(out);
    M.print(os, nullptr);
    os.flush();
    return out;
}

} // namespace

TEST_CASE("dataEntangledFlattenFunction grows the function and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kEntangle);
    Function *F = M->getFunction("entangle");
    REQUIRE(F);
    const std::size_t blocksBefore = F->size();
    const std::size_t binopsBefore = countBinops(*F);

    auto rng = makeRng(0x1337);
    CHECK(morok::passes::dataEntangledFlattenFunction(
        *F, morok::passes::DataEntangledFlattenParams{/*max_terms=*/4}, rng));

    // Flattening adds the dispatch/backedge/default scaffolding plus the split
    // entry, and the entangled token chain adds many binary operators.
    CHECK(F->size() > blocksBefore);
    CHECK(countBinops(*F) > binopsBefore);
    CHECK_FALSE(verifyModule(*M));

    // Exactly one shadow store and one dispatcher state slot are allocated.
    CHECK(countNamedAllocas(*F, "entfla.shadow") == std::size_t{1});
    CHECK(countNamedAllocas(*F, "fla.state") == std::size_t{1});
}

TEST_CASE("dataEntangledFlattenFunction refuses single-block functions") {
    LLVMContext ctx;
    auto M = parse(ctx, kSingleBlock);
    Function *F = M->getFunction("trivial");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng(0x2001);
    // Fewer than two blocks: nothing to flatten, function is left untouched.
    CHECK_FALSE(morok::passes::dataEntangledFlattenFunction(
        *F, morok::passes::DataEntangledFlattenParams{}, rng));
    CHECK(F->size() == before);
    CHECK(countNamedAllocas(*F, "entfla.shadow") == std::size_t{0});
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("dataEntangledFlattenFunction is safe on declarations") {
    LLVMContext ctx;
    auto M = parse(ctx, kDeclaration);
    Function *F = M->getFunction("external");
    REQUIRE(F);

    auto rng = makeRng(0x2002);
    // A declaration has zero blocks; the pass must not crash and reports no
    // change.
    CHECK_FALSE(morok::passes::dataEntangledFlattenFunction(
        *F, morok::passes::DataEntangledFlattenParams{}, rng));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("dataEntangledFlattenFunction builds the switch dispatcher scaffolding") {
    LLVMContext ctx;
    auto M = parse(ctx, kEntangle);
    Function *F = M->getFunction("entangle");
    REQUIRE(F);

    auto rng = makeRng(0x2003);
    CHECK(morok::passes::dataEntangledFlattenFunction(
        *F, morok::passes::DataEntangledFlattenParams{/*max_terms=*/4}, rng));

    // The flattening engine emits a switch over the dispatcher state variable
    // plus its fixed control blocks; the multi-way entry is split into fla.entry.
    CHECK(countOpcode(*M, Instruction::Switch) >= std::size_t{1});
    CHECK(hasBlockNamed(*F, "fla.dispatch"));
    CHECK(hasBlockNamed(*F, "fla.backedge"));
    CHECK(hasBlockNamed(*F, "fla.default"));
    CHECK(hasBlockNamed(*F, "fla.entry"));
    CHECK(findNamedInstruction(*F, "fla.cur") != nullptr);
    CHECK(countNamedAllocas(*F, "fla.state") == std::size_t{1});
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("dataEntangledFlattenFunction routes the token through volatile shadow memory") {
    LLVMContext ctx;
    auto M = parse(ctx, kEntangle);
    Function *F = M->getFunction("entangle");
    REQUIRE(F);

    auto rng = makeRng(0x2004);
    CHECK(morok::passes::dataEntangledFlattenFunction(
        *F, morok::passes::DataEntangledFlattenParams{/*max_terms=*/4}, rng));
    CHECK_FALSE(verifyModule(*M));

    // The shadow slab is a [2 x i32] alloca.
    auto *shadow =
        dyn_cast_or_null<AllocaInst>(findNamedInstruction(*F, "entfla.shadow"));
    REQUIRE(shadow != nullptr);
    auto *shadowTy = dyn_cast<ArrayType>(shadow->getAllocatedType());
    REQUIRE(shadowTy != nullptr);
    CHECK(shadowTy->getNumElements() == static_cast<std::uint64_t>(2));
    CHECK(shadowTy->getElementType()->isIntegerTy(32));

    // Each block's neutralizing token is stored to and reloaded from the shadow
    // slots volatilely, then cancelled and fused into the successor id.
    CHECK(countVolatileStores(*F) > std::size_t{0});
    CHECK(countVolatileLoads(*F) > std::size_t{0});
    CHECK(countNamedInstructions(*F, "entfla.cancel") > std::size_t{0});
    CHECK(countNamedInstructions(*F, "entfla.next") > std::size_t{0});
}

TEST_CASE("dataEntangledFlattenFunction is deterministic for a fixed seed") {
    LLVMContext ctxA;
    auto MA = parse(ctxA, kEntangle);
    Function *FA = MA->getFunction("entangle");
    REQUIRE(FA);
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0xBEEF);
    morok::ir::IRRandom rngA(engineA);
    CHECK(morok::passes::dataEntangledFlattenFunction(
        *FA, morok::passes::DataEntangledFlattenParams{/*max_terms=*/4}, rngA));

    LLVMContext ctxB;
    auto MB = parse(ctxB, kEntangle);
    Function *FB = MB->getFunction("entangle");
    REQUIRE(FB);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0xBEEF);
    morok::ir::IRRandom rngB(engineB);
    CHECK(morok::passes::dataEntangledFlattenFunction(
        *FB, morok::passes::DataEntangledFlattenParams{/*max_terms=*/4}, rngB));

    // Same seed + same input IR must yield byte-identical modules.
    CHECK(printModule(*MA) == printModule(*MB));
    CHECK_FALSE(verifyModule(*MA));
    CHECK_FALSE(verifyModule(*MB));
}

TEST_CASE("dataEntangledFlattenFunction with max_terms=0 mixes no live terms") {
    LLVMContext ctx;
    auto M = parse(ctx, kEntangle);
    Function *F = M->getFunction("entangle");
    REQUIRE(F);

    auto rng = makeRng(0x2005);
    CHECK(morok::passes::dataEntangledFlattenFunction(
        *F, morok::passes::DataEntangledFlattenParams{/*max_terms=*/0}, rng));
    CHECK_FALSE(verifyModule(*M));

    // With the term budget at zero, no live program value is folded into the
    // token, so no per-term mix instructions are emitted...
    CHECK(countNamedInstructions(*F, "entfla.token.term") == std::size_t{0});
    // ...but the flattening and the seeded token/shadow machinery still run.
    CHECK(countNamedInstructions(*F, "entfla.token.seed") > std::size_t{0});
    CHECK(countNamedInstructions(*F, "entfla.next") > std::size_t{0});
    CHECK(countNamedAllocas(*F, "entfla.shadow") == std::size_t{1});
}

TEST_CASE("dataEntangledFlattenFunction honors the max_terms bound") {
    LLVMContext ctxLo;
    auto MLo = parse(ctxLo, kEntangle);
    Function *FLo = MLo->getFunction("entangle");
    REQUIRE(FLo);
    auto engineLo = morok::core::Xoshiro256pp::fromSeed(0x5151);
    morok::ir::IRRandom rngLo(engineLo);
    CHECK(morok::passes::dataEntangledFlattenFunction(
        *FLo, morok::passes::DataEntangledFlattenParams{/*max_terms=*/1},
        rngLo));

    LLVMContext ctxHi;
    auto MHi = parse(ctxHi, kEntangle);
    Function *FHi = MHi->getFunction("entangle");
    REQUIRE(FHi);
    auto engineHi = morok::core::Xoshiro256pp::fromSeed(0x5151);
    morok::ir::IRRandom rngHi(engineHi);
    CHECK(morok::passes::dataEntangledFlattenFunction(
        *FHi, morok::passes::DataEntangledFlattenParams{/*max_terms=*/8},
        rngHi));

    // Per block the pass folds min(max_terms, #live_terms) values into the
    // token, so a larger budget can only mix at least as many terms.
    const std::size_t termsLo = countNamedInstructions(*FLo, "entfla.token.term");
    const std::size_t termsHi = countNamedInstructions(*FHi, "entfla.token.term");
    CHECK(termsLo >= std::size_t{1});
    CHECK(termsHi >= termsLo);
    CHECK_FALSE(verifyModule(*MLo));
    CHECK_FALSE(verifyModule(*MHi));
}
