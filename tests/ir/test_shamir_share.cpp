// SPDX-License-Identifier: MIT
//
// Tests for ShamirShare — GF(2^8) Shamir threshold sharing of scalar literals.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/ShamirShare.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;
using namespace morok::test;

namespace {

// Four eligible i32 literals, each an operand of a rewritable binary op.
const char *kArith = R"ir(
define i32 @arith(i32 %a, i32 %b) {
entry:
  %0 = add i32 %a, 42
  %1 = mul i32 %0, 1337
  %2 = xor i32 %1, 255
  %3 = sub i32 %2, 13
  ret i32 %3
}
)ir";

// Six eligible literals so the max_secrets cap can bite well below the total.
const char *kMany = R"ir(
define i32 @many(i32 %a) {
entry:
  %0 = add i32 %a, 11
  %1 = add i32 %0, 22
  %2 = add i32 %1, 33
  %3 = add i32 %2, 44
  %4 = add i32 %3, 55
  %5 = add i32 %4, 66
  ret i32 %5
}
)ir";

// A single named literal user, for the "operand actually replaced" check.
const char *kOne = R"ir(
define i32 @one(i32 %a) {
entry:
  %r = add i32 %a, 12345
  ret i32 %r
}
)ir";

// A double literal, exercising the FP raw-bit reconstruction + bitcast path.
const char *kFp = R"ir(
define double @fp(double %x) {
entry:
  %r = fadd double %x, 3.140000e+00
  ret double %r
}
)ir";

// A constant i1 branch condition, exercising the sub-byte truncation path.
const char *kBrc = R"ir(
define i32 @brc(i32 %a) {
entry:
  br i1 true, label %t, label %f
t:
  ret i32 %a
f:
  ret i32 %a
}
)ir";

// No eligible literal operands anywhere.
const char *kNoConsts = R"ir(
define i32 @noconsts(i32 %a, i32 %b) {
entry:
  %r = add i32 %a, %b
  ret i32 %r
}
)ir";

const char *kDecl = R"ir(
declare i32 @external(i32)
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

std::size_t instructionCount(Function &F) {
    std::size_t n = 0;
    for (Instruction &I : instructions(F)) {
        (void)I;
        ++n;
    }
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

TEST_CASE("shamirShareFunction shares literals, grows the function, stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t beforeInsts = instructionCount(*F);

    auto rng = makeRng(0x51A);
    CHECK(morok::passes::shamirShareFunction(
        *F, {/*prob=*/100, /*threshold=*/3, /*shares=*/5, /*max_secrets=*/8},
        rng));

    // The reconstruction lattice adds many instructions and share globals.
    CHECK(instructionCount(*F) > beforeInsts);
    CHECK(countGlobals(*M, "morok.shamir.") > 0);
    CHECK(M->getFunction("morok.gf8mul") != nullptr);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("shamirShareFunction is a no-op when probability or budget is zero") {
    LLVMContext ctx;

    auto M0 = parse(ctx, kArith);
    Function *F0 = M0->getFunction("arith");
    REQUIRE(F0);
    const std::size_t before0 = instructionCount(*F0);
    auto rng0 = makeRng(0x5B0);
    CHECK_FALSE(morok::passes::shamirShareFunction(
        *F0, {/*prob=*/0, /*threshold=*/3, /*shares=*/5, /*max_secrets=*/8},
        rng0));
    CHECK(instructionCount(*F0) == before0);
    CHECK(countGlobals(*M0, "morok.shamir.") == 0);
    CHECK_FALSE(verifyModule(*M0));

    auto Mb = parse(ctx, kArith);
    Function *Fb = Mb->getFunction("arith");
    REQUIRE(Fb);
    const std::size_t beforeB = instructionCount(*Fb);
    auto rngB = makeRng(0x5B1);
    CHECK_FALSE(morok::passes::shamirShareFunction(
        *Fb, {/*prob=*/100, /*threshold=*/3, /*shares=*/5, /*max_secrets=*/0},
        rngB));
    CHECK(instructionCount(*Fb) == beforeB);
    CHECK_FALSE(verifyModule(*Mb));
}

TEST_CASE("shamirShareFunction leaves declarations and literal-free code alone") {
    LLVMContext ctx;

    auto MD = parse(ctx, kDecl);
    Function *FD = MD->getFunction("external");
    REQUIRE(FD);
    auto rngD = makeRng(0x5C0);
    CHECK_FALSE(morok::passes::shamirShareFunction(
        *FD, {/*prob=*/100, /*threshold=*/3, /*shares=*/5, /*max_secrets=*/8},
        rngD));
    CHECK_FALSE(verifyModule(*MD));

    auto MN = parse(ctx, kNoConsts);
    Function *FN = MN->getFunction("noconsts");
    REQUIRE(FN);
    const std::size_t beforeN = instructionCount(*FN);
    auto rngN = makeRng(0x5C1);
    CHECK_FALSE(morok::passes::shamirShareFunction(
        *FN, {/*prob=*/100, /*threshold=*/3, /*shares=*/5, /*max_secrets=*/8},
        rngN));
    CHECK(instructionCount(*FN) == beforeN);
    CHECK(countGlobals(*MN, "morok.shamir.") == 0);
    CHECK_FALSE(verifyModule(*MN));
}

TEST_CASE("shamirShareFunction honors the max_secrets cap") {
    LLVMContext ctxA;
    auto MA = parse(ctxA, kMany);
    Function *FA = MA->getFunction("many");
    REQUIRE(FA);
    auto rngA = makeRng(0x5D0);
    CHECK(morok::passes::shamirShareFunction(
        *FA, {/*prob=*/100, /*threshold=*/3, /*shares=*/5, /*max_secrets=*/1},
        rngA));
    const std::size_t globalsCapped = countGlobals(*MA, "morok.shamir.");

    LLVMContext ctxB;
    auto MB = parse(ctxB, kMany);
    Function *FB = MB->getFunction("many");
    REQUIRE(FB);
    auto rngB = makeRng(0x5D1);
    CHECK(morok::passes::shamirShareFunction(
        *FB, {/*prob=*/100, /*threshold=*/3, /*shares=*/5, /*max_secrets=*/6},
        rngB));
    const std::size_t globalsFull = countGlobals(*MB, "morok.shamir.");

    // One secret deposits strictly fewer share/cell cells than six do.
    CHECK(globalsCapped > 0);
    CHECK(globalsFull > globalsCapped);
    CHECK_FALSE(verifyModule(*MA));
    CHECK_FALSE(verifyModule(*MB));
}

TEST_CASE("shamirShareFunction is deterministic for a fixed seed and input") {
    LLVMContext ctx1;
    auto M1 = parse(ctx1, kArith);
    auto engine1 = morok::core::Xoshiro256pp::fromSeed(0xBEEF);
    morok::ir::IRRandom rng1(engine1);
    CHECK(morok::passes::shamirShareFunction(
        *M1->getFunction("arith"),
        {/*prob=*/100, /*threshold=*/3, /*shares=*/5, /*max_secrets=*/8}, rng1));

    LLVMContext ctx2;
    auto M2 = parse(ctx2, kArith);
    auto engine2 = morok::core::Xoshiro256pp::fromSeed(0xBEEF);
    morok::ir::IRRandom rng2(engine2);
    CHECK(morok::passes::shamirShareFunction(
        *M2->getFunction("arith"),
        {/*prob=*/100, /*threshold=*/3, /*shares=*/5, /*max_secrets=*/8}, rng2));

    CHECK(printModule(*M1) == printModule(*M2));
    CHECK_FALSE(verifyModule(*M1));
}

TEST_CASE("shamirShareFunction emits the GF(256) helper and volatile share cells") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);

    auto rng = makeRng(0x5E0);
    CHECK(morok::passes::shamirShareFunction(
        *F, {/*prob=*/100, /*threshold=*/3, /*shares=*/5, /*max_secrets=*/8},
        rng));

    // The multiply helper is created exactly once, internal, and called back.
    CHECK(countFunctions(*M, "morok.gf8mul") == 1);
    Function *Gf8 = M->getFunction("morok.gf8mul");
    REQUIRE(Gf8);
    CHECK(Gf8->hasInternalLinkage());
    CHECK(countCallsTo(*F, "morok.gf8mul") > 0);

    // Both share-source and reconstruction cells are published.
    CHECK(countGlobals(*M, "morok.shamir.share") > 0);
    CHECK(countGlobals(*M, "morok.shamir.cell") > 0);
    CHECK(countNamedInstructions(*M, "morok.shamir.share.load") > 0);
    CHECK(countNamedInstructions(*M, "morok.shamir.cell.load") > 0);

    // The published shares are read through volatile loads.
    auto *shareLoad = dyn_cast_or_null<LoadInst>(
        findNamedInstruction(*F, "morok.shamir.share.load"));
    REQUIRE(shareLoad);
    CHECK(shareLoad->isVolatile());

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("shamirShareFunction reconstructs floating-point literals via bitcast") {
    LLVMContext ctx;
    auto M = parse(ctx, kFp);
    Function *F = M->getFunction("fp");
    REQUIRE(F);

    auto rng = makeRng(0x5F0);
    CHECK(morok::passes::shamirShareFunction(
        *F, {/*prob=*/100, /*threshold=*/3, /*shares=*/5, /*max_secrets=*/8},
        rng));

    // FP secrets are shared by raw bits and bitcast back to the float type.
    CHECK(countNamedInstructions(*M, "morok.shamir.value.fp") > 0);

    // The fadd no longer feeds on a ConstantFP operand.
    auto *fadd = findNamedInstruction(*F, "r");
    REQUIRE(fadd);
    bool hasFpConst = false;
    for (Value *Op : fadd->operands())
        if (isa<ConstantFP>(Op))
            hasFpConst = true;
    CHECK_FALSE(hasFpConst);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("shamirShareFunction replaces the literal operand at the use site") {
    LLVMContext ctx;
    auto M = parse(ctx, kOne);
    Function *F = M->getFunction("one");
    REQUIRE(F);

    auto *addBefore = findNamedInstruction(*F, "r");
    REQUIRE(addBefore);
    CHECK(instructionHasConstantOperand(addBefore, 12345));

    auto rng = makeRng(0x600);
    CHECK(morok::passes::shamirShareFunction(
        *F, {/*prob=*/100, /*threshold=*/3, /*shares=*/5, /*max_secrets=*/8},
        rng));

    auto *addAfter = findNamedInstruction(*F, "r");
    REQUIRE(addAfter);
    CHECK_FALSE(instructionHasConstantOperand(addAfter, 12345));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("shamirShareFunction rewrites constant branch conditions with truncation") {
    LLVMContext ctx;
    auto M = parse(ctx, kBrc);
    Function *F = M->getFunction("brc");
    REQUIRE(F);

    auto rng = makeRng(0x610);
    CHECK(morok::passes::shamirShareFunction(
        *F, {/*prob=*/100, /*threshold=*/3, /*shares=*/5, /*max_secrets=*/8},
        rng));

    // A 1-bit secret is reconstructed in a byte carrier then truncated to i1.
    CHECK(countNamedInstructions(*M, "morok.shamir.value.trunc") > 0);

    // The entry terminator is now a runtime condition, not a folded constant.
    auto *term = F->getEntryBlock().getTerminator();
    auto *br = dyn_cast<BranchInst>(term);
    REQUIRE(br);
    REQUIRE(br->isConditional());
    CHECK_FALSE(isa<ConstantInt>(br->getCondition()));

    CHECK_FALSE(verifyModule(*M));
}
