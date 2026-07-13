// SPDX-License-Identifier: MIT
//
// Tests for RuntimeSeal — dataflow-bound detector seal folds (foldFlag et al).

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/RuntimeSeal.hpp"

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;
using namespace morok::test;

namespace {

namespace rs = morok::passes::runtime_seal;

// A one-argument integer probe: gives us a live i64 flag/word operand and a
// terminator to insert the fold in front of. An explicit triple keeps the file
// platform-neutral (the helpers do not branch on the triple, but pin it anyway).
const char *kProbeModule = R"ir(
target triple = "x86_64-unknown-linux-gnu"
define i64 @probe(i64 %flag) {
entry:
  ret i64 %flag
}
)ir";

// A void, argument-less function: exercises the trivial single-block path with a
// constant flag operand.
const char *kTrivialModule = R"ir(
target triple = "x86_64-unknown-linux-gnu"
define void @tick() {
entry:
  ret void
}
)ir";

// Same probe, but with the anti_debug channel root pre-declared with a FIXED
// initializer. Because the fold helpers draw no randomness, this lets the
// determinism test compare printed IR without any RNG divergence.
const char *kSeededProbeModule = R"ir(
target triple = "x86_64-unknown-linux-gnu"
@morok.seal.root.anti_debug = private global i64 12345, align 8
define i64 @probe(i64 %flag) {
entry:
  ret i64 %flag
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

std::size_t countAllInstructions(Function &F) {
    std::size_t n = 0;
    for (Instruction &I : instructions(F)) {
        (void)I;
        ++n;
    }
    return n;
}

} // namespace

TEST_CASE("foldFlag grows the function and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kProbeModule);

    auto rng = makeRng(0xB001);
    Function *F = M->getFunction("probe");
    REQUIRE(F != nullptr);

    // The channel must exist before folding — foldFlag never creates it.
    rs::getChannel(*M, rs::kAntiDebugChannel, rng);
    std::size_t before = countAllInstructions(*F);

    IRBuilder<> B(F->getEntryBlock().getTerminator());
    rs::foldFlag(B, rs::kAntiDebugChannel, F->getArg(0), 0xABCDULL, "seal_x");

    std::size_t after = countAllInstructions(*F);
    CHECK(after > before);

    // The commit branch materialises as a named select.
    auto *Sel = dyn_cast_or_null<SelectInst>(findNamedInstruction(*F, "seal_x.next"));
    CHECK(Sel != nullptr);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("foldFlag binds against the named seal root channel") {
    LLVMContext ctx;
    auto M = parse(ctx, kProbeModule);

    auto rng = makeRng(0xB002);
    Function *F = M->getFunction("probe");
    REQUIRE(F != nullptr);

    GlobalVariable *Created = rs::getChannel(*M, rs::kAntiDebugChannel, rng);
    REQUIRE(Created != nullptr);

    // getChannel emits exactly one private, i64, unnamed-addr seal root.
    CHECK(countGlobals(*M, "morok.seal.root.") == 1);
    CHECK(Created->hasPrivateLinkage());
    CHECK(Created->getValueType()->isIntegerTy(64));

    // findChannel resolves the same object by channel name.
    GlobalVariable *Found = rs::findChannel(*M, rs::kAntiDebugChannel);
    CHECK(Found == Created);

    IRBuilder<> B(F->getEntryBlock().getTerminator());
    rs::foldFlag(B, rs::kAntiDebugChannel, F->getArg(0), 0x11ULL, "seal_bind");

    // Folding does not spawn a second root global.
    CHECK(countGlobals(*M, "morok.seal.root.") == 1);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("foldFlag without an existing channel is a no-op") {
    LLVMContext ctx;
    auto M = parse(ctx, kProbeModule);

    Function *F = M->getFunction("probe");
    REQUIRE(F != nullptr);

    std::size_t before = countAllInstructions(*F);

    // No getChannel call: findChannel returns null, so foldFlag emits nothing.
    IRBuilder<> B(F->getEntryBlock().getTerminator());
    rs::foldFlag(B, rs::kAntiDebugChannel, F->getArg(0), 0x22ULL, "seal_noop");

    CHECK(countAllInstructions(*F) == before);
    CHECK(countGlobals(*M, "morok.seal.root.") == 0);
    CHECK(findNamedInstruction(*F, "seal_noop.next") == nullptr);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("foldFlag clean input preserves the current seal (zero contribution)") {
    LLVMContext ctx;
    auto M = parse(ctx, kProbeModule);

    auto rng = makeRng(0xB003);
    Function *F = M->getFunction("probe");
    REQUIRE(F != nullptr);

    rs::getChannel(*M, rs::kAntiDebugChannel, rng);

    IRBuilder<> B(F->getEntryBlock().getTerminator());
    rs::foldFlag(B, rs::kAntiDebugChannel, F->getArg(0), 0x33ULL, "seal_clean");

    // Structural proof that a clean (flag == 0) fold contributes nothing:
    // Next = select(Tripped, Mixed, Cur), and the stored-back "false" arm is the
    // freshly-loaded current seal word. When the flag is 0 the seal is unchanged.
    auto *Sel =
        dyn_cast_or_null<SelectInst>(findNamedInstruction(*F, "seal_clean.next"));
    REQUIRE(Sel != nullptr);
    Instruction *Cur = findNamedInstruction(*F, "seal_clean.cur");
    REQUIRE(Cur != nullptr);
    CHECK(Sel->getFalseValue() == Cur);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("foldFlag reads and writes the seal through volatile memory ops") {
    LLVMContext ctx;
    auto M = parse(ctx, kProbeModule);

    auto rng = makeRng(0xB004);
    Function *F = M->getFunction("probe");
    REQUIRE(F != nullptr);

    GlobalVariable *Seal = rs::getChannel(*M, rs::kAntiDebugChannel, rng);

    IRBuilder<> B(F->getEntryBlock().getTerminator());
    rs::foldFlag(B, rs::kAntiDebugChannel, F->getArg(0), 0x44ULL, "seal_vol");

    // The current-seal load is a volatile i64 load of the channel root.
    auto *Cur = dyn_cast_or_null<LoadInst>(findNamedInstruction(*F, "seal_vol.cur"));
    REQUIRE(Cur != nullptr);
    CHECK(Cur->isVolatile());
    CHECK(Cur->getPointerOperand() == Seal);

    // Exactly one store-back exists and it is volatile.
    std::size_t stores = 0;
    for (Instruction &I : instructions(*F)) {
        if (auto *SI = dyn_cast<StoreInst>(&I)) {
            ++stores;
            CHECK(SI->isVolatile());
            CHECK(SI->getPointerOperand() == Seal);
        }
    }
    CHECK(stores == 1);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("foldFlag is deterministic for identical input") {
    LLVMContext ctx;
    auto M1 = parse(ctx, kSeededProbeModule);
    auto M2 = parse(ctx, kSeededProbeModule);

    Function *F1 = M1->getFunction("probe");
    Function *F2 = M2->getFunction("probe");
    REQUIRE(F1 != nullptr);
    REQUIRE(F2 != nullptr);

    // The seal root is pre-declared with a fixed initializer, so no RNG is used.
    IRBuilder<> B1(F1->getEntryBlock().getTerminator());
    IRBuilder<> B2(F2->getEntryBlock().getTerminator());
    rs::foldFlag(B1, rs::kAntiDebugChannel, F1->getArg(0), 0xDEADBEEFULL, "seal_det");
    rs::foldFlag(B2, rs::kAntiDebugChannel, F2->getArg(0), 0xDEADBEEFULL, "seal_det");

    std::string s1;
    std::string s2;
    {
        raw_string_ostream os1(s1);
        M1->print(os1, nullptr);
        os1.flush();
    }
    {
        raw_string_ostream os2(s2);
        M2->print(os2, nullptr);
        os2.flush();
    }
    CHECK(s1 == s2);

    CHECK_FALSE(verifyModule(*M1));
    CHECK_FALSE(verifyModule(*M2));
}

TEST_CASE("foldWord folds a data word into the channel and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kProbeModule);

    auto rng = makeRng(0xB005);
    Function *F = M->getFunction("probe");
    REQUIRE(F != nullptr);

    rs::getChannel(*M, rs::kEnvBindingChannel, rng);
    std::size_t before = countAllInstructions(*F);

    IRBuilder<> B(F->getEntryBlock().getTerminator());
    rs::foldWord(B, rs::kEnvBindingChannel, F->getArg(0), 0x55ULL, "seal_word");

    CHECK(countAllInstructions(*F) > before);

    // foldWord also gates the update through a named select on activity, and the
    // clean/false arm must be the current seal load (zero contribution).
    auto *Sel =
        dyn_cast_or_null<SelectInst>(findNamedInstruction(*F, "seal_word.next"));
    REQUIRE(Sel != nullptr);
    Instruction *Cur = findNamedInstruction(*F, "seal_word.cur");
    REQUIRE(Cur != nullptr);
    CHECK(Sel->getFalseValue() == Cur);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("foldWeightedFlag is a no-op when the weight is zero") {
    LLVMContext ctx;
    auto M = parse(ctx, kProbeModule);

    auto rng = makeRng(0xB006);
    Function *F = M->getFunction("probe");
    REQUIRE(F != nullptr);

    rs::getChannel(*M, rs::kAntiHookChannel, rng);
    std::size_t before = countAllInstructions(*F);

    // Weight == 0 short-circuits before any IR or score slots are emitted.
    IRBuilder<> B(F->getEntryBlock().getTerminator());
    rs::foldWeightedFlag(B, rs::kAntiHookChannel, F->getArg(0), /*Weight=*/0u,
                         /*EvidenceMask=*/0x4ULL, /*Threshold=*/2u,
                         /*Salt=*/0x66ULL, "seal_wf0");

    CHECK(countAllInstructions(*F) == before);
    CHECK(countGlobals(*M, "morok.seal.score.") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("foldWeightedFlag emits the three score slots and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kProbeModule);

    auto rng = makeRng(0xB007);
    Function *F = M->getFunction("probe");
    REQUIRE(F != nullptr);

    rs::getChannel(*M, rs::kAntiHookChannel, rng);
    std::size_t before = countAllInstructions(*F);

    IRBuilder<> B(F->getEntryBlock().getTerminator());
    rs::foldWeightedFlag(B, rs::kAntiHookChannel, F->getArg(0), /*Weight=*/3u,
                         /*EvidenceMask=*/0x4ULL, /*Threshold=*/2u,
                         /*Salt=*/0x77ULL, "seal_wf");

    // weight (i32), evidence (i64) and committed (i1) accumulator slots.
    CHECK(countGlobals(*M, "morok.seal.score.") == 3);
    CHECK(countAllInstructions(*F) > before);

    // The commit path threads through a named select before it hits foldWord.
    CHECK(findNamedInstruction(*F, "seal_wf.active") != nullptr);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("foldFlag is safe on a trivial single-block function") {
    LLVMContext ctx;
    auto M = parse(ctx, kTrivialModule);

    auto rng = makeRng(0xB008);
    Function *F = M->getFunction("tick");
    REQUIRE(F != nullptr);

    rs::getChannel(*M, rs::kTracerChannel, rng);
    std::size_t before = countAllInstructions(*F);

    // A non-i64 constant flag exercises the toI64 widening path.
    IRBuilder<> B(F->getEntryBlock().getTerminator());
    Value *Flag = ConstantInt::get(B.getInt32Ty(), 1);
    rs::foldFlag(B, rs::kTracerChannel, Flag, 0x88ULL, "seal_triv");

    CHECK(countAllInstructions(*F) > before);
    CHECK(rs::findChannel(*M, rs::kTracerChannel) != nullptr);
    CHECK_FALSE(verifyModule(*M));
}
