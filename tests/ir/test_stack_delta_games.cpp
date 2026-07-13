// SPDX-License-Identifier: MIT
//
// Tests for StackDeltaGames — dynamic stack-pointer delta obfuscation via
// bounded variable-sized allocas guarded by stacksave/stackrestore.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/StackDeltaGames.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstIterator.h"
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

// Single-block function with a real first instruction (a valid split point).
const char *kArith = R"ir(
define i32 @arith(i32 %a, i32 %b) {
entry:
  %0 = add i32 %a, %b
  %1 = mul i32 %a, %b
  %2 = xor i32 %0, %1
  ret i32 %2
}
)ir";

// Single-block function whose only instruction is the terminator: the pass
// finds no split point (guardSplitPoint returns null on a leading terminator).
const char *kRetOnly = R"ir(
define i32 @ret_only(i32 %x) {
entry:
  ret i32 %x
}
)ir";

// Multi-block chain where every block has a non-terminator instruction, so
// every block is an eligible transform site.
const char *kChain = R"ir(
define i32 @chain(i32 %a, i32 %b) {
entry:
  %e = add i32 %a, %b
  br label %b1
b1:
  %x1 = mul i32 %e, 3
  br label %b2
b2:
  %x2 = xor i32 %x1, %a
  br label %b3
b3:
  %x3 = sub i32 %x2, %b
  br label %b4
b4:
  %x4 = add i32 %x3, 7
  ret i32 %x4
}
)ir";

// Function whose name marks it as Morok-generated ("morok." prefix); the pass
// must leave it untouched.
const char *kGenerated = R"ir(
define i32 @morok.helper(i32 %a) {
entry:
  %0 = add i32 %a, 1
  ret i32 %0
}
)ir";

const char *kDecl = R"ir(
declare i32 @external(i32)
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

} // namespace

TEST_CASE("stackDeltaGamesFunction grows the function and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);
    const std::size_t before = F->size();

    morok::passes::StackDeltaParams params;
    params.probability = 100;
    params.max_blocks = 6;

    auto rng = makeRng();
    CHECK(morok::passes::stackDeltaGamesFunction(*F, params, rng));
    // SplitBlock adds a block; emitStackDelta adds the frame + touches.
    CHECK(F->size() > before);
    CHECK_FALSE(verifyModule(*M));

    // Named seed global emitted exactly once, with private linkage.
    CHECK(countGlobals(*M, "morok.stackdelta.seed") == 1);
    auto *seedGV = M->getGlobalVariable("morok.stackdelta.seed", true);
    REQUIRE(seedGV != nullptr);
    CHECK(seedGV->hasPrivateLinkage());

    // The dynamic frame alloca and the stacksave/stackrestore guard pair.
    CHECK(countNamedAllocas(*F, "morok.stackdelta.frame") >= 1);
    CHECK(countCallsToPrefix(*F, "llvm.stacksave") >= 1);
    CHECK(countCallsToPrefix(*F, "llvm.stackrestore") >= 1);
}

TEST_CASE("stackDeltaGamesFunction is a no-op when disabled") {
    LLVMContext ctx;

    // probability == 0 short-circuits before any mutation.
    {
        auto Mp = parse(ctx, kArith);
        Function *Fp = Mp->getFunction("arith");
        REQUIRE(Fp);
        const std::size_t before = Fp->size();
        morok::passes::StackDeltaParams params;
        params.probability = 0;
        params.max_blocks = 6;
        auto rng = makeRng();
        CHECK_FALSE(morok::passes::stackDeltaGamesFunction(*Fp, params, rng));
        CHECK(Fp->size() == before);
        CHECK(countGlobals(*Mp, "morok.stackdelta.seed") == 0);
        CHECK_FALSE(verifyModule(*Mp));
    }

    // max_blocks == 0 also short-circuits.
    {
        auto Mm = parse(ctx, kArith);
        Function *Fm = Mm->getFunction("arith");
        REQUIRE(Fm);
        const std::size_t before = Fm->size();
        morok::passes::StackDeltaParams params;
        params.probability = 100;
        params.max_blocks = 0;
        auto rng = makeRng();
        CHECK_FALSE(morok::passes::stackDeltaGamesFunction(*Fm, params, rng));
        CHECK(Fm->size() == before);
        CHECK(countGlobals(*Mm, "morok.stackdelta.seed") == 0);
        CHECK_FALSE(verifyModule(*Mm));
    }
}

TEST_CASE("stackDeltaGamesFunction leaves declarations and generated "
          "functions untouched") {
    LLVMContext ctx;

    // Declarations have no body to transform.
    {
        auto Md = parse(ctx, kDecl);
        Function *Fd = Md->getFunction("external");
        REQUIRE(Fd);
        morok::passes::StackDeltaParams params;
        params.probability = 100;
        auto rng = makeRng();
        CHECK_FALSE(morok::passes::stackDeltaGamesFunction(*Fd, params, rng));
        CHECK(countGlobals(*Md, "morok.stackdelta.seed") == 0);
        CHECK_FALSE(verifyModule(*Md));
    }

    // Functions whose names start with "morok." are skipped as self-generated.
    {
        auto Mg = parse(ctx, kGenerated);
        Function *Fg = Mg->getFunction("morok.helper");
        REQUIRE(Fg);
        const std::size_t before = Fg->size();
        morok::passes::StackDeltaParams params;
        params.probability = 100;
        auto rng = makeRng();
        CHECK_FALSE(morok::passes::stackDeltaGamesFunction(*Fg, params, rng));
        CHECK(Fg->size() == before);
        CHECK(countGlobals(*Mg, "morok.stackdelta.seed") == 0);
        CHECK_FALSE(verifyModule(*Mg));
    }
}

TEST_CASE("stackDeltaGamesFunction skips a block with no split point") {
    LLVMContext ctx;
    auto M = parse(ctx, kRetOnly);
    Function *F = M->getFunction("ret_only");
    REQUIRE(F);
    const std::size_t before = F->size();

    morok::passes::StackDeltaParams params;
    params.probability = 100;
    params.max_blocks = 6;

    auto rng = makeRng();
    // The lone block begins with its terminator, so guardSplitPoint yields
    // nothing and the pass reports no change.
    CHECK_FALSE(morok::passes::stackDeltaGamesFunction(*F, params, rng));
    CHECK(F->size() == before);
    CHECK(countGlobals(*M, "morok.stackdelta.seed") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stackDeltaGamesFunction emits a dynamic frame with a volatile "
          "seed load and stack guard") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);

    morok::passes::StackDeltaParams params;
    params.probability = 100;
    params.max_blocks = 6;

    auto rng = makeRng();
    CHECK(morok::passes::stackDeltaGamesFunction(*F, params, rng));

    // Exactly one transform on a single eligible block.
    CHECK(countNamedAllocas(*F, "morok.stackdelta.frame") == 1);
    CHECK(countCallsToPrefix(*F, "llvm.stacksave") == 1);
    CHECK(countCallsToPrefix(*F, "llvm.stackrestore") == 1);

    // The frame is a variable-sized `alloca i8, N` (data-dependent size).
    AllocaInst *frame = nullptr;
    for (Instruction &I : instructions(*F))
        if (auto *AI = dyn_cast<AllocaInst>(&I))
            if (AI->getName().starts_with("morok.stackdelta.frame")) {
                frame = AI;
                break;
            }
    REQUIRE(frame != nullptr);
    CHECK(frame->isArrayAllocation());
    CHECK(frame->getAllocatedType()->isIntegerTy(8));
    CHECK(dyn_cast<ConstantInt>(frame->getArraySize()) == nullptr);

    // The seed is read through a volatile load.
    auto *seedLoad = dyn_cast_or_null<LoadInst>(
        findNamedInstruction(*F, "morok.stackdelta.seed.load"));
    REQUIRE(seedLoad != nullptr);
    CHECK(seedLoad->isVolatile());

    // The first overlapping store lands one byte into the frame.
    CHECK(namedGepByteOffset(*F, "morok.stackdelta.overlap.i64") == 1);
}

TEST_CASE("stackDeltaGamesFunction honors the touches count with volatile "
          "stores") {
    LLVMContext ctx;

    // touches=N yields N byte stores plus one overlap store, all volatile.
    {
        auto M = parse(ctx, kArith);
        Function *F = M->getFunction("arith");
        REQUIRE(F);
        morok::passes::StackDeltaParams params;
        params.probability = 100;
        params.max_blocks = 6;
        params.touches = 4;
        auto rng = makeRng();
        CHECK(morok::passes::stackDeltaGamesFunction(*F, params, rng));

        std::size_t stores = 0;
        std::size_t volatileStores = 0;
        for (Instruction &I : instructions(*F))
            if (auto *SI = dyn_cast<StoreInst>(&I)) {
                ++stores;
                if (SI->isVolatile())
                    ++volatileStores;
            }
        CHECK(stores == static_cast<std::size_t>(params.touches) + 1);
        CHECK(volatileStores == stores);
        CHECK_FALSE(verifyModule(*M));
    }

    // touches=0 is clamped to at least one, so still >= 2 stores.
    {
        auto M = parse(ctx, kArith);
        Function *F = M->getFunction("arith");
        REQUIRE(F);
        morok::passes::StackDeltaParams params;
        params.probability = 100;
        params.max_blocks = 6;
        params.touches = 0;
        auto rng = makeRng();
        CHECK(morok::passes::stackDeltaGamesFunction(*F, params, rng));
        CHECK(countOpcode(*M, Instruction::Store) == 2);
        CHECK_FALSE(verifyModule(*M));
    }
}

TEST_CASE("stackDeltaGamesFunction normalizes min_bytes and masks with "
          "max_extra_bytes") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("arith");
    REQUIRE(F);

    morok::passes::StackDeltaParams params;
    params.probability = 100;
    params.max_blocks = 6;
    params.min_bytes = 20;        // even -> normalized up to 21 (odd)
    params.max_extra_bytes = 48;  // used as the AND mask on the mix

    auto rng = makeRng();
    CHECK(morok::passes::stackDeltaGamesFunction(*F, params, rng));

    // size = extra + normalizedMinBytes(20) == extra + 21.
    CHECK(instructionHasConstantOperand(
        findNamedInstruction(*F, "morok.stackdelta.size"), 21u));
    // extra = mix & max_extra_bytes == mix & 48.
    CHECK(instructionHasConstantOperand(
        findNamedInstruction(*F, "morok.stackdelta.extra"), 48u));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("stackDeltaGamesFunction caps transformed blocks at max_blocks") {
    LLVMContext ctx;

    auto Mcap = parse(ctx, kChain);
    Function *Fcap = Mcap->getFunction("chain");
    REQUIRE(Fcap);
    morok::passes::StackDeltaParams capped;
    capped.probability = 100;
    capped.max_blocks = 2;
    auto rngCap = makeRng();
    CHECK(morok::passes::stackDeltaGamesFunction(*Fcap, capped, rngCap));
    const std::size_t framesCapped =
        countNamedAllocas(*Fcap, "morok.stackdelta.frame");
    CHECK(framesCapped >= 1);
    CHECK(framesCapped <= capped.max_blocks);
    CHECK_FALSE(verifyModule(*Mcap));

    // With a higher cap the same input transforms strictly more blocks,
    // proving the cap is what bound the previous run.
    auto Mopen = parse(ctx, kChain);
    Function *Fopen = Mopen->getFunction("chain");
    REQUIRE(Fopen);
    morok::passes::StackDeltaParams open;
    open.probability = 100;
    open.max_blocks = 6;
    auto rngOpen = makeRng();
    CHECK(morok::passes::stackDeltaGamesFunction(*Fopen, open, rngOpen));
    const std::size_t framesOpen =
        countNamedAllocas(*Fopen, "morok.stackdelta.frame");
    CHECK(framesOpen > framesCapped);
    CHECK_FALSE(verifyModule(*Mopen));
}

TEST_CASE("stackDeltaGamesFunction is deterministic for a fixed seed") {
    LLVMContext ctxA;
    LLVMContext ctxB;
    auto MA = parse(ctxA, kArith);
    auto MB = parse(ctxB, kArith);

    auto engineA = morok::core::Xoshiro256pp::fromSeed(0xC0FFEEu);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0xC0FFEEu);
    morok::ir::IRRandom rngA(engineA);
    morok::ir::IRRandom rngB(engineB);

    morok::passes::StackDeltaParams params;
    params.probability = 100;
    params.max_blocks = 6;

    CHECK(morok::passes::stackDeltaGamesFunction(*MA->getFunction("arith"),
                                                 params, rngA));
    CHECK(morok::passes::stackDeltaGamesFunction(*MB->getFunction("arith"),
                                                 params, rngB));

    std::string textA;
    std::string textB;
    raw_string_ostream osA(textA);
    raw_string_ostream osB(textB);
    MA->print(osA, nullptr);
    MB->print(osB, nullptr);
    osA.flush();
    osB.flush();

    CHECK(textA == textB);
    CHECK_FALSE(verifyModule(*MA));
    CHECK_FALSE(verifyModule(*MB));
}
