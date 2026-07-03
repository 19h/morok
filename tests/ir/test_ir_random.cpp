// SPDX-License-Identifier: MIT
//
// Tests for IRRandom — PRNG-to-LLVM-IR bridge.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/LLVMContext.h"

using namespace llvm;
using namespace morok::test;

TEST_CASE("IRRandom next() produces non-zero values") {
    auto engine = morok::core::Xoshiro256pp::fromSeed(42);
    morok::ir::IRRandom rng(engine);

    bool sawNonZero = false;
    for (int i = 0; i < 100; ++i)
        if (rng.next() != 0)
            sawNonZero = true;
    CHECK(sawNonZero);
}

TEST_CASE("IRRandom range() respects bounds") {
    auto engine = morok::core::Xoshiro256pp::fromSeed(43);
    morok::ir::IRRandom rng(engine);

    for (int i = 0; i < 1000; ++i) {
        CHECK(rng.range(10) < 10);
        CHECK(rng.range(100) < 100);
        CHECK(rng.range(1) == 0);
    }
}

TEST_CASE("IRRandom chance(0) always false, chance(100) always true") {
    auto engine = morok::core::Xoshiro256pp::fromSeed(44);
    morok::ir::IRRandom rng(engine);

    for (int i = 0; i < 100; ++i) {
        CHECK_FALSE(rng.chance(0));
        CHECK(rng.chance(100));
    }
}

TEST_CASE("IRRandom constInt produces correct type width") {
    LLVMContext ctx;
    auto engine = morok::core::Xoshiro256pp::fromSeed(45);
    morok::ir::IRRandom rng(engine);

    auto *I8 = Type::getInt8Ty(ctx);
    auto *I16 = Type::getInt16Ty(ctx);
    auto *I32 = Type::getInt32Ty(ctx);
    auto *I64 = Type::getInt64Ty(ctx);

    auto *C8 = rng.constInt(I8);
    auto *C16 = rng.constInt(I16);
    auto *C32 = rng.constInt(I32);
    auto *C64 = rng.constInt(I64);

    CHECK(C8->getType() == I8);
    CHECK(C16->getType() == I16);
    CHECK(C32->getType() == I32);
    CHECK(C64->getType() == I64);
}

TEST_CASE("IRRandom deterministic with same seed") {
    auto e1 = morok::core::Xoshiro256pp::fromSeed(46);
    auto e2 = morok::core::Xoshiro256pp::fromSeed(46);
    morok::ir::IRRandom r1(e1);
    morok::ir::IRRandom r2(e2);

    for (int i = 0; i < 100; ++i)
        CHECK(r1.next() == r2.next());
}

TEST_CASE("IRRandom engine() returns underlying engine") {
    auto engine = morok::core::Xoshiro256pp::fromSeed(47);
    morok::ir::IRRandom rng(engine);

    // engine() should return a reference to the same engine
    CHECK(&rng.engine() == &engine);
}
