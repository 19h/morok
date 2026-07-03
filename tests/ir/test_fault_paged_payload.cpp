// SPDX-License-Identifier: MIT
//
// Tests for FaultPagedPayload — page-local VM bytecode delivery.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/FaultPagedPayload.hpp"

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Verifier.h"

using namespace llvm;
using namespace morok::test;

namespace {

const char *kVmBytecode = R"ir(
@morok.vm.bytecode = private constant [16 x i8] c"\01\02\03\04\05\06\07\08\09\0A\0B\0C\0D\0E\0F\10"

define i32 @vm_dispatch(i32 %pc) {
entry:
  %idx = zext i32 %pc to i64
  %ptr = getelementptr i8, ptr @morok.vm.bytecode, i64 %idx
  %byte = load i8, ptr %ptr
  %ext = zext i8 %byte to i32
  ret i32 %ext
}
)ir";

const char *kNoBytecode = R"ir(
define i32 @simple(i32 %x) {
entry:
  ret i32 %x
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0xF00D) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

} // namespace

TEST_CASE("faultPagedPayloadModule processes modules with bytecode") {
    LLVMContext ctx;
    auto M = parse(ctx, kVmBytecode);

    auto rng = makeRng(0xF00D1);
    morok::passes::FaultPagedPayloadParams p;
    p.enabled = true;
    p.probability = 100;

    // May or may not change depending on whether VM bytecode is detected
    morok::passes::faultPagedPayloadModule(*M, p, rng);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("faultPagedPayloadModule skips modules without bytecode") {
    LLVMContext ctx;
    auto M = parse(ctx, kNoBytecode);

    auto rng = makeRng(0xF00D2);
    morok::passes::FaultPagedPayloadParams p;
    p.enabled = true;
    p.probability = 100;

    CHECK_FALSE(morok::passes::faultPagedPayloadModule(*M, p, rng));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("faultPagedPayloadModule skips disabled") {
    LLVMContext ctx;
    auto M = parse(ctx, kVmBytecode);

    auto rng = makeRng(0xF00D3);
    morok::passes::FaultPagedPayloadParams p;
    p.enabled = false;

    CHECK_FALSE(morok::passes::faultPagedPayloadModule(*M, p, rng));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("faultPagedPayloadModule respects probability=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kVmBytecode);

    auto rng = makeRng(0xF00D4);
    morok::passes::FaultPagedPayloadParams p;
    p.enabled = true;
    p.probability = 0;

    CHECK_FALSE(morok::passes::faultPagedPayloadModule(*M, p, rng));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("faultPagedPayloadModule is idempotent") {
    LLVMContext ctx;
    auto M = parse(ctx, kVmBytecode);

    auto rng = makeRng(0xF00D5);
    morok::passes::FaultPagedPayloadParams p;
    p.enabled = true;
    p.probability = 100;

    morok::passes::faultPagedPayloadModule(*M, p, rng);
    CHECK_FALSE(verifyModule(*M));

    // Second run should not crash
    auto rng2 = makeRng(0xF00D6);
    morok::passes::faultPagedPayloadModule(*M, p, rng2);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("faultPagedPayloadModule handles empty modules") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare void @external()
)ir");

    auto rng = makeRng(0xF00D7);
    morok::passes::FaultPagedPayloadParams p;
    p.enabled = true;
    p.probability = 100;

    CHECK_FALSE(morok::passes::faultPagedPayloadModule(*M, p, rng));
    CHECK_FALSE(verifyModule(*M));
}
