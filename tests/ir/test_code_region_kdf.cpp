// SPDX-License-Identifier: MIT
//
// Tests for CodeRegionKdf — post-link code-region hash provider.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/CodeRegionKdf.hpp"
#include "morok/passes/RuntimeSeal.hpp"
#include "morok/passes/SelfChecksumConstants.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Verifier.h"

using namespace llvm;
using namespace morok::test;

namespace {

const char *kSimpleModule = R"ir(
define i32 @foo(i32 %x) {
entry:
  %r = add i32 %x, 42
  ret i32 %r
}
)ir";

} // namespace

TEST_CASE("hashStep is deterministic") {
    // hashStep(H, Byte) should produce the same result for the same inputs.
    const std::uint64_t h0 = 0x123456789ABCDEF0ULL;
    const std::uint8_t b = 0x42;
    const auto r1 = morok::passes::code_region_kdf::hashStep(h0, b);
    const auto r2 = morok::passes::code_region_kdf::hashStep(h0, b);
    CHECK(r1 == r2);
}

TEST_CASE("hashStep produces different results for different bytes") {
    const std::uint64_t h0 = 0;
    const auto r0 = morok::passes::code_region_kdf::hashStep(h0, 0);
    const auto r1 = morok::passes::code_region_kdf::hashStep(h0, 1);
    CHECK(r0 != r1);
}

TEST_CASE("hashBytes is deterministic for same input") {
    const std::uint8_t data[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"
    const auto r1 =
        morok::passes::code_region_kdf::hashBytes(data, 0xDEADBEEF);
    const auto r2 =
        morok::passes::code_region_kdf::hashBytes(data, 0xDEADBEEF);
    CHECK(r1 == r2);
}

TEST_CASE("hashBytes changes with different seeds") {
    const std::uint8_t data[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F};
    const auto r1 = morok::passes::code_region_kdf::hashBytes(data, 1);
    const auto r2 = morok::passes::code_region_kdf::hashBytes(data, 2);
    CHECK(r1 != r2);
}

TEST_CASE("hashBytes changes with different data") {
    const std::uint8_t a[] = {0x00, 0x00, 0x00};
    const std::uint8_t b[] = {0x00, 0x00, 0x01};
    const auto r1 = morok::passes::code_region_kdf::hashBytes(a, 42);
    const auto r2 = morok::passes::code_region_kdf::hashBytes(b, 42);
    CHECK(r1 != r2);
}

TEST_CASE("hashBytes handles empty input") {
    // Should not crash; result is the seed-dependent initial state.
    (void)morok::passes::code_region_kdf::hashBytes({}, 0);
}

TEST_CASE("emitSealedCodeHash produces valid IR") {
    LLVMContext ctx;
    auto M = parse(ctx, kSimpleModule);
    Function *Target = M->getFunction("foo");
    REQUIRE(Target);

    // Create a minimal harness: entry → code_check → code_loop → exit
    Function *Harness = Function::Create(
        FunctionType::get(Type::getVoidTy(ctx), {}, false),
        GlobalValue::PrivateLinkage, "harness", M.get());
    BasicBlock *Entry = BasicBlock::Create(ctx, "entry", Harness);
    BasicBlock *CodeCheck = BasicBlock::Create(ctx, "code_check", Harness);
    BasicBlock *CodeLoop = BasicBlock::Create(ctx, "code_loop", Harness);
    BasicBlock *Exit = BasicBlock::Create(ctx, "exit", Harness);

    IRBuilder<> B(Entry);
    B.CreateBr(CodeCheck);

    // Create a code_size global (simulating post-link seal)
    auto *CodeSize = new GlobalVariable(
        *M, Type::getInt32Ty(ctx), false, GlobalValue::PrivateLinkage,
        ConstantInt::get(Type::getInt32Ty(ctx),
                         morok::passes::code_region_kdf::kUnsealedCodeSize),
        "morok.postlink.code_size");

    B.SetInsertPoint(CodeCheck);
    auto *Seed = ConstantInt::get(Type::getInt64Ty(ctx), 0x1234);
    auto *UnsealedVal = ConstantInt::get(Type::getInt64Ty(ctx), 0);

    auto result = morok::passes::code_region_kdf::emitSealedCodeHash(
        B, CodeCheck, CodeLoop, Exit, Target, CodeSize, Seed, UnsealedVal,
        "test.crkdf", "test.hash");

    CHECK(result.has_code != nullptr);
    CHECK(result.final_hash != nullptr);

    // Wire up the exit block
    B.SetInsertPoint(Exit);
    B.CreateRetVoid();

    CHECK_FALSE(verifyModule(*M));
}
