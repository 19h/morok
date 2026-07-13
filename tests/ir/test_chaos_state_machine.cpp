// SPDX-License-Identifier: MIT
//
// Tests for ChaosStateMachine — nonlinear-state control-flow flattening whose
// dispatcher state is advanced through the logistic map or a T-function.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/ChaosStateMachine.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// A multi-block function with a conditional branch: the entry has two
// successors (so the flattener splits it), and `then`/`else` end in
// unconditional branches, so the CSM step callback fires on several blocks.
const char *kBranchy = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @branchy(i32 %a, i32 %b) {
entry:
  %c = icmp slt i32 %a, %b
  br i1 %c, label %then, label %else
then:
  %t = add i32 %a, 1
  br label %join
else:
  %e = sub i32 %b, 1
  br label %join
join:
  %p = phi i32 [ %t, %then ], [ %e, %else ]
  ret i32 %p
}
)ir";

// A function whose entry terminator is a switch, exercising the flattener's
// switch-to-ICmp routing path (and, hence, the multi-arm correction chain).
const char *kSwitchy = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @switchy(i32 %a, i32 %b, i32 %c) {
entry:
  switch i32 %a, label %default [i32 1, label %case1 i32 2, label %case2]
case1:
  %v1 = add i32 %b, 1
  br label %join
case2:
  %v2 = add i32 %c, 2
  br label %join
default:
  %v3 = add i32 %a, 3
  br label %join
join:
  %p = phi i32 [ %v1, %case1 ], [ %v2, %case2 ], [ %v3, %default ]
  ret i32 %p
}
)ir";

const char *kSingleBlock = R"ir(
define i32 @trivial(i32 %x) {
entry:
  %r = add i32 %x, 1
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

bool hasBlockNamed(Function &F, StringRef name) {
    for (BasicBlock &BB : F)
        if (BB.getName() == name)
            return true;
    return false;
}

std::string printModule(Module &M) {
    std::string text;
    raw_string_ostream os(text);
    M.print(os, nullptr);
    return os.str();
}

} // namespace

TEST_CASE("chaosStateMachineFunction flattens a multi-block function and stays "
          "valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kBranchy);
    Function *F = M->getFunction("branchy");
    REQUIRE(F);
    const std::size_t blocksBefore = F->size();
    const std::size_t binopsBefore = countBinops(*F);

    auto rng = makeRng();
    CHECK(morok::passes::chaosStateMachineFunction(*F, {}, rng));

    // The dispatcher wiring strictly grows the function.
    CHECK(F->size() > blocksBefore);
    CHECK(countBinops(*F) > binopsBefore);

    // Flattener backbone: a state slot, a single dispatch switch, its load.
    CHECK(countNamedAllocas(*F, "fla.state") >= 1u);
    CHECK(hasBlockNamed(*F, "fla.dispatch"));
    CHECK(countOpcode(*M, Instruction::Switch) == 1u);
    CHECK(countNamedInstructions(*F, "fla.cur") >= 1u);

    // CSM step: each rewritten block loads the state ("csm.cur") and telescopes
    // via a final XOR of the stepped value and the correction constant.
    CHECK(countNamedInstructions(*F, "csm.cur") >= 1u);
    CHECK(countOpcode(*M, Instruction::Xor) >= 1u);

    // Logistic (default) generator emits no T-function-named instructions.
    CHECK(countNamedInstructions(*F, "csm.tf") == 0u);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("chaosStateMachineFunction compatibility overload matches the "
          "logistic default") {
    LLVMContext ctx1;
    LLVMContext ctx2;
    auto M1 = parse(ctx1, kBranchy);
    auto M2 = parse(ctx2, kBranchy);
    Function *F1 = M1->getFunction("branchy");
    Function *F2 = M2->getFunction("branchy");
    REQUIRE(F1);
    REQUIRE(F2);

    // Independent engines from the same seed: the two-arg overload must produce
    // byte-identical IR to an explicit default-constructed CsmParams run.
    auto engine1 = morok::core::Xoshiro256pp::fromSeed(0x51ED);
    auto engine2 = morok::core::Xoshiro256pp::fromSeed(0x51ED);
    morok::ir::IRRandom rng1(engine1);
    morok::ir::IRRandom rng2(engine2);

    CHECK(morok::passes::chaosStateMachineFunction(*F1, rng1));
    CHECK(morok::passes::chaosStateMachineFunction(
        *F2, morok::passes::CsmParams{}, rng2));

    CHECK(printModule(*M1) == printModule(*M2));
    CHECK_FALSE(verifyModule(*M1));
    CHECK_FALSE(verifyModule(*M2));
}

TEST_CASE("chaosStateMachineFunction TFunction generator emits t-function step "
          "instructions") {
    LLVMContext ctx;
    auto M = parse(ctx, kBranchy);
    Function *F = M->getFunction("branchy");
    REQUIRE(F);

    const std::uint64_t tfConst = 5; // 5 mod 8 => valid single-cycle constant
    const morok::passes::CsmParams params{
        morok::passes::CsmGenerator::TFunction, tfConst};

    auto rng = makeRng();
    CHECK(morok::passes::chaosStateMachineFunction(*F, params, rng));

    // step(x) = x + (x*x | C): each rewritten block emits mul/or/next by name.
    CHECK(countNamedInstructions(*F, "csm.tf.mul") >= 1u);
    CHECK(countNamedInstructions(*F, "csm.tf.or") >= 1u);
    CHECK(countNamedInstructions(*F, "csm.tf.next") >= 1u);

    // The `| C` term carries the (valid) constant we supplied verbatim.
    Instruction *orI = findNamedInstruction(*F, "csm.tf.or");
    REQUIRE(orI);
    CHECK(instructionHasConstantOperand(orI, tfConst));

    // Still a flattened function: dispatch switch, telescoping XOR, valid IR.
    CHECK(countOpcode(*M, Instruction::Switch) == 1u);
    CHECK(countOpcode(*M, Instruction::Xor) >= 1u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("chaosStateMachineFunction routes switch terminators through the "
          "dispatcher") {
    LLVMContext ctx;
    auto M = parse(ctx, kSwitchy);
    Function *F = M->getFunction("switchy");
    REQUIRE(F);
    const std::size_t blocksBefore = F->size();

    auto rng = makeRng();
    CHECK(morok::passes::chaosStateMachineFunction(*F, {}, rng));

    CHECK(F->size() > blocksBefore);
    // The original multi-way switch is replaced by ICmp arms; the only switch
    // left is the dispatcher.
    CHECK(countOpcode(*M, Instruction::Switch) == 1u);
    CHECK(countOpcode(*M, Instruction::ICmp) >= 1u);
    // Multi-arm corrections are selected per taken edge.
    CHECK(countOpcode(*M, Instruction::Select) >= 1u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("chaosStateMachineFunction is a no-op on single-block functions") {
    LLVMContext ctx;
    auto M = parse(ctx, kSingleBlock);
    Function *F = M->getFunction("trivial");
    REQUIRE(F);
    const std::size_t before = F->size();

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::chaosStateMachineFunction(*F, {}, rng));
    CHECK(F->size() == before);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("chaosStateMachineFunction leaves declarations unchanged") {
    LLVMContext ctx;
    auto M = parse(ctx, kDecl);
    Function *F = M->getFunction("external");
    REQUIRE(F);

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::chaosStateMachineFunction(*F, {}, rng));
    CHECK(F->isDeclaration());
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("chaosStateMachineFunction is deterministic for a fixed seed") {
    LLVMContext ctxa;
    LLVMContext ctxb;
    auto Ma = parse(ctxa, kBranchy);
    auto Mb = parse(ctxb, kBranchy);
    Function *Fa = Ma->getFunction("branchy");
    Function *Fb = Mb->getFunction("branchy");
    REQUIRE(Fa);
    REQUIRE(Fb);

    auto enginea = morok::core::Xoshiro256pp::fromSeed(0xC0FFEE);
    auto engineb = morok::core::Xoshiro256pp::fromSeed(0xC0FFEE);
    morok::ir::IRRandom rnga(enginea);
    morok::ir::IRRandom rngb(engineb);
    const morok::passes::CsmParams params{
        morok::passes::CsmGenerator::TFunction};

    CHECK(morok::passes::chaosStateMachineFunction(*Fa, params, rnga));
    CHECK(morok::passes::chaosStateMachineFunction(*Fb, params, rngb));

    CHECK(printModule(*Ma) == printModule(*Mb));
    CHECK_FALSE(verifyModule(*Ma));
    CHECK_FALSE(verifyModule(*Mb));
}

TEST_CASE("chaosStateMachineFunction preserves original blocks while adding "
          "dispatcher blocks") {
    LLVMContext ctx;
    auto M = parse(ctx, kBranchy);
    Function *F = M->getFunction("branchy");
    REQUIRE(F);
    const std::size_t blocksBefore = F->size();

    auto rng = makeRng();
    CHECK(morok::passes::chaosStateMachineFunction(*F, {}, rng));

    // Dispatch, back-edge, and default blocks are all materialised, so at least
    // three blocks are added on top of the originals.
    CHECK(hasBlockNamed(*F, "fla.dispatch"));
    CHECK(hasBlockNamed(*F, "fla.backedge"));
    CHECK(hasBlockNamed(*F, "fla.default"));
    CHECK(F->size() >= blocksBefore + 3u);
    CHECK_FALSE(verifyModule(*M));
}
