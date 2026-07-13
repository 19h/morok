// SPDX-License-Identifier: MIT
//
// Tests for IndirectBranch — rewrite conditional branches and switches to
// `indirectbr` through a private, shuffled block-address table.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/IndirectBranch.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// A single conditional branch feeding two return-only successors: exactly one
// eligible terminator, two unique successors.
const char *kCondBranch = R"ir(
target triple = "x86_64-unknown-linux-gnu"
define i32 @cond(i32 %a, i32 %b) {
entry:
  %c = icmp slt i32 %a, %b
  br i1 %c, label %then, label %else
then:
  ret i32 %a
else:
  ret i32 %b
}
)ir";

// A switch with a default and three distinct case successors: one eligible
// terminator, four unique successors, three cases.
const char *kSwitch = R"ir(
target triple = "x86_64-unknown-linux-gnu"
define i32 @sw(i32 %x) {
entry:
  switch i32 %x, label %def [
    i32 1, label %a
    i32 2, label %b
    i32 3, label %c
  ]
def:
  ret i32 0
a:
  ret i32 1
b:
  ret i32 2
c:
  ret i32 3
}
)ir";

// No eligible terminators: a declaration, a trivial single-block return, and an
// unconditional-branch chain.
const char *kIneligible = R"ir(
target triple = "x86_64-unknown-linux-gnu"
declare i32 @ext(i32)

define i32 @trivial(i32 %x) {
entry:
  ret i32 %x
}

define void @uncond() {
entry:
  br label %next
next:
  ret void
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

// Build a switch whose case count is a parameter, so we can exercise the
// kMaxSwitchCases (256) guard. All cases fan into two blocks, keeping the block
// count small while inflating getNumCases().
std::string makeBigSwitchIR(unsigned numCases) {
    std::string s = "target triple = \"x86_64-unknown-linux-gnu\"\n"
                    "define i32 @bigsw(i32 %x) {\n"
                    "entry:\n"
                    "  switch i32 %x, label %def [\n";
    for (unsigned i = 0; i < numCases; ++i) {
        s += "    i32 ";
        s += std::to_string(i);
        s += ", label %";
        s += ((i % 2u) == 0u) ? "a" : "b";
        s += "\n";
    }
    s += "  ]\n"
         "def:\n  ret i32 -1\n"
         "a:\n  ret i32 1\n"
         "b:\n  ret i32 2\n"
         "}\n";
    return s;
}

std::string moduleText(Module &M) {
    std::string out;
    raw_string_ostream os(out);
    M.print(os, nullptr);
    os.flush();
    return out;
}

} // namespace

TEST_CASE("indirectBranchFunction rewrites a conditional branch to indirectbr "
          "and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kCondBranch);
    Function *F = M->getFunction("cond");
    REQUIRE(F);

    const std::size_t blocksBefore = F->size();
    REQUIRE(countGlobals(*M, "morok.ibtable") == 0u);
    REQUIRE(countOpcode(*M, Instruction::CondBr) == 1u);

    auto rng = makeRng();
    CHECK(morok::passes::indirectBranchFunction(*F, {/*prob=*/100}, rng));

    // The IR grew: a new private table global and an indirectbr appeared.
    CHECK(countGlobals(*M, "morok.ibtable") == 1u);
    CHECK(countOpcode(*M, Instruction::IndirectBr) == 1u);
    // The original direct branch is gone.
    CHECK(countOpcode(*M, Instruction::CondBr) == 0u);
    // The pass rewrites terminators in place, so block count is unchanged.
    CHECK(F->size() == blocksBefore);
    // The selector / table-load chain is emitted with the documented names.
    CHECK(findNamedInstruction(*F, "morok.indbr.index") != nullptr);
    CHECK(findNamedInstruction(*F, "morok.indbr.slot") != nullptr);
    CHECK(findNamedInstruction(*F, "morok.indbr.target") != nullptr);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("indirectBranchFunction emits a private blockaddress table") {
    LLVMContext ctx;
    auto M = parse(ctx, kCondBranch);
    Function *F = M->getFunction("cond");
    REQUIRE(F);

    auto rng = makeRng();
    REQUIRE(morok::passes::indirectBranchFunction(*F, {/*prob=*/100}, rng));

    GlobalVariable *table = M->getGlobalVariable("morok.ibtable", true);
    REQUIRE(table != nullptr);
    CHECK(table->isConstant());
    CHECK(table->hasPrivateLinkage());

    auto *arrTy = dyn_cast<ArrayType>(table->getValueType());
    REQUIRE(arrTy != nullptr);
    CHECK(arrTy->getElementType()->isPointerTy());
    // Two successors of the conditional branch => two slots.
    CHECK(arrTy->getNumElements() == 2u);

    // Every entry is a blockaddress constant.
    auto *init = dyn_cast<ConstantArray>(table->getInitializer());
    REQUIRE(init != nullptr);
    CHECK(init->getNumOperands() == 2u);
    for (unsigned i = 0; i < init->getNumOperands(); ++i)
        CHECK(isa<BlockAddress>(init->getOperand(i)));

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("indirectBranchFunction lowers a switch through per-case compares") {
    LLVMContext ctx;
    auto M = parse(ctx, kSwitch);
    Function *F = M->getFunction("sw");
    REQUIRE(F);
    REQUIRE(countOpcode(*M, Instruction::Switch) == 1u);

    auto rng = makeRng();
    CHECK(morok::passes::indirectBranchFunction(*F, {/*prob=*/100}, rng));

    // The switch is replaced by exactly one indirectbr.
    CHECK(countOpcode(*M, Instruction::Switch) == 0u);
    CHECK(countOpcode(*M, Instruction::IndirectBr) == 1u);
    // One icmp-eq is emitted per case value.
    CHECK(countNamedInstructions(*F, "morok.indbr.case") == 3u);

    // Table covers the default plus the three case successors.
    GlobalVariable *table = M->getGlobalVariable("morok.ibtable", true);
    REQUIRE(table != nullptr);
    auto *arrTy = dyn_cast<ArrayType>(table->getValueType());
    REQUIRE(arrTy != nullptr);
    CHECK(arrTy->getNumElements() == 4u);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("indirectBranchFunction respects probability=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kCondBranch);
    Function *F = M->getFunction("cond");
    REQUIRE(F);

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::indirectBranchFunction(*F, {/*prob=*/0}, rng));

    // Nothing was emitted and the direct branch remains.
    CHECK(countGlobals(*M, "morok.ibtable") == 0u);
    CHECK(countOpcode(*M, Instruction::IndirectBr) == 0u);
    CHECK(countOpcode(*M, Instruction::CondBr) == 1u);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("indirectBranchFunction is a no-op on ineligible terminators") {
    LLVMContext ctx;
    auto M = parse(ctx, kIneligible);

    Function *decl = M->getFunction("ext");
    Function *trivial = M->getFunction("trivial");
    Function *uncond = M->getFunction("uncond");
    REQUIRE(decl);
    REQUIRE(trivial);
    REQUIRE(uncond);

    auto rng = makeRng();
    // Declaration (no blocks), single-block return, and unconditional branch
    // all have no eligible terminator: no change, no crash.
    CHECK_FALSE(morok::passes::indirectBranchFunction(*decl, {/*prob=*/100}, rng));
    CHECK_FALSE(
        morok::passes::indirectBranchFunction(*trivial, {/*prob=*/100}, rng));
    CHECK_FALSE(
        morok::passes::indirectBranchFunction(*uncond, {/*prob=*/100}, rng));

    CHECK(countGlobals(*M, "morok.ibtable") == 0u);
    CHECK(countOpcode(*M, Instruction::IndirectBr) == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("indirectBranchFunction leaves oversized switches untouched") {
    LLVMContext ctx;
    // kMaxSwitchCases is 256; 257 cases must exceed the guard.
    const std::string ir = makeBigSwitchIR(257);
    auto M = parse(ctx, ir.c_str());
    Function *F = M->getFunction("bigsw");
    REQUIRE(F);

    auto rng = makeRng();
    CHECK_FALSE(morok::passes::indirectBranchFunction(*F, {/*prob=*/100}, rng));

    // The switch survives; no table and no indirectbr were produced.
    CHECK(countOpcode(*M, Instruction::Switch) == 1u);
    CHECK(countOpcode(*M, Instruction::IndirectBr) == 0u);
    CHECK(countGlobals(*M, "morok.ibtable") == 0u);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("indirectBranchFunction is deterministic for a fixed seed") {
    LLVMContext ctx;
    auto M1 = parse(ctx, kSwitch);
    auto M2 = parse(ctx, kSwitch);
    Function *F1 = M1->getFunction("sw");
    Function *F2 = M2->getFunction("sw");
    REQUIRE(F1);
    REQUIRE(F2);

    // Two independent engines seeded identically produce identical draws, so the
    // shuffled table order and emitted IR must match byte-for-byte.
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0x2024);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0x2024);
    morok::ir::IRRandom rngA(engineA);
    morok::ir::IRRandom rngB(engineB);

    CHECK(morok::passes::indirectBranchFunction(*F1, {/*prob=*/100}, rngA));
    CHECK(morok::passes::indirectBranchFunction(*F2, {/*prob=*/100}, rngB));

    CHECK(moduleText(*M1) == moduleText(*M2));
    CHECK_FALSE(verifyModule(*M1));
    CHECK_FALSE(verifyModule(*M2));
}
