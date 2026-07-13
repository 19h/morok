// SPDX-License-Identifier: MIT
//
// Tests for Nanomites — replaces conditional branches with trap-mediated
// nanomites decoded by a SIGTRAP handler from an encrypted PC->target table.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/Nanomites.hpp"

#include "llvm/IR/BasicBlock.h"
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

// A license-gate shape: a conditional branch whose arms both return.  Such
// "decision" branches are always admitted as nanomite candidates regardless of
// block order.  The triple is pinned so the pass finds a supported layout and
// fires identically on every CI platform (Linux/macOS, x86_64/arm64).
const char *kGate = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @gate(i32 %x) {
entry:
  %c = icmp eq i32 %x, 42
  br i1 %c, label %ok, label %bad
ok:
  ret i32 1
bad:
  ret i32 0
}
)ir";

// Same gate but with no target triple: the pass cannot pick a nanomite layout
// and must decline (platform-neutral no-op).
const char *kGateNoTriple = R"ir(
define i32 @gate(i32 %x) {
entry:
  %c = icmp eq i32 %x, 42
  br i1 %c, label %ok, label %bad
ok:
  ret i32 1
bad:
  ret i32 0
}
)ir";

// Three independent functions, each with one decision branch — used to probe
// the max_sites budget cap.
const char *kThreeGates = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @a(i32 %x) {
entry:
  %c = icmp eq i32 %x, 1
  br i1 %c, label %t, label %f
t:
  ret i32 1
f:
  ret i32 0
}

define i32 @b(i32 %x) {
entry:
  %c = icmp eq i32 %x, 2
  br i1 %c, label %t, label %f
t:
  ret i32 1
f:
  ret i32 0
}

define i32 @c(i32 %x) {
entry:
  %c = icmp eq i32 %x, 3
  br i1 %c, label %t, label %f
t:
  ret i32 1
f:
  ret i32 0
}
)ir";

// A declaration plus a branchless function: no eligible branches exist, so the
// pass must decline without crashing.
const char *kBranchless = R"ir(
target triple = "x86_64-unknown-linux-gnu"

declare void @ext()

define i32 @straight(i32 %x) {
entry:
  %y = add i32 %x, 7
  ret i32 %y
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

std::string moduleText(Module &M) {
    std::string text;
    raw_string_ostream os(text);
    M.print(os, nullptr);
    os.flush();
    return text;
}

bool hasBlockWithPrefix(Module &M, StringRef prefix) {
    for (Function &F : M)
        for (BasicBlock &BB : F)
            if (BB.getName().starts_with(prefix))
                return true;
    return false;
}

} // namespace

TEST_CASE("nanomitesModule grows the module and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kGate);

    const std::size_t fnsBefore = M->size();
    const std::size_t globalsBefore = countGlobals(*M, "morok.nanomite.");

    auto rng = makeRng(0x1001);
    morok::passes::NanomiteParams params;
    params.probability = 100; // chance(>=100) is always true -> guaranteed fire

    CHECK(morok::passes::nanomitesModule(*M, params, rng));

    // The pass added runtime functions (handler/install/sigaction) and state
    // globals, and it replaced a direct branch with a trap dispatch.
    CHECK(M->size() > fnsBefore);
    CHECK(countGlobals(*M, "morok.nanomite.") > globalsBefore);
    CHECK(countOpcode(*M, Instruction::IndirectBr) >= 1);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("nanomitesModule emits nanomite globals and runtime functions") {
    LLVMContext ctx;
    auto M = parse(ctx, kGate);

    auto rng = makeRng(0x2001);
    morok::passes::NanomiteParams params;
    params.probability = 100;

    REQUIRE(morok::passes::nanomitesModule(*M, params, rng));

    // decision + token + target + table state globals.
    CHECK(countGlobals(*M, "morok.nanomite.") == 4);
    // handler + install runtime functions.
    CHECK(countFunctions(*M, "morok.nanomite.") == 2);

    Function *handler = M->getFunction("morok.nanomite.handler");
    REQUIRE(handler != nullptr);
    CHECK(handler->hasPrivateLinkage());
    CHECK(handler->hasFnAttribute(Attribute::NoInline));

    Function *install = M->getFunction("morok.nanomite.install");
    REQUIRE(install != nullptr);
    CHECK(install->hasInternalLinkage());

    // The ctor is registered and the SIGTRAP handler is installed via sigaction.
    CHECK(M->getGlobalVariable("llvm.global_ctors", /*AllowInternal=*/true) !=
          nullptr);
    Function *sig = M->getFunction("sigaction");
    REQUIRE(sig != nullptr);
    CHECK(sig->isDeclaration());

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("nanomitesModule state globals are thread-local private") {
    LLVMContext ctx;
    auto M = parse(ctx, kGate);

    auto rng = makeRng(0x3001);
    morok::passes::NanomiteParams params;
    params.probability = 100;

    REQUIRE(morok::passes::nanomitesModule(*M, params, rng));

    for (const char *name :
         {"morok.nanomite.decision", "morok.nanomite.token",
          "morok.nanomite.target"}) {
        GlobalVariable *gv =
            M->getGlobalVariable(name, /*AllowInternal=*/true);
        REQUIRE(gv != nullptr);
        CHECK(gv->isThreadLocal());
        CHECK(gv->hasPrivateLinkage());
        CHECK_FALSE(gv->isConstant());
    }

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("nanomitesModule replaces the conditional branch with a trap dispatch") {
    LLVMContext ctx;
    auto M = parse(ctx, kGate);

    auto rng = makeRng(0x4001);
    morok::passes::NanomiteParams params;
    params.probability = 100;

    REQUIRE(morok::passes::nanomitesModule(*M, params, rng));

    // Exactly one site -> exactly one indirectbr fallback and a trap block.
    CHECK(countOpcode(*M, Instruction::IndirectBr) == 1);
    CHECK(hasBlockWithPrefix(*M, "morok.nanomite.trap"));
    CHECK(hasBlockWithPrefix(*M, "morok.nanomite.dispatch"));

    // The gate no longer terminates in a conditional branch — it was lowered
    // to volatile stores + trap.
    Function *gate = M->getFunction("gate");
    REQUIRE(gate != nullptr);
    BasicBlock &entry = gate->getEntryBlock();
    auto *term = dyn_cast<BranchInst>(entry.getTerminator());
    REQUIRE(term != nullptr);
    CHECK_FALSE(term->isConditional());

    // The encrypted PC->target table is an array-of-struct global.
    GlobalVariable *table =
        M->getGlobalVariable("morok.nanomite.table", /*AllowInternal=*/true);
    REQUIRE(table != nullptr);
    CHECK(table->getValueType()->isArrayTy());

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("nanomitesModule respects the max_sites cap") {
    LLVMContext ctx;
    auto M = parse(ctx, kThreeGates);

    auto rng = makeRng(0x5001);
    morok::passes::NanomiteParams params;
    params.probability = 100; // every candidate passes the chance gate
    params.max_sites = 2;     // ...but the budget only allows two sites

    REQUIRE(morok::passes::nanomitesModule(*M, params, rng));

    // One indirectbr fallback is emitted per lowered site, so the cap is
    // directly observable as the indirectbr count.
    CHECK(countOpcode(*M, Instruction::IndirectBr) == 2);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("nanomitesModule is a no-op when probability is zero") {
    LLVMContext ctx;
    auto M = parse(ctx, kGate);

    const std::string before = moduleText(*M);

    auto rng = makeRng(0x6001);
    morok::passes::NanomiteParams params;
    params.probability = 0; // disabled

    CHECK_FALSE(morok::passes::nanomitesModule(*M, params, rng));
    CHECK(countGlobals(*M, "morok.nanomite.") == 0);
    CHECK(countFunctions(*M, "morok.nanomite.") == 0);
    CHECK(moduleText(*M) == before); // truly unchanged
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("nanomitesModule is a no-op when max_sites is zero") {
    LLVMContext ctx;
    auto M = parse(ctx, kGate);

    const std::string before = moduleText(*M);

    auto rng = makeRng(0x7001);
    morok::passes::NanomiteParams params;
    params.max_sites = 0; // no budget

    CHECK_FALSE(morok::passes::nanomitesModule(*M, params, rng));
    CHECK(countGlobals(*M, "morok.nanomite.") == 0);
    CHECK(moduleText(*M) == before);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("nanomitesModule declines without a supported target triple") {
    LLVMContext ctx;
    auto M = parse(ctx, kGateNoTriple);

    const std::string before = moduleText(*M);

    auto rng = makeRng(0x8001);
    morok::passes::NanomiteParams params;
    params.probability = 100;

    // No triple -> no nanomite layout -> pass must decline, unchanged.
    CHECK_FALSE(morok::passes::nanomitesModule(*M, params, rng));
    CHECK(countGlobals(*M, "morok.nanomite.") == 0);
    CHECK(countFunctions(*M, "morok.nanomite.") == 0);
    CHECK(moduleText(*M) == before);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("nanomitesModule is safe on declarations and branchless functions") {
    LLVMContext ctx;
    auto M = parse(ctx, kBranchless);

    auto rng = makeRng(0x9001);
    morok::passes::NanomiteParams params;
    params.probability = 100;

    // No eligible conditional branch exists -> no candidates -> decline.
    CHECK_FALSE(morok::passes::nanomitesModule(*M, params, rng));
    CHECK(countOpcode(*M, Instruction::IndirectBr) == 0);
    CHECK_FALSE(verifyModule(*M));
}
