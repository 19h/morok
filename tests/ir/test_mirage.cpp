// SPDX-License-Identifier: MIT
//
// Tests for Mirage — counterfeit-computation substrate (real/fake candidate hub).

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/Mirage.hpp"
#include "morok/passes/RuntimeSeal.hpp"

#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include <string>

using namespace llvm;
using namespace morok::test;

namespace {

// A pure, single-block verdict-like function: iN return, scalar integer args,
// no side effects.  Eligible for Mirage once `sensitive_only` is relaxed.
const char *kVerdictFn = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @check(i32 %a, i32 %b) {
entry:
  %s = add i32 %a, %b
  %m = mul i32 %s, 7
  ret i32 %m
}
)ir";

// Two independently eligible verdict-like functions (for the cap test).
const char *kTwoVerdictFns = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @check1(i32 %a, i32 %b) {
entry:
  %s = add i32 %a, %b
  ret i32 %s
}

define i32 @check2(i32 %a, i32 %b) {
entry:
  %x = xor i32 %a, %b
  ret i32 %x
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

// A permissive parameter set: transform any eligible function, not just those
// carrying a `sensitive`/`mirage` annotation.
morok::passes::MirageParams openParams() {
    morok::passes::MirageParams p;
    p.sensitive_only = false;
    return p;
}

} // namespace

TEST_CASE("mirageModule grows the candidate population and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kVerdictFn);

    const std::size_t before = countFunctions(*M, "");

    auto rng = makeRng(0xA101);
    auto p = openParams();
    p.clone_count = 2;
    p.counterfeit_count = 2;

    CHECK(morok::passes::mirageModule(*M, p, rng));

    // Population grew: original F is now a hub plus real clones, counterfeits,
    // and a private selection helper.
    CHECK(countFunctions(*M, "") > before);

    // Two real clones and two counterfeits with the documented __mirage names.
    CHECK(countFunctions(*M, "check.__mirage.real") == 2u);
    CHECK(countFunctions(*M, "check.__mirage.fake") == 2u);
    CHECK(M->getFunction("check.__mirage.real0") != nullptr);
    CHECK(M->getFunction("check.__mirage.real1") != nullptr);

    // Candidate table + counterfeit mixing tables + per-hub epoch globals.
    CHECK(M->getNamedGlobal("check.__mirage.table") != nullptr);
    CHECK(M->getNamedGlobal("check.__mirage.epoch") != nullptr);
    CHECK(countGlobals(*M, "check.__mirage.fake") == 2u); // fake0.tbl, fake1.tbl

    // The private selection helper lives under a skipped morok.* name.
    Function *Sel = M->getFunction("morok.mirage.sel.check");
    REQUIRE(Sel != nullptr);

    // The hub forwards through the selection helper exactly once (the second
    // call in the hub is the indirect dispatch through the loaded pointer).
    Function *Hub = M->getFunction("check");
    REQUIRE(Hub != nullptr);
    CHECK(countCallsTo(*Hub, "morok.mirage.sel.check") == 1u);

    // Candidates never reach the object symbol table.
    CHECK(M->getFunction("check.__mirage.real0")->hasPrivateLinkage());
    CHECK(M->getNamedGlobal("check.__mirage.table")->hasPrivateLinkage());

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mirageModule leaves unannotated functions untouched under sensitive_only") {
    LLVMContext ctx;
    auto M = parse(ctx, kVerdictFn);

    const std::size_t before = countFunctions(*M, "");

    auto rng = makeRng(0xA102);
    morok::passes::MirageParams p; // default: sensitive_only = true

    // The lone function carries no `sensitive`/`mirage` annotation, so nothing
    // is eligible and the module is unchanged.
    CHECK_FALSE(morok::passes::mirageModule(*M, p, rng));
    CHECK(countFunctions(*M, "") == before);
    CHECK(countFunctions(*M, "check.__mirage.real") == 0u);
    CHECK(M->getFunction("morok.mirage.sel.check") == nullptr);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mirageModule is safe on declarations and non-integer returns") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare i32 @ext(i32)

define void @noop() {
entry:
  ret void
}
)ir");

    auto rng = makeRng(0xA103);
    auto p = openParams(); // even permissive, neither target is eligible

    // A declaration cannot be cloned and a void return is out of scope; the pass
    // must decline both without crashing.
    CHECK_FALSE(morok::passes::mirageModule(*M, p, rng));
    CHECK(countFunctions(*M, "morok.mirage.sel.") == 0u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mirageModule is deterministic for a fixed seed and input") {
    LLVMContext ctx1;
    LLVMContext ctx2;
    auto M1 = parse(ctx1, kVerdictFn);
    auto M2 = parse(ctx2, kVerdictFn);

    // Two independent engines from the same seed produce identical streams,
    // unlike the shared-static makeRng, so the emitted IR must match verbatim.
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0xBADC0DEULL);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0xBADC0DEULL);
    morok::ir::IRRandom rngA(engineA);
    morok::ir::IRRandom rngB(engineB);

    auto p = openParams();
    CHECK(morok::passes::mirageModule(*M1, p, rngA));
    CHECK(morok::passes::mirageModule(*M2, p, rngB));

    std::string out1;
    std::string out2;
    raw_string_ostream os1(out1);
    raw_string_ostream os2(out2);
    M1->print(os1, nullptr);
    M2->print(os2, nullptr);

    CHECK(os1.str() == os2.str());
    CHECK_FALSE(verifyModule(*M1));
    CHECK_FALSE(verifyModule(*M2));
}

TEST_CASE("mirageModule with force_route Real pins the real path and emits no seal machinery") {
    LLVMContext ctx;
    auto M = parse(ctx, kVerdictFn);

    auto rng = makeRng(0xA104);
    auto p = openParams();
    p.clone_count = 2;
    p.counterfeit_count = 2;
    p.force_route = morok::passes::MirageForceRoute::Real;

    CHECK(morok::passes::mirageModule(*M, p, rng));

    // Real routing skips the seal-delta / KDF path entirely, so no runtime seal
    // channels are ever materialized.
    using namespace morok::passes::runtime_seal;
    CHECK(findChannel(*M, kAntiDebugChannel) == nullptr);
    CHECK(findChannel(*M, kEnvBindingChannel) == nullptr);
    CHECK(findChannel(*M, kTracerChannel) == nullptr);

    // Counterfeits are still emitted as candidates even though the router never
    // reaches them.
    CHECK(countFunctions(*M, "check.__mirage.fake") == 2u);

    // No dirty-state test and no counterfeit-index arithmetic in the selector.
    Function *Sel = M->getFunction("morok.mirage.sel.check");
    REQUIRE(Sel != nullptr);
    CHECK(findNamedInstruction(*Sel, "mirage.dirty") == nullptr);
    CHECK(findNamedInstruction(*Sel, "mirage.idx") == nullptr);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mirageModule with force_route Fake pins the counterfeit index") {
    LLVMContext ctx;
    auto M = parse(ctx, kVerdictFn);

    auto rng = makeRng(0xA105);
    auto p = openParams();
    p.clone_count = 2;
    p.counterfeit_count = 2;
    p.force_route = morok::passes::MirageForceRoute::Fake;

    CHECK(morok::passes::mirageModule(*M, p, rng));

    Function *Sel = M->getFunction("morok.mirage.sel.check");
    REQUIRE(Sel != nullptr);

    // The Fake route pins the index to CloneCount + (pick % FakeCount): a plain
    // add named `mirage.idx` whose base operand is the clone count constant.
    Instruction *Idx = findNamedInstruction(*Sel, "mirage.idx");
    REQUIRE(Idx != nullptr);
    CHECK(isa<BinaryOperator>(Idx));
    CHECK(Idx->getOpcode() == Instruction::Add);
    CHECK(instructionHasConstantOperand(Idx, 2)); // CloneCount == 2

    // No seal-gated dirty-state select on the pinned counterfeit path.
    CHECK(findNamedInstruction(*Sel, "mirage.dirty") == nullptr);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mirageModule seal-gated routing wires the runtime seal channels") {
    LLVMContext ctx;
    auto M = parse(ctx, kVerdictFn);

    auto rng = makeRng(0xA106);
    auto p = openParams();
    p.clone_count = 2;
    p.counterfeit_count = 2;
    p.seal_gated_reality = true;
    p.force_route = morok::passes::MirageForceRoute::Auto;

    CHECK(morok::passes::mirageModule(*M, p, rng));

    // The default (Auto + seal_gated) route folds the anti-debug / env / tracer
    // seal channels into the routing key.
    using namespace morok::passes::runtime_seal;
    CHECK(findChannel(*M, kAntiDebugChannel) != nullptr);
    CHECK(findChannel(*M, kEnvBindingChannel) != nullptr);
    CHECK(findChannel(*M, kTracerChannel) != nullptr);

    // The selector branches on a dirty-state test and picks via a select.
    Function *Sel = M->getFunction("morok.mirage.sel.check");
    REQUIRE(Sel != nullptr);
    CHECK(findNamedInstruction(*Sel, "mirage.dirty") != nullptr);
    Instruction *Idx = findNamedInstruction(*Sel, "mirage.idx");
    REQUIRE(Idx != nullptr);
    CHECK(isa<SelectInst>(Idx));

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mirageModule respects the max_functions cap") {
    LLVMContext ctx;
    auto M = parse(ctx, kTwoVerdictFns);

    auto rng = makeRng(0xA107);
    auto p = openParams();
    p.max_functions = 1; // only one hub may be emitted

    CHECK(morok::passes::mirageModule(*M, p, rng));

    // Exactly one function was converted into a Mirage hub.
    CHECK(countFunctions(*M, "morok.mirage.sel.") == 1u);
    // The first eligible function (module order) is the one transformed.
    CHECK(countFunctions(*M, "check1.__mirage.real") == 2u);
    CHECK(countFunctions(*M, "check2.__mirage.real") == 0u);

    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("mirageModule with zero counterfeits emits only real clones") {
    LLVMContext ctx;
    auto M = parse(ctx, kVerdictFn);

    auto rng = makeRng(0xA108);
    auto p = openParams();
    p.clone_count = 2;
    p.counterfeit_count = 0;

    CHECK(morok::passes::mirageModule(*M, p, rng));

    // No counterfeit functions and no counterfeit mixing tables.
    CHECK(countFunctions(*M, "check.__mirage.fake") == 0u);
    CHECK(countGlobals(*M, "check.__mirage.fake") == 0u);

    // Real clones and the candidate table are still emitted.
    CHECK(countFunctions(*M, "check.__mirage.real") == 2u);
    CHECK(M->getNamedGlobal("check.__mirage.table") != nullptr);

    // With no counterfeits the seal-gated path is unreachable, so no seal
    // channels are created even under the default Auto route.
    CHECK(morok::passes::runtime_seal::findChannel(
              *M, morok::passes::runtime_seal::kAntiDebugChannel) == nullptr);

    CHECK_FALSE(verifyModule(*M));
}
