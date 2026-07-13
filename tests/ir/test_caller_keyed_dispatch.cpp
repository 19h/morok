// SPDX-License-Identifier: MIT
//
// Tests for CallerKeyedDispatch — rewrites direct internal call sites to a
// shared native dispatcher whose target is decoded from a caller-byte-keyed
// per-site hash and a sealed encoded delta.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/CallerKeyedDispatch.hpp"
#include "morok/passes/CodeRegionKdf.hpp"

#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;
using namespace morok::test;

namespace {

// A caller directly calling a defined internal callee.  An explicit x86_64
// triple is set so the pass reaches a supported arch on every CI host (the pass
// is inert without a supported target triple, so the assertion set stays
// platform-neutral).
const char *kCallerCallee = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define internal i32 @ckd_callee(i32 %x) {
entry:
  %y = add i32 %x, 1
  ret i32 %y
}

define i32 @ckd_caller(i32 %a) {
entry:
  %r = call i32 @ckd_callee(i32 %a)
  ret i32 %r
}
)ir";

// The same eligible call graph but WITHOUT a target triple: archOf() returns
// nullopt so the pass must decline.
const char *kCallerCalleeNoTriple = R"ir(
define internal i32 @ckd_callee(i32 %x) {
entry:
  %y = add i32 %x, 1
  ret i32 %y
}

define i32 @ckd_caller(i32 %a) {
entry:
  %r = call i32 @ckd_callee(i32 %a)
  ret i32 %r
}
)ir";

// A hub with eight independent direct call sites to one internal leaf.
const char *kEightCalls = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define internal i32 @ckd_leaf(i32 %x) {
entry:
  %y = mul i32 %x, 3
  ret i32 %y
}

define i32 @ckd_hub(i32 %a) {
entry:
  %r1 = call i32 @ckd_leaf(i32 %a)
  %r2 = call i32 @ckd_leaf(i32 %r1)
  %r3 = call i32 @ckd_leaf(i32 %r2)
  %r4 = call i32 @ckd_leaf(i32 %r3)
  %r5 = call i32 @ckd_leaf(i32 %r4)
  %r6 = call i32 @ckd_leaf(i32 %r5)
  %r7 = call i32 @ckd_leaf(i32 %r6)
  %r8 = call i32 @ckd_leaf(i32 %r7)
  ret i32 %r8
}
)ir";

// Declaration only: no defined caller/callee => nothing eligible.
const char *kDeclOnly = R"ir(
target triple = "x86_64-unknown-linux-gnu"

declare void @ckd_external()
)ir";

// A defined function with no calls at all.
const char *kLonely = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @ckd_lonely(i32 %x) {
entry:
  ret i32 %x
}
)ir";

// Direct self-recursion: caller == callee is intentionally left direct.
const char *kSelfRecursive = R"ir(
target triple = "x86_64-unknown-linux-gnu"

define i32 @ckd_rec(i32 %x) {
entry:
  %c = icmp eq i32 %x, 0
  br i1 %c, label %done, label %step
step:
  %n = sub i32 %x, 1
  %r = call i32 @ckd_rec(i32 %n)
  br label %done
done:
  %p = phi i32 [ 0, %entry ], [ %r, %step ]
  ret i32 %p
}
)ir";

// Callee is an external declaration: the carried jump target would have no
// defined body, so the site is ineligible.
const char *kExternalCallee = R"ir(
target triple = "x86_64-unknown-linux-gnu"

declare i32 @ckd_ext(i32)

define i32 @ckd_caller(i32 %a) {
entry:
  %r = call i32 @ckd_ext(i32 %a)
  ret i32 %r
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

std::string printModule(Module &M) {
    std::string text;
    raw_string_ostream os(text);
    M.print(os, nullptr);
    return os.str();
}

bool functionHasBlockPrefixed(Function &F, StringRef prefix) {
    for (BasicBlock &BB : F)
        if (BB.getName().starts_with(prefix))
            return true;
    return false;
}

bool globalInitEquals(Module &M, StringRef name, std::uint64_t expected) {
    auto *GV = M.getGlobalVariable(name, /*AllowInternal=*/true);
    if (!GV || !GV->hasInitializer())
        return false;
    auto *CI = dyn_cast<ConstantInt>(GV->getInitializer());
    return CI && CI->getZExtValue() == expected;
}

} // namespace

TEST_CASE("callerKeyedDispatchModule rewrites a direct call and grows the module") {
    LLVMContext ctx;
    auto M = parse(ctx, kCallerCallee);

    Function *Caller = M->getFunction("ckd_caller");
    REQUIRE(Caller != nullptr);
    const std::size_t functionsBefore = M->size();
    const std::size_t blocksBefore = Caller->size();

    auto rng = makeRng(0xC001);
    morok::passes::CallerKeyedDispatchParams p;

    CHECK(morok::passes::callerKeyedDispatchModule(*M, p, rng));
    // New dispatcher + init constructor lift the function count; the caller
    // block gains the cache hit/miss diamond.
    CHECK(M->size() > functionsBefore);
    CHECK(Caller->size() > blocksBefore);
    // Per-site enc/cache/code.size/seal.state slots (>= 4 for one site).
    CHECK(countGlobals(*M, "morok.ckd") >= 4);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("callerKeyedDispatchModule with disabled parameters is a no-op") {
    LLVMContext ctx;
    auto M = parse(ctx, kCallerCallee);

    auto rng = makeRng(0xC002);

    morok::passes::CallerKeyedDispatchParams zeroProb;
    zeroProb.probability = 0;
    CHECK_FALSE(morok::passes::callerKeyedDispatchModule(*M, zeroProb, rng));

    morok::passes::CallerKeyedDispatchParams zeroCalls;
    zeroCalls.max_calls = 0;
    CHECK_FALSE(morok::passes::callerKeyedDispatchModule(*M, zeroCalls, rng));

    morok::passes::CallerKeyedDispatchParams zeroRegion;
    zeroRegion.region_bytes = 0;
    CHECK_FALSE(morok::passes::callerKeyedDispatchModule(*M, zeroRegion, rng));

    // Nothing was emitted and the module is untouched.
    CHECK(countFunctions(*M, "morok.ckd") == 0);
    CHECK(countGlobals(*M, "morok.") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("callerKeyedDispatchModule is inert without a supported target triple") {
    LLVMContext ctx;
    auto M = parse(ctx, kCallerCalleeNoTriple);

    auto rng = makeRng(0xC003);
    morok::passes::CallerKeyedDispatchParams p;

    // archOf() rejects the empty/unknown triple even though the call is
    // otherwise eligible, so the pass declines and leaves the module valid.
    CHECK_FALSE(morok::passes::callerKeyedDispatchModule(*M, p, rng));
    CHECK(countFunctions(*M, "morok.ckd") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("callerKeyedDispatchModule leaves ineligible modules unchanged") {
    auto expectNoOp = [](const char *ir, std::uint64_t seed) {
        LLVMContext localCtx;
        auto localM = parse(localCtx, ir);
        auto localRng = makeRng(seed);
        morok::passes::CallerKeyedDispatchParams params;
        CHECK_FALSE(morok::passes::callerKeyedDispatchModule(*localM, params,
                                                             localRng));
        CHECK(countFunctions(*localM, "morok.ckd") == 0);
        CHECK_FALSE(verifyModule(*localM));
    };

    expectNoOp(kDeclOnly, 0xC010);       // no defined functions
    expectNoOp(kLonely, 0xC011);         // no call instructions
    expectNoOp(kSelfRecursive, 0xC012);  // caller == callee is excluded
    expectNoOp(kExternalCallee, 0xC013); // callee is a declaration
}

TEST_CASE("callerKeyedDispatchModule emits the dispatcher and routes the call") {
    LLVMContext ctx;
    auto M = parse(ctx, kCallerCallee);

    auto rng = makeRng(0xC004);
    morok::passes::CallerKeyedDispatchParams p; // carriers defaults to 1

    CHECK(morok::passes::callerKeyedDispatchModule(*M, p, rng));

    // carriers == 1 resolves to exactly the legacy default dispatcher; no
    // per-register variant is spun up.
    CHECK(countFunctions(*M, "morok.ckd.dispatch") == 1);
    CHECK(countFunctions(*M, "morok.ckd.init") == 1);

    Function *Dispatcher = M->getFunction("morok.ckd.dispatch");
    REQUIRE(Dispatcher != nullptr);
    CHECK(Dispatcher->hasFnAttribute(Attribute::Naked));
    CHECK(Dispatcher->hasInternalLinkage());

    Function *Caller = M->getFunction("ckd_caller");
    REQUIRE(Caller != nullptr);
    // The direct edge to the real callee is gone; the site now calls the
    // dispatcher instead.  The dispatched call reaches the naked dispatcher
    // through a signature-mismatched (callee-typed) call, so getCalledFunction()
    // reports it as indirect — match on the called *operand* being the
    // dispatcher rather than on a direct call edge.
    CHECK(countCallsTo(*Caller, "ckd_callee") == 0);
    CHECK(countCallsThroughOperand(*Caller, Dispatcher) == 1);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("callerKeyedDispatchModule emits per-site seal slots and a constant manifest") {
    LLVMContext ctx;
    auto M = parse(ctx, kCallerCallee);

    auto rng = makeRng(0xC005);
    morok::passes::CallerKeyedDispatchParams p;

    CHECK(morok::passes::callerKeyedDispatchModule(*M, p, rng));

    // One site => one of each per-site slot.
    CHECK(countGlobals(*M, "morok.ckd.enc") == 1);
    CHECK(countGlobals(*M, "morok.ckd.cache") == 1);
    CHECK(countGlobals(*M, "morok.ckd.code.size") == 1);
    CHECK(countGlobals(*M, "morok.ckd.seal.state") == 1);

    // The post-link manifest is a single read-only record table.
    CHECK(countGlobals(*M, "morok.postlink.ckd") == 1);
    auto *Manifest = M->getGlobalVariable("morok.postlink.ckd",
                                          /*AllowInternal=*/true);
    REQUIRE(Manifest != nullptr);
    CHECK(Manifest->isConstant());

    // The mutable code-size slot starts at the unsealed sentinel so unsealed
    // dev builds recompute in the constructor.
    CHECK(globalInitEquals(*M, "morok.ckd.code.size",
                           morok::passes::code_region_kdf::kUnsealedCodeSize));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("callerKeyedDispatchModule honors the max_calls cap") {
    LLVMContext ctx;
    auto M = parse(ctx, kEightCalls);

    auto rng = makeRng(0xC006);
    morok::passes::CallerKeyedDispatchParams p;
    p.max_calls = 1; // eight eligible sites available, but only one is routed

    CHECK(morok::passes::callerKeyedDispatchModule(*M, p, rng));

    // Exactly one site => one encoded slot and one manifest.
    CHECK(countGlobals(*M, "morok.ckd.enc") == 1);
    CHECK(countGlobals(*M, "morok.postlink.ckd") == 1);

    Function *Hub = M->getFunction("ckd_hub");
    REQUIRE(Hub != nullptr);
    Function *Dispatcher = M->getFunction("morok.ckd.dispatch");
    REQUIRE(Dispatcher != nullptr);
    // Seven direct calls survive; one was rewritten to the dispatcher (reached
    // through a signature-mismatched call, hence matched on the called operand).
    CHECK(countCallsTo(*Hub, "ckd_leaf") == 7);
    CHECK(countCallsThroughOperand(*Hub, Dispatcher) == 1);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("callerKeyedDispatchModule is deterministic for a fixed seed") {
    LLVMContext ctxA;
    LLVMContext ctxB;
    auto MA = parse(ctxA, kCallerCallee);
    auto MB = parse(ctxB, kCallerCallee);

    // Fresh independent engines with an identical seed: same input + same
    // randomness must yield byte-identical IR.
    auto engineA = morok::core::Xoshiro256pp::fromSeed(0xC0FFEE);
    auto engineB = morok::core::Xoshiro256pp::fromSeed(0xC0FFEE);
    morok::ir::IRRandom rngA(engineA);
    morok::ir::IRRandom rngB(engineB);

    morok::passes::CallerKeyedDispatchParams p;
    CHECK(morok::passes::callerKeyedDispatchModule(*MA, p, rngA));
    CHECK(morok::passes::callerKeyedDispatchModule(*MB, p, rngB));

    CHECK(printModule(*MA) == printModule(*MB));
    CHECK_FALSE(verifyModule(*MA));
    CHECK_FALSE(verifyModule(*MB));
}

TEST_CASE("callerKeyedDispatchModule seal_required drops the self-recovering fallback") {
    LLVMContext ctxUnsealed;
    auto MUnsealed = parse(ctxUnsealed, kCallerCallee);
    auto rngUnsealed = makeRng(0xC007);
    morok::passes::CallerKeyedDispatchParams unsealedParams;
    unsealedParams.seal_required = false;
    CHECK(morok::passes::callerKeyedDispatchModule(*MUnsealed, unsealedParams,
                                                   rngUnsealed));

    Function *InitUnsealed = MUnsealed->getFunction("morok.ckd.init");
    REQUIRE(InitUnsealed != nullptr);
    // Unsealed builds keep the live-byte recompute fallback path.
    CHECK(functionHasBlockPrefixed(*InitUnsealed, "morok.ckd.init.fallback"));
    CHECK(functionHasBlockPrefixed(*InitUnsealed, "morok.ckd.init.sealed"));
    CHECK_FALSE(verifyModule(*MUnsealed));

    LLVMContext ctxSealed;
    auto MSealed = parse(ctxSealed, kCallerCallee);
    auto rngSealed = makeRng(0xC008);
    morok::passes::CallerKeyedDispatchParams sealedParams;
    sealedParams.seal_required = true;
    CHECK(morok::passes::callerKeyedDispatchModule(*MSealed, sealedParams,
                                                   rngSealed));

    Function *InitSealed = MSealed->getFunction("morok.ckd.init");
    REQUIRE(InitSealed != nullptr);
    // Sealed-release mode makes the sealer the sole source of truth: no
    // fallback block, only the sealed store path.
    CHECK_FALSE(functionHasBlockPrefixed(*InitSealed, "morok.ckd.init.fallback"));
    CHECK(functionHasBlockPrefixed(*InitSealed, "morok.ckd.init.sealed"));
    CHECK_FALSE(verifyModule(*MSealed));
}

TEST_CASE("callerKeyedDispatchModule clamps carriers to the register pool") {
    LLVMContext ctx;
    auto M = parse(ctx, kEightCalls);

    auto rng = makeRng(0xC009);
    morok::passes::CallerKeyedDispatchParams p;
    p.carriers = 999; // far above any per-arch carrier pool

    CHECK(morok::passes::callerKeyedDispatchModule(*M, p, rng));

    // The x86_64 pool has four callee-saved carriers, so the number of distinct
    // dispatchers (counting the default plus any per-register variants) never
    // exceeds the pool size no matter how many carriers were requested.
    const std::size_t dispatchers = countFunctions(*M, "morok.ckd.dispatch");
    CHECK(dispatchers >= 1);
    CHECK(dispatchers <= 4);
    CHECK_FALSE(verifyModule(*M));
}
