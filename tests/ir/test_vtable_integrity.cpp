// SPDX-License-Identifier: MIT
//
// Tests for VTableIntegrity — Itanium C++ vptr/vtable-slot dispatch guard.

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/VTableIntegrity.hpp"

#include "llvm/IR/Constants.h"
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

// A realistic virtual dispatch: a `_ZTV` vtable (offset-to-top, RTTI, one slot),
// a runtime store of the vtable address point into the object's vptr storage
// (arms the tracked-slot table), then a load-vptr / load-slot / indirect-call
// chain that dispatches through it. The address point sits at byte offset 16
// (2 * pointer size) so both the stored-address-point and the conventional
// address-point detectors recognize it. Pinned to a 64-bit target so the byte
// offsets are platform-neutral.
const char *kGuardedModule = R"ir(
target datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

@_ZTI1A = external constant ptr
@_ZTV1A = constant [3 x ptr] [ptr null, ptr @_ZTI1A, ptr @_ZN1A3fooEv]

define void @_ZN1A3fooEv(ptr %this) {
entry:
  ret void
}

define void @use(ptr %obj) {
entry:
  store ptr getelementptr inbounds (i8, ptr @_ZTV1A, i64 16), ptr %obj
  %vptr = load ptr, ptr %obj
  %target = load ptr, ptr %vptr
  call void %target(ptr %obj)
  ret void
}
)ir";

// Same dispatch shape but with NO vptr store: the vtable is only recognized via
// the conventional address-point layout (func ptr at offset 16, non-func ptr at
// offset 8, a pointer entry at offset 0). Because nothing arms a tracked slot,
// the remember helper must NOT be emitted.
const char *kConventionalModule = R"ir(
target datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

@_ZTI1B = external constant ptr
@_ZTV1B = constant [3 x ptr] [ptr null, ptr @_ZTI1B, ptr @_ZN1B3barEv]

define void @_ZN1B3barEv(ptr %this) {
entry:
  ret void
}

define void @callBar(ptr %obj) {
entry:
  %vptr = load ptr, ptr %obj
  %target = load ptr, ptr %vptr
  call void %target(ptr %obj)
  ret void
}
)ir";

// No `_ZTV` global at all: nothing for the pass to guard.
const char *kNoVtableModule = R"ir(
define i32 @main(i32 %x) {
entry:
  ret i32 %x
}
)ir";

// A `_ZTV` vtable is present but no function performs a virtual dispatch, so the
// pass finds no sites to instrument.
const char *kVtableNoDispatchModule = R"ir(
target datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

@_ZTI1C = external constant ptr
@_ZTV1C = constant [3 x ptr] [ptr null, ptr @_ZTI1C, ptr @_ZN1C3bazEv]

define void @_ZN1C3bazEv(ptr %this) {
entry:
  ret void
}

define void @noDispatch() {
entry:
  ret void
}
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

} // namespace

TEST_CASE("vtableIntegrityModule guards a virtual dispatch and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kGuardedModule);
    REQUIRE_FALSE(verifyModule(*M)); // input is well-formed

    const std::size_t fnsBefore = countFunctions(*M, "");
    const std::size_t globalsBefore = countGlobals(*M, "");

    CHECK(morok::passes::vtableIntegrityModule(*M));

    // The pass adds a verifier (+ remember helper) and its constant tables.
    CHECK(countFunctions(*M, "") > fnsBefore);
    CHECK(countGlobals(*M, "") > globalsBefore);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("vtableIntegrityModule emits the verifier and tracked-slot table") {
    LLVMContext ctx;
    auto M = parse(ctx, kGuardedModule);

    CHECK(morok::passes::vtableIntegrityModule(*M));

    // The internal verifier function and its four constant lookup tables plus
    // the mutable tracked-slot table are all named under "morok.vti.".
    Function *verifyFn = M->getFunction("morok.vti.verify");
    REQUIRE(verifyFn != nullptr);
    CHECK(verifyFn->hasInternalLinkage());

    GlobalVariable *tracked =
        M->getGlobalVariable("morok.vti.tracked.slots", /*AllowInternal=*/true);
    REQUIRE(tracked != nullptr);
    CHECK_FALSE(tracked->isConstant());

    // vptrs + slots + targets + cookies + tracked.slots == 5 globals.
    CHECK(countGlobals(*M, "morok.vti.") == 5);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("vtableIntegrityModule instruments the vptr store with a remember call") {
    LLVMContext ctx;
    auto M = parse(ctx, kGuardedModule);

    CHECK(morok::passes::vtableIntegrityModule(*M));

    // The armed vptr store gets a morok.vti.remember call spliced in after it.
    Function *rememberFn = M->getFunction("morok.vti.remember");
    REQUIRE(rememberFn != nullptr);
    CHECK(rememberFn->hasInternalLinkage());

    Function *useFn = M->getFunction("use");
    REQUIRE(useFn != nullptr);
    CHECK(countCallsTo(*useFn, "morok.vti.remember") == 1);

    // verify + remember are the only morok.vti.* functions.
    CHECK(countFunctions(*M, "morok.vti.") == 2);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("vtableIntegrityModule inserts the verifier call before the dispatch") {
    LLVMContext ctx;
    auto M = parse(ctx, kGuardedModule);

    CHECK(morok::passes::vtableIntegrityModule(*M));

    Function *useFn = M->getFunction("use");
    REQUIRE(useFn != nullptr);
    // Exactly one dispatch site => exactly one verifier call inserted.
    CHECK(countCallsTo(*useFn, "morok.vti.verify") == 1);

    // The fail path traps, so the module must declare llvm.trap.
    CHECK(M->getFunction("llvm.trap") != nullptr);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("vtableIntegrityModule fires without a vptr store via conventional layout") {
    LLVMContext ctx;
    auto M = parse(ctx, kConventionalModule);
    REQUIRE_FALSE(verifyModule(*M));

    CHECK(morok::passes::vtableIntegrityModule(*M));

    // Still guards the dispatch...
    CHECK(M->getFunction("morok.vti.verify") != nullptr);
    // ...but with no armed store there is nothing to remember.
    CHECK(M->getFunction("morok.vti.remember") == nullptr);
    CHECK(countFunctions(*M, "morok.vti.") == 1);
    // Tracked-slot table + four verifier tables are still materialized.
    CHECK(countGlobals(*M, "morok.vti.") == 5);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("vtableIntegrityModule leaves a module without vtables unchanged") {
    LLVMContext ctx;
    auto M = parse(ctx, kNoVtableModule);

    CHECK_FALSE(morok::passes::vtableIntegrityModule(*M));
    CHECK(countFunctions(*M, "morok.vti.") == 0);
    CHECK(countGlobals(*M, "morok.vti.") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("vtableIntegrityModule leaves a vtable with no dispatch site unchanged") {
    LLVMContext ctx;
    auto M = parse(ctx, kVtableNoDispatchModule);

    // A vtable exists but no virtual call dispatches through it.
    CHECK_FALSE(morok::passes::vtableIntegrityModule(*M));
    CHECK(countFunctions(*M, "morok.vti.") == 0);
    CHECK(countGlobals(*M, "morok.vti.") == 0);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("vtableIntegrityModule is safe on declaration-only modules") {
    LLVMContext ctx;
    auto M = parse(ctx, R"ir(
declare void @external()
)ir");

    // No definitions, no vtables: must not crash and must not change anything.
    CHECK_FALSE(morok::passes::vtableIntegrityModule(*M));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("vtableIntegrityModule is deterministic for identical inputs") {
    LLVMContext ctx;
    auto M1 = parse(ctx, kGuardedModule);
    auto M2 = parse(ctx, kGuardedModule);

    CHECK(morok::passes::vtableIntegrityModule(*M1));
    CHECK(morok::passes::vtableIntegrityModule(*M2));

    std::string s1;
    std::string s2;
    raw_string_ostream os1(s1);
    raw_string_ostream os2(s2);
    M1->print(os1, nullptr);
    M2->print(os2, nullptr);
    os1.flush();
    os2.flush();

    // The pass carries no RNG; the same input must yield byte-identical IR.
    CHECK(s1 == s2);
    CHECK_FALSE(verifyModule(*M1));
    CHECK_FALSE(verifyModule(*M2));
}
