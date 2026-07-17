// SPDX-License-Identifier: MIT

#include "doctest.h"

#include "TestHelpers.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/NativeCodePack.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Verifier.h"

using namespace llvm;
using namespace morok;

TEST_CASE("native pack moves bodies behind lazy ABI stubs") {
    LLVMContext C;
    auto M = test::parse(C, R"(
      target triple = "x86_64-unknown-linux-gnu"
      define i32 @secret(i32 %x) {
      entry:
        %a = add i32 %x, 1
        %b = xor i32 %a, 17
        %c = mul i32 %b, 3
        %d = sub i32 %c, 4
        ret i32 %d
      }
      define i32 @caller(i32 %x) {
      entry:
        %r = call i32 @secret(i32 %x)
        ret i32 %r
      }
    )");

    passes::NativeCodePackParams P;
    P.min_instructions = 4;
    P.max_functions = 1;
    core::Xoshiro256pp Engine = core::Xoshiro256pp::fromSeed(91);
    ir::IRRandom Rng(Engine);
    REQUIRE(passes::nativeCodePackModule(*M, P, Rng));
    CHECK_FALSE(verifyModule(*M, &errs()));

    Function *Stub = M->getFunction("secret");
    REQUIRE(Stub != nullptr);
    CHECK(Stub->getSection() == ".text.morok.npack.stub");
    CHECK(Stub->hasFnAttribute(Attribute::NoInline));

    Function *Body = nullptr;
    for (Function &F : *M)
        if (F.getSection() == ".morok.npack.text")
            Body = &F;
    REQUIRE(Body != nullptr);
    CHECK(Body->hasPrivateLinkage());
    CHECK(Body->hasFnAttribute(Attribute::NoInline));

    Function *Open = M->getFunction("__morok_npack_open");
    REQUIRE(Open != nullptr);
    CHECK(Open->isDeclaration());
    CHECK(Open->getVisibility() == GlobalValue::HiddenVisibility);

    bool StubCallsOpen = false;
    bool StubCallsBody = false;
    for (Instruction &I : instructions(*Stub))
        if (auto *CI = dyn_cast<CallInst>(&I)) {
            Value *Callee = CI->getCalledOperand()->stripPointerCasts();
            StubCallsOpen |= Callee == Open;
            StubCallsBody |= Callee == Body;
        }
    CHECK(StubCallsOpen);
    CHECK(StubCallsBody);

    Function *Caller = M->getFunction("caller");
    REQUIRE(Caller != nullptr);
    bool CallerUsesStub = false;
    for (Instruction &I : instructions(*Caller))
        if (auto *CI = dyn_cast<CallInst>(&I))
            CallerUsesStub |=
                CI->getCalledOperand()->stripPointerCasts() == Stub;
    CHECK(CallerUsesStub);
}

TEST_CASE("native pack excludes constructors and unsupported targets") {
    LLVMContext C;
    auto M = test::parse(C, R"(
      target triple = "x86_64-unknown-linux-gnu"
      @llvm.global_ctors = appending global [1 x { i32, ptr, ptr }]
        [{ i32, ptr, ptr } { i32 0, ptr @early, ptr null }]
      define void @early() {
      entry:
        %a = add i32 1, 2
        %b = add i32 %a, 3
        %c = add i32 %b, 4
        ret void
      }
    )");
    passes::NativeCodePackParams P;
    P.min_instructions = 1;
    core::Xoshiro256pp Engine = core::Xoshiro256pp::fromSeed(7);
    ir::IRRandom Rng(Engine);
    CHECK_FALSE(passes::nativeCodePackModule(*M, P, Rng));
    CHECK(M->getFunction("early") != nullptr);
    CHECK(M->getFunction("__morok_npack_open") == nullptr);
}

TEST_CASE("native pack annotation overrides the instruction threshold") {
    LLVMContext C;
    auto M = test::parse(C, R"(
      target triple = "aarch64-unknown-linux-gnu"
      define i32 @tiny(i32 %x) !morok.obf !0 {
      entry:
        ret i32 %x
      }
      !0 = !{!"nativepack"}
    )");
    passes::NativeCodePackParams P;
    P.min_instructions = 100;
    core::Xoshiro256pp Engine = core::Xoshiro256pp::fromSeed(8);
    ir::IRRandom Rng(Engine);
    CHECK(passes::nativeCodePackModule(*M, P, Rng));
    CHECK_FALSE(verifyModule(*M, &errs()));
    CHECK(M->getFunction("tiny")->getSection() ==
          ".text.morok.npack.stub");
}

TEST_CASE("native pack preserves COMDAT on the public ODR stub") {
    LLVMContext C;
    auto M = test::parse(C, R"(
      target triple = "x86_64-unknown-linux-gnu"
      $shared = comdat any
      define linkonce_odr i32 @shared(i32 %x) comdat($shared) {
      entry:
        %a = add i32 %x, 1
        %b = xor i32 %a, 17
        ret i32 %b
      }
    )");
    passes::NativeCodePackParams P;
    P.min_instructions = 1;
    core::Xoshiro256pp Engine = core::Xoshiro256pp::fromSeed(12);
    ir::IRRandom Rng(Engine);
    REQUIRE(passes::nativeCodePackModule(*M, P, Rng));
    CHECK_FALSE(verifyModule(*M, &errs()));

    Function *Stub = M->getFunction("shared");
    REQUIRE(Stub != nullptr);
    REQUIRE(Stub->hasComdat());
    CHECK(Stub->getComdat()->getName() == "shared");
    for (Function &F : *M)
        if (F.getSection() == ".morok.npack.text")
            CHECK_FALSE(F.hasComdat());
}
