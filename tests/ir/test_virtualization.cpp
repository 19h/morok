// SPDX-License-Identifier: MIT
//
// Tests for Virtualization — per-function bytecode VM lifting (threaded
// computed-goto interpreter over an encrypted per-function bytecode stream).

#include "TestHelpers.hpp"

#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/RuntimeSeal.hpp"
#include "morok/passes/Virtualization.hpp"

#include "llvm/IR/DerivedTypes.h"
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

// A small, straight-line integer kernel: eligible for lifting (scalar i32
// signature, no calls, no loop, supported terminator, all lift-able ops).
const char *kArith = R"ir(
define i32 @vm_target(i32 %a, i32 %b) {
entry:
  %x = add i32 %a, %b
  %y = xor i32 %x, 305419896
  %z = mul i32 %y, %a
  %w = sub i32 %z, %b
  ret i32 %w
}
)ir";

// Three independent eligible kernels, used to exercise the per-module cap.
const char *kThreeKernels = R"ir(
define i32 @round_a(i32 %a, i32 %b) {
entry:
  %x = add i32 %a, %b
  %y = xor i32 %x, 19088743
  ret i32 %y
}

define i32 @round_b(i32 %a, i32 %b) {
entry:
  %x = mul i32 %a, %b
  %y = sub i32 %x, %a
  ret i32 %y
}

define i32 @round_c(i32 %a, i32 %b) {
entry:
  %x = and i32 %a, %b
  %y = or i32 %x, %a
  ret i32 %y
}
)ir";

const char *kDeclaration = R"ir(
declare i32 @imported(i32)
)ir";

morok::ir::IRRandom makeRng(std::uint64_t seed = 0x1337) {
    static auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
    return morok::ir::IRRandom(engine);
}

// Shared lifting parameters: always fire (probability 100) with a budget large
// enough to fully lift the small kernels above.
morok::passes::VirtualizationParams liftParams(std::uint32_t maxFns = 1) {
    morok::passes::VirtualizationParams p;
    p.probability = 100;
    p.max_functions = maxFns;
    p.max_instructions = 64;
    p.max_registers = 64;
    return p;
}

// Render a whole module to text so two independent runs can be compared.
std::string renderModule(Module &M) {
    std::string text;
    raw_string_ostream os(text);
    M.print(os, nullptr);
    os.flush();
    return text;
}

} // namespace

TEST_CASE("virtualizeFunction grows the function and stays valid") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("vm_target");
    REQUIRE(F);

    const std::size_t fnsBefore = countFunctions(*M, "");
    const std::size_t globalsBefore = countGlobals(*M, "");

    auto rng = makeRng();
    const morok::passes::VirtualizationParams params = liftParams();
    CHECK(morok::passes::virtualizeFunction(*F, params, rng));

    // A private interpreter helper and its backing globals were materialized.
    CHECK(countFunctions(*M, "") > fnsBefore);
    CHECK(countGlobals(*M, "") > globalsBefore);
    CHECK(M->getFunction("morok.vm.vm_target.exec") != nullptr);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("virtualizeFunction respects probability=0 and max_functions=0") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("vm_target");
    REQUIRE(F);

    const std::size_t fnsBefore = countFunctions(*M, "");
    const std::size_t binopsBefore = countBinops(*F);

    // probability == 0: never fires, nothing changes.
    morok::passes::VirtualizationParams zeroProb = liftParams();
    zeroProb.probability = 0;
    auto rng0 = makeRng();
    CHECK_FALSE(morok::passes::virtualizeFunction(*F, zeroProb, rng0));

    // max_functions == 0: budget exhausted, never fires.
    morok::passes::VirtualizationParams zeroBudget = liftParams();
    zeroBudget.max_functions = 0;
    auto rng1 = makeRng();
    CHECK_FALSE(morok::passes::virtualizeFunction(*F, zeroBudget, rng1));

    CHECK(countFunctions(*M, "") == fnsBefore);
    CHECK(countBinops(*F) == binopsBefore);
    CHECK(M->getFunction("morok.vm.vm_target.exec") == nullptr);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("virtualizeFunction is a no-op on declarations") {
    LLVMContext ctx;
    auto M = parse(ctx, kDeclaration);
    Function *F = M->getFunction("imported");
    REQUIRE(F);

    auto rng = makeRng();
    const morok::passes::VirtualizationParams params = liftParams();
    // Declarations have no body to lift: no fire, no crash, still valid.
    CHECK_FALSE(morok::passes::virtualizeFunction(*F, params, rng));
    CHECK(F->isDeclaration());
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("virtualizeFunction is deterministic for a fixed seed") {
    auto render = [](std::uint64_t seed) {
        LLVMContext ctx;
        auto M = parse(ctx, kArith);
        Function *F = M->getFunction("vm_target");
        REQUIRE(F);
        auto engine = morok::core::Xoshiro256pp::fromSeed(seed);
        morok::ir::IRRandom rng(engine);
        const morok::passes::VirtualizationParams params = liftParams();
        CHECK(morok::passes::virtualizeFunction(*F, params, rng));
        CHECK_FALSE(verifyModule(*M));
        return renderModule(*M);
    };

    // Same seed + same input IR => byte-identical lifted module (handler
    // shuffle, encoding keys, and bytecode are all drawn from the seeded RNG).
    const std::string first = render(0x51ED);
    const std::string second = render(0x51ED);
    CHECK(first == second);
}

TEST_CASE("virtualizeFunction agrees with virtualizationWillLift") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("vm_target");
    REQUIRE(F);

    const morok::passes::VirtualizationParams params = liftParams();
    // The read-only predicate must agree with the lifter's decision on the
    // pristine function, before any mutation.
    CHECK(morok::passes::virtualizationWillLift(*F, params));

    // probability == 0 disables the predicate the same way it disables lifting.
    morok::passes::VirtualizationParams disabled = params;
    disabled.probability = 0;
    CHECK_FALSE(morok::passes::virtualizationWillLift(*F, disabled));

    // A declaration is never a lift candidate.
    auto DM = parse(ctx, kDeclaration);
    Function *Decl = DM->getFunction("imported");
    REQUIRE(Decl);
    CHECK_FALSE(morok::passes::virtualizationWillLift(*Decl, params));

    // The prediction holds: the eligible function actually fires.
    auto rng = makeRng();
    CHECK(morok::passes::virtualizeFunction(*F, params, rng));
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("virtualizeFunction emits an encrypted threaded bytecode VM") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("vm_target");
    REQUIRE(F);

    auto rng = makeRng();
    const morok::passes::VirtualizationParams params = liftParams();
    CHECK(morok::passes::virtualizeFunction(*F, params, rng));

    Function *Helper = M->getFunction("morok.vm.vm_target.exec");
    REQUIRE(Helper);

    // The three backing globals, each named after the source function.
    CHECK(countGlobals(*M, "morok.vm.bytecode.vm_target") == 1u);
    CHECK(countGlobals(*M, "morok.vm.targets.vm_target") == 1u);
    // Record integrity metadata is embedded in bytes 12..15 of every encrypted
    // instruction; there is no separately decodable opcode shadow table.
    CHECK(countGlobals(*M, "morok.vm.opguard.vm_target") == 0u);

    // The dispatch table is a fixed 256-slot blockaddress array.
    GlobalVariable *targets = nullptr;
    for (GlobalVariable &GV : M->globals())
        if (GV.getName().starts_with("morok.vm.targets"))
            targets = &GV;
    REQUIRE(targets != nullptr);
    auto *arrTy = dyn_cast<ArrayType>(targets->getValueType());
    REQUIRE(arrTy != nullptr);
    CHECK(arrTy->getNumElements() == 256u);

    // The bytecode is a private constant byte blob (not readable plaintext).
    GlobalVariable *bytecode = nullptr;
    for (GlobalVariable &GV : M->globals())
        if (GV.getName().starts_with("morok.vm.bytecode"))
            bytecode = &GV;
    REQUIRE(bytecode != nullptr);
    CHECK(bytecode->isConstant());
    CHECK(bytecode->hasPrivateLinkage());
    CHECK(dyn_cast<ConstantDataArray>(bytecode->getInitializer()) != nullptr);

    // The helper dispatches through a computed goto and carries the poison and
    // duplicated-arithmetic handler blocks.
    std::size_t indirectBranches = 0;
    std::size_t addHandlers = 0;
    bool hasPoisonHandler = false;
    for (BasicBlock &BB : *Helper) {
        if (BB.getName().starts_with("morok.vm.h.add"))
            ++addHandlers;
        if (BB.getName() == "morok.vm.h.poison")
            hasPoisonHandler = true;
        for (Instruction &I : BB)
            if (isa<IndirectBrInst>(&I))
                ++indirectBranches;
    }
    CHECK(indirectBranches == 1u);
    CHECK(addHandlers >= 2u);
    CHECK(hasPoisonHandler);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("virtualizeFunction rewrites the source into a native wrapper") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    Function *F = M->getFunction("vm_target");
    REQUIRE(F);
    REQUIRE(countBinops(*F) > 0u);

    auto rng = makeRng();
    const morok::passes::VirtualizationParams params = liftParams();
    CHECK(morok::passes::virtualizeFunction(*F, params, rng));

    // The native arithmetic is gone from the source; its body is now a single
    // tail-through call into the interpreter helper.
    CHECK(countBinops(*F) == 0u);
    CHECK(countCallsTo(*F, "morok.vm.vm_target.exec") == 1u);
    CHECK(F->size() == 1u);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("virtualizeModule lifts multiple functions up to max_functions") {
    LLVMContext ctx;
    auto M = parse(ctx, kThreeKernels);
    REQUIRE(M->getFunction("round_a"));
    REQUIRE(M->getFunction("round_b"));
    REQUIRE(M->getFunction("round_c"));

    auto rng = makeRng();
    const morok::passes::VirtualizationParams params = liftParams(/*maxFns=*/2);
    CHECK(morok::passes::virtualizeModule(*M, params, rng));

    // Exactly max_functions kernels are lifted, in module order; the cap is a
    // hard clamp (one bytecode blob is emitted per lifted function).
    CHECK(countGlobals(*M, "morok.vm.bytecode.") == 2u);
    CHECK(M->getFunction("morok.vm.round_a.exec") != nullptr);
    CHECK(M->getFunction("morok.vm.round_b.exec") != nullptr);
    CHECK(M->getFunction("morok.vm.round_c.exec") == nullptr);
    CHECK_FALSE(verifyModule(*M));
}

TEST_CASE("virtualizeModule provisions the anti-debug seal channel") {
    LLVMContext ctx;
    auto M = parse(ctx, kArith);
    REQUIRE(M->getFunction("vm_target"));

    // Before lifting there is no seal root; the module lifter must create the
    // anti_debug channel so the keystream decode can fold it in.
    CHECK(morok::passes::runtime_seal::findChannel(
              *M, morok::passes::runtime_seal::kAntiDebugChannel) == nullptr);

    auto rng = makeRng();
    const morok::passes::VirtualizationParams params = liftParams();
    CHECK(morok::passes::virtualizeModule(*M, params, rng));

    CHECK(morok::passes::runtime_seal::findChannel(
              *M, morok::passes::runtime_seal::kAntiDebugChannel) != nullptr);
    CHECK(M->getFunction("morok.vm.vm_target.exec") != nullptr);
    CHECK_FALSE(verifyModule(*M));
}
