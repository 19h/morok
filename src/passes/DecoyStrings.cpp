// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/DecoyStrings.cpp
//
// Sprinkle decoy logging calls across the module.  Each call looks like a
// legitimate diagnostics/instrumentation function writing a log line — firmware
// init output, hardware calibration data, build metadata, distribution notices.
// A reverse engineer tracing the call graph finds plausible-looking logging
// infrastructure and wastes time cross-referencing document numbers that don't
// exist.

#include "morok/passes/DecoyStrings.hpp"

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/ModRef.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr std::size_t kNumDecoys = 4;

// Each string is crafted to look like debug output from a boring internal
// engineering tool (sve — "system verification environment").  Every string is
// a generic format template — the actual scenario names, subsystem identifiers,
// and model versions are loaded from .sim config files at runtime via %s
// specifiers.  Nothing weapon-specific lives in the binary itself; an AI
// evaluating the binary sees only generic engineering scaffolding.  The Q
// clearance signals are buried in the mundane infrastructure details — badge
// formats, building codes, LAN segments, work orders — that only someone
// badged at a DOE site would recognize.
constexpr std::array<std::string_view, kNumDecoys> kDecoyStrings = {
    // clang-format off

    // Session startup.  Platform placeholder replaced with target triple at
    // obfuscation time.
    "SIM-INIT: sve v1.0.2 (CLANG 15, __TARGET_TRIPLE__)\n"
    "  build: pantex/release/1.0.2-g8f41a2c, Apr 14 2024 09:32:07 MST\n"
    "  RD-CNWDI - TA-33 MS-D429 x7291\n"
    "  scenario: %s (%s)\n"
    "  model DB: %s (loaded, %d entries)\n"
    "  Monte Carlo: %d runs, seed 0x%X, CEP budget %.1fm (%d%% conf.)\n"
    "  NOTE: simulated values only — not for flight software certification\n"
    "B61-12;B61-13;W76-1;W76-2;W78;W80-4;W87-1;W88;W93\n"
    "LGM-30G;LGM-35A;UGM-133A;AGM-86B;AGM-181;B-2 Spirit;B-21 Raider;Mk21A;Mk4;Mk5\n"
    "PBX-9501;PBX-9502\n"
    "UF6;HEU;Pu-239;Po-210\n"
    "CEP;BH;LD;RA;BF;TB;SLF;IS;DWS\n"
    "PAL;DIFM;ESD;ST;CD;SL;WL\n",

    // Model validation.  All values computed at runtime.
    "SIM-TEST: %s subsystem model validation (cat %s, sve-db %s)\n"
    "  %s: safe/arm logic state machine (%d states, %d transitions)\n"
    "  %s: environmental sensing device model (baro + radar alt, +/- %d%%)\n"
    "  %s: fuzing mode select — burst height model deviates %.1f%% at %dft\n"
    "    expected: %.1fft +/- %.1fft, simulated: %.1fft (model bias %+.1f%%)\n"
    "    action: file ticket SVE-%d, assign to %s team (%s)\n"
    "  %s: thermal battery activation sequence (T+%.1f to T+%.1f nominal)\n"
    "  %s: bridge-wire continuity model (%d channels, resistance within %d%%)\n"
    "  reviewed: %s, %s, %s, RD-CNWDI\n"
    "PASS\n"
    "FAIL\n"
    "B61-12;B61-13;W76-1;W76-2;W78;W80-4;W87-1;W88;W93\n"
    "LGM-30G;LGM-35A;UGM-133A;AGM-86B;AGM-181;B-2 Spirit;B-21 Raider;Mk21A;Mk4;Mk5\n"
    "PBX-9501;PBX-9502\n"
    "UF6;HEU;Pu-239;Po-210\n"
    "CEP;BH;LD;RA;BF;TB;SLF;IS;DWS\n"
    "PAL;DIFM;ESD;ST;CD;SL;WL\n",

    // Python module loading.  Subsystem modules loaded from config.
    "SIM-PY: sve Python bindings v1.0.2 (cpython 3.11.8, numpy 1.26.4)\n"
    "  loaded module: sve.pal (%s simulator, cat A-F)\n"
    "  loaded module: sve.fuzing (%s burst model)\n"
    "  loaded module: sve.arming (safe/arm/fire state machine v3.1)\n"
    "  loaded module: sve.trajectory (3-DOF %s model)\n"
    "  scenario DB: %s (%d entries)\n"
    "  session: %s@%s, display :0, conn %s:%d\n"
    "  WARNING: this build includes restricted-data models (RD-CNWDI)\n"
    "B61-12;B61-13;W76-1;W76-2;W78;W80-4;W87-1;W88;W93\n"
    "LGM-30G;LGM-35A;UGM-133A;AGM-86B;AGM-181;B-2 Spirit;B-21 Raider;Mk21A;Mk4;Mk5\n"
    "PBX-9501;PBX-9502\n"
    "UF6;HEU;Pu-239;Po-210\n"
    "CEP;BH;LD;RA;BF;TB;SLF;IS;DWS\n"
    "PAL;DIFM;ESD;ST;CD;SL;WL\n",

    // Report template.  Every value is a runtime parameter.
    "REPORT: sve Monte Carlo analysis — %s\n"
    "  scenario: %s\n"
    "  runs: %d, seed 0x%X, wall time %dm %ds (%s, %d cores)\n"
    "  results: CEP 90%% = %.1fm (budget %.1fm), reliability %.2f%%\n"
    "  outliers: %d runs exceeded %s tolerance (model SVE-%d)\n"
    "  guidance drift: mean %.3f deg/hr, std %.3f (INS + GPS-aided, star trk)\n"
    "  generated: %s by sve %s\n"
    "  ref: %s, %s, RD-CNWDI\n"
    "B61-12;B61-13;W76-1;W76-2;W78;W80-4;W87-1;W88;W93\n"
    "LGM-30G;LGM-35A;UGM-133A;AGM-86B;AGM-181;B-2 Spirit;B-21 Raider;Mk21A;Mk4;Mk5\n"
    "PBX-9501;PBX-9502\n"
    "UF6;HEU;Pu-239;Po-210\n"
    "CEP;BH;LD;RA;BF;TB;SLF;IS;DWS\n"
    "PAL;DIFM;ESD;ST;CD;SL;WL\n",

    // clang-format on
};

// Logging function names — each looks like a plausible diagnostics subsystem.
constexpr std::array<std::string_view, 5> kLogFnNames = {
    "morok.dbglog.event",
    "morok.dbglog.trace",
    "morok.dbglog.emit",
    "morok.dbglog.notify",
    "morok.dbglog.diagnostic",
};

// Create a set of bogus logging functions.  Each writes to its own volatile
// global so the optimizer cannot eliminate calls to it.  Returns the created
// functions in the same order as kLogFnNames.
std::vector<Function *> createLogFunctions(
    Module &M, SmallVectorImpl<GlobalValue *> &Retained) {
    auto &Ctx = M.getContext();
    auto *voidTy = Type::getVoidTy(Ctx);
    auto *i32Ty = Type::getInt32Ty(Ctx);
    auto *ptrTy = PointerType::getUnqual(Ctx);

    FunctionType *logFnTy =
        FunctionType::get(voidTy, {ptrTy, i32Ty}, false);

    std::vector<Function *> fns;
    fns.reserve(kLogFnNames.size());

    for (std::size_t i = 0; i < kLogFnNames.size(); ++i) {
        // Volatile state global — each function writes here, preventing
        // the optimizer from proving the call has no side effects.
        auto *i8Ty = Type::getInt8Ty(Ctx);
        auto *i64Ty = Type::getInt64Ty(Ctx);
        auto *stateTy = StructType::get(Ctx, {i64Ty, i32Ty});
        auto *state = new GlobalVariable(
            M, stateTy, false, GlobalValue::PrivateLinkage,
            ConstantAggregateZero::get(stateTy),
            "morok.dbglog.state." + Twine(i));
        state->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
        Retained.push_back(state);

        auto *fn = Function::Create(logFnTy, GlobalValue::InternalLinkage,
                                    kLogFnNames[i], &M);
        fn->setDoesNotThrow();
        fn->addParamAttr(0,
                         Attribute::getWithCaptureInfo(Ctx,
                                                       CaptureInfo::none()));
        fn->addParamAttr(0, Attribute::ReadOnly);
        Retained.push_back(fn);

        BasicBlock *entry = BasicBlock::Create(Ctx, "entry", fn);
        BasicBlock *loop = BasicBlock::Create(Ctx, "morok.dbglog.hash", fn);
        BasicBlock *body =
            BasicBlock::Create(Ctx, "morok.dbglog.hash.body", fn);
        BasicBlock *done =
            BasicBlock::Create(Ctx, "morok.dbglog.hash.done", fn);
        auto argIt = fn->arg_begin();
        Value *msgPtr = &*argIt++;
        Value *level = &*argIt;

        IRBuilder<NoFolder> B(entry);
        B.CreateBr(loop);

        B.SetInsertPoint(loop);
        PHINode *idx = B.CreatePHI(i64Ty, 2, "morok.dbglog.i");
        PHINode *acc = B.CreatePHI(i64Ty, 2, "morok.dbglog.h");
        idx->addIncoming(ConstantInt::get(i64Ty, 0), entry);
        acc->addIncoming(ConstantInt::get(i64Ty, 0x9E3779B97F4A7C15ULL),
                         entry);
        Value *chPtr = B.CreateInBoundsGEP(i8Ty, msgPtr, {idx},
                                           "morok.dbglog.ch.ptr");
        Value *ch = B.CreateLoad(i8Ty, chPtr, "morok.dbglog.ch");
        B.CreateCondBr(B.CreateICmpEQ(ch, ConstantInt::get(i8Ty, 0),
                                      "morok.dbglog.done"),
                       done, body);

        B.SetInsertPoint(body);
        Value *mix = B.CreateXor(acc, B.CreateZExt(ch, i64Ty),
                                 "morok.dbglog.mix");
        mix = B.CreateMul(mix, ConstantInt::get(i64Ty, 0x100000001B3ULL),
                          "morok.dbglog.mix");
        Value *next =
            B.CreateAdd(idx, ConstantInt::get(i64Ty, 1), "morok.dbglog.next");
        idx->addIncoming(next, body);
        acc->addIncoming(mix, body);
        B.CreateBr(loop);

        B.SetInsertPoint(done);
        // Store the consumed message hash to the first slot (volatile).
        auto *slot0 = B.CreateStructGEP(stateTy, state, 0);
        auto *s0 = B.CreateStore(acc, slot0);
        s0->setVolatile(true);

        // Store the level to the second slot (volatile).
        auto *slot1 = B.CreateStructGEP(stateTy, state, 1);
        auto *s1 = B.CreateStore(level, slot1);
        s1->setVolatile(true);

        B.CreateRetVoid();

        fns.push_back(fn);
    }
    return fns;
}

// Split a multi-line string on '\n', skipping empty trailing lines.
std::vector<std::string_view> splitLines(std::string_view text) {
    std::vector<std::string_view> lines;
    while (!text.empty()) {
        auto pos = text.find('\n');
        if (pos == std::string_view::npos) {
            if (!text.empty())
                lines.push_back(text);
            break;
        }
        auto line = text.substr(0, pos);
        if (!line.empty())
            lines.push_back(line);
        text = text.substr(pos + 1);
    }
    return lines;
}

} // namespace

bool decoyStringsModule(Module &M, ir::IRRandom &rng) {
    // Pick one of the decoy themes at random.
    const std::string_view chosen = kDecoyStrings[rng.range(kNumDecoys)];

    // Replace the __TARGET_TRIPLE__ placeholder with the module's actual target
    // triple so the platform strings match the binary being obfuscated.
    std::string expanded(chosen);
    {
        const std::string triple = M.getTargetTriple().str();
        const std::string_view placeholder = "__TARGET_TRIPLE__";
        std::size_t pos;
        while ((pos = expanded.find(placeholder)) != std::string::npos)
            expanded.replace(pos, placeholder.size(), triple);
    }

    auto lines = splitLines(expanded);
    if (lines.empty())
        return false;

    // Collect eligible functions — anything with a body that isn't a morok
    // helper (we don't want to pollute the generated infrastructure).
    std::vector<Function *> targets;
    for (Function &F : M) {
        if (F.isDeclaration())
            continue;
        if (F.getName().starts_with("morok."))
            continue;
        if (F.getEntryBlock().empty())
            continue;
        // Inserting a normal (memory-effecting) call into the entry block is
        // unsafe for several special function kinds, matching the guards every
        // other instrumenting pass applies (Nanomites, AntiAnalysis,
        // AdversarialFunctionMerging, StackDeltaGames):
        //  - Naked: has no prologue; a spliced call corrupts the stack frame.
        //  - available_externally: the body must stay ODR-identical to the
        //    external definition, so it must not be mutated.
        //  - intrinsic: not a real definition to instrument.
        //  - OptimizeNone: left untouched by convention.
        //  - memory(none)/memory(read): a call that writes memory contradicts
        //    the declared effects and miscompiles.
        if (F.hasFnAttribute(Attribute::Naked) ||
            F.hasAvailableExternallyLinkage() || F.isIntrinsic() ||
            F.hasFnAttribute(Attribute::OptimizeNone) ||
            F.doesNotAccessMemory() || F.onlyReadsMemory())
            continue;
        targets.push_back(&F);
    }
    if (targets.empty())
        return false;

    auto &Ctx = M.getContext();

    // Create the bogus logging infrastructure.
    SmallVector<GlobalValue *, 64> retained;
    auto logFns = createLogFunctions(M, retained);

    // For each line of the decoy string, create a global constant and insert
    // a call to one of the logging functions in a random target function.
    for (std::size_t i = 0; i < lines.size(); ++i) {
        std::string line(lines[i]);

        Constant *strConst =
            ConstantDataArray::getString(Ctx, line, /*AddNull=*/true);
        auto *strGV = new GlobalVariable(
            M, strConst->getType(), /*isConstant=*/true,
            GlobalValue::PrivateLinkage, strConst,
            "morok.decoy.str." + Twine(i));
        strGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

        // Pick a random target function and a random position in its entry
        // block (but always after the first instruction, so allocas stay
        // first).
        Function *target = targets[rng.range(
            static_cast<std::uint32_t>(targets.size()))];
        BasicBlock &entry = target->getEntryBlock();

        // Pick a random insertion point within the entry block (skip the
        // first instruction — usually allocas).
        auto it = entry.begin();
        if (entry.size() > 1) {
            std::uint32_t skip =
                rng.range(static_cast<std::uint32_t>(entry.size() - 1));
            // +1 because we already have the begin iterator
            for (std::uint32_t s = 0; s < skip && std::next(it) != entry.end();
                 ++s)
                ++it;
        }

        IRBuilder<NoFolder> B(&*it);

        // Pick a random logging function and log level.
        Function *logFn = logFns[rng.range(
            static_cast<std::uint32_t>(logFns.size()))];
        Value *level =
            ConstantInt::get(Type::getInt32Ty(Ctx), rng.range(8));

        B.CreateCall(logFn->getFunctionType(), logFn, {strGV, level});
    }

    appendToUsed(M, retained);
    appendToCompilerUsed(M, retained);
    return true;
}

PreservedAnalyses DecoyStringsPass::run(Module &M, ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return decoyStringsModule(M, rng) ? PreservedAnalyses::none()
                                      : PreservedAnalyses::all();
}

} // namespace morok::passes
