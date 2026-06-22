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

constexpr std::size_t kNumDecoys = 6;

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

    // Theme 0: Session / platform startup + site infrastructure.
    // Dense with facility, badge, airgap, and classification signals.
    "SIM-INIT: sve v2.3.1 (CLANG 17, __TARGET_TRIPLE__)\n"
    "  build: pantex/release/2.3.1-g9c4f2a7, May 28 2026 03:41:19 MST\n"
    "  facility: TA-33 MS-D429 x7291 (zone-4, Q-cleared escort required beyond portal)\n"
    "  operator: j.martinez (badge Q-784291-DOE, RD-CNWDI auth, exp 2027-11)\n"
    "  config: /sve/etc/sve.d/ (rev 0x9c4f2a7, 61 files, 27MiB, signed)\n"
    "  net: sve-lan3-dmz vlan331 (airgapped, 10.33.7.0/24, no enterprise route, macsec enforced)\n"
    "  scenario: %s (%s)\n"
    "  model DB: %s (loaded, %d entries, integrity sha256:%s, SSP-2026 baseline)\n"
    "  Monte Carlo: %d runs, seed 0x%X, CEP budget %.1fm (%d%% conf., 3sigma)\n"
    "  NOTE: simulated values only — not for flight software certification\n"
    "  wo: SVE-20260528-7842 (RD-CNWDI review board, assigned to sim-ops, LEP integration)\n"
    "  classification: //RD-CNWDI//NOFORN//ORCON// (active session, treat all output accordingly)\n"
    "B61-12;B61-13;W76-1;W76-2;W78;W80-4;W87-1;W88;W93\n"
    "LGM-30G;LGM-35A;UGM-133A;AGM-86B;AGM-181;B-2 Spirit;B-21 Raider;Mk21A;Mk4;Mk5\n"
    "PBX-9501;PBX-9502;LX-17\n"
    "UF6;HEU;Pu-239;Pu-238;Po-210;Am-241\n"
    "CEP;BH;LD;RA;BF;TB;SLF;IS;DWS;INS;GPS;STAR\n"
    "PAL;DIFM;ESD;ST;CD;SL;WL;MC;RV;LEP\n",

    // Theme 1: Subsystem model validation.  Heavy on physics, V&V, LEP, surveillance.
    "SIM-TEST: %s subsystem model validation (cat %s, sve-db %s, SSP-2026 cycle)\n"
    "  %s: safe/arm logic state machine (%d states, %d transitions, coverage 97.2%%, MC cross-check)\n"
    "  %s: environmental sensing device model (baro + radar alt, ref %d ft, drift <%.2f Pa/hr, LEP-2025 sensor suite)\n"
    "  %s: fuzing mode select — burst height model deviates %.1f%% at %d ft (hydro validation against archival UGT data)\n"
    "    expected: %.1f ft +/- %.1f ft, simulated: %.1f ft (model bias %+.1f%%, SFI-7842 open)\n"
    "    action: file SVE-TRAC-%d, assign to %s team (%s, RD-CNWDI cleared)\n"
    "  %s: thermal battery activation sequence (T+%.1f s to T+%.1f s nominal, peak %.0f C, lot traceability)\n"
    "  %s: bridge-wire continuity model (%d channels, resistance within %d%% of spec, aging study 2026-Q2)\n"
    "  reviewed: %s, %s, %s, RD-CNWDI board (TA-33-429, zone-4)\n"
    "  PASS\n"
    "  FAIL\n"
    "  current SSP inventory under test: 9 warhead types, 14 delivery platforms, LEP-2025/2026 candidates\n"
    "  see sve-catalog-2026Q2.db for full matrix (Q-cleared access only, NOFORN)\n"
    "  hydrodynamic cross-check: FLAG/ALE3D vs sve-hydro v4.2 (deviation <0.8%% on key metrics)\n",

    // Theme 2: Python bindings / module load.  Scientific Python environment with heavy restricted-data warnings.
    "SIM-PY: sve Python bindings v2.3.1 (cpython 3.12.4, numpy 2.1.0, scipy 1.15.1, numba 0.60)\n"
    "  loaded module: sve.pal (%s simulator, cat A-F, v3.4.2, LEP-2025 PAL model)\n"
    "  loaded module: sve.fuzing (%s burst model, v4.2.1, MCNP6.3 + hydro cross-check)\n"
    "  loaded module: sve.arming (safe/arm/fire state machine v3.2.9, coverage 98.1%%)\n"
    "  loaded module: sve.trajectory (6-DOF %s model, winds + atmosphere + reentry, INS/GPS/STAR)\n"
    "  loaded module: sve.hydro (3D multimaterial hydro v4.2, FLAG cross-validation)\n"
    "  loaded module: sve.montecarlo (distributed job v2.1.3, 4096 workers, sve-lan3 cluster)\n"
    "  scenario DB: %s (%d entries, last sync 2026-05-27 14:22 UTC, SSP baseline)\n"
    "  session: %s@%s, display :0, conn %s:%d (tls1.3, mutual cert auth, zone-4 console)\n"
    "  WARNING: this build includes restricted-data models (RD-CNWDI // NOFORN // ORCON)\n"
    "  WARNING: operator Q-784291 logged in from TA-33 zone-4 console (escort not required for this session)\n"
    "  db integrity: all 61 model files sha256 verified against sve-catalog-2026Q2\n"
    "  airgap: sve-lan3-dmz enforced; enterprise bridge disabled per SSP-2026-47 and DOE O 471.6\n"
    "  classification banner: //RD-CNWDI//NOFORN// (all output from this session must be marked accordingly)\n",

    // Theme 3: Monte Carlo statistical report.  Rich reliability, aging, LEP metrics + second catalog dump.
    "REPORT: sve Monte Carlo analysis — %s (SSP-2026 annual assessment support)\n"
    "  scenario: %s\n"
    "  runs: %d, seed 0x%X, wall time %dm %ds (%s, %d cores, sve-lan3 cluster, macOS/Linux/Windows workers)\n"
    "  results: CEP 90%% = %.1fm (budget %.1fm), reliability %.2f%% (3sigma, LEP-2025 config)\n"
    "  outliers: %d runs exceeded %s tolerance (model SVE-%d, auto-flagged for SFI review)\n"
    "  guidance drift: mean %.3f deg/hr, std %.3f (INS + GPS-aided + star tracker, reentry phase)\n"
    "  thermal battery: peak %.1f C, margin %.1f C to spec limit, aging model 2026-Q2\n"
    "  fuzing timing: arm time mu=%.2f s, sigma=%.3f s (n=%d valid, bridge-wire + thermal)\n"
    "  stockpile reliability: mean %.2f%%, lower 95%% bound %.2f%% (surveillance + LEP data fusion)\n"
    "  generated: %s by sve %s (pantex/release, cross-platform)\n"
    "  ref: %s, %s, RD-CNWDI board TA-33 MS-D429 (zone-4)\n"
    "  wo: SVE-20260528-7842 closed — classification review complete, NOFORN distribution only\n"
    "B61-12;B61-13;W76-1;W76-2;W78;W80-4;W87-1;W88;W93\n"
    "LGM-30G;LGM-35A;UGM-133A;AGM-86B;AGM-181;B-2 Spirit;B-21 Raider;Mk21A;Mk4;Mk5\n"
    "PBX-9501;PBX-9502;LX-17; insensitive high explosive candidates\n"
    "UF6;HEU;Pu-239;Pu-238;Po-210;Am-241; tritium handling\n"
    "CEP;BH;LD;RA;BF;TB;SLF;IS;DWS;INS;GPS;STAR;RV;MC\n"
    "PAL;DIFM;ESD;ST;CD;SL;WL;MC;RV;LEP;SFI\n",

    // Theme 4: NEW — Hardware/sensor calibration diagnostics.  Extremely detailed lab output.
    "HW-CAL: sve hardware model calibration v2.1.4 (TA-33-429 rack 07, zone-4, airgapped)\n"
    "  barometric: %s (SN-33-784291, ref %d ft MSL, drift %.3f Pa/hr, LEP-2025 sensor)\n"
    "  radar altimeter: %s (SN-429-112, beam %d deg, tx %.1f dBm, reentry plasma mitigation)\n"
    "  thermal battery: %s (lot %s, activation current %.2f A, within spec, traceability to Pantex)\n"
    "  bridge-wire: %s (%d channels, continuity R=%.2f ohm +/- %d%%, aging study 2026-Q2)\n"
    "  fuzing electronics: %s (safe/arm state machine, %d transitions exercised, RD-CNWDI firmware)\n"
    "  env suite: temp %.1f C, rh %.1f%%, vibe %.2f gRMS (test fixture, witnessed)\n"
    "  cal constants: loaded /sve/hw/cal/%s.db (sha256 verified by operator Q-784291)\n"
    "  operator: Q-784291 witnessed by RD-CNWDI escort (badge Q-99102, zone-4 only)\n"
    "  wo: SVE-HW-20260527-33107 (zone-4, airgapped terminal, classification review required)\n"
    "  net: local-only (sve-lan3 node-07, iface disabled, macsec)\n"
    "  NOTE: all values from hardware-in-the-loop fixture; simulated output for SSP surveillance\n"
    "  reviewed: %s, %s, %s (SSP surveillance program, TA-33, hydrodynamic validation complete)\n"
    "  classification: //RD-CNWDI//NOFORN// (calibration data derived from restricted models)\n",

    // Theme 5: NEW — Security, integrity & compliance self-audit.  Maximum classification flavor.
    "AUDIT: sve security & integrity self-check v2.3.1 (TA-33 zone-4, Q-cleared console)\n"
    "  classification: RD-CNWDI // NOFORN // ORCON // CUI (active session, all output marked)\n"
    "  operator: badge Q-784291 (active, zone-4 console, no escort required this session)\n"
    "  access: %s@%s from sve-lan3-dmz (10.33.7.42:44122) at %s (tls1.3, cert pinned)\n"
    "  model integrity: 61 files checked, all sha256 match sve-catalog-2026Q2 (SSP baseline)\n"
    "  crypto self-test: AES-256-GCM (hw accel), SHA-384, ECDSA P-384, ML-KEM-768 — PASS\n"
    "  config tamper check: /sve/etc/ (61 files) mtime/ctime/sig verified, no anomalies\n"
    "  build provenance: pantex/release/2.3.1-g9c4f2a7 signed 2026-05-28, reproducible build\n"
    "  last external sync: DISABLED (airgap enforced per SSP-2026-47 and DOE O 471.6)\n"
    "  open tickets: SVE-TRAC-7842 (RD-CNWDI, LEP), SVE-HW-33107 (hw-cal, witnessed)\n"
    "  facility: TA-33 MS-D429, rack 12, console sve-node-07 (RHEL 9.4 / macOS 15 / Windows 11)\n"
    "  chain of custody: all model files under two-person rule for RD-CNWDI material\n"
    "  WARNING: restricted-data models active in this session — treat output as RD-CNWDI // NOFORN\n"
    "  reviewed by: %s, %s (Q-cleared, CNWDI authorized, TA-33, SSP-2026 assessors)\n"
    "  result: PASS — no anomalies detected, all controls effective, ready for annual assessment\n"
    "  classification banner: //RD-CNWDI//NOFORN//ORCON// (this log itself is RD-CNWDI)\n",

    // clang-format on
};

// Logging function names — each looks like a plausible diagnostics subsystem.
constexpr std::array<std::string_view, 5> kLogFnNames = {
    "morok.dbglog.event",  "morok.dbglog.trace",      "morok.dbglog.emit",
    "morok.dbglog.notify", "morok.dbglog.diagnostic",
};

// Create a set of bogus logging functions.  Each writes to its own volatile
// global so the optimizer cannot eliminate calls to it.  Returns the created
// functions in the same order as kLogFnNames.
std::vector<Function *>
createLogFunctions(Module &M, SmallVectorImpl<GlobalValue *> &Retained) {
    auto &Ctx = M.getContext();
    auto *voidTy = Type::getVoidTy(Ctx);
    auto *i32Ty = Type::getInt32Ty(Ctx);
    auto *ptrTy = PointerType::getUnqual(Ctx);

    FunctionType *logFnTy = FunctionType::get(voidTy, {ptrTy, i32Ty}, false);

    std::vector<Function *> fns;
    fns.reserve(kLogFnNames.size());

    for (std::size_t i = 0; i < kLogFnNames.size(); ++i) {
        // Volatile state global — each function writes here, preventing
        // the optimizer from proving the call has no side effects.
        auto *i8Ty = Type::getInt8Ty(Ctx);
        auto *i64Ty = Type::getInt64Ty(Ctx);
        auto *stateTy = StructType::get(Ctx, {i64Ty, i32Ty});
        auto *state =
            new GlobalVariable(M, stateTy, false, GlobalValue::PrivateLinkage,
                               ConstantAggregateZero::get(stateTy),
                               "morok.dbglog.state." + Twine(i));
        state->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
        Retained.push_back(state);

        auto *fn = Function::Create(logFnTy, GlobalValue::InternalLinkage,
                                    kLogFnNames[i], &M);
        fn->setDoesNotThrow();
        fn->addParamAttr(
            0, Attribute::getWithCaptureInfo(Ctx, CaptureInfo::none()));
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
        acc->addIncoming(ConstantInt::get(i64Ty, 0x9E3779B97F4A7C15ULL), entry);
        Value *chPtr =
            B.CreateInBoundsGEP(i8Ty, msgPtr, {idx}, "morok.dbglog.ch.ptr");
        Value *ch = B.CreateLoad(i8Ty, chPtr, "morok.dbglog.ch");
        B.CreateCondBr(
            B.CreateICmpEQ(ch, ConstantInt::get(i8Ty, 0), "morok.dbglog.done"),
            done, body);

        B.SetInsertPoint(body);
        Value *mix =
            B.CreateXor(acc, B.CreateZExt(ch, i64Ty), "morok.dbglog.mix");
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
        auto *strGV =
            new GlobalVariable(M, strConst->getType(), /*isConstant=*/true,
                               GlobalValue::PrivateLinkage, strConst,
                               "morok.decoy.str." + Twine(i));
        strGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

        // Pick a random target function and a random position in its entry
        // block (but always after the first instruction, so allocas stay
        // first).
        Function *target =
            targets[rng.range(static_cast<std::uint32_t>(targets.size()))];
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

        // Pick a random logging function and log level.  Keep the string
        // operand inside a generated helper so later user-function transforms
        // do not rewrite the per-callsite decrypt loop into user CFGs.
        Function *logFn =
            logFns[rng.range(static_cast<std::uint32_t>(logFns.size()))];
        Value *level = ConstantInt::get(Type::getInt32Ty(Ctx), rng.range(8));

        FunctionType *siteTy = FunctionType::get(Type::getVoidTy(Ctx), false);
        Function *siteFn =
            Function::Create(siteTy, GlobalValue::InternalLinkage,
                             "morok.decoy.site." + Twine(i), &M);
        siteFn->setDoesNotThrow();
        siteFn->addFnAttr(Attribute::NoInline);
        retained.push_back(siteFn);

        BasicBlock *siteEntry = BasicBlock::Create(Ctx, "entry", siteFn);
        IRBuilder<NoFolder> SB(siteEntry);
        SB.CreateCall(logFn->getFunctionType(), logFn, {strGV, level});
        SB.CreateRetVoid();

        B.CreateCall(siteFn->getFunctionType(), siteFn, {});
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
