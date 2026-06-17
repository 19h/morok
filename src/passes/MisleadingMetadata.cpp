// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// MisleadingMetadata.cpp

#include "morok/passes/MisleadingMetadata.hpp"

#include "llvm/BinaryFormat/Dwarf.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <array>
#include <cstdint>
#include <string>

using namespace llvm;

namespace morok::passes {
namespace {

constexpr unsigned kDecoyFunctions = 5;

constexpr std::array<const char *, 8> kFunctionStems = {
    "license_cache_rebuild",
    "validate_entitlement_chain",
    "decrypt_manifest_payload",
    "sync_activation_receipt",
    "crash_unwind_symbolicate",
    "update_rollout_guard",
    "keybag_shadow_refresh",
    "policy_snapshot_verify",
};

constexpr std::array<const char *, 8> kAliasStems = {
    "parse_receipt_v2",
    "verify_nonce_window",
    "load_keybag_shadow",
    "decode_config_segment",
    "flush_diagnostic_ring",
    "rotate_session_ticket",
    "normalize_feature_flags",
    "seal_manifest_epoch",
};

constexpr std::array<const char *, 8> kDebugNames = {
    "LicenseManager::validateTrialWindow",
    "ReceiptVerifier::decodeSignedBlob",
    "CrashReporter::symbolicateFrame",
    "KeybagCache::reloadGeneration",
    "UpdateManifest::verifyRolloutSeed",
    "TelemetrySpooler::flushBackgroundBatch",
    "PolicySnapshot::hydrateFallback",
    "ActivationState::sealOfflineLease",
};

constexpr std::array<const char *, 8> kFiles = {
    "LicenseManager.mm",
    "ReceiptVerifier.cpp",
    "CrashSymbolication.cpp",
    "KeybagCache.cpp",
    "UpdateManifest.cc",
    "TelemetrySpooler.c",
    "PolicySnapshot.cpp",
    "ActivationState.mm",
};

std::string hex64(std::uint64_t value) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out(16, '0');
    for (int i = 15; i >= 0; --i) {
        out[static_cast<std::size_t>(i)] = kDigits[value & 0xFu];
        value >>= 4;
    }
    return out;
}

std::string uniqueName(Module &M, const char *stem, std::uint64_t salt) {
    std::string base(stem);
    base.push_back('_');
    base.append(hex64(salt).substr(0, 8));
    std::string name = base;
    unsigned suffix = 0;
    while (M.getNamedValue(name)) {
        name = base;
        name.push_back('_');
        name.append(std::to_string(++suffix));
    }
    return name;
}

DICompileUnit *createCompileUnit(DIBuilder &dib, DIFile *file,
                                 morok::ir::IRRandom &rng) {
    const std::uint64_t dwo = rng.next();
    return dib.createCompileUnit(
        DISourceLanguageName(dwarf::DW_LANG_C_plus_plus_14), file,
        "Apple clang version 16.0.0 (clang-1600.0.26.3)",
        /*isOptimized=*/true, "-O2 -gline-tables-only", 0, "",
        DICompileUnit::DebugEmissionKind::FullDebug, dwo,
        /*SplitDebugInlining=*/true,
        /*DebugInfoForProfiling=*/false,
        DICompileUnit::DebugNameTableKind::Default,
        /*RangesBaseAddress=*/false);
}

Function *createDecoyFunction(Module &M, StringRef name,
                              morok::ir::IRRandom &rng) {
    LLVMContext &ctx = M.getContext();
    auto *i64 = Type::getInt64Ty(ctx);
    auto *fnTy = FunctionType::get(i64, {i64}, false);
    auto *fn = Function::Create(fnTy, GlobalValue::InternalLinkage, name, M);
    fn->setDSOLocal(true);
    fn->setAlignment(Align(16u << rng.range(2)));
    fn->addFnAttr(Attribute::NoInline);
    fn->addFnAttr(Attribute::OptimizeNone);
    fn->addFnAttr(Attribute::Cold);

    Argument *arg = fn->getArg(0);
    arg->setName("ctx");

    IRBuilder<> b(BasicBlock::Create(ctx, "entry", fn));
    AllocaInst *slot = b.CreateAlloca(i64, nullptr, "state");
    Value *salt = ConstantInt::get(i64, rng.next());
    Value *mul = ConstantInt::get(i64, rng.next() | 1ull);
    Value *mix = b.CreateMul(b.CreateXor(arg, salt, "mix.x"), mul, "mix.m");
    StoreInst *store = b.CreateStore(mix, slot);
    store->setVolatile(true);
    LoadInst *load = b.CreateLoad(i64, slot, "state.v");
    load->setVolatile(true);
    Value *out =
        b.CreateXor(load, ConstantInt::get(i64, rng.next()), "state.out");
    b.CreateRet(out);
    return fn;
}

GlobalVariable *createDebugStringBait(Module &M) {
    Triple tt(M.getTargetTriple());
    if (!tt.isOSBinFormatMachO())
        return nullptr;

    LLVMContext &ctx = M.getContext();
    std::string payload;
    for (const char *name : kDebugNames) {
        payload.append(name);
        payload.push_back('\0');
    }
    payload.append("DerivedSources-Cache.mm");
    payload.push_back('\0');
    payload.append("/Users/build/agent/_work/product/DerivedData/../Sources");
    payload.push_back('\0');
    payload.append("Apple clang version 16.0.0 (clang-1600.0.26.3)");
    payload.push_back('\0');

    auto *init = ConstantDataArray::getString(ctx, payload, false);
    auto *gv = new GlobalVariable(M, init->getType(), /*isConstant=*/true,
                                  GlobalValue::PrivateLinkage, init,
                                  "morok.md.debug.str");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    gv->setAlignment(Align(1));
    gv->setSection("__TEXT,__debug_str");
    return gv;
}

void attachMisleadingDebug(Module &M, ArrayRef<Function *> functions,
                           morok::ir::IRRandom &rng) {
    if (!M.getModuleFlag("Debug Info Version"))
        M.addModuleFlag(Module::Warning, "Debug Info Version",
                        DEBUG_METADATA_VERSION);
    if (!M.getModuleFlag("Dwarf Version"))
        M.addModuleFlag(Module::Warning, "Dwarf Version", 4);

    DIBuilder dib(M);
    DIFile *unitFile = dib.createFile(
        "DerivedSources-Cache.mm",
        "/private/var/folders/zz/Build/Intermediates.noindex/../../Source");
    DICompileUnit *cu = createCompileUnit(dib, unitFile, rng);
    DIType *u64 =
        dib.createBasicType("uintptr_t", 64, dwarf::DW_ATE_unsigned);
    DISubroutineType *subTy =
        dib.createSubroutineType(dib.getOrCreateTypeArray({u64, u64}));

    for (unsigned i = 0; i != functions.size(); ++i) {
        Function *fn = functions[i];
        const unsigned pick = static_cast<unsigned>(rng.range(kDebugNames.size()));
        DIFile *file = dib.createFile(
            kFiles[(pick + i) % kFiles.size()],
            "/Users/build/agent/_work/product/DerivedData/../Sources");
        const unsigned line =
            0x200000u + static_cast<unsigned>(rng.range(0x3fff0));
        const unsigned scopeLine =
            3u + static_cast<unsigned>(rng.range(97));
        auto flags = DINode::FlagPrototyped | DINode::FlagArtificial;
        auto spFlags = DISubprogram::SPFlagDefinition |
                       DISubprogram::SPFlagLocalToUnit |
                       DISubprogram::SPFlagOptimized;
        DISubprogram *sp = dib.createFunction(
            cu, kDebugNames[pick], fn->getName(), file, line, subTy, scopeLine,
            flags, spFlags);
        fn->setSubprogram(sp);

        unsigned instLine = line + 17u + static_cast<unsigned>(rng.range(64));
        for (BasicBlock &bb : *fn) {
            for (Instruction &inst : bb) {
                inst.setDebugLoc(DILocation::get(
                    M.getContext(), instLine++,
                    1u + static_cast<unsigned>(rng.range(200)), sp));
            }
        }
    }

    dib.finalize();
}

} // namespace

bool misleadingMetadataModule(Module &M, morok::ir::IRRandom &rng) {
    if (M.getNamedMetadata("morok.misleading.metadata"))
        return false;

    LLVMContext &ctx = M.getContext();
    M.getOrInsertNamedMetadata("morok.misleading.metadata")
        ->addOperand(MDNode::get(ctx, {}));

    SmallVector<Function *, kDecoyFunctions> functions;
    SmallVector<GlobalValue *, kDecoyFunctions * 2> retained;
    functions.reserve(kDecoyFunctions);
    retained.reserve(kDecoyFunctions * 2);

    for (unsigned i = 0; i != kDecoyFunctions; ++i) {
        const char *stem =
            kFunctionStems[(i + rng.range(kFunctionStems.size())) %
                           kFunctionStems.size()];
        Function *fn = createDecoyFunction(M, uniqueName(M, stem, rng.next()),
                                           rng);
        functions.push_back(fn);
        retained.push_back(fn);

        const char *aliasStem =
            kAliasStems[(i + rng.range(kAliasStems.size())) %
                        kAliasStems.size()];
        std::string aliasName = uniqueName(M, aliasStem, rng.next());
        auto *alias =
            GlobalAlias::create(GlobalValue::InternalLinkage, aliasName, fn);
        alias->setDSOLocal(true);
        retained.push_back(alias);
    }

    if (GlobalVariable *DebugStr = createDebugStringBait(M)) {
        retained.push_back(DebugStr);
        appendToUsed(M, {DebugStr});
    }
    appendToCompilerUsed(M, retained);
    attachMisleadingDebug(M, functions, rng);
    return true;
}

PreservedAnalyses MisleadingMetadataPass::run(Module &M,
                                              ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return misleadingMetadataModule(M, rng) ? PreservedAnalyses::none()
                                           : PreservedAnalyses::all();
}

} // namespace morok::passes
