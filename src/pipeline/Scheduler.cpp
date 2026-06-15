// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/pipeline/Scheduler.cpp

#include "morok/pipeline/Scheduler.hpp"

#include "morok/core/Entropy.hpp"
#include "morok/core/Xoshiro256.hpp"
#include "morok/ir/Annotations.hpp"
#include "morok/ir/IRRandom.hpp"
#include "morok/passes/AdversarialFunctionMerging.hpp"
#include "morok/passes/AliasOpaquePredicates.hpp"
#include "morok/passes/AntiAnalysis.hpp"
#include "morok/passes/ArithmeticTables.hpp"
#include "morok/passes/BogusControlFlow.hpp"
#include "morok/passes/ChaosStateMachine.hpp"
#include "morok/passes/CoherentDecoys.hpp"
#include "morok/passes/ConstantEncryption.hpp"
#include "morok/passes/DataEntangledFlattening.hpp"
#include "morok/passes/DataFlowIntegrity.hpp"
#include "morok/passes/DispatcherlessRouting.hpp"
#include "morok/passes/ExternalOpaquePredicates.hpp"
#include "morok/passes/Flattening.hpp"
#include "morok/passes/FunctionCallObfuscate.hpp"
#include "morok/passes/FunctionWrapper.hpp"
#include "morok/passes/HashGatedSelfDecrypt.hpp"
#include "morok/passes/IndirectBranch.hpp"
#include "morok/passes/InterproceduralFsm.hpp"
#include "morok/passes/Mba.hpp"
#include "morok/passes/MutualGuardGraph.hpp"
#include "morok/passes/NonInvertibleState.hpp"
#include "morok/passes/OptimizerAmplification.hpp"
#include "morok/passes/PathExplosion.hpp"
#include "morok/passes/PerBuildPolymorphism.hpp"
#include "morok/passes/PhiTangling.hpp"
#include "morok/passes/PointerLaundering.hpp"
#include "morok/passes/SelfChecksumConstants.hpp"
#include "morok/passes/SplitBasicBlocks.hpp"
#include "morok/passes/StackCoalescing.hpp"
#include "morok/passes/StateOpaquePredicates.hpp"
#include "morok/passes/StringEncryption.hpp"
#include "morok/passes/SubThresholdPersistence.hpp"
#include "morok/passes/Substitution.hpp"
#include "morok/passes/TraceKeying.hpp"
#include "morok/passes/TypePunning.hpp"
#include "morok/passes/UniformPrimitiveLowering.hpp"
#include "morok/passes/Virtualization.hpp"
#include "morok/passes/VectorObfuscation.hpp"

#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"

#include <string>

using namespace llvm;

namespace morok::pipeline {

PreservedAnalyses MorokPass::run(Module &M, ModuleAnalysisManager &) {
    // Seed the shared engine: explicit seed for reproducible builds, otherwise
    // collected entropy.
    core::Xoshiro256pp engine = config_.seed != 0
                                    ? core::Xoshiro256pp::fromSeed(config_.seed)
                                    : core::makeSeededEngine();
    ir::IRRandom rng(engine);

    ir::materializeAnnotations(M);

    const config::Demangler demangle = [](std::string_view s) -> std::string {
        return llvm::demangle(std::string(s));
    };

    const std::string moduleName = M.getSourceFileName();
    bool changed = false;

    // Anti-analysis module passes run earliest.
    if (config_.passes.anti_hook.enabled.value_or(false))
        changed |= passes::antiHookingModule(M);
    if (config_.passes.anti_class_dump.enabled.value_or(false))
        changed |= passes::antiClassDumpModule(M);
    if (config_.passes.anti_dbg.enabled.value_or(false))
        changed |= passes::antiDebuggingModule(M);

    // Hide library imports behind dlsym.
    if (config_.passes.fco.enabled.value_or(false)) {
        passes::FcoParams fp;
        changed |= passes::functionCallObfuscateModule(M, fp, rng);
    }

    // Module-level string encryption (its decryptor constructor and key globals
    // are independent of the per-function transforms).
    if (config_.passes.str_enc.enabled.value_or(false)) {
        passes::StrEncParams sp;
        sp.probability = config_.passes.str_enc.probability.value_or(100);
        changed |= passes::stringEncryptModule(M, sp, rng);
    }

    // VM lifting must run before block splitting / flattening make straight-line
    // functions ineligible.  The generated morok.* helpers are skipped below.
    if (config_.passes.virtualization.enabled.value_or(false)) {
        passes::VirtualizationParams p;
        p.probability = config_.passes.virtualization.probability.value_or(20);
        p.max_functions =
            config_.passes.virtualization.max_functions.value_or(1);
        p.max_instructions =
            config_.passes.virtualization.max_instructions.value_or(64);
        p.max_registers =
            config_.passes.virtualization.max_registers.value_or(96);
        changed |= passes::virtualizeModule(M, p, rng);
    }

    if (config_.passes.hash_self_decrypt.enabled.value_or(false)) {
        passes::HashGatedSelfDecryptParams p;
        p.probability =
            config_.passes.hash_self_decrypt.probability.value_or(100);
        p.max_payloads =
            config_.passes.hash_self_decrypt.max_payloads.value_or(2);
        changed |= passes::hashGatedSelfDecryptModule(M, p, rng);
    }

    for (Function &F : M) {
        if (F.isDeclaration() || F.getName().starts_with("morok."))
            continue;

        const config::PassConfig eff =
            config::resolve(config_, moduleName, F.getName(), demangle);

        // Structural passes first: split creates more dispatch targets, then
        // bogus control flow widens the CFG, before the value-level passes.
        if (ir::shouldObfuscate(F, "split",
                                eff.split.enabled.value_or(false))) {
            passes::SplitParams p;
            p.splits = eff.split.splits.value_or(3);
            changed |= passes::splitBlocksFunction(F, p, rng);
        }

        if (ir::shouldObfuscate(F, "bcf", eff.bcf.enabled.value_or(false))) {
            passes::BcfParams p;
            p.probability = eff.bcf.probability.value_or(60);
            p.iterations = eff.bcf.iterations.value_or(1);
            changed |= passes::bogusControlFlowFunction(F, p, rng);
        }

        // PM-sensitive: for `-mllvm -morok` this runs from the plugin's
        // vectorizer-start callback. This scheduler fallback supports manual
        // `-passes=morok` placement without requiring a separate pass name.
        if (ir::shouldObfuscate(F, "optamp",
                                eff.opt_amplify.enabled.value_or(false))) {
            passes::OptAmpParams p;
            p.probability = eff.opt_amplify.probability.value_or(20);
            p.max_forms = eff.opt_amplify.max_forms.value_or(2);
            changed |= passes::optimizerAmplifyFunction(F, p, rng);
        }

        // Substitution before MBA, mirroring the documented ordering.
        if (ir::shouldObfuscate(F, "sub", eff.sub.enabled.value_or(false))) {
            passes::SubstitutionParams p;
            p.probability = eff.sub.probability.value_or(50);
            p.iterations = eff.sub.iterations.value_or(1);
            changed |= passes::substituteFunction(F, p, rng);
        }

        if (ir::shouldObfuscate(F, "mba", eff.mba.enabled.value_or(false))) {
            passes::MbaParams p;
            p.probability = eff.mba.probability.value_or(60);
            p.layers = eff.mba.layers.value_or(2);
            p.heuristic = eff.mba.heuristic.value_or(true);
            changed |= passes::mbaFunction(F, p, rng);
        }

        // Add small volatile-neutral webs after Sub/MBA have expanded scalar
        // expressions but before CFG-heavy passes make the local value graph
        // harder to place near the original operation.
        if (ir::shouldObfuscate(
                F, "threshold", eff.sub_threshold.enabled.value_or(false))) {
            passes::SubThresholdParams p;
            p.probability = eff.sub_threshold.probability.value_or(25);
            p.max_terms = eff.sub_threshold.max_terms.value_or(1);
            changed |= passes::subThresholdPersistFunction(F, p, rng);
        }

        // Alias-invariant guards widen the CFG after value-level expansion, so
        // their own pointer/int scaffolding does not get amplified by Sub/MBA.
        if (ir::shouldObfuscate(F, "aliasop",
                                eff.alias_op.enabled.value_or(false))) {
            passes::AliasOpParams p;
            p.probability = eff.alias_op.probability.value_or(45);
            p.iterations = eff.alias_op.iterations.value_or(1);
            p.max_blocks = eff.alias_op.max_blocks.value_or(16);
            changed |= passes::aliasOpaquePredicatesFunction(F, p, rng);
        }

        // Context-derived opaque predicates add side-effecting guard calls
        // before decoys and flattening absorb the widened CFG.
        if (ir::shouldObfuscate(F, "extop",
                                eff.external_op.enabled.value_or(false))) {
            passes::ExternalOpaqueParams p;
            p.probability = eff.external_op.probability.value_or(35);
            p.max_blocks = eff.external_op.max_blocks.value_or(8);
            p.decoy_stores = eff.external_op.decoy_stores.value_or(2);
            changed |= passes::externalOpaquePredicatesFunction(F, p, rng);
        }

        // Coherent dead paths use opaque-true guards but return plausible
        // alternate results, so flattening later absorbs them as real-looking
        // CFG structure rather than obvious junk.
        if (ir::shouldObfuscate(
                F, "decoy", eff.coherent_decoy.enabled.value_or(false))) {
            passes::CoherentDecoyParams p;
            p.probability = eff.coherent_decoy.probability.value_or(35);
            p.max_blocks = eff.coherent_decoy.max_blocks.value_or(4);
            p.depth = eff.coherent_decoy.depth.value_or(3);
            changed |= passes::coherentDecoysFunction(F, p, rng);
        }

        // Exactly one control-flow-flattening layer per function, after the
        // value-level passes: prefer non-invertible encoded states, then
        // data-entangled state updates, then the chaos state machine, then
        // plain flattening.
        bool flattened = false;
        if (ir::shouldObfuscate(
                F, "nistate",
                eff.non_invertible_state.enabled.value_or(false))) {
            passes::NonInvertibleStateParams p;
            p.max_terms = eff.non_invertible_state.max_terms.value_or(4);
            p.rounds = eff.non_invertible_state.rounds.value_or(3);
            flattened = passes::nonInvertibleStateFunction(F, p, rng);
            changed |= flattened;
        }
        if (!flattened &&
            ir::shouldObfuscate(
                F, "entfla",
                eff.data_entangled_flatten.enabled.value_or(false))) {
            passes::DataEntangledFlattenParams p;
            p.max_terms = eff.data_entangled_flatten.max_terms.value_or(4);
            flattened = passes::dataEntangledFlattenFunction(F, p, rng);
            changed |= flattened;
        }
        if (!flattened &&
            ir::shouldObfuscate(F, "csm", eff.csm.enabled.value_or(false))) {
            flattened = passes::chaosStateMachineFunction(F, rng);
            changed |= flattened;
        }
        if (!flattened && ir::shouldObfuscate(
                              F, "fla", eff.flatten.enabled.value_or(false))) {
            changed |= passes::flattenFunction(F, rng);
        }

        if (ir::shouldObfuscate(
                F, "stateop", eff.state_opaque.enabled.value_or(false))) {
            passes::StateOpParams p;
            p.probability = eff.state_opaque.probability.value_or(45);
            p.max_blocks = eff.state_opaque.max_blocks.value_or(16);
            p.max_terms = eff.state_opaque.max_terms.value_or(4);
            changed |= passes::stateOpaquePredicatesFunction(F, p, rng);
        }

        if (ir::shouldObfuscate(
                F, "ifsm",
                eff.interprocedural_fsm.enabled.value_or(false))) {
            passes::InterproceduralFsmParams p;
            p.probability =
                eff.interprocedural_fsm.probability.value_or(100);
            p.max_sites = eff.interprocedural_fsm.max_sites.value_or(64);
            p.max_terms = eff.interprocedural_fsm.max_terms.value_or(4);
            changed |= passes::interproceduralFsmSplitFunction(F, p, rng);
        }

        if (ir::shouldObfuscate(F, "phitangle",
                                eff.phi_tangle.enabled.value_or(false))) {
            passes::PhiTangleParams p;
            p.probability = eff.phi_tangle.probability.value_or(45);
            p.layers = eff.phi_tangle.layers.value_or(2);
            p.max_phis = eff.phi_tangle.max_phis.value_or(32);
            changed |= passes::phiTangleFunction(F, p, rng);
        }

        if (ir::shouldObfuscate(F, "typepun",
                                eff.type_pun.enabled.value_or(false))) {
            passes::TypePunParams p;
            p.probability = eff.type_pun.probability.value_or(35);
            p.include_floating = eff.type_pun.include_floating.value_or(true);
            p.max_targets = eff.type_pun.max_targets.value_or(64);
            changed |= passes::typePunFunction(F, p, rng);
        }

        // Collapse user and Reg2Mem-created locals after flattening has
        // introduced its frame slots, directly attacking lvar recovery.
        if (ir::shouldObfuscate(F, "stackcoalesce",
                                eff.stack_coalesce.enabled.value_or(false))) {
            passes::StackCoalesceParams p;
            p.probability = eff.stack_coalesce.probability.value_or(100);
            p.opaque_offsets = eff.stack_coalesce.opaque_offsets.value_or(true);
            changed |= passes::stackCoalesceFunction(F, p, rng);
        }

        // Launder the frame/GEP pointers introduced above and selected integer
        // SSA values through pointer-int and vector-scalar boundaries.
        if (ir::shouldObfuscate(F, "ptrlaunder",
                                eff.pointer_launder.enabled.value_or(false))) {
            passes::PointerLaunderParams p;
            p.pointer_probability =
                eff.pointer_launder.pointer_probability.value_or(80);
            p.integer_probability =
                eff.pointer_launder.integer_probability.value_or(35);
            changed |= passes::pointerLaunderFunction(F, p, rng);
        }

        // Integrity-bound byte tables consume selected byte ops before the
        // generic arithmetic table pass handles the remaining ones.
        if (ir::shouldObfuscate(
                F, "dfi", eff.data_flow_integrity.enabled.value_or(false))) {
            passes::DataFlowIntegrityParams p;
            p.probability =
                eff.data_flow_integrity.probability.value_or(35);
            p.max_tables =
                eff.data_flow_integrity.max_tables.value_or(2);
            p.region_bytes =
                eff.data_flow_integrity.region_bytes.value_or(32);
            changed |= passes::dataFlowIntegrityFunction(F, p, rng);
        }

        // Replace surviving byte arithmetic with encrypted lazy lookup tables.
        if (ir::shouldObfuscate(F, "tablearith",
                                eff.table_arith.enabled.value_or(false))) {
            passes::TableArithParams p;
            p.probability = eff.table_arith.probability.value_or(30);
            p.max_tables = eff.table_arith.max_tables.value_or(8);
            changed |= passes::tableArithmeticFunction(F, p, rng);
        }

        // Uniform primitive lowering moves byte ops to tables and selected
        // direct branch structure to memory-loaded indirect dispatch.
        if (ir::shouldObfuscate(
                F, "uniform", eff.uniform_lower.enabled.value_or(false))) {
            passes::UniformLowerParams p;
            p.op_probability =
                eff.uniform_lower.op_probability.value_or(25);
            p.branch_probability =
                eff.uniform_lower.branch_probability.value_or(35);
            p.max_tables = eff.uniform_lower.max_tables.value_or(4);
            p.max_branches = eff.uniform_lower.max_branches.value_or(8);
            changed |= passes::uniformPrimitiveLowerFunction(F, p, rng);
        }

        // SIMD lifting after the control-flow passes, so even dispatcher
        // arithmetic gets vectorised.
        if (ir::shouldObfuscate(F, "vobf", eff.vec.enabled.value_or(false))) {
            passes::VecParams p;
            p.probability = eff.vec.probability.value_or(40);
            p.width = eff.vec.width.value_or(128);
            p.shuffle = eff.vec.shuffle.value_or(false);
            p.lift_comparisons = eff.vec.lift_comparisons.value_or(true);
            changed |= passes::vectorObfuscateFunction(F, p, rng);
        }

        // Anti-DSE decoy loops run after flattening/vectorization so their
        // indirectbr regions do not block the CFG-structuring passes.
        if (ir::shouldObfuscate(F, "pathexplode",
                                eff.path_explosion.enabled.value_or(false))) {
            passes::PathExplosionParams p;
            p.probability = eff.path_explosion.probability.value_or(25);
            p.max_blocks = eff.path_explosion.max_blocks.value_or(4);
            p.max_iterations = eff.path_explosion.max_iterations.value_or(16);
            changed |= passes::pathExplosionFunction(F, p, rng);
        }

        // Fold the observed CFG order into a rolling accumulator, then guard
        // selected blocks and poison data/control only if the trace diverges.
        if (ir::shouldObfuscate(F, "tracekey",
                                eff.trace_keying.enabled.value_or(false))) {
            passes::TraceKeyParams p;
            p.probability = eff.trace_keying.probability.value_or(20);
            p.max_blocks = eff.trace_keying.max_blocks.value_or(8);
            changed |= passes::traceKeyFunction(F, p, rng);
        }

        // Dispatcherless routing converts remaining direct branches/switches to
        // local indirectbr table lookups after every CFG-structuring pass.
        if (ir::shouldObfuscate(F, "dispatchless",
                                eff.dispatcherless.enabled.value_or(false))) {
            passes::DispatcherlessRoutingParams p;
            p.probability = eff.dispatcherless.probability.value_or(50);
            p.max_routes = eff.dispatcherless.max_routes.value_or(32);
            p.max_terms = eff.dispatcherless.max_terms.value_or(4);
            changed |= passes::dispatcherlessRoutingFunction(F, p, rng);
        }

        // Feed a runtime checksum diff into constants as data, not a branch.
        if (ir::shouldObfuscate(F, "selfcheck",
                                eff.self_checksum.enabled.value_or(false))) {
            passes::SelfChecksumParams p;
            p.probability = eff.self_checksum.probability.value_or(35);
            p.max_constants = eff.self_checksum.max_constants.value_or(8);
            p.region_bytes = eff.self_checksum.region_bytes.value_or(32);
            changed |= passes::selfChecksumConstantsFunction(F, p, rng);
        }

        // Overlap several checksum nodes and poison selected return values
        // with the aggregate graph diff.  Constant encryption can still hide
        // the literals introduced in the user function.
        if (ir::shouldObfuscate(F, "mutualguard",
                                eff.mutual_guard.enabled.value_or(false))) {
            passes::MutualGuardGraphParams p;
            p.probability = eff.mutual_guard.probability.value_or(35);
            p.nodes = eff.mutual_guard.nodes.value_or(3);
            p.region_bytes = eff.mutual_guard.region_bytes.value_or(32);
            p.max_returns = eff.mutual_guard.max_returns.value_or(2);
            changed |= passes::mutualGuardGraphFunction(F, p, rng);
        }

        // Constant encryption hides the literals the other passes introduce.
        if (ir::shouldObfuscate(F, "constenc",
                                eff.const_enc.enabled.value_or(false))) {
            passes::ConstEncParams p;
            p.probability = 100; // encrypt every eligible literal when enabled
            p.share_count = eff.const_enc.share_count.value_or(2);
            p.iterations = eff.const_enc.iterations.value_or(1);
            changed |= passes::constantEncryptFunction(F, p, rng);
        }

        // Indirect branching last per function (it consumes the conditional
        // branches the other passes leave behind).
        if (ir::shouldObfuscate(F, "indibran",
                                eff.indir_branch.enabled.value_or(false))) {
            passes::IndirParams p;
            changed |= passes::indirectBranchFunction(F, p, rng);
        }
    }

    // Late whole-module call-graph confusion: keep original symbols but route
    // same-signature bodies through shared selector dispatchers, with selected
    // scalar fragments outlined into shared noinline helpers.
    if (config_.passes.adversarial_merge.enabled.value_or(false)) {
        passes::AdversarialMergeParams p;
        p.probability =
            config_.passes.adversarial_merge.probability.value_or(25);
        p.max_groups =
            config_.passes.adversarial_merge.max_groups.value_or(1);
        p.max_functions =
            config_.passes.adversarial_merge.max_functions.value_or(4);
        p.outline_probability =
            config_.passes.adversarial_merge.outline_probability.value_or(35);
        p.max_outlines =
            config_.passes.adversarial_merge.max_outlines.value_or(8);
        changed |= passes::adversarialFunctionMergingModule(M, p, rng);
    }

    // Module-level call-site wrapping runs after the per-function transforms so
    // it proxies calls into already-obfuscated functions.
    if (config_.passes.func_wrap.enabled.value_or(false)) {
        passes::FuncWrapParams wp;
        wp.probability = config_.passes.func_wrap.probability.value_or(50);
        wp.times = config_.passes.func_wrap.times.value_or(1);
        changed |= passes::functionWrapModule(M, wp, rng);
    }

    // Final seed-driven diversity layer: reorder the emitted IR layout and add
    // neutral volatile return anchors after every other configured transform.
    if (config_.passes.per_build_polymorphism.enabled.value_or(false)) {
        passes::PerBuildPolymorphismParams p;
        p.function_order =
            config_.passes.per_build_polymorphism.function_order.value_or(true);
        p.block_order =
            config_.passes.per_build_polymorphism.block_order.value_or(true);
        p.anchor_probability =
            config_.passes.per_build_polymorphism.anchor_probability.value_or(
                25);
        p.max_anchors =
            config_.passes.per_build_polymorphism.max_anchors.value_or(16);
        changed |= passes::perBuildPolymorphismModule(M, p, rng);
    }

    return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

} // namespace morok::pipeline
