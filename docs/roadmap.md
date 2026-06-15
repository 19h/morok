Scope: everything below is expressible as an LLVM pass (or a two-stage IR-pass + post-link rewriter, flagged where needed). Tags: **[IR]** pure IR; **[IR+rt]** IR pass emitting a runtime stub/libcall; **[MIR]** needs a MachineFunctionPass/backend awareness; **[link]** needs post-link/relocation cooperation; **[PM]** pass-placement matters.

## Off the table — what OLLVM/Hikari/forks already do

OLLVM: instruction substitution (fixed equivalent arith/bitwise rewrites); bogus control flow (algebraic opaque predicate `7y²−1≠x²`-class guarding a cloned junk block); control-flow flattening (one `switch` dispatcher + plaintext/optionally-encrypted state var); basic-block splitting; pass repetition.
Hikari: string encryption (ctor/lazy decrypt); integer/constant encryption; function wrapper (call forwarding); indirect branch / indirect call / indirect GV (jump/pointer tables, encrypted index); library-call obfuscation via `dlopen`/`dlsym`; anti-debug; anti-hook; anti-class-dump; split-BB.
Pluto/Arkari/goron: linear MBA substitution; alias-access/indirect-pointer; "enhanced" fla/bcf.

All of the above are signatured and have public deobfuscators (D-810, Triton/angr DSE, SiMBA/Qsynth for the MBA). Excluded entirely below.

## Design principle

An LLVM pass's real leverage is not instruction-level noise — it's (1) attacking the **decompiler's recovery stages** (CFG structuring, lvar/stack-frame recovery, type propagation, alias analysis), which OLLVM/Hikari never touch; (2) **aiming the optimizer and backend** to do the obfuscation for you so the artifact looks like idiomatic optimized code (no obfuscation signature); (3) **per-build polymorphism** so diffing/FLIRT fail. Each technique below names the analyst capability it structurally breaks.

## A. Beyond flattening — break CFG structuring

- **State-variable data-entanglement (de-flattening killer) [IR].** OLLVM's dispatcher state var is *control-only and dead w.r.t. data*, so D-810/Triton backward-slice it out. Instead make `next_state = f(live_program_value, prev_state)` — fuse the FSM index into real data flow so any slice of the state pulls in the whole computation and the FSM can't be isolated.
- **Interprocedural FSM splitting [IR, Module].** Per-function deobfuscators die when the machine spans functions. Hoist alternating dispatcher states into callees, thread state through args/returns/globals, use mutually-recursive dispatchers. No single function contains the FSM.
- **Dispatcherless flattening [IR].** Replace the central `switch` with a DAG of `indirectbr`s whose targets are computed indices into a block-address table, index derived from the entangled state. Defeats every "find the dispatcher" heuristic — there is no switch and no separable state var. (Distinct from Hikari indirect-branch, which leaves CFG topology and structuring intact and only indirects edges.)
- **Non-invertible next-state [IR].** Compute the successor index through a one-way step (keyed PRF/perfect-hash of the entangled state), precomputed-correct at build time, so static successor enumeration fails and DSE must invert.

## B. Break variable/type recovery (the Hex-Rays lvar/microcode layer — your value layer)

- **Single-buffer stack coalescing (lvar killer) [IR].** Emit one `alloca [N x i8]`; realize every "local" as a GEP at a computed (optionally runtime-perturbed) offset, with deliberately overlapping live ranges. Hex-Rays sees one opaque buffer + pointer arithmetic, not N typed lvars — stack-frame and type recovery collapse. OLLVM/Hikari leave the frame pristine; this is the highest-leverage decompiler-specific attack.
- **Pointer/integer laundering [IR].** Cycle SSA values through `ptrtoint`/`inttoptr`/`bitcast` and computed-offset GEPs. Triple effect: LLVM's own AA loses precision (carries into weaker downstream recovery, blocks opt-based deobf), decompiler type propagation mistypes, DSE symbolic memory blows up.
- **Type-punning chains [IR].** Round-trip scalars through unions/vector↔scalar bitcasts so the microcode type system assigns conflicting types and structure recovery drifts.
- **SSA/phi tangling [IR].** Introduce dense cross-block phi webs (via the entangled state + redundant copies) so expression propagation emits deeply nested / duplicated expressions.
- **Stack-pointer-delta games [MIR].** Emit code lowering to dynamic SP deltas and odd/overlapping slot sizes that defeat `mba_t` stack allocation and force goto output. (See §I.)

## C. Resilient opaque predicates (not OLLVM's algebraic, signatured class)

- **Pointer/aliasing-invariant OPs [IR].** Build a small heap structure at runtime, maintain an invariant, branch on it (Collberg-style). LLVM AA can't prove the invariant → optimizer won't fold it; no public signature, unlike the number-theoretic identities. This is a *different hardness class*, not a different formula.
- **External/volatile-derived OPs [IR].** Seed the predicate from a `volatile` load or an IPO-blocked external return the optimizer cannot constant-fold (SCCP/CVP/InstCombine pass it through).
- **MBA-over-entangled-state OPs [IR].** Express the predicate as MBA over the data-entangled state var so it can't be sliced or normalized (stateful → SiMBA/Qsynth's purity assumption fails).
- **Coherent decoy dead paths [IR].** Fill the dead arm with a *plausible alternate implementation*, not junk, so live/dead can't be told apart. (Adjacent to BCF; the differentiator is semantic coherence of the decoy.)

## D. Aim the optimizer/backend (it does the obfuscation; output has no obfuscation signature)

- **Optimizer-amplified shapes [IR+PM].** Place the pass early (new-PM, before the vectorizers) and emit IR that `-O3` aggressively unrolls, vectorizes (SLP/loop), strength-reduces, and reassociates into idiomatic-but-unrecognizable optimized code. The result reads as a normal optimized binary yet is semantically far from any clean form.
- **Forced scalarβ†’SIMD lowering [IR].** Rewrite scalar integer logic into `<N x iM>` ops + `shufflevector` so the decompiler renders simple arithmetic as opaque vector intrinsics (`__m128i …`) — high analyst cost, zero signature.
- **Sub-threshold persistence [IR+PM].** Tune constructs to sit just below InstCombine/GVN folding thresholds so they survive canonicalization intact.

## E. Alien computational substrate, IR-expressible

- **Arithmetic-as-table [IR].** Replace small-width binary ops with `load` from per-build precomputed global tables indexed by the operands (i8⊕i8 → 64KB table; tables-of-tables for wider). The arithmetic identity is gone; the decompiler shows array indexing. Encrypt + lazily materialize tables to deny static recovery.
- **Uniform-primitive lowering [IR/MIR].** Compile all branches to arithmetic-`select` + computed memory dispatch and all ops to table loads — a MOV-only-style uniformity where no instruction reveals intent (the IR/MIR analogue of movfuscator), defeating opcode-histogram and dispatch-recognition heuristics.
- **Custom devirt-resistant VM via pass [IR/IR+rt].** Lift selected functions to a per-build bytecode ISA and emit the interpreter in IR. Differentiators from VMProtect/Themida/Tigress: cross-language (IR-level), native↔bytecode interleave, **threaded/computed-goto dispatch — no central decode switch, so devirt has no anchor**, polymorphic/duplicated handlers (defeats one-handler-per-opcode matching), per-instruction bytecode decryption keyed on the VM PC (a static dump never holds the whole program), randomized operand encoding per build. This is the single biggest item and is squarely a Module pass.

## F. Anti-DSE / anti-symbolic (real adversary lifts to Triton/angr from your binary)

- **Path-explosion injection [IR].** Insert input-dependent loops with symbolic bounds + per-iteration symbolic stores and input-derived indirect jumps the engine can't statically bound.
- **Execution-trace keying [IR/IR+rt].** Fold each obfuscated block into a rolling-hash accumulator; key block decryption / an opaque predicate on the accumulator. Static analysis can't predict it; single-step/replay/instrumentation perturbs ordering → wrong key → divergence (an entangled, non-separable anti-debug — nothing to NOP). The IR-implementable form of context keying; beats concolic input-solving because the key isn't a function of input.
- **Hash-gated self-decrypting blocks [IR+rt+link].** Store the block as an encrypted global; emit decrypt + W^X (`mprotect`/`VirtualProtect`) + indirect-call stub, key from preimage/trace. Caveats: producing the encrypted *native* form at IR time is chicken-and-egg — do it in the post-link stage, or encrypt **VM bytecode** instead to sidestep native W^X (mandatory on iOS/macOS codesign — relevant given Hikari's lineage).

## G. Tamper-entanglement (not separable runtime checks like Hikari's anti-debug)

- **Self-checksum-fused constants [IR+rt+link].** Replace constant `K` with `K' = K ⊕ h(code_region)`; recompute `K = K' ⊕ h` at runtime. The hash feeds *data*, not a branch — a patched byte silently corrupts output; there is nothing to NOP. Needs post-link sizing.
- **Data-flow-entangled integrity [IR+rt+link].** Generalize: derive live data tables from the program's own bytes so any modification poisons results intrinsically.
- **Mutual-guard graph [IR+rt+link].** Emit many overlapping checkers that verify each other's bytes; resilience scales with graph connectivity, not one chokepoint (post-link fills sizes/offsets).

## H. Defeat diffing / signatures

- **Adversarial function merging + outlining [IR/MIR].** Repurpose MergeFunctions to fuse *unrelated* functions behind a hidden selector, and outline mid-block fragments into shared helpers chosen to maximize call-graph and function-boundary confusion. FLIRT/BinDiff/Diaphora similarity and call-graph recovery break (mark `noinline` so downstream inlining doesn't undo it).
- **Per-build polymorphism [IR].** Seed every randomized choice (substitution patterns, block order, handler encodings, table layouts, bytecode ISA) → structurally distinct binaries per build; signatures and inter-version diffing fail. Layer over everything above.

## I. Hex-Rays-microcode-targeted (meta — you build the adversary)

- **Microcode-optimizer DoS/misdirection [MIR/asm-aware].** Emit IR lowering to MIR/asm that hits pathological microcode behavior across maturity levels: dynamic SP deltas, odd/overlapping stack-slot sizes, sparse/oversized jump tables that defeat `mba` simplification and force goto-spaghetti, aliased memory the type system can't resolve. Tune to make the optimizer bail or mis-optimize (output decompiles but is unreadable or subtly wrong).
- **Adversarial self-tuning [IR + harness].** Treat the target decompiler as a black-box oracle; search the transformation space to maximize its failure metric (microcode node count, lvar-recovery error, emitted-SMT size for a downstream DSE, BinDiff distance). Obfuscation that fits its specific adversary — the most promising open direction, and you have ground-truth oracle access.

## Strongest compounds

A trace-keyed, lazily-decrypted **bytecode VM** (E+F) with **interprocedural entangled dispatch** (A), arithmetic-as-table (E) inside polymorphic handlers, **single-buffer stack + pointer laundering** (B) throughout, **self-checksum-fused constants** (G), all **per-build diversified** (H) and **adversarially tuned** to your microcode optimizer (I). Each layer breaks a different recovery stage, so no single tool advance collapses the stack.

## Implementation reality & known weaknesses (design around these)

- **Two-stage pipeline is mandatory** for self-decrypt/integrity: the IR pass marks/reserves and emits stubs; a post-link rewriter (objcopy-class) fills encrypted payloads, sizes, and checksums after addresses are fixed.
- **Entangled-state flattening** only resists slicing if the fusion is genuine (shallow entanglement is still sliceable).
- **VM** is pattern-recoverable if dispatch centralizes or handlers aren't diversified; the bytecode key is recoverable unless PC/trace-bound; expect 10–100× slowdown on lifted functions — virtualize only hot-secret code.
- **Trace keying** is timing/order-fragile and hostile to testing; LTO/PGO reordering can break it — freeze accumulator points and exclude from late reordering.
- **Table arithmetic** explodes past 16-bit operands and the tables are themselves static unless encrypted + lazily materialized; cache cost is real.
- **Native self-decrypt** trips AV/EDR RWX heuristics and is forbidden under iOS/macOS W^X codesign → use the bytecode-VM form there.
- **Optimizer-aimed** results vary across LLVM versions (nondeterministic) — pin the toolchain per release.
- **Merge/outline** hurts perf and can be undone by aggressive downstream inlining (`noinline`, place late).
- **Any input-only gating** falls to concolic input-solving — always prefer trace/context keys.
