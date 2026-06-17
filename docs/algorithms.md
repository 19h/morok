# Morok — algorithm reference

This is the porting cheat-sheet linking each obfuscation pass to its pure core
(`include/morok/core/*`) and recording the IR-emission details that live in the
pass layer rather than the math layer.  The *math* of every item below is
implemented and exhaustively tested in `morok_core`; this document records the
*plumbing* a New-PM pass must add around it.

All integer identities hold in the ring Z/2ⁿ (two's-complement wraparound).

## PRNG & seeding — `core/Splitmix64`, `core/Xoshiro256`, `core/Random`, `core/Entropy`
- Engine: xoshiro256++ (period 2²⁵⁶−1).  `fromSeed(u64)` for deterministic runs,
  `makeSeededEngine()` for entropy-seeded production runs.
- Bounded sampling: `boundedU32` (rejection, no modulo bias), `rangeU32`, `chance(pct)`.
- splitmix64 reference vector: `Splitmix64::mix(0) == 0xE220A8397B1DCDAF`.

## Instruction substitution — `core/SubstitutionIdentities`
- Driver: eligible = `isBinaryOp() && type->isIntegerTy()`. Opcodes dispatched:
  Add/Sub/Mul/Shl/LShr/AShr/And/Or/Xor. Skips F* and divisions.
- Per-instruction probability `sub_prob` (default 50), sweeps `sub_loop` (default 1).
  Acceptance test is `get_range(100) <= prob`. Variant chosen by `get_range(N)`.
- Variant counts: Add 13, Sub 10, And 10, Or 10, Xor 12, Mul 7, Shl/LShr/AShr 2.
- Shifts only substituted when shift amount is a `ConstantInt`; LShr/AShr skip k==0;
  all skip k>=width. AShr identity = "XOR distributes over arithmetic shift".
- One-bit arithmetic identities lower `2*x` to zero instead of `x << 1`, because
  shifting an `i1` by one would be poison even though the mathematical value is
  zero modulo 2.
- Direct memory cap: each sweep collects at most 256 target binary operators.
  Larger functions are partially transformed rather than expanding every
  eligible operation in one pass invocation.

## Mixed Boolean-Arithmetic — `core/MbaIdentities`
- Variant counts: Add 8, Sub 7, Xor 7, And 8, Or 7, Mul 5. `mba_prob` (default 60),
  `mba_layers` (default 2, clamp 1..3), `mba_heuristic` (default true).
- Layers compound: layer L+1 sees layer L output. Each layer collects at most
  256 target binary operators, so MBA cannot compound across an unbounded
  eligible set in one pass invocation.
- Heuristic noise = `zeroTerm` (k terms) added/subtracted; always nets to 0.
- Carry lemma `x+r == (x^r)+2*(x&r)` underpins the random-constant variants.
- Constant shifts are also rewritten (mirroring substitution): `shl a, k` ⇒
  `a * 2^k`; `lshr a, k` ⇒ `(a & high-bits) >>u k`; `ashr a, k` ⇒
  `((a^r) >>s k) ^ (r >>s k)`.  Variable / out-of-range shift amounts stay
  untouched.

## String encryption — `ir/SymbolCloak` keystream
- *Every* eligible private i8-array global is encrypted with its OWN cipher: a
  per-string keystream generator (murmur3 / splitmix64 / xorshift\*, chosen per
  string), XOR- or ADD-combined, with per-string key material
  `k0 = (seedVal + volatile-stable-zero) ^ siteKey` and an odd multiplier.  No
  two strings share an encryption.
- Recovery is stack-first and per use site for constant C strings whose uses are
  direct noncapturing call/invoke arguments.  Each such pointer operand gets a
  fresh `morok.str.stack.buf` alloca and a call to a private per-site
  `morok.strsite` helper that fills the buffer immediately before the use.
  Short helpers are unrolled; long helpers run a local `morok.str.stack.loop`.
  No global constructor or shared decrypt helper is emitted for those sites.
- If a string has unsupported uses where address identity or global mutation may
  matter, the pass falls back to the old distributed constructor model: one
  private `morok.strdec` constructor for that string only, with the keystream
  inlined and randomized constructor priority.  There is still no single place
  that decrypts every string.
- Keyed on the runtime-opaque module seed `morok.cloak.seed` (a private *mutable*
  i64 read with a volatile load), so the optimizer cannot fold ciphertext back to
  text.  The runtime key path is perturbed through a volatile stack slot whose
  two loads cancel at runtime; this preserves bytes exactly while avoiding a
  single static `seed ^ key` signature.  Recovered stack pointers are separated
  from the consuming call by a target inline-asm barrier with a memory clobber.
  *Mutable* string globals (which the program may itself read/write or decrypt in
  place) use exactly this in-place model so the program observes the recovered
  plaintext.
- Generated `morok.decoy.str.*` globals are deliberately excluded from string
  encryption.  They are honeypot plaintext for cheap triage tools like
  `strings`; encrypting them removes the bait and makes the binary look cleaner
  than intended.
- Length hiding: read-only C strings are padded to a random multiple of a block
  size (16) with random trailing bytes before encryption.  The runtime consumer
  still stops at the original NUL, but the stored array size no longer reveals
  the string's length.  Raw (non-C-string) byte arrays keep their exact size.
- `strcry_prob` default 100; per-string coin leaves a string clear when it loses.
  Caps are sized only to bound pathological inputs (≤ 8192 strings, ≤ 1 MiB per
  string, ≤ 8 MiB per module), not to leave strings in the clear.

## VTable integrity — Itanium ABI virtual-dispatch guards
- The pass recognizes C++ Itanium ABI vtables (`_ZTV*`) and flattens pointer
  entries by byte offset.  Vptr address points are harvested from constructor
  stores first, with a conservative fallback that treats only the first function
  entry after two non-function metadata entries as an address point.
- Recognized dispatch sites are the common LLVM shapes `load vptr -> gep slot
  -> load target -> indirect call`, covering both pointer-index GEPs and
  byte-offset GEPs.  Arbitrary indirect calls without a loaded object vptr are
  ignored.
- The emitted private tables store expected vptr address points, slot offsets,
  expected targets, and deterministic per-entry cookies.  Each guarded call
  invokes `morok.vti.verify(vptr, slot, target)` immediately before dispatch.
  The verifier matches vptr+slot, recomputes a mixed pointer/slot/cookie hash
  for the live and expected target, and traps on mismatch or unknown vptr.
- Direct caps bound harvesting to 256 address points and 1024 guard entries, so
  pathological C++ modules cannot explode memory or IR size.  Generated
  `morok.vti.*` helpers are eligible for the scheduler's sensitive-helper
  hardening shell.
- Scheduler placement is after StringEnc/FCO and before VM/per-function
  transforms.  At that point strings/imports have been handled, while virtual
  dispatch still has recognizable vptr/slot load structure.

## Constant encryption — `core/XorShare`, `core/Feistel`
- Pipeline: `origC ─[Feistel if feistel && bits>=16]→ workC ─[k-share XOR or single XOR]→ shares`.
  Runtime reverses: XOR-fold shares → workC → inverse Feistel → origC.
- k-share when `k>=3` (k clamp 2..8), else classic single-XOR for selected
  `i1` through `i64` integer constants and scalar `half`/`bfloat`/`float`/
  `double` constants in binary, comparison, `select`, cast, PHI incoming,
  conditional branch/switch conditions, return, store-value, and ordinary
  call-argument operands.  Floating constants are shared as their raw integer
  bit pattern and bitcast back at the use, preserving NaN payloads and signed
  zero exactly.  Branch destinations, store pointers, callees, GEP indices,
  switch cases, intrinsic immediates, and operand bundles remain structural and
  are never rewritten.  Shares: private non-const `morok.share` globals loaded
  volatilely at each rewritten use.  PHI incoming constants are reconstructed on
  the corresponding predecessor edge; conditional predecessors are split first
  so volatile reconstruction does not execute on an untaken edge.
- Feistel: balanced, 4 rounds, per-round odd multiplier + xor key (random, masked to
  half width). `feistelEncrypt/Decrypt(value, bits, keys)`.
- Flags: `constenc_times` 1, `constenc_kshare` 2, `constenc_feistel` off,
  `constenc_subxor` off / `_prob` 40, `constenc_togv` off / `_prob` 50.
  Max-mode forces kshare=4, feistel=true. `skip_value`/`force_value` regex on hex.
- Direct memory cap: each constant-encryption sweep rewrites at most 128
  literal operands.  With the default two-share mode that bounds new share
  globals to 256 per function per sweep.

## Data-entangled flattening — IR structure
- The pass reuses the standard switch dispatcher, but replaces direct
  `state = successor_id` stores with `successor_id ^ token ^ token`.  `token`
  is mixed from the previous dispatcher state, the current block id, branch
  guards, and up to `max_terms` live scalar integer/FP-producing instructions
  from the block being rewritten.
- The duplicate token is stored to two volatile slots in an `alloca [2 x i32]`
  named `entfla.shadow`, then reloaded and xored together.  Runtime semantics
  are unchanged because both slots receive the same token, while optimizer and
  decompiler slices must keep the state/data dependency instead of seeing a
  plaintext successor constant.
- This remains a standalone and fallback flattening layer.  The scheduler
  prefers NonInvertibleState when enabled, then this pass, then CSM/plain
  flattening; only one flattening family runs per function.

## Non-invertible next-state — IR structure
- The pass uses the same dispatcher skeleton as flattening, but logical
  per-block successor ids are distinct from the concrete switch case labels.
  Case labels are generated by a per-build keyed lossy hash; the flattener keeps
  logical ids out of the dispatcher state domain and only stores encoded ids.
- Each rewritten terminator selects a logical successor id, mixes the previous
  encoded state, the current logical block id, branch guards, and up to
  `max_terms` live scalar integer/FP values into `nistate.token`, then
  stores/reloads that token through two volatile `nistate.shadow` slots.  The
  volatile xor cancels to zero at runtime but keeps the data dependency in the
  slice.
- The actual store is `nistate.next = H(logical_successor ^ volatile_zero)`,
  where `H` is emitted as several keyed rounds of 64-bit multiply high/low
  folding and an explicit 31-bit mask.  The mask makes the map non-injective in
  the full i32 domain; the pass chooses logical ids until all encoded case
  labels are unique and disjoint from raw logical ids.
- This targets de-flatteners that match plaintext state constants or invert
  `next_state` expressions.  They can still enumerate switch destinations, but
  the transition expression no longer exposes a direct successor-id constant to
  case-label lookup.

## Stateful MBA opaque predicates — IR structure
- This pass requires an existing flattened dispatcher state alloca named
  `fla.state`, so it runs after NiState/EntFla/CSM/plain flattening.  Selected
  blocks are split and guarded with an opaque-true predicate before their first
  real instruction.
- The predicate loads the current dispatcher state, mixes it with scalar integer
  and floating-point function arguments/live values into `morok.stateop.token`,
  then stores that token to two volatile slots in `morok.stateop.shadow`.
  Floating-point terms (`half`, `bfloat`, `float`, `double`) are bitcast to
  equal-width integer carriers and reduced to the i32 token width.  The volatile
  reloads xor to zero at runtime but remain opaque to InstCombine and scalar
  symbolic simplifiers.
- The guard checks an MBA identity over the state:
  `(((state^k)+token')^m)^m-token' == state^k`, where `token'` includes the
  volatile cancellation.  Runtime truth is guaranteed, but the expression is
  stateful and entangled with flattened-control state rather than a pure
  algebraic formula.
- The false edge enters `morok.stateop.false`, performs a volatile shadow write,
  then rejoins the body.  The pass skips unflattened functions, generated
  stateop/IFSM/path blocks, EH pads, and entry-block setup.

## Interprocedural FSM splitting — IR structure
- The pass composes after any flattening family by finding non-entry stores to
  `fla.state`.  Each selected transition store is replaced with a call to one of
  two private helpers, `morok.ifsm.step.a/b`, and the store writes the helper's
  return value instead of the locally-computed next-state expression.
- The helper signature is `i32(i32 current, i32 proposed, i32 token, ptr thread,
  i32 phase)`.  `current`, the proposed next state, and a live-data token are
  threaded through arguments; `thread` is a private volatile global
  `morok.ifsm.thread`.  The token mixes live scalar integer and FP terms visible
  before the transition store; FP terms (`half`, `bfloat`, `float`, `double`)
  are bitcast to equal-width integer carriers and reduced to i32.  Helper A
  calls helper B at phase 0, helper B calls helper A at phase 0, and phase 1
  returns after unmasking the state.
- Runtime semantics are identity: the helper returns `proposed`.  The returned
  value is deliberately reached through one bounded mutual-recursion step,
  volatile global load/store, current-state masking, and token cancellation, so a
  per-function de-flattener no longer sees the whole FSM transition relation in
  the flattened function.
- Scheduler placement is immediately after NiState/EntFla/CSM/plain flattening
  and before PHI tangling/stack work.  The pass skips initial entry-block state
  stores and already-wrapped IFSM calls, so it is idempotent under repeated runs.

## Dispatcherless routing — IR structure
- Selected direct branch and switch terminators are rewritten to local
  `indirectbr` instructions through a private per-function `morok.dlf.table` of
  `blockaddress` entries.  There is no central dispatcher block or switch for a
  de-flattener to identify.
- The table index is the original selected successor id xored with a volatile
  zero term.  That zero term is built from two volatile shadow loads after
  storing the same token to `morok.dlf.shadow[0/1]`; the token is mixed from the
  previous `morok.dlf.state` and up to `max_terms` live scalar integer/FP
  values from the source block.  FP terms use the same equal-width integer
  bitcast and i32 reduction as the flattened state-token passes.
- Route selection has hard standalone ceilings of 32 route sites, 8 mixed live
  terms per site, and 32 successors per site.  Larger functions are partially
  routed, and very large switches are left direct.
- PHI correctness is preserved because each original predecessor still
  terminates to the same possible successors, only via `indirectbr`.  The pass
  skips EH pads, generated `morok.*` blocks, and entry-block targets.
- The scheduler runs this late, after flattening and path-explosion, so it
  removes remaining direct CFG edges without blocking earlier CFG transforms.

## Chaos state machine — `core/LogisticMap` / `core/TFunction`
- The CSM flattening slot now has a generator selector.  `generator=logistic`
  emits the original Q16 logistic step `r*x*(1-x)` with r encoded as 65533,
  `>>30`, and zero guards.  `generator=tfunction` emits the Klimov-Shamir
  quadratic T-function `step(x) = x + (x*x | C) mod 2^32`.
- T-function constants are valid when `C mod 8` is 5 or 7.  `tf_const=0` means
  the pass draws a per-build valid constant from the shared PRNG; an invalid
  configured constant also falls back to a random valid one.  The first
  `numBlocks` states are guaranteed distinct within the 32-bit dispatcher
  domain because this family is a single 2^n-cycle permutation.
- Transitions keep the existing telescoping form:
  `next = step(current) ^ correction(i,j)`, where
  `correction(i,j)=step(case_i)^case_j`.  The runtime step is nonlinear
  (`mul`/`or`/`add`) and the compile-time correction lands exactly on the target
  dispatcher id, so the switch skeleton and downstream StateOpaque/IFSM passes
  compose unchanged.
- Standalone `morok-csm` uses the default logistic generator for compatibility.
  Standalone `morok-tfa` runs the same flattener with `generator=tfunction`.
  In the scheduler, mid/high presets select the T-function generator; the CSM
  slot still participates in the same precedence cascade:
  NonInvertibleState → DataEntangledFlattening → CSM → plain Flattening.

## Stack coalescing — IR structure
- Eligible locals are static entry-block allocas in address space 0 with fixed,
  non-scalable allocation size and local-only memory uses.  Allocas whose
  address escapes (stored as a pointer, returned, passed to unknown calls, or
  observed by ptr/int code) are deliberately skipped.
- Selected slots are shuffled per build, aligned with the module DataLayout,
  and packed into one `alloca [N x i8]` named `morok.stack`; the replacement
  pointers are byte-addressed GEPs into that frame.
- With `opaque_offsets` enabled, each slot offset is stored as a private mutable
  global encoded by XOR with a per-slot key, loaded volatilely, then decoded in
  the entry block.  This keeps the frame as pointer arithmetic instead of typed
  locals in the IR handed to the backend/decompiler.
- Lifetime markers naming coalesced allocas are removed, because LLVM lifetime
  intrinsics may only name an alloca or poison after opaque pointers.

## Stack-pointer-delta games — IR-forced backend structure
- This is the target-independent IR form of the roadmap's MIR stack-delta item.
  Selected blocks are split and prefixed with `llvm.stacksave`, a bounded
  variable-sized `alloca i8, morok.stackdelta.size`, odd-offset volatile stack
  writes, and `llvm.stackrestore`.
- The dynamic size is derived from a volatile private `morok.stackdelta.seed`
  load, scalar integer/FP arguments and live terms visible at the split point, a
  per-build salt, an odd minimum byte count, and a bounded `max_extra_bytes`
  mask.  Floating terms are bitcast to same-width integer carriers before the
  i64 mix reduction, so FP-heavy code still contributes live data to the dynamic
  stack size.  The allocation is therefore not a static frame object the
  decompiler can fold into ordinary typed locals.
- The volatile stores deliberately overlap: an unaligned i64 write at byte
  offset 1 is followed by configurable i8 writes at offsets inside that word.
  Runtime program data is unchanged, but the backend must materialize irregular
  stack memory and stack-pointer movement.
- `stackrestore` runs before the original body, so loops do not accumulate
  unbounded dynamic allocations.  The pass skips generated `morok.*` functions,
  EH pads, landing pads, naked functions, and generated stack-delta blocks.
- Scheduler placement is after StackCoalescing and before PointerLaundering:
  static locals are first folded into the opaque frame, then stack deltas are
  added, then later pointer laundering can further obscure stack accesses.

## Pointer/integer laundering — IR structure
- Pointer operands of loads, stores, GEPs, atomics, memory intrinsics, ordinary
  call arguments, and returns are laundered when their address space is integral
  and target rules allow both `ptrtoint` and `inttoptr`.  Non-integral/unstable
  pointer spaces are skipped.  Callees, operand bundles, intrinsics, inline asm,
  and musttail-sensitive positions remain structural and are not rewritten.
- Runtime shape: `ptr -> ptrtoint -> xor volatile-key -> xor same-key ->
  inttoptr -> gep i8, computed-zero`.  The value is unchanged, but LLVM AA and
  downstream type recovery must cross an explicit integer/pointer boundary.
- Scalar SSA values are laundered through a byte-vector view.  Integer widths
  from `i1` through `i1024` use
  `iN -> <N/8 x i8> -> shufflevector identity -> iN`; sub-byte and odd widths
  first zero-extend to the smallest covering byte width, then truncate back
  after the identity shuffle.  Scalar FP values (`half`, `bfloat`, `float`,
  `double`) first bitcast to equal-width integer carriers, then return through
  the same byte-vector path.  The extra high bits are never observed, while
  decompilers still have to reconcile the conflicting scalar/vector views.
- Direct memory caps: each invocation launders at most 128 pointer operands and
  at most 128 scalar SSA values.

## Type punning — IR structure
- Eligible scalar-producing instructions (`i1` through `i1024`, `half`,
  `bfloat`, `float`, `double`), including ordinary PHI results, are stored into
  a local store-size `alloca [N x i8]` union buffer with a volatile typed store,
  then reloaded volatilely through a conflicting view.  PHI result punning is
  inserted after the block's PHI cluster; EH-pad PHIs and PHI-to-PHI edge uses
  are skipped to preserve LLVM placement and edge-use rules.
- Byte-multiple integer scalars reload as `<N x i8>` byte vectors and bitcast
  back.  Non-byte-multiple integers are zero-extended to the covering byte-sized
  integer, reloaded, and truncated back to the exact source width.  Floating
  scalars reload as same-width integers and bitcast back.  The value/bit pattern
  is unchanged while the IR exposes contradictory scalar/vector/integer views.
- `max_targets` caps per-function punning after a per-build shuffle.  This is
  the same guardrail class as substitution/MBA throttles: high-value type noise
  without unbounded compile-time growth after MBA/substitution expansion.
- The pass runs before StackCoalescing in the scheduler so these union buffers
  can be folded into the single opaque frame and then pointer-laundered.

## PHI tangling — IR structure
- Eligible values are scalar integer PHIs of any bit width and scalar
  half/bfloat/float/double PHIs with at least two normal predecessor edges.  EH
  pads, landing pads, invoke predecessors, unsupported aggregate/vector/pointer
  PHIs, and generated Morok PHIs are skipped so the inserted edge copies have
  legal placement and do not reprocess the pass's own scaffolding.
- For each selected PHI incoming edge, the pass materializes an edge-local copy
  `x ^ k ^ k`.  Floating-point incoming values are bitcast to equal-width
  integer carriers for that xor and bitcast back before entering the copied edge
  PHI.  It then builds a copied edge PHI and a direct PHI over the same incoming
  values, xors those together over their integer carriers to form a zero
  cross-term, and xors that term into the original value before replacing
  downstream non-generated uses.
- `layers` repeats the redundant web for the same selected value, while
  `max_phis` caps the number of selected PHIs after a per-build shuffle.  This
  gives decompilers extra cross-block SSA pressure without unbounded IR growth.
- The pass runs after CSM/Flattening because those transforms introduce the
  dispatcher PHIs worth tangling, and before TypePunning/StackCoalescing so the
  resulting values can still be reinterpreted and folded into later noise.

## Alias opaque predicates — IR structure
- Each transformed function gets one `alloca [3 x i64]` cell named
  `morok.aliasop.cell`.  A selected block maintains the invariant
  `slot1 == slot0 ^ slot2`, where `slot0` is derived from the cell address and
  a per-build salt, and `slot2` is a per-build odd key.
- Stores and loads are volatile and reached through `ptrtoint -> xor key -> xor
  key -> inttoptr` aliases before the guard compares `(slot0 ^ slot2) == slot1`.
  The branch is always true at run time, but proving that requires memory/alias
  reasoning instead of simplifying a pure algebraic predicate.
- The false edge enters a coherent decoy block that performs additional aliased
  loads/stores before rejoining the original body.  No PHI repair is needed
  because the original block is split before its first non-PHI/non-alloca
  instruction.
- `max_blocks` caps transformed blocks per function across all iterations,
  keeping the CFG pressure explicit instead of allowing BCF-amplified functions
  to dominate compile time.
- This pass runs after Substitution/MBA and before flattening: it still widens
  the CFG before dispatcher construction, but its own pointer/int scaffolding is
  not amplified by value-level rewrites.

## External/volatile-derived opaque predicates — IR structure
- Each selected block is split before its first non-PHI/non-alloca instruction
  and guarded by two calls to an internal `morok.extop.context` helper.  The
  helper is `noinline`/`optnone`, has unknown memory effects, and volatile-loads
  a private mutable `morok.extop.seed` global before mixing the call-site
  function pointer and a per-build tag.
- The two helper calls use identical arguments, so their xor is zero at runtime
  and the guard is always true.  The predicate is nevertheless not a pure
  algebraic identity: simplifying it requires proving through side-effecting
  calls, volatile memory, and IPO-blocked helper semantics.
- The false edge enters a `morok.extop.decoy` block that performs configurable
  volatile loads/stores against `morok.extop.scratch` before rejoining the real
  body.  This gives the dead arm memory/context behavior instead of obvious
  junk, while keeping PHI repair unnecessary because the split preserves the
  original predecessor relation.
- The standalone pass skips generated `morok.*` functions by default, plus EH
  pads, landing pads, and generated `morok.extop.*` blocks.  The scheduler can
  opt back into generated functions only for its sensitive-helper allowlist.
  `max_blocks` caps transformed blocks per function; `decoy_stores` controls
  scratch-store density.
- Scheduler placement is after AliasOpaquePredicates and before CoherentDecoys
  and flattening.  That layers a volatile/context hardness class on top of
  alias-invariant predicates before later CFG passes absorb the extra edges.

## Sensitive-density boosting — scheduler behavior
- A function annotated `__attribute__((annotate("sensitive")))` gets denser
  BCF/MBA/ExternalOpaque treatment without changing global presets: unset
  enable flags are treated as enabled for those three families, BCF/extop block
  probabilities are raised to 100, MBA probability is raised to 100, MBA keeps
  at least two layers, and extop gets larger block/store caps.  For this
  `sensitive` boost, explicit `nobcf`/`nomba`/`noextop` annotations and
  explicit disabled config fields keep the family off.
- Generated protection helpers are normally skipped by the per-function loop
  because their names start with `morok.`.  After per-function passes finish
  emitting helpers, the scheduler applies the same dense BCF/extop/MBA shell to
  an allowlist of sensitive helpers: per-string decryptors, hash-gated bytecode
  ensure functions, table/DFI/self-check/mutual-guard hash helpers, and
  anti-debug/anti-hook constructors/helpers.
- The generated-helper phase is bounded by the normal module growth gate, a
  helper visit cap, and a separate sensitive-function size cap.  It does not
  recursively harden its own scaffold (`morok.extop.*`, `morok.bcf.*`) or every
  generated layout helper.

## Coherent decoy dead paths — IR structure
- The pass selects scalar integer or floating-point return blocks, splits the
  return into a real return block and a `morok.decoy.alt` false arm, then guards
  the real path with an opaque-true predicate from two volatile loads of private
  global `morok.decoy.opaque`.
- The false arm does not rejoin and does not contain arbitrary junk.  It returns
  a type-correct alternate value computed from the real return value, function
  arguments, and live values visible at the split point.  Integer returns use
  plausible `xor`/`add`/odd `mul` folds over integer terms and raw-bit carriers
  for compatible FP terms.  Floating returns (`half`, `bfloat`, `float`,
  `double`) fold compatible FP terms and integer terms converted into the return
  type through ordinary `fadd`/`fsub`/`fmul` arithmetic, so static triage cannot
  discard the arm by spotting meaningless noise.
- Runtime semantics are preserved because the volatile predicate is true for
  the private global at execution, while LLVM may not fold the volatile loads.
  If the false arm is patched into execution, it volatile-mixes the alternate
  value into private `morok.decoy.state` and marks it nonzero.  DFI consumes
  that state when present, so a patched decoy check can poison later
  integrity-entangled table indices and decode keys rather than failing only at
  the decoy site.  The pass skips void, aggregate/vector, and generated
  `morok.decoy.*` blocks.
- Scheduler placement is after AliasOpaquePredicates and before flattening, so
  flattening/IFSM/dispatcherless routing absorb coherent dead arms as ordinary
  CFG rather than exposing a late BCF signature.

## Optimizer amplification — IR structure
- Eligible operations are scalar integer `add/sub/mul/and/or/xor` binary
  operators (including `nuw`/`nsw`/`disjoint`-flagged forms), scalar integer
  `icmp` predicates from `i1` upward, and unflagged scalar floating `fcmp`
  predicates over `half`, `bfloat`, `float`, and `double`.  Poison-generating
  arithmetic flags are accepted because the base op is re-emitted *without*
  them (`morok.optamp.base`) and selected against flag-free equivalent forms —
  a sound refinement identical for every input the flag promised about.
  Fast-math `fcmp` flags are still skipped (the compare is reproduced verbatim,
  so `nnan`-style semantics cannot be safely erased), as are the generated
  `morok.optamp.*` expressions.
- Each selected op is cloned as `morok.optamp.base`, then expanded into up to
  `max_forms` mathematically equivalent forms: carry-split addition,
  borrow-split subtraction, De Morgan forms, xor-as-or-minus-and, and wrapping
  multiplication variants.  `icmp` forms use swapped predicates, inverted
  predicates wrapped in `not`, and xor-zero equality/inequality forms.  `fcmp`
  forms use only exact predicate rewrites: swapped predicates and inverse
  predicates wrapped in `not`, preserving ordered/unordered NaN behavior.  The
  FP guards are derived from bitcast operand bits plus a per-build salt; one-bit
  integer add/sub avoid the carry/borrow forms whose shift-by-one would be
  poison at width 1.  The result is a chain of `select` instructions.
- All arms are equivalent, so runtime semantics do not depend on the guard.  The
  guard is still input-derived, so InstCombine cannot collapse the select chain
  with a local constant proof.  There are no volatile loads, allocas, globals, or
  helper calls; the surface handed to the backend is ordinary branchless
  arithmetic.
- Plugin placement matters.  Under `clang -fpass-plugin ... -mllvm -morok`, this
  runs from the New-PM vectorizer-start extension point and the later scheduler
  copy is disabled to avoid double amplification.  Manual `-passes=morok`
  retains a scheduler fallback after BCF and before Substitution/MBA.

## Sub-threshold persistence — IR structure
- Eligible operations are scalar integer `add/sub/mul/and/or/xor` and
  constant-agnostic shift binary operators from `i1` upward, plus unflagged
  scalar floating `fadd/fsub/fmul/fdiv/frem` over `half`, `bfloat`, `float`,
  and `double`.  Poison-generating integer flags (`nuw`/`nsw`/`exact`/disjoint)
  are accepted — `cloneBaseOp` re-emits the operation without them and the
  original is replaced, a sound refinement — so the pass fires on the flagged
  arithmetic that `-O2` produces.  Fast-math FP flags are still skipped.
- Each selected op is cloned as `morok.threshold.base`, then receives up to
  `max_terms` opaque-neutral combines.  A term is `zero = load volatile seed ^
  load volatile seed` from a private local seed slot, followed by
  `base + zero`, `base - zero`, or `base ^ zero` for integer results.  Floating
  results are bitcast to an equal-width integer carrier, combined with the same
  zero term, then bitcast back to preserve the exact FP result bits without
  relying on unsafe `+0.0` identities.  Runtime value is unchanged, while the
  two volatile loads remain separate side-effecting values for common
  InstCombine/GVN folds.
- The seed slot is a single per-function `morok.threshold.seed` alloca initialized
  in the entry block.  `max_terms` is clamped to a small bound, deliberately
  keeping the expression web below the large-pattern thresholds that would make
  canonicalization obvious or compile-time-expensive.
- Scheduler placement is immediately after Substitution/MBA and before CFG-heavy
  passes, so the pass persists value-level shape around the expanded arithmetic
  without wrapping later indirect-branch or helper scaffolding.

## Table arithmetic — IR structure
- Eligible operations are wrapping scalar `i1` through `i8`
  `add/sub/mul/and/or/xor` binary operators, constant `shl/lshr/ashr` with
  shift amount less than the type width, plus scalar integer `icmp` predicates
  over same-width `i1` through `i8` operands.  The pass also lowers `i9` through
  `i16` binary operations, constant shifts, and comparisons when exactly one
  operand is a constant, using that constant to keep the lookup one-dimensional.
  `nuw`/`nsw` arithmetic, `exact` shifts, variable shifts, out-of-range constant
  shifts, and two-variable `i9..i16` operations are skipped because replacing a
  potentially poison-producing operation with a total table load would change
  LLVM semantics or require an explosive table.
- Each selected `i1..i8` operator or comparison gets a private mutable
  `[65536 x i8]` table indexed as `(zext(lhs) << 8) | zext(rhs)`.  Const-indexed
  `i9..i16` arithmetic gets `[65536 x i16]` indexed by the non-constant operand;
  const-indexed wider comparisons still use byte result tables.  Sub-byte
  operands are zero-extended for the lookup; decoded arithmetic values are
  truncated back to the source width, while decoded comparison bytes are
  truncated to `i1`.  The table initializer is encrypted with a per-table
  affine/xor integer stream, so the module does not contain the plaintext
  opcode/predicate truth table.
- A private `morok.tablearith.ensure` decoder materializes the table lazily on
  first use.  It loops over the table, decrypts in place, and sets a volatile
  readiness flag.  Function bodies call the decoder, compute the byte-pair
  index, and load the result, so decompilers see array indexing instead of the
  original arithmetic.
- `max_tables` caps per-function table growth, and standalone invocation has a
  hard ceiling of 16 selected tables.  The scheduler skips generated `morok.*`
  helper functions so decoders are not recursively obfuscated.

## Uniform primitive lowering — IR structure
- This is the IR-level half of the roadmap's IR/MIR item.  It deliberately
  avoids target-specific MOV-only lowering, but pushes visible intent toward a
  small set of uniform primitives: table loads, GEPs, `select`, and `indirectbr`.
- Selected `i1` through `i8` `add/sub/mul/and/or/xor` operations, constant
  in-range shifts, and integer comparisons reuse the encrypted lazy table
  materialization from TableArithmetic, governed by `op_probability` and
  `max_tables`.  The same path covers `i9` through `i16` operations and
  comparisons when exactly one operand is constant, preserving the
  one-dimensional lookup shape.  This removes opcode/predicate intent from the
  function body while keeping plaintext truth tables out of static initializers.
- Selected direct branches and switches are collected up to `max_branches` with
  a hard ceiling of 16 branch sites and 32 successors per site, then lowered to
  a private per-function `morok.uniform.table` of `blockaddress` entries.
  Conditional branches become `select cond, true_id, false_id`; switches become
  chained `icmp`/`select`; the resulting index GEPs into the table, loads a
  target pointer, and dispatches through `indirectbr`.
- PHI correctness is preserved because each transformed predecessor still has
  the same possible successor set, only reached through memory-loaded dispatch.
  EH pads, landing pads, entry-block backedges, and generated `morok.*` blocks
  are skipped.
- Scheduler placement is after TableArithmetic and before SIMD/path/dispatcher
  passes.  Standalone `morok-uniform` composes both halves for targeted use.

## Virtualization — threaded bytecode VM
- Selected functions are lifted only when the pass can prove a bounded scalar
  subset: 1- to 64-bit integer or address-space-0 pointer returns/arguments,
  ordinary branches/switches, entry allocas, scalar loads/stores, GEPs,
  integer arithmetic/bitwise ops, integer comparisons, scalar selects, integer
  casts, and a small pure-intrinsic set.  Generated protection-helper VMs add a
  call handler for scalar direct calls to defined non-vararg functions, scalar
  indirect calls, and inline-asm calls, which lets checker graphs and direct
  syscall probes move behind the VM without enabling arbitrary user call-graph
  virtualization.  Non-atomic volatile memory accesses are accepted and
  conservatively re-emitted as volatile VM memory accesses.  Unsupported IR is
  left untouched rather than approximated.
- The lifted function becomes a native wrapper that calls an internal
  `morok.vm.<function>.exec` helper.  The original computation is encoded as a
  private `morok.vm.bytecode.*` byte array; bytecode fields are first randomized
  by operand/immediate encoding and then encrypted byte-by-byte with a stream
  key derived from the VM PC.
- This is the stolen-code boundary: `rewriteAsWrapper` deletes the selected
  function's original IR body, so the on-disk native code for that function is
  only an ABI-preserving wrapper.  The removed instructions execute only as
  encrypted VM bytecode interpreted by the helper.
- The helper keeps a bounded `i64` virtual-register file, masks results back to
  the original integer width after each operation, and decodes one instruction
  at a time.  Constants, operands, and opcodes are decrypted from the current PC
  rather than materializing a plaintext program image.
- Address constants used by generated checkers are routed through a private
  per-helper `morok.vm.ptrs.*` table.  The encrypted bytecode carries only the
  table index, and the helper materializes the pointer at the use site.
- Dispatch is threaded computed-goto: the decoded opcode indexes a private
  `morok.vm.targets.*` blockaddress table, loads the target pointer, and reaches
  handlers through `indirectbr`.  There is no central `switch` decode anchor.
- Arithmetic handlers are duplicated and shuffled per build.  Alternate
  variants use equivalent formulas for add/sub/xor/and/or and PC-neutralized
  polymorphic forms for the remaining operations, so one opcode does not map to
  one stable handler shape.
- Scheduler placement has two phases.  User-code VM lifting runs before
  per-function splitting/flattening, otherwise structural passes would make
  clean source kernels ineligible.  A second protection-helper-only VM pass runs
  after anti-debug, anti-hook, timing/trap, self-checksum, mutual-guard, DFI,
  and vtable helpers have been emitted.  That late pass only considers
  allowlisted generated checker prefixes (`morok.antidbg`, `morok.antihook`,
  `morok.timing`, `morok.trap`, `morok.sc.diff.*`, `morok.mg.*`,
  `morok.dfi.hash.*`, `morok.vti.*`) so VM infrastructure and unrelated
  decoys are not recursively lifted.

## Hash-gated self-decrypting VM bytecode — IR structure
- Native block encryption needs post-link layout and W^X runtime cooperation,
  so the current IR-safe form targets VM bytecode payloads emitted by
  Virtualization rather than native machine-code basic blocks.
- Selected `morok.vm.bytecode.*` globals are rewritten from constant encrypted
  VM bytecode to mutable payloads with a second encrypted outer layer.  The VM's
  original per-PC bytecode encryption remains inside that layer.
- For each wrapped payload the pass emits an internal
  `morok.sdb.ensure.*` helper, a matching `morok.sdb.seal.*` helper, and a
  private `morok.sdb.ready.*` active flag.  The VM helper calls the ensure
  function before its dispatch loop reads bytecode and calls the seal function
  before every normal return, passing through the helper's original arguments.
- The ready flag is no longer a permanent "decrypted once" cache.  It is set
  only while the bytecode slice is plaintext.  Re-entering the ensure helper
  while the flag is already set trips the failure path, so an interrupted or
  recursively re-used plaintext payload does not get xor-decrypted twice.
- The ensure function first hashes the still-encrypted payload through volatile
  byte loads.  A `morok.sdb.gate` compare is computed, but it does not branch
  before decryption: the fixed-length decrypt loop always runs, then a
  post-decrypt decision either marks the payload ready or calls `llvm.trap`.
  This keeps the payload-key work shape constant and makes a patched failure
  path carry corrupted bytecode instead of a cleanly skipped decryptor.
- With `context_keying=true`, the ensure helper also folds VM call context into
  the stream key: each argument is volatile-stored to a local context slot,
  loaded twice, xored to a runtime zero, and mixed as `morok.sdb.key.context`.
  The correct path still decrypts exactly, but the IR key now carries
  argument-derived, volatile memory-dependent provenance instead of being a
  purely static payload-hash expression.
- The same key path carries local environmental provenance.  Each payload gets
  a private bound flag plus volatile `morok.sdb.bound.hash.*` and
  `morok.sdb.bound.keymask.*` state.  The first decrypt uses the portable
  build-time ciphertext hash/keymask; the matching seal re-encrypts the VM
  bytecode under a stable live fingerprint (the VM helper/payload addresses,
  CPUID vendor/features on x86, and Linux x86_64 `statfs("/")` filesystem
  identity via a direct syscall with the path built on the stack), hashes that
  new ciphertext, and stores the runtime hash/keymask for later calls.
  Subsequent decrypts must see the same local fingerprint and the same sealed
  image bytes or the VM bytecode key drifts.  Noisy probes
  (`llvm.readcyclecounter` and x86 RDTSCP) still flow through volatile paired
  reads as zero-valued provenance so instrumentation has to preserve the same
  observation path without making the payload depend on an unstable counter
  value.
- The ensure helper derives the stream key from the computed hash, decrypts each
  payload byte with volatile stores, sets the active flag volatile only after
  the post-decrypt gate succeeds, and returns.  The seal helper derives the same
  stream from the expected encrypted-payload hash, volatile-xors the plaintext
  bytes back to ciphertext before VM helper return, and clears the active flag.
  Later calls therefore re-hash encrypted bytes and expose plaintext only for
  the current helper invocation.
- Scheduler placement is directly after Virtualization and before the
  per-function pipeline, so VM bytecode exists and generated `morok.*` helpers
  remain outside later function-local transforms.

## Self-checksum-fused constants — IR structure
- True code-region checksums need post-link byte ranges.  The IR pass emits the
  runtime/data-flow contract over private `morok.sc.region.*` byte regions,
  patchable `morok.sc.code.size.*` live-code window lengths, and
  `morok.sc.expected.*` hash globals.  A post-link rewriter can set the code
  window size and patch the expected hash after final native bytes are fixed.
- Each selected `i1` through `i64` integer constant, and each scalar
  half/bfloat/float/double constant via its raw integer bit pattern, is
  reconstructed as
  `encoded ^ volatile_mask ^ (runtime_hash(region) ^ expected_hash)`.
  Supported sites are binary/FP-binary operations, integer/FP comparisons,
  `select`, cast, PHI incoming, conditional branch/switch conditions, return,
  store-value, and ordinary call-argument operands.  PHI incoming constants are
  materialized on their predecessor edge, splitting conditional predecessors
  before inserting volatile loads/calls.  Floating-point values are bitcast
  back after reconstruction, preserving payloads such as NaNs and signed zero.
  When the region matches the expected hash, the diff is zero and the original
  constant appears.  If bytes change without updating the expected hash, the
  diff flows into the program value and silently corrupts output.
- The pass deliberately emits no trap and no check branch.  The integrity value
  is data, so there is no separable success/failure edge to patch out.
- Runtime hash helpers are internal `morok.sc.diff.*` functions with volatile
  region loads, patchable code-window loads from the protected function's live
  address, volatile expected loads, `noinline`, and `optnone`.  The code window
  defaults to zero bytes so ordinary IR-only builds keep the placeholder-region
  semantics until post-link sizing is applied.  Per-constant masks live in
  private mutable `morok.sc.mask.*` globals and are volatile-loaded at each use
  site.
- The pass also emits a retained `morok.postlink.sc.*` manifest and places it
  in `llvm.compiler.used`.  The manifest records a non-printable magic/version,
  pointers to the `morok.sc.region.*` and `morok.sc.expected.*` globals, the
  region byte count, the hash seed, the current expected hash, the protected
  function pointer, and the `morok.sc.code.size.*` global.  A post-link rewriter
  can use that manifest to keep the placeholder region, add a final code-byte
  window, and patch the expected-hash global without reverse-engineering the IR
  shape or leaving an ASCII product marker in the binary.
- Scheduler placement is after trace keying/dispatcherless routing and before
  constant encryption, so the integrity fusion is late while ordinary constant
  encryption can still hide the encoded constants introduced by this pass.

## Data-flow-entangled integrity — IR structure
- The pass generalizes checksum-fused constants from scalars to live lookup
  tables.  Selected `i1` through `i8` `a OP b` operations, in-range constant
  shifts, and same-width integer comparisons are replaced by volatile loads
  from private `morok.dfi.table.*` globals.  It also handles `i9` through `i16`
  operations/comparisons when exactly one operand is constant, using that
  constant to keep the table indexed by one live value.
- Table entries are encoded with a stream key derived from the expected hash of
  a private `morok.dfi.region.*` byte region.  The runtime helper
  `morok.dfi.hash.*` hashes that region with volatile loads, volatile-loads
  `morok.dfi.expected.*`, and returns `actual_hash ^ expected_hash`.
- Each lookup derives its decode seed as `expected_hash_const ^ runtime_diff`
  and also XORs the live table index with the low bits of `runtime_diff`,
  masked back to the 16-bit table range.  On the valid region the diff is zero,
  the original table cell is loaded, and the byte decodes to the original
  operation result.  Sub-byte and pair-indexed narrow operands are zero-extended
  for the table index; const-indexed wide operations index by the non-constant
  operand and use `i16` table cells for arithmetic results or byte cells for
  comparisons.  Decoded arithmetic values are truncated back to the source width
  and decoded comparison bytes to `i1`.  Region or expected-hash tampering
  changes both the selected table cell and the key, corrupting the value in data
  flow.  If coherent decoys have emitted `morok.decoy.state`, DFI volatile-loads
  that hidden state and XORs it into `runtime_diff`; valid runs see zero, while
  patched decoy arms feed the same index/key corruption path.
- The table stays encoded at rest; unlike generic TableArithmetic, there is no
  lazy plaintext materialization pass.  There is also no trap or integrity
  branch, only data poisoning.
- `max_tables` is further bounded by a hard ceiling of 8 selected DFI tables per
  function, so standalone runs cannot emit one integrity table per eligible
  byte op in a huge function.
- Scheduler placement is before generic TableArithmetic, so this pass claims a
  configurable subset of narrow operations for integrity-bound tables and
  leaves the remaining narrow ops to ordinary encrypted table lowering.

## Mutual guard graph — IR structure
- True overlapping code-byte checkers need post-link ranges.  The IR pass emits
  the final contract over private `morok.mg.region.*` byte regions and mutable
  `morok.mg.expected.*` hash globals; a post-link rewriter can replace both
  with native ranges and final expected hashes after layout is fixed.
- Each selected function receives several internal `morok.mg.node.*` helpers.
  A node hashes its own region and adjacent peer regions with volatile byte
  loads, volatile-loads each covered region's expected hash, and also compares
  those expected globals against baked constants.  With three or more nodes,
  every region byte is covered by three independent node helpers; two-node
  graphs still cover every byte twice.  The node returns a mixed diff that is
  zero only when all covered regions and expected globals match the baked graph
  constants.
- The internal `morok.mg.diff.*` aggregator calls every node and xors/mixes the
  node diffs.  Valid graphs contribute zero.  Tampering with one region or
  expected hash makes every covering node contribute nonzero data.
- The pass also emits a retained `morok.postlink.mg.*` manifest in
  `llvm.compiler.used`.  The manifest records a non-printable magic/version,
  node count, region byte count, coverage depth, and per-node records containing
  the region pointer, expected-hash pointer, hash seed, and current expected
  hash.  A post-link rewriter can patch every node region and expected global
  from that single graph record, while preserving the ring-derived coverage
  topology and avoiding a readable manifest marker.
- Selected scalar integer and floating-point returns are rewritten as
  `ret_value ^ graph_diff` (truncated to the return width as needed).  Floating
  returns (`half`, `bfloat`, `float`, `double`) are bitcast to an equal-width
  integer carrier for the xor and bitcast back, so an intact graph preserves the
  exact returned bit pattern.  There is no trap and no check branch; the
  integrity graph affects program data directly.
- Scheduler placement is after self-checksum constants and before constant
  encryption, so it sees late control/data shape while ordinary literal
  encryption can still obscure constants introduced in the user function.

## Shamir threshold sharing — `core/ShamirGf256` / `core/Galois8`
- The pure core implements GF(2^8) polynomial evaluation, `(k,n)` splitting,
  and Lagrange reconstruction at zero.  Tests cover a fixed reference vector,
  every 3-of-5 subset for all 256 byte secrets, invalid-parameter clamps, and
  constexpr reconstruction.
- The pass targets safe `i1` through `i64` integer constants and scalar
  `half`/`bfloat`/`float`/`double` constants in binary ops, `icmp`/`fcmp`,
  `select`, casts, PHI incoming values, conditional branch/switch conditions,
  returns, store values, and ordinary call arguments, then caps selected secrets
  by `max_secrets` after the per-operand probability gate.  Branch destinations,
  switch case values, store pointers, and other structural operands are skipped.
  PHI incoming constants reconstruct on the incoming edge and split conditional
  predecessors when needed.  Values are split into the covering little-endian
  bytes; integer values are truncated back to the exact source width, and
  floating values are bitcast back from the reconstructed raw bit pattern to
  preserve NaN payloads and signed zero exactly.
- Current IR is dominator-deposited fixed-quorum reconstruction: each byte
  secret is split into `n` build-time shares, the first `k` shares are loaded
  volatilely from private mutable `morok.shamir.share.*` globals in the entry
  block and stored volatilely into private `morok.shamir.cell.*` globals.  The
  use site reloads those cells, multiplies them by build-time Lagrange basis
  constants through `morok.gf8mul`, XOR-folds the terms, and reassembles the
  original scalar type.  No runtime inverse table or loop is emitted.
- Scheduler placement is after `SelfChecksum`/`MutualGuardGraph` and before
  `ConstEnc`, so the late integrity passes still see original constants while
  Shamir claims selected remaining operands before generic XOR sharing.  This
  implementation guarantees deposits dominate uses but does not yet distribute
  shares across genuinely distinct path-specific deposit blocks; that is a
  stronger future mode rather than a property of the current pass.

## Adversarial function merging + outlining — IR structure
- This is the IR half of the roadmap's IR/MIR item.  It groups unrelated
  same-signature, same-calling-convention functions and keeps their original
  symbols as noinline wrappers.  The original bodies are cloned to internal
  `morok.afm.impl.*` functions.
- Each group receives one internal noinline/optnone
  `morok.afm.dispatch.*` helper.  Wrappers recover a hidden selector from two
  volatile private globals (`morok.afm.selector.*` and `morok.afm.key.*`) and
  call the shared dispatcher, whose switch calls the selected implementation.
  Function identity is preserved for external callers while call-graph recovery
  sees unrelated functions converge through one hidden selector surface.
- Selected scalar integer `add/sub/mul/and/or/xor/shl/lshr/ashr/udiv/sdiv/
  urem/srem`, unflagged scalar floating `fadd/fsub/fmul/fdiv/frem`, integer
  comparison, and unflagged floating comparison fragments inside the cloned
  implementations are outlined into
  shared noinline/optnone `morok.afm.outline.*` helpers.  Helpers include
  volatile key loads whose xor contributes a semantic zero, so they remain
  side-effecting to the optimizer while returning the original operation
  result.  Floating operation results apply that zero through raw integer
  bitcasts rather than extra FP arithmetic, preserving signed-zero and NaN
  payload bits from the outlined operation.
- The pass accepts variadic signatures when the body does not use vararg
  intrinsics; the original ABI remains variadic while the VM helper receives
  only the fixed named parameters.  It skips declarations, generated `morok.*`
  functions, personality/EH functions, noreturn/naked functions, and functions
  already referenced by `blockaddress` constants.  The last guard avoids cloning
  post-dispatcher jump tables whose entries are tied to the original function's
  basic blocks.
- It also skips functions above the clone budget.  AFM copies selected bodies,
  so large functions are not eligible even when the pass is invoked directly.
- Scheduler placement is a late module step after the per-function
  transformations and before FunctionWrapper.  That lets the pass perturb final
  function boundaries while FunctionWrapper can still proxy ordinary call sites
  afterwards; generated `morok.afm.*` helpers are skipped by later wrappers.

## Adversarial self-tuning — score-guided IR search harness
- This is the IR+harness item from the roadmap.  The pass treats the current
  module as the ground-truth specimen, clones it for each candidate bundle, runs
  existing semantics-preserving Morok transforms on the clone, verifies the
  clone, scores the resulting IR, and replays only the highest-scoring verified
  candidate on the original module.
- The built-in oracle scores the recovery stages the roadmap targets:
  CFG-recovery pressure (`indirectbr`, switches, PHIs, blockaddress tables),
  lvar/stack pressure (single byte buffers, dynamic allocas, volatile memory),
  type-recovery pressure (`ptrtoint`/`inttoptr`, bitcasts, vectors/shuffles),
  symbolic-pressure (volatile loads/stores, table dispatch, path structure),
  and diff-resistance (generated helpers, private globals, large tables).  The
  total score weights CFG and lvar failures highest because those are the
  dominant decompiler collapse points.
- Candidate bundles deliberately cover different adversary surfaces:
  StackCoalescing/PointerLaundering/PhiTangling/TypePunning for value recovery,
  TypePunning/PointerLaundering/StackCoalescing for alias/type recovery,
  PathExplosion/TraceKeying/PhiTangling for anti-DSE pressure,
  DispatcherlessRouting/MicrocodeStress/StackDeltaGames for microcode CFG/stack
  pressure, and TableArithmetic/UniformPrimitiveLowering/VectorObfuscation for
  alien-substrate pressure.  `max_candidates` and `max_candidate_passes` bound
  the search cost.
- The pass requires the best verified candidate to beat the baseline by
  `score_floor` before modifying the real module.  With `emit_marker=true` it
  writes private `morok.tune.choice` and `morok.tune.score` globals containing
  the selected bundle id, baseline/final score, component scores, and candidate
  seed.  That marker is evidence for tests and for downstream release audits.
- The pass refuses oversized modules before cloning and skips oversized
  functions inside candidate actions.  It is not enabled by the built-in
  presets; real application builds must opt in explicitly.
- Scheduler placement is after the full per-function obfuscation pipeline and
  before AdversarialFunctionMerging/FunctionWrapper/PerBuildPolymorphism.  The
  tuner therefore optimizes the already-layered IR shape, while the final module
  passes can still perturb function boundaries and layout afterwards.

## Per-build polymorphism — final IR diversity
- This is an explicit final diversity layer over the shared seeded PRNG.  With
  an explicit `-morok-seed`, the same input and configuration reproduce the same
  IR; different seeds perturb layout and salt initializers without changing
  runtime semantics.
- The pass shuffles defined function order at module scope and shuffles each
  function's non-entry basic blocks using LLVM list operations.  Entry blocks
  stay first, and no CFG edge is retargeted, so PHI and branch semantics are
  preserved while textual IR and backend layout inputs vary per build.
- Selected scalar integer and floating-point returns receive a neutral volatile anchor:
  two volatile loads from the same private mutable `morok.poly.salt.*` global
  are xored to zero, truncated to the return width, and xored into the returned
  value as `morok.poly.value`.  Floating returns (`half`, `bfloat`, `float`,
  `double`) are bitcast to an equal-width integer carrier for the xor and
  bitcast back, preserving the exact returned bit pattern.  The salt initializer
  is seed-dependent and the volatile loads keep the zero term visible to later
  analysis.
- The pass is idempotent once any `morok.poly.*` global exists.  It also relaxes
  memory-effect attributes on anchored functions and their callers, because the
  inserted volatile loads make previous readnone/readonly/nosync summaries too
  strong.
- Scheduler placement is after FunctionWrapper as the final obfuscating pass
  before feature elimination and cleanup.  That lets the layer diversify the
  complete function set, including wrappers and helpers emitted by earlier
  stages.

## Vector obfuscation — IR structure
- Eligible scalar integer binary ops and scalar floating binary ops
  (`half`, `bfloat`, `float`, `double`) are lifted to `<N x T>` operations,
  where `N = floor(width / bitwidth(T))` for configured widths 128, 256, or 512
  bits.  Lane `realLane` holds the original operands and all other lanes are
  per-build junk constants, so per-lane vector semantics preserve the scalar
  value.  Floating ops/compares carrying fast-math flags are lifted too: the
  flags (and the integer `nuw`/`nsw`/`exact` flags) are copied onto the vector
  op, so `realLane` computes the identical flagged result while any junk lane
  that violates a flag only poisons that unused lane.
- With `shuffle=false`, the pass extracts `realLane` directly.  With
  `shuffle=true`, `shufflevector` first moves `realLane` to lane 0 and fills the
  rest of the result with randomized lane references before extraction.  This
  forces the decompiler surface toward SIMD shuffle/intrinsic idioms instead of
  a trivial two-lane insert/extract pattern.
- With `lift_comparisons=true`, scalar integer `icmp` and unflagged floating
  `fcmp` instructions are lifted in the same way and extracted back to `i1`.
  This lets select/branch conditions acquire vector provenance without changing
  control semantics.
- Scalar casts between integer/floating scalar types are lifted as
  `<N x src> -> <N x dst>` vector casts when both source and destination fit at
  least two lanes in the configured width.  Supported casts are integer
  extend/truncate, FP extend/truncate, integer/FP conversions, and same-width
  scalar bitcasts.  Pointer casts remain pointer-domain transforms and are left
  to pointer laundering.
- Scalar integer/floating `select i1 cond, T t, T f` instructions lift the
  true/false values into junk-filled vectors, perform a scalar-conditioned
  vector select, then extract the original lane.  The condition remains scalar,
  but the chosen value inherits SIMD provenance.
- Direct memory caps: each invocation lifts at most 128 binary operators, at
  most 128 compares, at most 128 selects, and at most 128 casts.
- The scheduler runs this after table arithmetic and before path explosion:
  arithmetic and dispatcher values can be lifted, while later indirectbr-heavy
  anti-DSE regions are left intact.

## Path explosion — IR structure
- Selected blocks are split and guarded by an opaque-true volatile predicate.
  The original body remains the true edge; the false edge enters a decoy region
  that rejoins the body after a bounded loop.  Runtime semantics are preserved,
  while DSE engines that cannot discharge the guard must explore the decoy.
- The decoy loop derives its trip bound and dispatch tag from function inputs
  (integer, pointer, and scalar FP inputs folded through raw-bit carriers),
  stores a symbolic accumulator to `morok.path.scratch` on every iteration with
  volatile stores, and dispatches through an `indirectbr` over several case
  blocks using `blockaddress` values selected from the symbolic tag.
- `max_blocks` and `max_iterations` make the explosion explicit and bounded.
  The pass runs after flattening/vectorization because its `indirectbr` regions
  intentionally defeat later CFG structuring.

## MQ opaque gate — `core/MqGf2`
- The pure core represents quadratic forms over GF(2), triangularly packed
  coefficients, planted constant rebasing, and gate evaluation.  Tests prove
  `triIndex` coverage, compare `evalForm` against a brute-force reference, and
  check planted gates open at the planted assignment while rejecting a large
  random non-root sample.
- The current pass is a semantics-preserving planted opaque gate, not arbitrary
  user-input validation.  It selects input-derived conditional branches, builds
  `vars` gate bits from integer, pointer, and scalar floating-point
  argument/load sources, stores each source bit to a volatile scratch byte,
  reloads it twice, xors the two loads to zero, then xors in the planted bit.
  Floating-point sources (`half`, `bfloat`, `float`, `double`) are bitcast to
  equal-width integer carriers before bit extraction.  The emitted bits
  therefore equal the planted assignment at runtime while still carrying
  volatile input-derived structure in IR.
- Each selected branch gets an unrolled dense MQ term tree: quadratic terms are
  `morok.mq.term` `and`s, forms are `morok.mq.form` `xor`s, equations are
  `morok.mq.eq` comparisons to zero, and their conjunction is `morok.mq.gate`.
  A private constant `morok.mq.sys.*` stores the packed system for auditing; the
  hot path uses the unrolled tree, not a coefficient interpreter.
- The original conditional branch is moved into a continuation block.  The MQ
  gate branches either to that continuation or to `morok.mq.fail`, whose
  volatile scratch write rejoins the same continuation, so even an unexpected
  fail preserves program semantics.  Scheduler placement is after
  `PathExplosion` and before `TraceKeying`/`Dispatcherless`, letting later
  anti-DSE passes hide the guard edge.

## Execution-trace keying — IR structure
- The pass creates one private volatile `i64` accumulator in the function entry
  and seeds it from a private `morok.trace.seed` global plus a per-build salt.
  This makes the key stream a property of the execution context and build, not
  an input-only expression.
- Selected non-entry direct-CFG blocks receive a `morok.trace.expected` PHI.  For
  every predecessor branch or switch edge into selected blocks, the pass loads
  the current accumulator, selects an edge tag based on the actual successor,
  freezes and normalizes a bounded set of live scalar values near the edge,
  folds those runtime values into the edge tag with the same avalanche primitive,
  stores the resulting rolling hash back volatile, and feeds the new value into
  the successor's expected PHI.
- This is an oblivious runtime hash over branch and value trace, not a static
  byte checksum.  Integer, pointer, and scalar FP values are normalized to `i64`
  after `freeze`, so extra uses of poison-producing computations do not change
  valid-program semantics while still making replay/emulation reproduce the
  observed value trace.
- At the selected block entry, a volatile accumulator load is compared with the
  expected edge value.  The normal body is reached through
  `morok.trace.guard`; the mismatch edge enters `morok.trace.record`, mixes the
  nonzero diff into a private volatile `morok.trace.latent` global, and rejoins
  the real body.  The trace site therefore records tamper and continues instead
  of presenting a nearby `trap` branch to patch out.
- Unrelated branch, switch, and integer-return terminators are separately
  sampled as delayed probes.  Each probe volatile-loads `morok.trace.latent`,
  avalanches it with per-site tags, and fires only when low bits hit a
  per-build nonzero-for-valid-state needle.  On the valid trace latent state is
  zero and the select/XOR key is zero; after a wrong trace, later probes
  probabilistically flip branch/switch routing or corrupt return values away
  from the original guard site.
- EH pads, generated `morok.*` blocks, entry blocks, and blocks with unsupported
  indirect predecessor terminators are skipped.  Scheduler placement is after
  path explosion and before dispatcherless routing, so trace points are frozen
  late and later routing can still hide the guard branches.

## Microcode stress — sparse computed jump tables
- This is the IR-lowering half of the roadmap's Hex-Rays microcode stress item
  that targets sparse/oversized jump-table recovery and aliased-memory pressure.
  It is deliberately distinct from DispatcherlessRouting: it does not encode
  source branch semantics.  Every table destination either reaches the original
  body directly or through a decoy that rejoins it.
- Each selected block is split, then the predecessor loads a target pointer from
  a private `morok.micro.table` of `blockaddress` entries and reaches it via
  `indirectbr`.  The table size is normalized to a power of two, usually much
  larger than the number of unique destinations, so microcode sees a computed
  table with many opaque holes rather than a compact source switch.
- The table index is derived from a volatile private `morok.micro.seed`, live
  integer/pointer/scalar-FP terms at the split point, and per-build odd
  multipliers, then masked into the table range.  FP terms are bitcast to
  same-width integer carriers before the i64 mix reduction.  Because all entries
  are semantically safe, the index may be genuinely data-derived without
  changing program results.
- Decoy destinations perform configurable volatile loads/stores through
  `ptrtoint -> xor -> xor -> inttoptr` aliases into a per-function
  `morok.micro.scratch` frame before branching to the original body.  This
  combines goto-spaghetti CFG pressure with alias/lvar recovery pressure.
- Each rewritten site also emits a side-effecting anti-disassembly hop before
  the computed branch.  x86/x86_64 sites use `call`/`pop` to recover PIC state,
  derive a local label, and `jmp *reg` over fake call/ret/trap bytes; AArch64
  sites use `adr` plus `br x16` over fake branch/return words.  Together with
  the existing signal/exception control-flow handlers, this covers the
  signal-as-goto/PIC/computed-jump anti-disasm pattern without a new preset knob.
- When the transform fires on x86/x86_64/aarch64, the module also retains a
  cold local `morok.micro.analysis.bait` byte-sled helper.  Its inline-asm body
  immediately jumps over bogus landing/prologue/epilogue bytes (`endbr64` on
  x86_64, prologue-looking frame setup, fake `ret`), so normal execution is
  unchanged while linear sweep and auto-function discovery see plausible but
  unreachable function boundaries.
- Scheduler placement is after TraceKeying and DispatcherlessRouting and before
  checksum/integrity fusion.  Earlier CFG transforms see ordinary structure;
  later integrity passes can hash/fuse the final microcode-stress shape.

## Indirect branch — `core/KnuthHash`
- Per-function key: random `delta`, odd `mult`, `xork`. `encode = ((raw+delta)*mult)^xork`,
  `decode = ((enc^xork)*multInv) - delta`, `multInv = modInverse64(mult)` (5 Newton steps).
- Global jump table of `ptr`; per-conditional-branch local 1–2 entry tables indexed by
  `zext(cond)`. Optional `EncryptJumpTarget` adds a GEP pointer-offset + index-XOR layer.
  `indibran-use-stack` default true.
- Golden vector: delta=0x0123456789ABCDEF, mult=0xDEADBEEFCAFEF00D, xork=0xA5A5A5A55A5A5A5A
  ⇒ multInv=0xA761C9B0BCBEDEC5; encode(0x140001000)=0x1A00A88C7CB60F79.

## Passes without a pure numeric core (IR-structure only)
- BogusControlFlow: opaque hardware-predicate edges; `bcf_prob`/loop/complexity/entropy_chain/junk_asm.
- NonInvertibleState: encoded-state flattening with lossy keyed next-state hash.
- StateOpaquePredicates: MBA opaque guards over flattened dispatcher state plus scalar integer/FP terms.
- Sensitive-density boost: scheduler-only BCF/MBA/ExternalOpaque pressure for
  `annotate("sensitive")` functions and allowlisted generated protection helpers.
- InterproceduralFsm: flattened state stores call mutually-recursive transition helpers with scalar integer/FP token terms.
- DataEntangledFlattening: switch dispatcher with scalar integer/FP live-data/previous-state transition tokens.
- ChaosStateMachine: switch dispatcher driven by logistic or single-cycle T-function state maps.
- DispatcherlessRouting: per-block state-entangled indirectbrs through blockaddress tables with scalar integer/FP route tokens.
- MicrocodeStress: oversized blockaddress tables plus aliased decoy destinations that always rejoin.
- Flattening: classic CFF; runs only when NiState/EntFla/CSM skipped.
- SplitBasicBlocks: split + stack-confusion; `split_num`, stack_confusion.
- StackCoalescing: one byte frame for static locals; opaque loaded offsets; skips escaping allocas.
- StackDeltaGames: dynamic stack saves/restores plus odd overlapping volatile stack slots.
- PointerLaundering: pointer-int round trips + computed byte GEPs; integer/FP byte-vector bitcasts.
- TypePunning: volatile union-buffer scalar↔vector/integer reinterpretation chains.
- PhiTangling: redundant scalar integer/FP edge-copy/direct PHI webs; zero cross-terms rewrite uses.
- AliasOpaquePredicates: maintained pointer/alias memory invariant guards with decoy edges.
- ExternalOpaquePredicates: IPO-blocked volatile context helper guards with scratch decoy edges.
- CoherentDecoys: opaque-dead alternate return computations plus hidden decoy-tamper state, not junk blocks.
- DataFlowIntegrity: `i1..i8` and const-indexed `i9..i16` op tables decoded by runtime integrity hashes and decoy hidden state.
- OptimizerAmplification: early branchless select lattice over equivalent integer op / integer compare / FP compare forms.
- SubThresholdPersistence: volatile local-seed opaque-zero terms for scalar integer/FP ops under a small cap.
- TableArithmetic: encrypted lazy `i1..i8` and const-indexed `i9..i16` op lookup tables.
- UniformPrimitiveLowering: `i1..i8`/const-indexed `i9..i16` op tables plus memory-loaded indirectbr dispatch.
- Virtualization: encrypted per-function bytecode plus threaded computed-goto VM helpers.
- HashGatedSelfDecrypt: VM bytecode globals get hash/context-gated outer
  decryptors that re-encrypt each payload on VM helper exit.
- MutualGuardGraph: overlapping checksum nodes whose combined diff poisons scalar integer/FP returns.
- AdversarialFunctionMerging: same-signature functions routed through shared selector dispatchers plus outlined scalar integer/FP operation and comparison helpers.
- AdversarialSelfTuning: cloned-candidate search over hardness metrics with best verified bundle replay.
- PerBuildPolymorphism: seed-driven function/block order and volatile-zero scalar integer/FP return anchors.
- PathExplosion: opaque-guarded input-derived loops with volatile symbolic stores and indirectbr dispatch.
- MqGate: planted GF(2) quadratic opaque gates over volatile integer/pointer/FP input-derived bits.
- TraceKeying: edge-carried rolling trace accumulator with latent tamper recording and delayed probabilistic probes.
- SelfChecksumConstants: scalar constants XORed with runtime checksum diffs for data-only tamper corruption.
- ShamirShare: selected scalar literals reconstructed from volatile GF(2^8) threshold shares.
- VectorObfuscation: scalar op/cast/compare/select → SIMD lifting; width 128/256/512, shuffle, lift_comparisons.
- FunctionWrapper: polymorphic proxies including concrete variadic call/invoke sites; prob/times/max_wrappers/hard cap 256.
- FunctionCallObfuscate: per-site import indirection; hard cap 256 call/invoke
  sites. On 64-bit Linux and macOS the target symbol name is not emitted at all:
  each site carries only `FNV-1a(symbol)` and calls a private manual resolver.
  Linux walks the loaded ELF program headers and `.dynamic` data, scans
  `DT_HASH`/`DT_SYMTAB`/`DT_STRTAB`, handles direct-loader musl images without
  `PT_PHDR`, then falls back through `DT_DEBUG`, `AT_BASE`, and
  `dl_iterate_phdr` when needed. macOS walks `_dyld_*` images, reads
  `LC_SEGMENT_64`, `LC_DYLD_INFO(_ONLY)` / `LC_DYLD_EXPORTS_TRIE`, and
  `LC_SYMTAB` metadata, hashing exported names after stripping the Mach-O ABI
  underscore. Common libSystem fast-path aliases such as `_platform_strlen`,
  `_platform_memmove`, and `_platform_memcmp` are tried by hash as fallbacks,
  so dyld shared-cache private exports do not force a plaintext `dlsym` path.
  Unsupported targets keep the old cloaked `dlsym`
  path: each site carries its own ciphertext (`morok.cloak.c`) and unrolled
  per-site keystream, decrypts into a stack buffer, then feeds the computed name
  to `dlsym`.
  Direct call sites cache the resolved pointer lazily in a private
  per-callsite `morok.fco.cache` global, but only after XOR-encoding it with a
  volatile module seed and per-site key material; invoke sites keep the older
  volatile stack slot form.  In both cases the raw pointer exists only as SSA
  immediately before the indirect call/invoke.  There is no reusable plaintext
  function-pointer slot for static IAT-style recovery.
  On Linux x86_64 direct call sites also take the exception-mediated path: the
  site stores a pending request `(FNV-1a(symbol), null-name, out-slot,
  continuation blockaddress)` and deliberately faults through inline asm. A
  `SIGSEGV` `SA_SIGINFO` handler validates the pending hash request, clears it,
  and rewrites the saved RIP to the continuation block. The continuation runs
  the manual resolver outside the signal context, encodes the pointer, and then
  performs the indirect call. Invokes and non-Linux-x86_64 targets avoid this
  exception path rather than guessing platform-specific exception-context
  offsets.
- AntiClassDump / AntiDebugging / AntiHooking / TimingOracle / TrapOracle:
  platform anti-analysis
  (module passes). AntiDebugging combines startup checks with a mutable hidden
  state word, platform-specific recheck helpers, pthread watchdogs where
  available, and once-gated randomized calls inserted into user functions so
  debugger evidence is sampled from both constructors and normal execution paths
  without repeatedly running expensive probes in hot loops.  POSIX targets also
  start a separate watchdog constructor: one pthread re-runs the anti-debug
  probe on a per-build jittered sleep cadence and advances a volatile heartbeat,
  while a second pthread samples that heartbeat and folds repeated staleness into
  `morok.antidbg.state`.  Confirmed staleness also mutates a volatile
  `morok.watchdog.crypto` drift word.  `SelfChecksumConstants` xors that word
  into its checksum-derived constant key and `TraceKeying` xors it into delayed
  latent samples, so a stopped heartbeat changes later data/branch keys instead
  of exposing a single branch to patch.  On Linux, the startup path also applies
  a Landlock ruleset, when the kernel supports it, to
  deny destructive filesystem rights (writes, creates, removes, renames,
  truncates, and device ioctls by ABI level) while keeping reads/exec available.
  It then installs a seccomp-BPF filter that kills `ptrace` requests and
  `process_vm_readv`/`process_vm_writev` in the protected process lineage.  In
  configurations without TrapOracle, the filter can allow Morok's own
  `PTRACE_TRACEME` re-arm.  When TrapOracle is enabled, Linux self-tracing is
  omitted so `SIGTRAP` stimuli are delivered to Morok's handler instead of
  job-stopping under the parent shell.  On Linux x86_64, Morok can instead fork
  a DR sentinel helper before the seccomp filter is installed, authorize that
  child with `PR_SET_PTRACER`, enumerate `/proc/<pid>/task`, and use direct
  `PTRACE_SEIZE`/`PTRACE_INTERRUPT`/`PTRACE_POKEUSER` syscalls to occupy the
  tracer slot and zero the verified `u_debugreg[0..7]` slots for every thread.
  The forked child persists while the parent lives, mirrors selected parent code
  bytes with `PTRACE_PEEKDATA` against its fork-clean copy, and exits on
  mismatch.  The parent stores the buddy PID and its watchdog checks
  `kill(pid, 0)` plus `wait4(..., WNOHANG)` with direct syscalls, folding a
  missing or exited child into the hidden anti-debug state.  When that helper is
  present it replaces the self-trace re-arm path, because a process cannot be
  simultaneously self-traced and scrubbed by a helper tracer.  On macOS
  x86_64/arm64, a pthread watchdog enumerates Mach threads with `task_threads`,
  reads the architecture debug state, clears the x86 DR slots or ARM
  breakpoint/watchpoint/MDSCR state, writes it back with `thread_set_state`, and
  releases the returned thread array with `vm_deallocate`.
  On x86_64 Linux, sensitive anti-debug syscalls (`ptrace`, `prctl`,
  `openat`/`read`/`close` for `/proc` probes, Landlock, and seccomp install)
  are emitted as inline `syscall` instructions instead of libc imports.
  On x86_64 macOS, BSD anti-debug probes (`ptrace`, `getpid`, `sysctl`,
  `csops`) are likewise emitted as inline Darwin syscall instructions. dyld
  symbol resolution such as `dlsym` is not a syscall; FunctionCallObfuscate's
  64-bit macOS path avoids that surface with the manual Mach-O hash resolver.
  AntiHooking also emits a clean-copy byte-diff checker for POSIX targets.  The
  checker resolves the current executable path, maps a fresh read-only copy of
  the on-disk ELF or Mach-O image, applies the runtime load bias/slide, compares
  executable load segments byte-for-byte against memory, and folds any mismatch
  into private anti-hook state.  Linux x86_64 uses inline syscalls for the file
  and mapping path; macOS x86_64 uses inline Darwin BSD syscalls for
  `open`/`lseek`/`mmap`/`munmap`/`close` and avoids adding the legacy `dlsym`
  anti-hook probe on Darwin.
  AntiHooking also samples prologues from a bounded set of user functions plus
  the generated clean-copy helper.  x86 targets fold `E9`, `FF 25`, `68 .. C3`,
  `EB`, and short/near `jcc` entry patterns into anti-hook state; arm64 targets
  fold unconditional branch, `br`, and `ldr literal x16/x17; br` trampoline
  shapes.
  The clean-copy helper also carries a private table of selected user-function
  entries and computes a keyed 32-byte MAC over each function window from live
  memory and from the freshly mapped image.  Any MAC mismatch is folded into
  the same delayed anti-hook state, so mid-body patches are caught before the
  full byte scan reports segment drift.
  On Linux, AntiHooking also walks the main ELF dynamic table's `DT_JMPREL`
  PLT relocations at runtime, volatile-loads each GOT/PLT slot, and verifies the
  resolved target lands inside an executable `PT_LOAD` segment from the main
  image or a loader `link_map` module discovered through `DT_DEBUG`.  When the
  binary advertises `BIND_NOW` and the slot lies in `PT_GNU_RELRO`, the checker
  re-applies read-only protection to the slot page with an inline x86_64
  `mprotect` syscall path; bad targets or failed reprotection are folded into
  delayed anti-hook state.
  On macOS, AntiHooking walks the main Mach-O load commands, scans
  `S_NON_LAZY_SYMBOL_POINTERS` and `S_LAZY_SYMBOL_POINTERS` sections such as
  `__got` and `__la_symbol_ptr`, volatile-loads each non-null pointer, and
  checks it against executable segments from dyld's loaded image list.  Pointers
  that do not land in any loaded image `__TEXT`-style executable range are
  folded into the delayed anti-hook state.
  AntiHooking also emits a bounded address-space census.  Linux parses a cloaked
  `/proc/self/maps` buffer with direct syscalls where available, flags `rwx`
  mappings, executable non-readable mappings, anonymous/private executable
  mappings, and unexpected `LD_PRELOAD`/`LD_AUDIT`.  macOS walks
  `mach_vm_region` with `VM_REGION_BASIC_INFO_64`, flags RWX/NOACCESS mappings,
  executable regions outside dyld image text ranges, and loaded text ranges whose
  live protection is no longer RX.  Windows x86_64 emits a `VirtualQuery` census
  that flags committed guard/NOACCESS/RWX pages and private executable mappings;
  deeper PE loader-list reconciliation remains tied to the later Windows/PE
  foundation.
  A companion W^X enforcer re-protects executable load segments before the
  census: Linux walks `AT_PHDR` program headers and uses direct x86_64
  `mprotect` where available, macOS walks the main Mach-O `LC_SEGMENT_64`
  commands and uses direct x86_64 Darwin `mprotect` where available, and Windows
  uses `VirtualQuery`/`VirtualProtect` to downgrade committed RWX regions to
  execute-read.  Protection failures are folded into the same delayed anti-hook
  state instead of branching to an immediate exit.
  Selected non-`main` user functions also get an entry-time stack-origin check:
  the pass reads the function's immediate return address with
  `llvm.returnaddress(0)` and verifies it against the platform executable-origin
  model.  Linux reuses ELF program-header RX checks for the main executable,
  macOS checks dyld executable image ranges, and Windows checks `VirtualQuery`
  protection for committed executable, non-guard, non-RWX pages.  Failures are
  folded into anti-hook state at the protected function entry, so suspicious
  injected calls or DBI trampolines poison later state without a separable
  immediate branch.
  On x86_64 POSIX targets, AntiHooking also emits a method-divergence oracle:
  the helper samples stable process-identity primitives through both an inline
  direct syscall path and the libc wrapper path, counts mismatches, and folds
  any divergence into the same delayed anti-hook state.  This catches wrapper
  hooks or syscall-path hooks without introducing a readable probe string or a
  libc `syscall` import on the direct path.
  AntiHooking also emits a decoy-grade VM/sandbox battery where safe for the
  target: x86 CPUID hypervisor/vendor leaves, a VMware I/O backdoor probe
  guarded behind the numeric VMware vendor leaf and a cold volatile tripwire,
  SIDT/SGDT/SLDT descriptor probes behind the same tripwire, Linux
  CPU-count/RAM-page/boottime heuristics, a short sleep elapsed-time probe, and
  existing timing-oracle acceleration signals.  These are weak signatures
  individually, so the helper returns a bounded score and folds only
  multi-signal suspicion into delayed anti-hook state instead of exiting at the
  probe site.
  AntiHooking also extends the address-space census into an anti-DBI battery:
  return-address origin checks reject code-cache callers, Darwin/Windows VM
  scans flag large RWX regions, Linux scans cloaked `/proc/self/maps`,
  `/proc/net/tcp`, and current-thread names for Frida-style signatures without
  embedding readable signature strings, and a cold SMC tripwire touches a code
  page through a volatile gate to stress DBI code-cache coherence.
  Negative-space verification is folded into the same delayed state: clean-copy
  executable-section scans report foreign `0xCC` bytes that are absent from the
  on-disk image, address-space census diffs are also treated as "extra module"
  evidence, a compact two-clock span asserts timing is not slow, and the Linux
  DR sentinel records when any debug-register zeroing write fails.
  Aggressive responses are guarded by a corroboration score.  AntiHooking
  accrues bounded evidence bits from clean-copy drift, GOT/fixup drift, W^X
  failures, module census, syscall/wrapper divergence, sandbox/DBI probes, and
  negative-space timing; the Linux hook-symbol exit path requires both the
  symbol hit and a multi-signal score before taking the bail branch.
- TimingOracle emits a private constructor helper that samples several short
  volatile spans with two clock sources.  x86 targets use serialized `rdtscp`
  paired with a raw OS clock; Darwin targets use `mach_absolute_time` and
  `CLOCK_MONOTONIC_RAW`.  Slow or divergent sample distributions are folded
  into private state instead of causing immediate false-positive-prone exits.
- TrapOracle temporarily installs a trap handler during startup, fires x86
  `int3`/`icebp`/trap-flag stimuli where supported, falls back to portable
  `raise(SIGTRAP)` on non-x86 POSIX targets, and folds missing or swallowed trap
  delivery into private state before restoring the previous handler.  Linux
  x86_64 uses a `sigaction` `SA_SIGINFO` handler for both `SIGTRAP` and
  `SIGILL`, advancing RIP over `icebp` when emulators such as Orb report byte
  `0xf1` as a non-resumable illegal instruction.  Windows `INT 2Dh`/VEH
  coverage remains gated on the future Windows foundation.

## Scheduler memory guardrails
- The scheduler re-measures instruction and block counts before each
  growth-producing function pass.  Once earlier transforms push a function over
  the relevant budget, later expansion passes for that function are skipped.
- Whole-module growth passes are guarded by module instruction/block/function
  budgets.  Early module-wide transforms such as FCO and string encryption are
  also skipped when the input module already exceeds the growth budget.  The
  self-tuning harness uses the stricter clone budget because it evaluates
  candidates on full module copies.
- String encryption also has its own byte caps because large global initializers
  can be small in IR instruction count but expensive to lower into a decryptor.
- Direct pass caps bound standalone growth for substitution, MBA, table
  arithmetic, DFI, uniform/dispatcherless CFG routing, constant encryption,
  pointer laundering, vector lifting, FCO, VTableIntegrity, and FunctionWrapper,
  so those passes remain finite even when invoked outside the scheduler.
- IR-stage post-link contracts are emitted as retained `morok.postlink.*`
  manifests rather than implicit placeholder globals; downstream patchers should
  consume those records and update the referenced region/expected globals.  The
  manifest sentinels are fixed binary values, not printable `MOROK*` strings.
- MisleadingMetadata runs near the final symbol-hygiene phase and plants a
  bounded set of retained local decoy text symbols, internal aliases that create
  duplicate apparent function starts, and contradictory-but-valid DWARF
  subprogram ranges (debug names, source files, and line spans disagree with
  the emitted local symbol).  ELF relies on LLVM's normal non-alloc DWARF
  emission; Mach-O additionally gets a retained malformed debug-string bait
  payload in `__TEXT,__debug_str` because linked executables may otherwise
  discard standalone `__DWARF` sections unless a dSYM-oriented debug build is
  requested.  The decoys are kept through `llvm.compiler.used` and do not
  export ABI symbols or alter user code.
- The high preset is bounded-aggressive by default: it enables small capped
  slices of VM lifting/hash self-decrypt, self-check constants, DFI, MQ,
  MicrocodeStress, and FunctionWrapper while keeping MutualGuardGraph,
  AdversarialSelfTuning, and AdversarialFunctionMerging disabled unless
  explicitly configured.  The enabled heavyweight slices use local caps before
  they can clone or generate dense IR.

## Scheduler order (to preserve semantics)
Virtualization(user) → HashSelfDecrypt → AntiHook → AntiClassDump → AntiDebug → TimingOracle → TrapOracle → StringEnc → FCO(fn) → VTableIntegrity → per-fn{ Split, BCF, OptAmp, Sub,
MBA, AliasOp, ExtOp, CoherentDecoys, NiState/EntFla/CSM(generator)/Flatten, StateOp, IFSM, PhiTangle, TypePun, StackCoalesce, StackDelta, PointerLaunder, DataFlowIntegrity, TableArith, Uniform, Vec, PathExplosion, MqGate, TraceKeying, Dispatcherless, MicrocodeStress, SelfChecksum, MutualGuardGraph, ShamirShare, ConstEnc, IndirectBranch } → ProtectionHelperVM → SensitiveHelperHardening → AdversarialSelfTuning → AdversarialFunctionMerging → FunctionWrapper → PerBuildPolymorphism →
MisleadingMetadata → FeatureElimination (strip debug/names) → cleanup marker decls.
