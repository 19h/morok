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
- Max-target throttle: if `eligible*prob/100 > 10000`, scale prob down.

## Mixed Boolean-Arithmetic — `core/MbaIdentities`
- Variant counts: Add 8, Sub 7, Xor 7, And 8, Or 7, Mul 5. `mba_prob` (default 60),
  `mba_layers` (default 2, clamp 1..3), `mba_heuristic` (default true).
- Layers compound: layer L+1 sees layer L output. Per-layer max-target throttle 10000.
- Heuristic noise = `zeroTerm` (k terms) added/subtracted; always nets to 0.
- Carry lemma `x+r == (x^r)+2*(x&r)` underpins the random-constant variants.

## String encryption — `core/Galois8`
- i8 arrays: Vernam-GF8. Per byte: random pad `k1`, random non-zero `k2`; store
  `c = (p^k1)·k2`, `k1`, and `k2inv = inv(k2)`. Runtime: `p = (c·k2inv)^k1`.
- Three GVs: `EncryptedString` (compact ciphertext), key GV (`k1`, full layout),
  `DecryptSpace` (`k2inv`/plaintext, full layout). One-time atomic-flag–gated
  decrypt block; element order Fisher-Yates shuffled.
- Wider types (i16/i32/i64): plain XOR cipher (`enc = K^V`), not GF8.
- `strcry_prob` default 100; per-element coin `get_range(100) >= prob` ⇒ left clear.
  Content regex `skip_content`/`force_content` over raw bytes.

## Constant encryption — `core/XorShare`, `core/Feistel`
- Pipeline: `origC ─[Feistel if feistel && bits>=16]→ workC ─[k-share XOR or single XOR]→ shares`.
  Runtime reverses: XOR-fold shares → workC → inverse Feistel → origC.
- k-share when `k>=3` (k clamp 2..8), else classic single-XOR (i1/i8/i16/i32/i64 only).
  Shares: private non-const GVs `constenc.share`, in `llvm.compiler.used`.
- Feistel: balanced, 4 rounds, per-round odd multiplier + xor key (random, masked to
  half width). `feistelEncrypt/Decrypt(value, bits, keys)`.
- Flags: `constenc_times` 1, `constenc_kshare` 2, `constenc_feistel` off,
  `constenc_subxor` off / `_prob` 40, `constenc_togv` off / `_prob` 50.
  Max-mode forces kshare=4, feistel=true. `skip_value`/`force_value` regex on hex.

## Chaos state machine — `core/LogisticMap`
- Q16 logistic map `step(x)`: `r·x·(1−x)` with r encoded 65533, `>>30`, guards
  0x1337 (input 0) / 0xC0DE (output 0). Default seed 0x4B1D, `csm_warmup` 64.
- Dispatcher state held XOR-masked by per-function `feistelK`. Transition realised as
  `next = step(current) ^ correction(i,j)`, `correction(i,j)=step(case_i)^case_j`.
- `csm_nested` (default off): when numBBs>=4, relay blocks add an inner switch on the
  low nibble (`&0xF`) — CFG multiplier, semantic no-op. `csm_maxblocks` 10000 size guard.
- Sequence build uses unique-state collection + anti-stuck XOR perturbation (impure;
  the pure `step` alone cycles after a few hundred states — by design).

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
- Flattening: classic CFF; runs only on functions CSM skipped (checks `csm.done`).
- SplitBasicBlocks: split + stack-confusion; `split_num`, stack_confusion.
- VectorObfuscation: scalar→SIMD lifting; width 128/256/512, shuffle, lift_comparisons.
- FunctionWrapper: polymorphic proxies; prob/times.
- FunctionCallObfuscate: dlopen/dlsym indirection; uses a JSON symbol DB (`json.hpp`).
- AntiClassDump / AntiDebugging / AntiHooking: platform anti-analysis (module passes).

## Scheduler order (to preserve semantics)
AntiHook → AntiClassDump → FCO(fn) → AntiDebug → StringEnc → per-fn{ Split, BCF, Sub,
MBA, CSM, Flatten, Vec } → ConstEnc → IndirectBranch → FunctionWrapper →
FeatureElimination (strip debug/names) → cleanup marker decls.
