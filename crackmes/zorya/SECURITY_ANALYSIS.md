# ZORYA — Obfuscation, Anti-Analysis & Anti-Debugging Strategy

*Exhaustive cross-validated audit. Two protection layers: (A) the crackme's own
source-level design; (B) the Morok LLVM obfuscator battery. Every claim was
re-derived from source (`zorya.c`, `zcommon.h`, `tweetnacl.c`), the Morok pass
sources (`/Users/int/dev/morok/src/passes/*.cpp`), and the two shipped ELFs via
`llvm-readelf`/`llvm-objdump`/`strings`/raw byte scans, then adversarially
re-verified.*

---

## 0. Two facts that reframe everything

Before the strategy, two verified facts about the **shipped artifacts** that the
design docs do not advertise:

1. **The shipped binaries are UNSEALED.** `zoryabc` (0x2000) and `zoryaseal`
   (0x60) are still the link-time placeholders — a single leading `0xA5` byte
   then all zeros, in *both* `zorya-linux-x86_64` and `-static`. The post-link
   `zorya-mint seal` step (which injects the real encrypted bytecode + the
   encrypted MAGIC‖flag) was never run on these files. **Consequence:** no
   honest run and no static reconstruction can print a real flag from these
   exact binaries — there is nothing minted in. They are tamper-proofing
   *machinery* without a payload. A playable artifact requires the issuer to
   seal first with `zorya-mint` + `zorya.sk`.

2. **The config of record is almost certainly `preset=max` defaults, not the
   elaborate `morok-linux-dynamic.toml`.** `build-morok.sh:24` defaults
   `CONFIG=morok-linux-static.toml` (which is just `preset="max"` +
   `function_call_obfuscate=false`). The binary fingerprints match `max`
   defaults rather than the elevated knobs in `morok-linux-dynamic.toml`
   (e.g. `caller_keyed_dispatch` produced **0** sites; `nanomites` lowered only
   ~2 traps consistent with `max_sites=16`, not 1024; `dispatcherless` shows no
   sign of the 96-route tuning). Both `.toml`s are `preset=max`, so the
   **qualitative pass set is identical**; only the **quantitative tuning** is in
   question. Where this report cites a specific knob value, treat the
   `dynamic.toml` numbers as *intended maxima*, and the `max`-preset defaults as
   the *likely compiled* values.

---

## Executive summary

**Layer A** is a single cryptographic invariant disguised as six sensors. The
32-byte XSalsa20 key that decrypts the flag is

```
S0   = SHA512(DOM_PRE  || t || mclaimed || name)
S    = VM(S0, bytecode)                 # bytecode = XSalsa20(SHA512(DOM_VM||checksum)) ⊕ ZBC
key  = SHA512(DOM_POST || S || checksum || LE64(tracer) || LE64(ge))[:32]
flag = XSalsa20(key, ZN_SEAL) ⊕ ZSEAL
```

Six independent inputs — recomputed Ed25519 point `t`, the signed message,
the entered name, the SHA-512 self-checksum of the `zoryatext` ELF section, the
single-step bit `ge`, and a tracer-injected word — are each **hash-preimage
operands, not compared booleans.** There is **no win-branch to flip**: the
16-byte MAGIC compare is cosmetic, it only chooses whether garbage or the
(already-correct-or-already-wrong) flag bytes are printed. Perturbing any sensor
(breakpoint, single-step, attach, patch) silently changes the key → wrong flag,
never an honest refusal.

**Layer B** wraps that design in `preset=max` Morok obfuscation: a fully-stripped,
non-PIE musl ELF **~70× the baseline size**, with ~11 verifier functions lifted
into a PC-keyed bytecode interpreter whose decode keystream is folded with an
anti-debug verdict seal. The dominant strength is **anti-static-analysis +
polymorphism** (flattening family, dispatcherless routing, constant/string
encryption, virtualization, nanomites), plus genuine integrity passes, plus a
real-but-**narrow** anti-debug enforcement surface on Linux.

**Thesis + caveat.** The two layers reinforce through one SHA-512 fold — no
single sensor can be neutralised in isolation. *But* a large fraction of Morok's
*configured* surface is dead or inert on this Linux ELF: all 10 `windows_*`
passes, `anti_class_dump`, and `vtable_integrity` emit nothing; on Linux nearly
every runtime anti-debug verdict folds into **write-only accumulator globals
that nothing reads**; `self_checksum`'s native-code hash loop is dead while
unsealed; and `-O3` even leaked the supposedly-masked MAGIC sentinel into
plaintext. The durable, active defence on the *shipped* binaries is (1) the
no-boolean-to-flip cryptographic architecture and (2) the static-analysis /
virtualization battery — **not** the advertised runtime anti-debug verdicts.

---

## Part 1 — Layer A: source-level protections

Everything funnels through one sink: **`zt_derive`** (`zorya.c:262-277`), the
only function in section `zoryatext` (verified `0x832c` = 33,580 B, flags `AX`).
`checksum` enters the key **twice**: via `z_bc_bootstrap = SHA512(DOM_VM ||
checksum)[:32]` (decides whether the VM bytecode decrypts to honest bytecode, and
thus what `S` becomes) and directly in `z_post_key`. The sealer recomputes the
identical chain on plaintext with honest constants (`tracer = ZORYA_TRACER_WORD`,
`ge = 0`, on-disk `zoryatext` bytes), so seal-time and run-time agree bit-for-bit
**only** when the runtime environment is honest.

| Goal | Mechanism | How it binds the key | Load-bearing | Defeat cost |
|---|---|---|---|---|
| **Correctness-IS-the-key (no magic patch)** | Flag is XSalsa20 ciphertext in `zoryaseal`; key = the SHA-512 fold. MAGIC `memcmp(plain,magic,16)` (`zorya.c:371`) only selects GRANTED+print vs DENIED. | This *is* the key; all sensors are operands. Patching `ok=1` prints XSalsa20(wrong-key)⊕ct = garbage. | **Yes** | Reproduce every honest operand (dynamic) or recompute offline (static). Patching MAGIC ≈ 0 cost but yields garbage. |
| **No-keygen (Ed25519 signed messages)** | `z_ed25519_recompute` (`tweetnacl.c:822`) packs `t = pack(S·B − h·A)` **unconditionally** — no `crypto_verify_32` accept/reject; errors only on `n<64`/`n>1024`/malformed *public* key. `t` → `z_pre_state`. Verifier ships only `ZORYA_PK`. | `t` is a direct SHA-512 operand in `S0`. Genuine sig → `t==R`; wrong sig → a different valid point → wrong key, **never an error**. | **Yes** | Forge a sig that recomputes to the sealed `t` = break Ed25519 (closed). Or replay the shipped valid license. |
| **Self-checksum (SHA-512 over `zoryatext`)** | `compute_checksum` SHA-512s `[__start_zoryatext, __stop_zoryatext)`. `-no-pie` → file bytes == memory bytes. Feeds **both** `z_bc_bootstrap` and `z_post_key`. | A `0xCC`/patch/hook inside `zoryatext` changes the digest → wrong bootstrap (garbage bytecode) **and** wrong post-key. | **Yes** | Use HW breakpoints / read-without-modify. **Note:** SHA-512/XSalsa20 themselves live in `.text` (called out at `0x4032d0`/`0x402f50`), **not** measured — a breakpoint *there* does not poison the key. |
| **Sensor: single-step detection** | `z_singlestep_bit` (`zorya.c:175-200`) brackets a 4096-iter loop with `perf_event_open(SW_CONTEXT_SWITCHES)`; fallback `getrusage(RUSAGE_THREAD)`; else 0. `ge=(Δ≥4)` branchless. | `ge` is an LE64 operand in `z_post_key`; sealer assumes `ge=0`. Single-step inflates switches → `ge=1` → wrong key. | **Yes** | Never single-step the worker. The honest path *is* `ge=0`. |
| **Sensor: self-ptrace fork + key handshake** | main forks; child `PTRACE_TRACEME`+`SIGSTOP`; parent `PTRACE_O_EXITKILL`+`CONT`; parent `POKEDATA`s `ZORYA_TRACER_WORD` into a stack slot; `tracer_word=slot` (0 unless injected). | `tracer_word` is an LE64 operand in `z_post_key`; sealer assumes `ZORYA_TRACER_WORD`. No cooperating parent → 0 → wrong key. | **Yes** | Don't attach to the worker (one-tracer-per-task blocks external attach; external attach → TRACEME fails → unhandled SIGTRAP → EXITKILL). |
| **Sensor: userfaultfd-delivered encrypted bytecode** | `ZBC` (`zoryabc`, 0x2000 = 2 pages) = XSalsa20(bootstrap)⊕bytecode; uffd handler decrypts & serves pages on fault; eager flat-decrypt fallback; `UFFDIO_ZEROPAGE` on COPY failure. | `bootstrap = SHA512(DOM_VM||checksum)[:32]`; wrong checksum → garbage bytecode → unknown-opcode diffusion → wrong-but-defined `S`. | **Yes** (anti-dump of cleartext bytecode) | Compute bootstrap, XSalsa-decrypt `ZBC`, emulate the VM (~1 evening; all in `zcommon.h`). |
| **Sensor: stack-VM key schedule** | `z_vm_run` (`zcommon.h:119`) executes opcode pairs over 64-byte state: XORC/ADDC/ROTL/MULO/SETP/INCP/MIXN/SBOX/SWEEP/HALT; bijective nonlinear S-box; **unknown opcode = defined diffusion** (`zcommon.h:140`). | Nonlinearly maps `S0→S`, the dominant operand of `z_post_key`. | **Yes** | Reimplement offline. |
| **Direct raw syscalls** | Inline `z_sc0..z_sc6` (`zorya.c:45-79`) for all I/O and every privileged op (ptrace/perf/uffd/mmap/fork/wait4/kill/ioctl/poll/getrusage). | Does **not** change the key; removes libc/PLT hook points + import names that would advertise the sensors. | No (indirect) | Forces kernel-level tracing over cheap libc hooks; you still can't disable a sensor without disturbing its operand. |
| **String/MAGIC XOR-masking** | Banners XOR `0x5A`, unmasked at print by `zb_say`; MAGIC stored as `ZMAGIC_X ^ 0x5A`, unmasked by `z_unmask_magic`. | No key contribution; hides win text + which compare is cosmetic. | No | **Partially defeated by `-O3`** — see §3.4. |
| **Graceful degradation (fail-closed)** | perf→getrusage→`ge=0`; uffd→eager decrypt; COPY-fail→zeropage (wrong key); unknown opcode→defined diffusion. | Reproduces the honest key only under honest-but-limited conditions; wrong key (never the flag) under tampering. | No (no bypass) | N/A |

**TweetNaCl:** no primitive modified. Two same-TU additions —
`z_ed25519_recompute` (branch-free point math, the linchpin of "no boolean to
flip") and `z_ed25519_keypair` (issuer-only keygen).

---

## Part 2 — Layer B: the Morok battery (`preset = max`)

Build: `-O3 -no-pie -ffast-math`, target `x86_64-linux-musl`, `MOROK_SEED=1234`
(deterministic). `-no-pie` is required so `zoryatext` file bytes == runtime
bytes. The only *intended* config difference between builds is
`function_call_obfuscate` (on for dynamic / off for static) — but see §0(2):
the dynamic binary shows **no positive evidence** that FCO actually ran (libc
edges uncloaked, no deliberate-fault byte pattern, names plaintext in
`.dynsym`/PLT), so in practice the two shipped binaries differ by **linkage, not
obfuscation config**.

### 2.0 — DEAD / NO-OP passes on this Linux ELF (do **not** count toward active surface)

| Pass / knob | Status | Evidence |
|---|---|---|
| **All 10 `windows_*`** (pe_foundation, peb_heap_debug, debug_object, thread_hide, anti_attach, kernel_debugger, syscalls, unhook, veh_audit, process_mitigations) | **DEAD — emit nothing** | Each probe returns `nullptr` at `if(!TT.isOSWindows()||arch!=x86_64||ptr!=64)`; no ctor appended. |
| **`anti_class_dump`** | **DEAD** | Returns false without `OBJC_`/`__objc` metadata; pure C has none. |
| **`vtable_integrity`** | **DEAD** | `collectVTables` empty → bails; pure C has zero `_ZTV`. |
| **`caller_keyed_dispatch`** | **0 sites materialised** | `jmpq *%r14` (`41 ff e6`) **verified absent (count 0)** in both binaries. |
| **7 runtime-verdict states** (`antidbg/timing/trap/pftlb/cachetime/microcanary/antihook` *state*) | **Write-only accumulators nothing reads** | On Linux every `sealFold()` site is inside Darwin-only helpers; verdicts fold into dead state. |
| **`bcf` knobs** complexity/entropy_chain/junk_asm* | **Inert** | `BcfParams` carries only `{probability,iterations}`; the rest parsed then dropped. |
| **`csm` nested_dispatch/warmup; `const_enc` globalize\*** | **Inert** | Explicitly `(void)`-ed / no consumer reads them. |
| **`vec width=512`** | **Not realised** | Generic x86-64 (no `-mavx512`) legalises to **SSE2**: zero zmm/ymm. |
| **`sub_threshold`/`opt_amplify` FP paths** | **NO-OP** | Both gate out FP under any fast-math flag; `-ffast-math` stamps all FP. (Integer paths still active.) |
| **`self_checksum` native code loop (while unsealed)** | **Dead** | `kUnsealedCodeSize=0xFFFFFFFF` sentinel → `CreateCondBr(HasCode,…)` branches straight to Exit. |
| **`adversarial_tuning`** | **Likely NO-OP** | Self-disables on large modules; `emit_marker` globals are PrivateLinkage → stripped/invisible. |

### 2.1 — Control-flow & dispatch (anti-static, the headline)

Only **one** flattening-family pass runs per function (`Scheduler.cpp:607-646`)
in priority `non_invertible_state` > `data_entangled_flatten` > `csm` >
`flatten`, so plain `flatten` is a weak last resort. Manifest in both ELFs: 21
register-indirect `jmpq *%rax` dispatch sites, ~1300 8-byte block-address
pointers in `.data.rel.ro`, a 256-entry jump table at `0x602a60`, Murmur64 fmix
constants (`0xff51afd7ed558ccd`/`0xc4ceb9fe1a85ec53`) fingerprinting
`trace_keying`.

| Pass | Role | Notes / manifest | Defeat |
|---|---|---|---|
| bcf | anti-static, polymorphism | volatile-global self-compare → Jcc + dead junk arm | Low |
| flatten | anti-static | switch dispatcher on `fla.state` (weak fallback) | Low-med |
| split | dilution | tiny blocks (`stack_confusion` inert) | Trivial |
| indir_branch | anti-static | `mov rax,[tbl+idx*8]; jmp *rax` (`-no-pie` keeps absolute) | Medium |
| dispatcherless | anti-static, anti-DSE | indirectbr index XOR-fused w/ route-state via volatile shadow; clamp caps routes→32/terms→8 (**no clamp under `max` defaults of 24/6**) | Med-high |
| path_explosion | anti-symbolic | opaque-true guard; false arm = input-derived bounded loop + 3-way decoys (never runs) | Med (tools) / Low (manual) |
| uniform_lower | anti-static | arith→encrypted byte-table loads; branches→indirectbr | Medium |
| data_entangled_flatten | anti-static, anti-DSE | next-state = succ ^ token ^ token via volatile shadow | Med-high |
| csm | anti-static | T-function `step(x)=x+(x*x\|C)` telescoped transition (strongest static flatten) | High static / Low dynamic |
| **caller_keyed_dispatch** | (intended anti-tamper) | **VERIFIED ABSENT (0 sites)** | N/A |
| interprocedural_fsm | anti-static | state store → mutually-recursive identity helpers via volatile global | Medium |
| **trace_keying** | **anti-tamper + anti-instr (primary)** | rolling 64-bit edge hash; mismatch → latent global → **delayed nonlocal poison** of returns/conds | **High** (delocalised) |

### 2.2 — Data / constant / expression (anti-static + polymorphism)

Most load-bearing for a *license* crackme: **`const_enc`** (8-share XOR split +
4-round nonlinear Feistel via volatile loads, 3 modes incl. a `conditions_only`
rescue under a 6000-inst integrity budget) and **`str_enc`** (verified: all
baseline user strings gone; `.rodata` entropy **7.999**; 30 `cmpxchgb`
once-guards; 75 `pause` barriers). **Caveat:** const_enc encrypts *compare
immediates and de-switched magics*, **not every constant** — the anti-debug tag
`0x5a4f5259417631ff` (`ZORYA_TRACER_WORD`) still appears as a literal `movabsq`
(**2× in each binary, verified**). The absence of a single patchable license
`cmp #imm` gate is a *source-design* property (there is no such compare),
reinforced by const_enc — not proof that const_enc removed all magics.

| Pass | Role | Effective on Linux? |
|---|---|---|
| **const_enc** | anti-static (headline) + anti-tamper | **Yes — most load-bearing** (`globalize` inert) |
| **str_enc** | anti-static + lazy-decrypt anti-debug | **Yes — confirmed** |
| sub | anti-static, polymorphism | Partial (`-O3` recanonicalises; budget-gated) |
| mba | anti-static (SMT) | Partial (fixed catalog) |
| table_arith | anti-static (op→64K table) | **Low-yield** (i1..i16, no nsw/nuw; `-O3` flags most arith) |
| sub_threshold | anti-static | Integer only (**FP NO-OP** via `-ffast-math`) |
| type_pun | anti-static (type recovery) | Yes |
| pointer_launder | anti-static (alias/provenance) | Yes |
| alias_op | anti-static (aliasing opaque preds) | Yes (tight 1200-inst budget → small fns only) |
| opt_amplify | polymorphism | Integer/icmp only (**FP NO-OP**) |
| phi_tangle | anti-static (SSA web) | Yes (budget → small fns) |
| vec | anti-static (SIMD surface) | **128-bit SSE2 only** (no AVX/512) |

### 2.3 — Integrity / anti-tamper / cryptographic gating

Verified manifests: **13× `self_checksum`** magic `0xA7D13C5E9000C3B2`, **10×
`mutual_guard`** magic `0x8E21B7C4005AF10D` (both binaries, raw little-endian
byte search). Caveats: (a) `vtable_integrity` is a guaranteed no-op (pure C);
(b) **shipped unsealed** → `self_checksum`'s native code-byte loop is dead behind
the `0xFFFFFFFF` sentinel; (c) `mutual_guard` *does* emit a volatile per-byte
hash loop (`MutualGuardGraph.cpp:261-277`) but over a **self-referential random
IR-data region** whose expected hash was precomputed at IR time → folds a **zero
diff** on clean runs and covers **no native code** until a sealer rewrites the
postlink manifest. So both integrity passes are presently *tripwires for their
own globals + return poisoners*, latent on live-code integrity until sealed.

| Pass | Role | Effective on Linux? |
|---|---|---|
| self_checksum | anti-tamper + seal XOR | **Partial** — code path dead (unsealed); data-region tripwire only |
| data_flow_integrity | anti-tamper + anti-static (64K keyed tables) | **Yes** (sealing-independent) |
| mutual_guard | anti-tamper (mesh) + return poison | **Partial** — own IR region only, zero diff clean |
| shamir_share | anti-static (GF(256) immediate hiding) | **Yes — fully** |
| mq_gate | anti-symbolic/SMT | **Yes where it fires** (skips fns >700 insns/96 blk) |
| hash_self_decrypt | anti-static + anti-tamper + anti-debug | **Yes — Linux-tuned** (statfs syscall-137/cpuid/rdtscp; env/timing-keyed moving payload, trap-on-tamper) — **High** to defeat |
| vtable_integrity | C++ only | **DEAD** |
| **nanomites** | anti-static + anti-debug + anti-tamper | **Yes — active on Linux x86-64** (see below) |
| non_invertible_state | anti-static (lossy 31-bit state) | **Yes** |
| state_opaque | anti-static + anti-symbolic | **Yes** |

**Nanomites (corrected):** a `sigaction(SIGTRAP)`-installing ctor sits in
`.init_array` (**19 entries / 0x98**, vs 1 in baseline), branches are removed and
replaced by an `int3` (**not** `ud2`) with an `indirectbr` fallback, and the
SIGTRAP handler decodes an encrypted PC→target table. **But** only ~**2** sites
actually lowered per binary (consistent with `max`-preset `max_sites=16` + a
per-function cap of 4, *not* the `dynamic.toml` value of 1024). The ~10,242 raw
`0xCC` bytes are mostly operand/padding bytes (linear-sweep desync — itself
anti-disasm), not standalone traps. The 18 `ud2` come from unrelated unreachable
lowering.

### 2.4 — Anti-debug & runtime sensors (the decisive subtlety)

Verified hardware on x86-64 Linux: **96 rdtscp, 192 lfence, 112 cpuid, 337
syscall, 18 ud2** (static); `sigaction(SIGTRAP/SIGILL)`, `int3`/`icebp`,
Trap-Flag set/clear at 2 sites, `getppid` parent check; dynamic build imports
`clock_gettime`/`sigaction`/`dlsym`/`pthread_*`/`getenv`/`nanosleep`;
`.init_array` = 19 ctors. **The catch:** only two globals are *read* —
`morok.antidbg.seal` (read by `SelfChecksumConstants.cpp:527` /
`Virtualization.cpp:1579`) and `morok.watchdog.crypto`
(`SelfChecksumConstants.cpp:520`). Every other state global is a **write-only
accumulator**, and every `sealFold()` site is inside **Darwin-only** helpers —
**zero on the Linux path**. So on these binaries the direct ptrace/TracerPid/stat
verdicts and all five micro-arch oracles **fold into dead state and are
discarded.**

The **only real Linux teeth**:
1. **`anti_hook`'s hard `exit(1)`** — gated on corroboration ≥2 **AND** a
   resident `MSHookFunction` resolving via `dlsym`, itself gated on `_DYNAMIC`
   present → **dynamic build only; dead in the static build.**
2. **Watchdog heartbeat staleness** → `morok.watchdog.crypto` → checksum
   corruption — catches a debugger that **freezes** worker threads, not a passive
   ptrace attach.

| Pass | Linux status | Verdict bound? |
|---|---|---|
| anti_dbg | Active plumbing (ptrace/TracerPid/stat/seccomp/landlock/memfd-reexec) | **No** — folds to write-only state; teeth are seccomp/landlock + watchdog |
| anti_hook | **Active — only hard-kill path** | Partial — dynamic build only |
| timing/trap/page_fault/cache_timing/microarch_canary oracles | Active hardware | **No** — write-only state (cosmetic on this target) |
| microcode_stress | **Fully effective at rest** (computed indirectbr + overlapping-byte anti-disasm + ud2 bait) | N/A (anti-static) |
| anti_class_dump + 10× windows_* | **DEAD** | — |

### 2.5 — Virtualization / polymorphism / decoys / merging

**Two distinct VMs — do not conflate them:**

- **Morok's virtualization VM (Layer B):** lifts ~11 functions into encrypted
  PC-keyed bytecode in a **read-only** `.rodata` global `morok.vm.bytecode.*`
  (`isConstant=true`), driven by an `indirectbr`/`jmp *%rax` computed-goto
  interpreter. Critically `emitStreamKey` folds the **anti-debug verdict seal**
  (`seal XOR S0`) into the decode keystream — a tripped detector corrupts every
  decoded byte. **This is the load-bearing Morok pass** (weeks to defeat).
- **The crackme's own bootstrap VM (Layer A):** `z_vm_run`, a `switch`-dispatch
  interpreter whose XSalsa20-encrypted bytecode lives in the **writable** source
  section `zoryabc`, runs inside `zoryatext`, and calls its reader via
  `callq *%r13` at `0x4e48d5`/`0x4e48e4`. The `zoryabc`/`zoryatext` sections and
  that `*%r13` handler are **source-level**, not Morok artifacts.

| Pass | Role | Effective on Linux? |
|---|---|---|
| **virtualization** | anti-static (primary) + anti-tamper (seal-bound keystream) + polymorphism | **Yes — load-bearing** (~11 fns; protection helpers excluded by design) |
| func_wrap | call-graph dilution | Yes (modest) |
| function_call_obfuscate | anti-static/anti-hook | **No positive evidence it ran** on the shipped dynamic binary; off in static |
| stack_coalesce / stack_delta | anti-static (local/SP recovery) | Yes (dilution) |
| external_op | anti-static (volatile opaque preds) | Yes |
| coherent_decoy | anti-static + anti-tamper (decoy return poisons `morok.decoy.state`) | Yes |
| adversarial_merge | anti-similarity (signature-group dispatcher + outlining) | Yes (needs ≥2 same-sig fns) |
| adversarial_tuning | polymorphism (meta) | **Likely NO-OP** |
| per_build_polymorphism | polymorphism (cross-build) | Yes (cross-build only; `seed=1234` deterministic here) |
| **decoy_strings** | deception | **Yes — confirmed** ("sve"/B61-12/W76-1/RD-CNWDI bait dominate triage) |

---

## Part 3 — Binary forensics (what actually shipped)

Both `zorya-linux-x86_64` (dynamic) and `-static` are fully-stripped, **non-PIE**
(`Type=EXEC`, base `0x400000`) musl x86-64 ELFs. Baseline `zorya` = 31K vanilla
gcc build.

### 3.1 — Size blow-up (verified, figures corrected)

| Metric | Baseline | Dynamic | Static |
|---|---|---|---|
| File size | 30,568 B (~31K) | 2,136,888 B (**69.9×**) | 2,164,840 B (**70.8×**) |
| `.text` | 12,349 B (0x303d) | 931,854 B (0xe380e, **75.5×**) | 960,853 B (0xea955, **77.8×**) |
| `.rodata` | 2,720 B (0xaa0) | ~1.12 MB (entropy **7.9985**, ~413×) | 1,125,434 B (0x112c3a) |
| `zoryatext` | 1,340 B (0x53c) | **33,580 B (0x832c)** | **33,580 B (identical)** |
| `.init_array` | 8 B (1 ctor) | **0x98 (19 ctors)** | **0x98 (19 ctors)** |

### 3.2 — Unsealed state (verified)

`zoryabc` (0x2000) and `zoryaseal` (0x60) begin `a5 00 00 …`, all zeros after the
leading `0xA5` — link-time placeholders. The `zorya-mint seal` step never ran.
No real bytecode/flag is present.

### 3.3 — Confirmed Morok fingerprints

- **str_enc:** all baseline user strings gone (`ZORYA crackme`, `<name> <license>`,
  `ZORYA.nonce.*`, `license>` → **0 occurrences each**, verified); `.rodata`
  entropy 7.999; 30 `cmpxchgb` once-guards; 75 `pause` barriers.
- **opaque/state-opaque predicates:** `cmpl 0x..(%rip)` self-compares ×**9105**
  vs 0 in baseline.
- **dispatch:** 21 hash-indexed `jmpq *%rax`; 256-entry table at `0x602a60`.
- **integrity:** 13× self_checksum + 10× mutual_guard manifests (verified).
- **anti-debug:** 96 rdtscp / 192 lfence / 112 cpuid / 337 syscall / 18 ud2;
  sigaction(SIGTRAP/SIGILL) + int3/icebp + Trap-Flag toggles; getppid check.
- **nanomites:** ~2 standalone `int3` per binary (linear-sweep desync hides the rest).
- **caller_keyed_dispatch:** `jmpq *%r14` = **0** (pass produced no sites).

### 3.4 — Notable weaknesses surfaced

1. **`-O3` defeated the source string mask.** `ZMAGIC_X ^ 0x5A` ("ZORYAv1:UNSEALED")
   was meant to keep the MAGIC sentinel out of `strings`. The optimizer
   constant-folded `z_unmask_magic`, so the **plaintext** `ZORYAv1:UNSEALED`
   appears (1×) in both obfuscated builds while the **masked** form appears 0× —
   the opposite of the design intent. (It is the cosmetic sentinel, not the flag,
   and would appear sealed or not — so it is *not* a sealing tell — but it does
   tell a reverser exactly which compare is the MAGIC gate.)
2. **Static build leaks 139 plaintext musl libc strings** Morok never touched,
   giving an attacker a clean library cross-reference around the protected
   `zoryatext` island.
3. **IDA database artifacts** (`zorya-linux-x86_64.id0/.id1/.id2/.nam/.til`) show
   an analysis session already occurred on the dynamic build.

---

## Part 4 — Composition & adversary cost

### 4.1 — How the layers entangle

- **`checksum` is the hub:** gates VM-bytecode decryption *and* enters
  `z_post_key` directly — one `0xCC` in `zoryatext` corrupts both. Morok
  virtualization adds a second checksum-like binding: its decode keystream folds
  the anti-debug verdict seal, so observing/tampering the seal corrupts every
  decoded opcode.
- **Self-ptrace serves double duty:** occupies the one-tracer slot (blocks
  external attach) *and* delivers `tracer_word`. Detach → lose the word; stay
  attached → child TRACEME fails → unhandled SIGTRAP → EXITKILL kills the worker.
- **Single-stepping** the key math inflates context switches → `ge=1` → wrong key.
- **Morok integrity stacks on source integrity** — but the redundancy is
  **partially latent on the shipped binaries** (source unsealed; Morok
  `self_checksum` code loop dead; most Morok anti-debug verdicts inert on Linux).

### 4.2 — Honest active surface (shipped Linux ELFs)

**Real:** the Layer-A correctness-IS-the-key architecture + the six
operand-sensors (load-bearing for the *runtime-honesty* requirement regardless of
sealing) + Morok's static-analysis battery (flatten family, dispatcherless,
indir/uniform, const_enc, str_enc, shamir_share, data_flow_integrity,
virtualization, nanomites, microcode_stress, hash_self_decrypt) + two anti-debug
teeth (anti_hook kill *dynamic-only*; watchdog heartbeat).
**Overstated/dead:** all `windows_*`, `anti_class_dump`, `vtable_integrity`,
`caller_keyed_dispatch`, the 7 write-only-verdict oracle/anti_dbg paths,
`vec width=512`, the FP paths of `sub_threshold`/`opt_amplify`,
`adversarial_tuning`, and — for the shipped artifacts — the source seal +
`self_checksum` code loop.

### 4.3 — Cost to win

- **Path 1 — survive dynamically:** Let the worker run untraced; let the parent
  inject `tracer_word`; never single-step; let uffd serve pages.
  **On the shipped (unsealed) binaries: cannot win** — `ZSEAL`/`ZBC` are
  placeholders, so even a perfect honest run yields a wrong key. Requires the
  issuer to seal first. On a *sealed* binary: low-moderate (run honestly, read
  the printed flag) — Morok's runtime anti-debug barely impedes a *passive*
  observer on Linux.
- **Path 2 — reconstruct statically (the intended fair path):** recover the
  checksum (SHA-512 of readable `-no-pie` `zoryatext` bytes), derive `bootstrap`,
  XSalsa-decrypt `ZBC`, emulate the VM, recompute `t` from the shipped license,
  run the full SHA-512 fold. **Morok friction multiplies the cost**: the verifier
  logic is virtualized behind a PC-keyed, seal-entangled interpreter (weeks for a
  VM specialist), constants are 8-share Feistel-encrypted, control flow is
  flattened/dispatcherless, branches are nanomite-removed into a SIGTRAP table,
  decoy strings burn triage budget. Possible but expensive — and on the *shipped
  unsealed* binaries it reconstructs the machinery but not a real flag.

### Bottom line

ZORYA's defence is genuinely deep and well-entangled, and the **no-boolean-to-flip
cryptographic architecture** plus the **static-analysis/virtualization battery**
are its durable, active strength. But the *shipped Linux artifacts* are an
**unsealed verifier** whose strongest runtime teeth (source seal, Morok
`self_checksum` code loop) are latent, and whose advertised anti-debug *verdict*
surface is largely **write-only/inert on Linux**. A fair, playable challenge
requires the issuer to **seal a binary first**; the runtime anti-debug story is
also where the design over-promises relative to what executes on Linux.
