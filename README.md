# Morok

Morok is a modular C++23 LLVM New-PM IR obfuscator. It loads as a pass
plugin inside `clang` or `opt`, rewrites LLVM IR, and emits a behaviorally
equivalent program with fewer stable static landmarks, more hostile control and
data flow, and optional runtime self-protection.

The project is deliberately test-first. Pure arithmetic and encoding
primitives live below LLVM and are exercised by exhaustive/property unit tests.
The LLVM passes are tested as IR emitters and then as a whole pipeline by
compiling and running real C/C++ programs clean vs obfuscated.

Morok is intended for binaries you own or are explicitly authorized to protect
and test. It raises static and dynamic analysis cost; it is not a trust
boundary, a license system by itself, or a substitute for platform signing,
attestation, sandboxing, or server-side policy.

## Contents

- [Scope](#scope)
- [Repository Layout](#repository-layout)
- [Build Requirements](#build-requirements)
- [Build](#build)
- [Authoritative Test Gate](#authoritative-test-gate)
- [Quick Use](#quick-use)
- [Cross Builds and Post-Link Sealing](#cross-builds-and-post-link-sealing)
- [Configuration Model](#configuration-model)
- [Presets](#presets)
- [Annotations](#annotations)
- [Scheduler Order](#scheduler-order)
- [Pass Inventory](#pass-inventory)
- [TOML Option Reference](#toml-option-reference)
- [Platform Notes](#platform-notes)
- [Static-Recovery Resistance Notes](#static-recovery-resistance-notes)
- [Development Workflow](#development-workflow)
- [Troubleshooting](#troubleshooting)
- [Related Documents and Examples](#related-documents-and-examples)
- [License](#license)

## Scope

Morok can do things an LLVM IR pass can produce:

- Rewrite integer, floating, pointer, stack, PHI, branch, call, string,
  constant, vtable, and VM bytecode IR.
- Emit constructors, helper functions, helper threads, inline assembly,
  signal/exception handlers, direct syscalls, and platform-specific runtime
  probes into the target binary.
- Generate deterministic per-build and per-callsite diversity from a seed.
- Emit post-link manifests for later patching where final native bytes are
  needed, with release gates that scrub retained bypass data after sealing.
- Keep growth bounded with function, module, callsite, table, payload, clone,
  route, and visit caps.

Morok cannot do things that require external infrastructure:

- It cannot sign Mach-O or PE files, provision entitlements, enable HVCI/PPL,
  or turn on compiler/linker features such as CFG/XFG/CET/PAC/BTI/RELRO.
- It cannot provide TPM/SGX/TrustZone/SEV/Secure-Enclave remote roots of trust.
- It cannot make a hostile kernel, debugger, hypervisor, or administrator
  trustworthy.
- It cannot make all platforms equally complete. Some high-intensity runtime
  paths are currently Apple-first and are gated in the test suite elsewhere.

The implementable protection backlog is tracked in
[`docs/insurance-tasks.md`](docs/insurance-tasks.md). Algorithm and pass details
live in [`docs/algorithms.md`](docs/algorithms.md) and
[`docs/hardness.md`](docs/hardness.md).

## Repository Layout

Morok is layered so each level depends strictly downward:

```text
morok::core       Pure algorithms: PRNGs, Feistel, GF(2^8), XOR sharing,
                  MBA/substitution identities, MQ/T-function/Knuth helpers.
                  No LLVM, no I/O.

morok::config     Presets, TOML loading, policy resolution, pass options.
                  No LLVM; demangling is injected.

morok::ir         LLVM helper layer: annotations, symbol cloaking, IR random
                  adapters, shared emit utilities.

morok::passes     New-PM pass implementations plus testable free functions.

morok_plugin      Loadable New-PM pass plugin, emitted as libMorok.
```

Tracked top-level paths:

```text
include/morok/{core,config,ir,passes,pipeline}/   public headers
src/{core,config,ir,passes,pipeline}/             implementations
tests/{unit,ir,e2e}/                              unit, IR, and e2e gates
third_party/{doctest,tomlplusplus}/               vendored header-only deps
cmake/Morok{LLVM,Test,Warnings}.cmake             build policy modules
docs/algorithms.md                                pass and scheduler reference
docs/hardness.md                                  primitive hardness notes
docs/insurance-tasks.md                           implementable protection checklist
docs/roadmap.md                                   design backlog and reality notes
cross_build.sh                                    Linux/macOS cross-build helper
run_tests.sh                                      authoritative local test entrypoint
```

Optional local paths may exist in a developer tree:

```text
programs/                                         stress corpus for compile/run sweeps
crackmes/                                        example protected programs
issues/                                          local issue triage material
build*/                                          generated build trees
```

## Build Requirements

- CMake 3.28 or newer.
- Ninja.
- A C11 and C++23 capable toolchain.
- LLVM 18 or newer with the New-PM plugin API Morok targets; current vanilla
  LLVM 22/23-style builds are the expected path.

Morok does not require a private LLVM fork. It does require the LLVM headers and
the `clang`/`opt` binaries used at runtime to agree on the same New-PM pass
plugin ABI. The build currently checks for `<llvm/Plugins/PassPlugin.h>` with
`LLVM_PLUGIN_API_VERSION == 2`; older LLVM installs that only expose
`<llvm/Passes/PassPlugin.h>` with API version 1 are a different plugin ABI and
will be rejected by [`cmake/MorokLLVM.cmake`](cmake/MorokLLVM.cmake) instead of
failing later with a cryptic plugin-load error.

The test/build helper defaults to a local LLVM install under `/Users/int/local`.
Override with `CC`, `CXX`, and `LLVM_DIR` when using another matching LLVM.

## Build

```sh
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DLLVM_DIR="$LLVM_PREFIX/lib/cmake/llvm"
cmake --build build
ctest --test-dir build -j
```

Useful CMake options:

```text
MOROK_BUILD_TESTS=ON       build tests
MOROK_BUILD_PLUGIN=ON      build libMorok
MOROK_WERROR=OFF           treat warnings as errors when ON
MOROK_SANITIZE=OFF         ASan/UBSan for pure layers/tests when ON
```

Plugin output names:

```text
macOS:   build/src/pipeline/libMorok.dylib
Linux:   build/src/pipeline/libMorok.so
Windows: build/src/pipeline/libMorok.dll
```

On Unix, the plugin is a loadable module that resolves LLVM symbols from the
loading `clang`/`opt` process. On Windows, the plugin statically links the LLVM
component libraries it uses and explicitly exports `llvmGetPassPluginInfo`.

## Authoritative Test Gate

Use the top-level script unless you are intentionally narrowing the loop:

```sh
./run_tests.sh            # incremental configure/build + entire ctest suite
./run_tests.sh --clean    # remove build/ and configure from scratch
./run_tests.sh -R passes  # ctest name regex
./run_tests.sh -L ir      # label filter; labels include core/config/ir/e2e,
                          # security/adversarial/programs/max/linux/threading,
                          # and core/config/ir/unit/aggregate
```

The full gate covers:

| Layer | Test style | Evidence |
|---|---|---|
| `core` | exhaustive/property doctest suites | arithmetic, field, cipher, PRNG, sharing, and identity primitives are correct independently of LLVM |
| `config` | doctest suites | presets, merge precedence, policy resolution, TOML parsing, and error paths |
| `ir` / `passes` | LLVM-linked IR tests | every pass emits verifier-clean IR and fires on representative shapes |
| whole pipeline | clean-vs-obfuscated differentials | compiled binaries preserve output across presets/configs/seeds |
| build/release hygiene | shell/Python e2e gates | static config layering, entropy-seeded cross-build default, pinned privileged GitHub Actions, release audit policy, and fail-closed unsealed behavior stay enforced |
| `programs/` corpus | compile and runtime sweeps, when present | real C/C++ programs compile at high/max intensity; curated deterministic programs also run byte-for-byte equal |

Platform behavior in the e2e suite:

| Host | E2E behavior |
|---|---|
| Apple | Exercises built-in `high`/`max`, `tests/e2e/max.toml`, VM-specific differential tests, release audit, and adversarial post-link patch/fail-closed tests when Python is available. |
| Non-Apple | Uses `tests/e2e/portable.toml` for high-intensity e2e paths where virtualization and some anti-analysis/mutual-guard runtime paths are not yet fully ported. |
| Windows | Skips behavioral plugin-dlopen e2e tests; coverage comes from core/config/IR tests and targeted object-level checks. |

## Quick Use

Set the plugin path once:

```sh
PLUGIN=build/src/pipeline/libMorok.dylib  # macOS
# PLUGIN=build/src/pipeline/libMorok.so   # Linux
# PLUGIN=build/src/pipeline/libMorok.dll  # Windows
```

Whole pipeline from `clang`:

```sh
clang -O2 -fpass-plugin="$PLUGIN" \
  -mllvm -morok \
  -mllvm -morok-preset=high \
  -mllvm -morok-seed=1234 \
  prog.c -o prog
```

Whole pipeline from `opt`:

```sh
opt -load-pass-plugin "$PLUGIN" \
  -passes=morok prog.ll -o out.bc
```

One standalone pass:

```sh
opt -load-pass-plugin "$PLUGIN" \
  -passes=morok-strenc prog.ll -o out.bc
```

Configuration can be supplied by flag or environment:

```sh
clang -O2 -fpass-plugin="$PLUGIN" \
  -mllvm -morok \
  -mllvm -morok-config=morok.toml \
  -mllvm -morok-seed=0xC0FFEE \
  prog.c -o prog

MOROK_CONFIG=morok.toml \
MOROK_SEED=0xC0FFEE \
clang -O2 -fpass-plugin="$PLUGIN" -mllvm -morok prog.c -o prog
```

Environment switches recognized by the plugin:

```text
MOROK_ENABLE=1                         opt into clang auto-injection without -mllvm -morok
MOROK_CONFIG=path                      config file fallback when -morok-config is absent
MOROK_PRESET=high                      preset fallback when no config file is loaded
MOROK_SEED=1234                        seed fallback when -morok-seed is absent or zero
MOROK_CKD_SEAL_REQUIRED=1              require a post-link CKD seal instead of startup self-seal fallback
MOROK_FAIL_CLOSED_ON_UNSEALED=1        poison seal-dependent paths if retained manifests are still unsealed
```

When `-morok-config` or `MOROK_CONFIG` loads successfully, that file supplies
the preset base through `[global].preset`; `-morok-preset` is only used when no
config file is loaded. `-morok-seed` and `MOROK_SEED` override the config seed
for reproducible builds.

The command-line equivalents for the strict release switches are
`-mllvm -morok-ckd-seal-required` and
`-mllvm -morok-fail-closed-on-unsealed`. Only enable them for builds where the
binary will be post-link sealed before first run; an unsealed strict build is
supposed to fail closed rather than silently self-recover.

For `clang -fpass-plugin`, Morok also registers extension-point callbacks:

- vectorizer-start: early optimizer amplification when enabled.
- pipeline-early-simplification: VM candidate preservation for `-mllvm -morok`.
- optimizer-last: the main Morok scheduler.

## Cross Builds and Post-Link Sealing

The helper in [`cross_build.sh`](cross_build.sh) builds a source file through
Morok for Linux and/or macOS:

```sh
./cross_build.sh --source programs/cf_license_crackme.c --out-dir build/cross
./cross_build.sh --linux-only --source boo.c --out-dir build/cross
./cross_build.sh --macos-arches "arm64 x86_64" --preset max
./cross_build.sh --config morok.toml --seed 832040
```

Common options:

| Option | Meaning |
|---|---|
| `--source PATH` | Source file to build. A positional source path is also accepted. |
| `--out-dir DIR` | Output directory. |
| `--preset NAME` | Preset to use when `--config` is not supplied. |
| `--config PATH` | TOML config file to use instead of a preset-only build. |
| `--seed N` | Deterministic Morok seed. |
| `--clang PATH`, `--clangxx PATH` | C/C++ compiler drivers matching the plugin LLVM ABI. |
| `--plugin PATH` | Morok plugin path. |
| `--linux-target TRIPLE` | Linux target triple. |
| `--linux-cc PATH` | GCC-compatible Linux cross toolchain driver for crt/libgcc lookup. |
| `--macos-arches LIST` | Space-separated macOS arches or target triples. |
| `--macos-min VERSION` | macOS deployment target. |
| `--linux-only`, `--macos-only` | Build only one platform family. |
| `--no-linux`, `--no-macos` | Skip one platform family. |
| `--no-strip` | Leave produced binaries unstripped. |
| `--no-audit` | Skip the final `morok-audit` release gate. |
| `-h`, `--help` | Show the script help. |

Recognized environment overrides include `BUILD_DIR`, `OUT_DIR`, `CLANG`,
`CLANGXX`, `PLUGIN`, `PRESET`, `SEED`, `OPT_LEVEL`, `LINUX_TARGET`,
`LINUX_CC`, `LINUX_STATIC`, `LINUX_SYSROOT`, `LINUX_STRIP`, `MACOS_ARCHES`,
`MACOS_MIN`, `MACOS_SDK`, `SEAL_BINARIES`, `SEAL_WINDOW`, `SEAL_TOOL`,
`AUDIT_BINARIES`, `AUDIT_TOOL`, `AUDIT_PROVENANCE`, `AUDIT_ALLOWLIST`,
and `PYTHON`.

Important defaults:

```text
source:       programs/cf_license_crackme.c
out dir:      build/cross
preset:       max, unless --config is provided
seed:         0, which means per-build entropy
optimization: -O3
clang:        clang-23
plugin:       build/src/pipeline/libMorok.dylib
Linux target: x86_64-linux-musl
macOS min:    13.0
strip:        enabled
sealing:      enabled
```

For static Linux outputs, `cross_build.sh` derives a temporary TOML config that
forces `[passes.function_call_obfuscate].enabled = false`. A fully static binary
has no dynamic loader, so dynamic import lookup has no useful hiding surface and
can crash if left enabled.

Post-link sealing is mandatory for shippable binaries that rely on
`self_checksum_constants`, `mutual_guard_graph`, or `caller_keyed_dispatch`
native-code windows. The IR passes reserve retained manifests, but final code
byte ranges are only known after linking and stripping. `cross_build.sh` seals
automatically after strip and fails closed if no manifests are present. The
post-link sealer uses the requested `--window` as the native-code hash coverage
limit; the self-check random-data `region_bytes` setting does not cap code
coverage. It then runs `tools/morok-audit.py` over the final output directory to
reject unsealed manifests, placeholder manifest state, private-key sidecars,
embedded development paths, plaintext high-value release markers, and plaintext
magic/sentinel markers before anything is shipped.

When macOS sealing is enabled, `cross_build.sh` also passes the strict seal
flags (`-morok-ckd-seal-required` and
`-morok-fail-closed-on-unsealed`) before the post-link seal/re-sign step. Linux
outputs are still sealed and audited by default, but the helper leaves those
strict plugin flags off for the Linux compile path; add them only in a pipeline
that has proven its Linux sealing step is mandatory and runs before the binary
can execute.

Manual sealing is:

```sh
python3 tests/e2e/adversarial_binary.py seal path/to/binary --window 262144
```

On macOS, an in-place seal invalidates the ad hoc signature, so the helper
re-signs the binary after patching.

Manual release audit is:

```sh
python3 tools/morok-audit.py build/cross --release --require-sealed-manifest \
  --provenance build/cross/morok-audit.json
```

The audit verifies self-check, mutual-guard, and caller-keyed-dispatch post-link
records, then writes a provenance manifest with file hashes, detected binary
formats, sealed-manifest counts, and any findings. Release findings are hard
failures. Test fixtures must be allowlisted explicitly with a versioned JSON
file:

```json
{
  "version": 1,
  "allow": [
    {"path": "fixtures/*.pem", "checks": ["private-key-sidecar"]}
  ]
}
```

## Configuration Model

Config layering is intentionally simple:

1. `[global].preset` loads `low`, `mid`, `high`, `max`, or `none`.
2. `[passes.*]` sections override only fields they mention.
3. Ordered `[[policy]]` rules can apply another preset and/or pass overrides to
   matching module/function regexes.
4. `-mllvm -morok-seed=N` or `MOROK_SEED=N` overrides the config seed for
   deterministic builds.

Top-level global keys:

```toml
[global]
preset = "high"
seed = 0xDEADBEEF1337
verbose = false
trace = false
demangle_names = true
```

Example:

```toml
[global]
preset = "high"
seed = 0xDEADBEEF1337
demangle_names = true

[passes.string_encryption]
enabled = true
probability = 100
skip_content = ["Usage:"]

[passes.function_call_obfuscate]
enabled = true

[passes.windows_process_mitigations]
enabled = true

[[policy]]
function = "^main$"
passes.bcf.enabled = false
passes.substitution.enabled = false

[[policy]]
function = "license|verify|decrypt"
passes.mba.enabled = true
passes.external_opaque_predicates.enabled = true
passes.virtualization.enabled = true
```

Policies are evaluated in file order by
[`src/config/Resolver.cpp`](src/config/Resolver.cpp). Regexes match the module
source filename and/or function name. If `demangle_names = true`, policy
function matching uses demangled names where possible.

## Presets

| Preset | Intent |
|---|---|
| `none` | No preset base. Only explicitly enabled pass sections or policies apply. |
| `low` | Light scalar/control rewriting, string encryption, constant sharing, split blocks, and retained decoy strings. |
| `mid` | Broader scalar/control obfuscation with more density and vector/table features than `low`. |
| `high` | Bounded aggressive mode: capped VM/self-decrypt/integrity/table/MQ/microstress/function-wrapper slices while keeping expensive graph-wide searches controlled. Fault-paged payload knobs are preset but opt-in while the portable backend is `lazy_accessor`. |
| `max` | Full preset-managed stack: high probabilities, maximal tested budgets, anti-debug/anti-hook/timing/trap bundle, FCO, VM, self-decrypt, integrity, routing, wrappers, Windows pass toggles, and decoys. Fault-paged payload delivery remains opt-in until an OS-backed backend meets the max runtime gate. |

The scheduler enforces instruction, block, function, module, byte, table,
route, callsite, clone, payload, and visit caps. If a function or module grows
beyond the relevant budget, later growth passes are skipped rather than
allowing unbounded IR expansion.

## Annotations

Source annotations are copied from Clang's `llvm.global.annotations` into Morok
metadata before scheduling:

```c
__attribute__((annotate("sub")))       static int force_sub(int x) { return x + 1; }
__attribute__((annotate("nosub")))     static int skip_sub(int x)  { return x + 1; }
__attribute__((annotate("sensitive"))) static int hot_secret(int x) { return x * 7; }
```

Per-function annotation keys are the scheduler tags:

```text
aliasop, bcf, csm, constenc, decoy, dfi, dispatchless, entfla, extop,
fla, ifsm, indibran, mba, microstress, mq, mutualguard, nistate, optamp,
pathexplode, phitangle, ptrlaunder, selfcheck, shamir, split,
stackcoalesce, stackdelta, stateop, sub, tablearith, threshold, tracekey,
typepun, uniform, vobf
```

Prefix any key with `no` to force that pass off for a function, for example
`nomba`, `nobcf`, or `noconstenc`.

`sensitive` is special: when BCF, MBA, or external opaque predicates are unset
or enabled, the scheduler raises their density on that function. Explicit
negative annotations still win.

## Scheduler Order

The whole-pipeline `morok` pass is ordered to preserve semantics and maximize
composition:

```text
VM(user code)
-> fault-paged VM payload delivery
-> hash-gated VM self-decrypt for remaining eager payloads
-> anti-hook / anti-class-dump / Windows substrate and Windows probes
-> anti-debug / timing / scheduler-step / trap / page-fault / cache / microarchitectural probes
-> decoy strings
-> string encryption
-> function-call obfuscation
-> vtable integrity
-> per-function structural, scalar, CFG, data-flow, integrity, and literal passes
-> leaf-helper seal binding
-> VM/hardening for generated protection helpers
-> nanomites
-> adversarial self-tuning / merge
-> caller-keyed dispatch
-> function wrappers
-> per-build polymorphism
-> misleading metadata
-> generated-symbol privacy cleanup
```

Within the per-function loop, Morok runs structural and value-level transforms
before routing/integrity/literal hiding:

```text
de-switch wide gate constants
-> split
-> BCF
-> optimizer amplification
-> substitution
-> MBA
-> sub-threshold persistence
-> alias/external opaque predicates
-> coherent decoys
-> exactly one flattening family member: NiState / EntFla / CSM / Flatten
-> state opaque predicates
-> interprocedural FSM
-> PHI tangling
-> type punning
-> stack coalescing
-> stack delta games
-> pointer laundering
-> DFI
-> table arithmetic
-> uniform primitive lowering
-> vector obfuscation
-> path explosion
-> MQ gates
-> trace keying
-> dispatcherless routing
-> microcode stress
-> self-checksum constants
-> mutual guard graph
-> Shamir sharing
-> constant encryption
-> condition-only constant encryption rescue
-> indirect branch
```

The precise maintained order is documented in
[`docs/algorithms.md`](docs/algorithms.md#scheduler-order-to-preserve-semantics).

## Pass Inventory

Each pass can be run standalone with `-passes=morok-*` where registered, or
through the scheduler with a TOML section. Some final hygiene transforms, such
as misleading metadata, leaf-helper seal binding, protection-helper hardening,
and private-linkage cleanup for generated `morok.*` helpers, are scheduler-only.

### Structural, Control-Flow, and Decompiler Stress

| Capability | `-passes` name | TOML section | Summary |
|---|---|---|---|
| Split basic blocks | `morok-split` | `split_blocks` | Splits blocks into more dispatch targets. |
| Bogus control flow | `morok-bcf` | `bcf` | Adds opaque-true guarded junk/decoy edges with optional entropy and inline-asm pressure. |
| Flattening | `morok-flatten` | `flattening` | Classic switch-dispatcher control-flow flattening. |
| Data-entangled flattening | `morok-entfla` | `data_entangled_flattening` | Stores successor state through live-data and previous-state tokens. |
| Non-invertible state | `morok-nistate` | `non_invertible_state` | Uses keyed lossy hashes for encoded dispatcher states. |
| Stateful opaque predicates | `morok-stateop` | `state_opaque_predicates` | Places opaque guards over flattened state plus scalar live terms. |
| Interprocedural FSM | `morok-ifsm` | `interprocedural_fsm` | Routes flattened state transitions through mutually-recursive helper calls. |
| Chaos state machine | `morok-csm` | `chaos_state_machine` | Flattens through logistic-map or T-function state evolution. |
| T-function flattening | `morok-tfa` | `chaos_state_machine` | Convenience standalone CSM variant using a single-cycle T-function generator. |
| Dispatcherless routing | `morok-dispatchless` | `dispatcherless_routing` | Replaces direct branch/switch edges with state-entangled `indirectbr` DAGs. |
| Indirect branch | `morok-indbr` | `indirect_branch` | Lowers surviving conditional/switch edges through randomized `indirectbr` tables. |
| Microcode stress | `morok-microstress` | `microcode_stress` | Emits oversized blockaddress tables and aliased decoy destinations. |
| Path explosion | `morok-pathexplode` | `path_explosion` | Adds opaque-guarded input-derived decoy loops and volatile symbolic stores. |
| Coherent decoys | `morok-decoy` | `coherent_decoys` | Adds plausible dead alternate return computations and hidden decoy-tamper state. |
| Alias opaque predicates | `morok-aliasop` | `alias_opaque_predicates` | Maintains pointer/alias invariants that guard decoy edges. |
| External opaque predicates | `morok-extop` | `external_opaque_predicates` | Uses IPO-blocked volatile helper guards and scratch decoy arms. |
| MQ gate | `morok-mq` | `mq_gate` | Plants GF(2) quadratic opaque gates over argument-derived bits. |
| Nanomites | `morok-nanomites` | `nanomites` | Replaces selected branches with trap-mediated encrypted target lookup on supported POSIX triples. |
| Adversarial merge/outline | `morok-afm` | `adversarial_function_merging` | Merges same-signature functions behind selector dispatchers and outlines scalar fragments. |
| Adversarial self-tuning | `morok-selftune` | `adversarial_self_tuning` | Scores cloned candidate bundles and replays the strongest verifier-clean bundle. |
| Per-build polymorphism | `morok-polymorph` | `per_build_polymorphism` | Reorders functions/blocks and adds neutral volatile return anchors from the seed. |

### Scalar, Data-Flow, Stack, and Literal Obfuscation

| Capability | `-passes` name | TOML section | Summary |
|---|---|---|---|
| Instruction substitution | `morok-substitution` | `substitution` | Rewrites integer ops into equivalent expression trees. |
| Mixed Boolean-Arithmetic | `morok-mba` | `mba` | Layers MBA identities and zero-noise terms. |
| Optimizer amplification | `morok-optamp` | `optimizer_amplification` | Emits input-selected equivalent forms before optimizer lowering. |
| Sub-threshold persistence | `morok-threshold` | `sub_threshold_persistence` | Adds volatile local-seed opaque-zero terms below fold thresholds. |
| Constant encryption | `morok-constenc` | `constant_encryption` | Reconstructs literals from volatile XOR shares and optional Feistel/sharing layers. |
| Shamir threshold sharing | `morok-shamir` | `shamir_share` | Reconstructs selected scalar literals from volatile GF(2^8) threshold shares. |
| Table arithmetic | `morok-tablearith` | `table_arithmetic` | Lowers narrow/const-indexed ops to encrypted lazy lookup tables. |
| Uniform primitive lowering | `morok-uniform` | `uniform_primitive_lowering` | Table-lowers byte ops and selected branches into memory-loaded dispatch. |
| Vector obfuscation | `morok-vec` | `vector_obfuscation` | Lifts scalar ops/casts/comparisons/selects into SIMD lanes. |
| Stack coalescing | `morok-stackcoalesce` | `stack_coalescing` | Collapses static allocas into one opaque byte buffer. |
| Stack delta games | `morok-stackdelta` | `stack_delta_games` | Adds dynamic stack-pointer deltas and overlapping volatile stack touches. |
| Pointer laundering | `morok-ptrlaunder` | `pointer_laundering` | Sends pointers/scalars through pointer-int and byte-vector boundaries. |
| Type punning | `morok-typepun` | `type_punning` | Round-trips scalars through volatile union-buffer reinterpretation chains. |
| PHI tangling | `morok-phitangle` | `phi_tangling` | Builds redundant scalar PHI webs and cross-edge value copies. |

### Strings, Imports, Calls, and C++ Dispatch

| Capability | `-passes` name | TOML section | Summary |
|---|---|---|---|
| String encryption | `morok-strenc` | `string_encryption` | Encrypts eligible private byte-array globals with a unique per-string cipher. Safe C-string callsites are materialized into per-use stack buffers; unsupported uses get per-string constructor decryptors. |
| Sealed blobs | `morok-sealedblob` | `sealed_blob` | Encrypts explicit `.morok.sealed` byte-array globals and rewrites supported reads through per-blob lazy accessors keyed by RuntimeSeal/external-proof material, with optional runtime-keyed magic-prefix diagnostics. |
| Function-call obfuscation | `morok-fco` | `function_call_obfuscate` | Hides external calls behind per-site import indirection. Linux/macOS 64-bit paths use manual export-by-hash resolvers where supported; unsupported targets use per-site cloaked dynamic lookup. |
| Caller-keyed dispatch | `morok-ckd` | `caller_keyed_dispatch` | Collapses surviving direct user calls through a shared dispatch hub keyed by caller context and post-link sealed integrity bytes. |
| Function wrapper | `morok-funcwrap` | `function_wrapper` | Wraps calls after per-function transforms so callers see proxy edges. |
| VTable integrity | `morok-vtable` | `vtable_integrity` | Guards Itanium C++ virtual dispatches by expected vptr, slot, target, and cookie hash. |
| Decoy strings | `morok-decoystr` | `decoy_strings` | Distributes retained plaintext honeypot diagnostics and fake logging infrastructure. |

String encryption intentionally excludes generated `morok.decoy.str.*` globals.
Those decoys must remain visible to cheap triage tools such as `strings`; real
user strings are encrypted, length-padded where safe, and materialized lazily.
Sealed blobs are opt-in: mark a private byte-array global with section
`.morok.sealed` or a `morok.sealed.` prefix. Supported load/no-capture call
uses materialize into per-use stack buffers via a per-blob `morok.sealed.open.*`
helper, then volatile-zero the temporary buffer when configured.
With `runtime_keyed_magic=true`, each generated accessor derives a per-blob
prefix tag from the anti-debug RuntimeSeal channel and the blob id, compares it
against the materialized plaintext prefix without early exit, and stores only an
opaque volatile diagnostic word. The compare is not the primary access gate and
does not require a plaintext sentinel to survive in `.rodata`.

### Virtualization and Integrity Entanglement

| Capability | `-passes` name | TOML section | Summary |
|---|---|---|---|
| Virtualization | `morok-vm` | `virtualization` | Lifts eligible integer/pointer computation kernels to encrypted threaded bytecode VMs, including multi-block, memory, cast, compare, division, selected intrinsics, and direct internal helper calls when safe. |
| Fault-paged payload delivery | `morok-fpp` | `fault_paged_payload` | Encrypts VM bytecode per page and replaces direct bytecode loads with a lazy accessor that decrypts one page-local cache at a time, re-clears page state on switches, and binds anomalous access to the `fault_paged_payload` runtime seal channel. |
| Hash-gated self-decrypt | `morok-selfdecrypt` | `hash_gated_self_decrypt` | Lazily decrypts VM bytecode from runtime hashes/context and re-encrypts on helper exit. |
| External proof binding | `morok-proofbind` | `external_secret_binding` | Materializes a proof feed/finish API and folds the proof digest difference into the `external_proof` runtime seal channel, so only the expected proof keeps the clean key state. |
| Tracer attestation | `morok-tracer` | `tracer_attestation` | Uses a Linux/x86_64 buddy tracer to inject runtime-only share words into the parent and folds only delivery mismatch deltas into the `tracer` and anti-debug runtime seal channels. |
| Self-checksum constants | `morok-selfcheck` | `self_checksum_constants` | Fuses constants with runtime checksum diffs so tamper corrupts data instead of branching. |
| Mutual guard graph | `morok-mutualguard` | `mutual_guard_graph` | Emits overlapping checksum nodes whose aggregate diff poisons scalar returns. |
| Data-flow integrity | `morok-dfi` | `data_flow_integrity` | Decodes narrow op tables from runtime integrity hashes and decoy hidden state. |
| Execution-trace keying | `morok-tracekey` | `execution_trace_keying` | Carries a rolling trace accumulator and delayed tamper samples through data/control state. |

For `external_secret_binding`, `expected_digest` is the expected 64-bit final
proof accumulator accepted by `morok.proof.finish`. If it is omitted or invalid,
the pass uses a per-build random expected value so arbitrary proof presence fails
closed instead of keeping the clean seal state.

VM dispatch is total over all 256 decoded handler IDs. Invalid decoded opcodes,
registers, pointer-table indexes, branch targets, and unsafe div/rem operands
are folded into a local poison accumulator and canonicalized to in-bounds state
instead of trapping or indexing out of range. A guarded per-PC opcode check also
poisons valid-but-wrong handler IDs, so a wrong key cannot cleanly land on
another real handler. Fault-paged payload delivery is
preferred for configured VM payloads and leaves already protected bytecode
mutable, so hash-gated self-decrypt only wraps remaining eager payloads. It does
not allocate a full-payload plaintext scratch buffer; the accessor decrypts the
requested page into a fixed-size cache and clears it before another page is
materialized. Hash-gated self-decrypt follows the same release-mode policy: a
failed payload hash poisons the bytecode and publishes it as ready so tamper
surfaces as wrong VM output, not a fixed `llvm.trap` oracle.

The scheduler runs a second, restricted VM/hardening stage over allowlisted
generated protection helpers so anti-debug, anti-hook, decryptor, and integrity
logic is not left as a simple native plaintext island.

### Anti-Analysis and Platform Runtime Passes

| Capability | `-passes` name | TOML section | Summary |
|---|---|---|---|
| Anti-debugging | `morok-antidbg` | `anti_debugging` | Layered POSIX debugger probes, watchdog cadence, direct syscalls where supported, Linux Landlock/seccomp/memfd re-exec/DR helper paths, macOS ptrace/sysctl/csops/Mach debug-state paths, and hidden-state folding. |
| Anti-hooking | `morok-antihook` | `anti_hooking` | Clean-copy executable byte diff, prologue hook scan, function-window MACs, GOT/PLT or Mach-O fixup validation, W^X enforcement, address-space census, guarded pages, anti-dump, call-stack origin checks, method divergence, anti-VM/DBI heuristics, negative-space verification, and corroboration scoring. |
| Anti-class-dump | `morok-antiacd` | `anti_class_dump` | Scrambles Objective-C metadata when present. |
| Platform runtime | internal API | `platform_runtime` | Centralizes POSIX direct-syscall/libc fallback, Darwin direct anti-debug syscall, page-protection, file, and Windows runtime policy decisions for the anti-analysis producers. |
| Timing oracle | `morok-timing` | `timing_oracles` | Samples short spans with independent clocks and folds slow/divergent distributions into private state. |
| Scheduler-step oracle | `morok-step` | `scheduler_step_oracles` | Samples context-switch counters or thread-time/wall-clock skew over short spans and folds high-confidence anomalies into the anti-debug seal. |
| Trap oracle | `morok-trap` | `trap_oracles` | Installs temporary trap handlers and checks trap delivery. |
| Page-fault/TLB oracle | `morok-pftlb` | `page_fault_oracles` | Maps protected code islands, validates fault provenance, and folds missing/extra/slow faults into state. |
| Cache-timing oracle | `morok-cachetime` | `cache_timing_oracles` | Pseudo-random pointer chase over code bytes with clock distribution checks. |
| Microarchitectural canary | `morok-microcanary` | `microarchitectural_canaries` | Samples branch-prediction/speculation side effects as low-confidence timing evidence. |
| Misleading metadata | scheduler-only | automatic | Plants retained fake local symbols, aliases, and contradictory-but-valid debug metadata, then hides generated helper symbols with private linkage. |

### Windows x86_64 Passes

The Windows passes are opt-in module passes. They share the Windows PE
foundation helpers instead of hardcoding duplicate offsets or import paths.

| Capability | `-passes` name | TOML section | Summary |
|---|---|---|---|
| PE foundation | `morok-winpe` | `windows_pe_foundation` | Emits GS-relative TEB/PEB readers, PE header/export-by-hash resolver, syscall-stub scanner, direct/indirect syscall thunks, and VEH registration substrate. |
| PEB/heap debug checks | `morok-winpeb` | `windows_peb_heap_debug` | Reads `BeingDebugged`, `NtGlobalFlag`, `ProcessHeap`, `Flags`, and `ForceFlags` directly. |
| Debug-object battery | `morok-windbgobj` | `windows_debug_object` | Resolves NT APIs by hashed export and probes debug port/object/flags plus debug-object type count. |
| Thread hide | `morok-winthide` | `windows_thread_hide` | Walks threads, applies `ThreadHideFromDebugger`, queries it back, and folds failures. |
| Anti-attach | `morok-winattach` | `windows_anti_attach` | Patches debugger attach helpers, probes invalid-handle behavior, and avoids plaintext API names. |
| Kernel-debugger census | `morok-winkdbg` | `windows_kernel_debugger` | Reads `SharedUserData`, queries kernel-debugger state, samples module/parent/window-class signals. |
| Direct/indirect syscalls | `morok-winsys` | `windows_syscalls` | Resolves syscall numbers from runtime stubs and compares direct vs recycled-gadget syscall paths. |
| KnownDlls unhook | `morok-winunhook` | `windows_unhook` | Maps pristine `ntdll.dll`/`kernel32.dll` text from KnownDlls and locally refreshes hooked `.text`. |
| VEH audit | `morok-winveh` | `windows_veh_audit` | Locates/decode-candidates the internal VEH list and folds suspicious handler findings without mutating process-wide VEH state. |
| Process mitigations | `morok-winmitigate` | `windows_process_mitigations` | Hash-resolves `SetProcessMitigationPolicy` and opts into ACG/CIG after Morok's startup text repair. |

## TOML Option Reference

Every per-pass field is optional. Unset fields fall through to the preset,
policy, or pass default. Percentages use `0..100` unless noted.

### Global and Policy

| Scope | Keys |
|---|---|
| `[global]` | `preset`, `seed`, `verbose`, `trace`, `demangle_names` |
| `[passes]` | `fail_closed_on_unsealed` plus nested pass sections |
| `[[policy]]` | `module`, `function`, `preset`, nested `passes.<section>.<key>` overrides |

`fail_closed_on_unsealed` is a cross-pass release switch. When enabled, runtime
paths that depend on post-link manifests fail closed if a binary still contains
unsealed manifest sentinels instead of sealed code-window metadata.

### Structural and Control-Flow Sections

| Section | Keys |
|---|---|
| `bcf` | `enabled`, `probability`, `iterations`, `complexity`, `entropy_chain`, `junk_asm`, `junk_asm_min`, `junk_asm_max` |
| `split_blocks` | `enabled`, `splits`, `stack_confusion` |
| `flattening` | `enabled` |
| `data_entangled_flattening` | `enabled`, `max_terms` |
| `non_invertible_state` | `enabled`, `max_terms`, `rounds` |
| `state_opaque_predicates` | `enabled`, `probability`, `max_blocks`, `max_terms` |
| `interprocedural_fsm` | `enabled`, `probability`, `max_sites`, `max_terms` |
| `chaos_state_machine` | `enabled`, `generator`, `tf_const`, `nested_dispatch`, `warmup` |
| `dispatcherless_routing` | `enabled`, `probability`, `max_routes`, `max_terms` |
| `indirect_branch` | `enabled` |
| `microcode_stress` | `enabled`, `probability`, `max_sites`, `table_entries`, `decoy_blocks`, `alias_stores` |
| `path_explosion` | `enabled`, `probability`, `max_blocks`, `max_iterations` |
| `coherent_decoys` | `enabled`, `probability`, `max_blocks`, `depth` |
| `alias_opaque_predicates` | `enabled`, `probability`, `iterations`, `max_blocks` |
| `external_opaque_predicates` | `enabled`, `probability`, `max_blocks`, `decoy_stores` |
| `mq_gate` | `enabled`, `probability`, `vars`, `eqs`, `density`, `max_gates`, `fold_diff` |
| `nanomites` | `enabled`, `probability`, `max_sites` |

`chaos_state_machine.generator` accepts `logistic` or `tfunction`.

### Scalar, Data, Stack, and Literal Sections

| Section | Keys |
|---|---|
| `substitution` | `enabled`, `probability`, `iterations` |
| `mba` | `enabled`, `probability`, `layers`, `heuristic` |
| `optimizer_amplification` | `enabled`, `probability`, `max_forms` |
| `sub_threshold_persistence` | `enabled`, `probability`, `max_terms` |
| `constant_encryption` | `enabled`, `iterations`, `share_count`, `feistel`, `substitute_xor`, `substitute_xor_prob`, `globalize`, `globalize_prob`, `skip_value`, `force_value` |
| `shamir_share` | `enabled`, `probability`, `threshold`, `shares`, `max_secrets` |
| `table_arithmetic` | `enabled`, `probability`, `max_tables` |
| `uniform_primitive_lowering` | `enabled`, `op_probability`, `branch_probability`, `max_tables`, `max_branches` |
| `vector_obfuscation` | `enabled`, `probability`, `width`, `shuffle`, `lift_comparisons` |
| `stack_coalescing` | `enabled`, `probability`, `opaque_offsets` |
| `stack_delta_games` | `enabled`, `probability`, `max_blocks`, `min_bytes`, `max_extra_bytes`, `touches` |
| `pointer_laundering` | `enabled`, `pointer_probability`, `integer_probability` |
| `type_punning` | `enabled`, `probability`, `include_floating`, `max_targets` |
| `phi_tangling` | `enabled`, `probability`, `layers`, `max_phis` |

`constant_encryption.globalize` routes selected reconstructed carrier values
through private volatile globals after share folding; `globalize_prob` controls
that extra layer per rewritten literal.

`vector_obfuscation.width` accepts the pass-supported SIMD width values
`128`, `256`, and `512`.

### Strings, Calls, VM, Integrity, and Runtime Sections

| Section | Keys |
|---|---|
| `string_encryption` | `enabled`, `probability`, `skip_content`, `force_content` |
| `function_call_obfuscate` | `enabled` |
| `caller_keyed_dispatch` | `enabled`, `probability`, `max_calls`, `region_bytes`, `seal_required` |
| `function_wrapper` | `enabled`, `probability`, `times` |
| `vtable_integrity` | `enabled` |
| `decoy_strings` | `enabled` |
| `virtualization` | `enabled`, `probability`, `max_functions`, `max_instructions`, `max_registers` |
| `fault_paged_payload` | `enabled`, `probability`, `max_payloads`, `max_payload_bytes`, `page_size`, `delivery`, `backend`, `per_page_keys`, `reseal_after_use`, `decoy_pages`, `fallback`, `bind_to_runtime_seal`, `virtualize_helpers` |
| `hash_gated_self_decrypt` | `enabled`, `probability`, `max_payloads`, `max_payload_bytes`, `context_keying` |
| `external_secret_binding` | `enabled`, `mode`, `public_key`, `expected_digest`, `identity_policy`, `bind_to_runtime_seal`, `virtualize_helpers` |
| `tracer_attestation` | `enabled`, `mode`, `shares`, `renewal`, `bind_to_runtime_seal`, `virtualize_helpers` |
| `sealed_blob` | `enabled`, `max_blobs`, `max_blob_bytes`, `key_sources`, `delivery`, `zeroize_after_use`, `runtime_keyed_magic`, `magic_bytes` |
| `self_checksum_constants` | `enabled`, `probability`, `max_constants`, `region_bytes` |
| `data_flow_integrity` | `enabled`, `probability`, `max_tables`, `region_bytes` |
| `mutual_guard_graph` | `enabled`, `probability`, `nodes`, `region_bytes`, `max_returns` |
| `execution_trace_keying` | `enabled`, `probability`, `max_blocks` |
| `adversarial_function_merging` | `enabled`, `probability`, `max_groups`, `max_functions`, `outline_probability`, `max_outlines` |
| `adversarial_self_tuning` | `enabled`, `max_candidates`, `max_candidate_passes`, `score_floor`, `emit_marker` |
| `per_build_polymorphism` | `enabled`, `function_order`, `block_order`, `anchor_probability`, `max_anchors` |

`skip_content`, `force_content`, `skip_value`, and `force_value` are string
arrays.

### Anti-Analysis and Platform Toggle Sections

These sections currently accept only `enabled`:

```text
anti_debugging
anti_hooking
anti_class_dump
windows_pe_foundation
windows_peb_heap_debug
windows_debug_object
windows_thread_hide
windows_anti_attach
windows_kernel_debugger
windows_syscalls
windows_unhook
windows_veh_audit
windows_process_mitigations
timing_oracles
scheduler_step_oracles
trap_oracles
page_fault_oracles
cache_timing_oracles
microarchitectural_canaries
```

`platform_runtime` accepts `enabled`, `direct_syscalls` (`auto`, `always`,
`never`), `windows_mode` (`documented_api`, `hashed_import`, `direct_syscall`),
`per_build_stubs`, `minimize_imports`, and `import_table_audit`. The runtime is
an internal emitter layer; these fields document and preset the platform policy
used by anti-analysis producers rather than adding a standalone `-passes` entry.

## Platform Notes

- macOS arm64/x86_64: primary full-pipeline e2e target. The Apple test path
  exercises the full `high`/`max` presets, VM-specific tests, and adversarial
  post-link patch tests when Python is available.
- Linux x86_64: supported for core/config/IR and portable e2e gates. Static
  cross-builds disable FCO automatically unless an explicit config chooses
  otherwise.
- Linux arm64 and other non-Apple hosts: use the portable e2e configuration for
  high-intensity runtime tests until the VM/trap/anti-analysis runtime paths are
  fully ported.
- Windows x86_64: Windows-specific passes emit PE/PEB/TEB/export/syscall/VEH
  helpers into Windows-targeted IR. Behavioral e2e plugin loading is skipped on
  Windows hosts; coverage comes from core/config/IR tests and targeted object
  smokes.
- Unsupported triples keep conservative fallbacks or no-op for passes that need
  platform-specific context layouts.

## Static-Recovery Resistance Notes

The current string/import strategy is designed against simple static decoders:

- Real private byte-array strings do not share a global decryptor. Safe C-string
  uses get per-use stack materialization; unsupported uses get one private
  constructor per string.
- Each string has independent key material, keystream variant, ADD/XOR combine,
  and odd multiplier, all perturbed through volatile runtime state.
- Linux/macOS FCO avoids plaintext symbol strings for supported 64-bit manual
  resolver paths and otherwise falls back conservatively.
- Per-callsite cached function pointers are encoded with volatile seed/key
  material and exist as raw pointers only immediately before the indirect call.
- Caller-keyed dispatch, function wrappers, adversarial merge/outline, and
  per-build polymorphism reduce stable caller/callee shape across builds.
- Decoy strings are retained and plaintext by design, so `strings` should find
  bait while real user strings remain hidden.
- Generated `morok.*` helpers are demoted to private linkage at the end of the
  scheduler so descriptive helper names do not reach the object symbol table.

## Development Workflow

For a narrow pass edit, use the smallest focused tests first:

```sh
cmake --build build --target morok_ir_tests morok_config_tests morok_plugin
./build/tests/ir/morok_ir_tests
./build/tests/unit/config/morok_config_tests
```

For core/config edits:

```sh
cmake --build build --target morok_core_tests morok_config_tests
./build/tests/unit/core/morok_core_tests
./build/tests/unit/config/morok_config_tests
```

Before merging or pushing a completed code feature, run:

```sh
./run_tests.sh
git diff --check
```

When touching platform runtime emitters, add a targeted object/binary smoke that
proves the relevant strings/symbols are absent where expected and that the
emitted object contains the expected constructor/helper shape.

When touching post-link integrity, verify both halves:

```sh
./run_tests.sh -L adversarial
python3 tests/e2e/adversarial_binary.py seal path/to/binary --window 262144
```

The default seal command must cover the full requested native-code window. Do
not use `region_bytes` as a code-window cap; it sizes only the synthetic
self-check data region.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| CMake cannot find `llvm/Plugins/PassPlugin.h` | Host LLVM is upstream or wrong fork/API | Point `LLVM_DIR` at the matching custom LLVM install. |
| Plugin load reports API/version mismatch | `clang`/`opt` and Morok were built against different LLVM plugin ABIs | Rebuild Morok with the same LLVM used by the host driver. |
| `-mllvm -morok` is unknown on Windows | Windows plugin cl::opts are not parsed by host clang the same way | Use `MOROK_ENABLE=1` plus `MOROK_CONFIG`, `MOROK_PRESET`, and `MOROK_SEED`. |
| Static Linux binary crashes around import indirection | FCO was left enabled in a static link | Use `cross_build.sh` or force `[passes.function_call_obfuscate].enabled = false`. |
| Self-checksum does not detect a native patch | Post-link manifests were not sealed | Seal after final link/strip and run `tools/morok-audit.py --release --require-sealed-manifest`. |
| E2E max fails off Apple | Some max-level runtime/backend paths are still Apple-first | Use `tests/e2e/portable.toml` and consult the comments in that file. |
| A huge input stops getting later transforms | Scheduler growth budgets are firing | Narrow with policy/annotations or increase the specific pass budget after adding tests. |

## Related Documents and Examples

- [`docs/algorithms.md`](docs/algorithms.md): algorithm and scheduler reference.
- [`docs/hardness.md`](docs/hardness.md): hardness-backed primitive specs.
- [`docs/insurance.md`](docs/insurance.md): broader binary self-protection catalog.
- [`docs/insurance-tasks.md`](docs/insurance-tasks.md): implementable task list.
- [`docs/roadmap.md`](docs/roadmap.md): design backlog and known limits.
- [`tests/e2e/*.toml`](tests/e2e): tested pipeline configurations.
- [`crackmes/siloterminal/README.md`](crackmes/siloterminal/README.md):
  freestanding/static crackme example.
- [`crackmes/zorya/AUTHORS_NOTE.md`](crackmes/zorya/AUTHORS_NOTE.md):
  sealed verifier example and security model.

## License

MIT. See [`LICENSE`](LICENSE).
