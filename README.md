# Morok

A modular, layered, test-first C++23 LLVM-IR obfuscator. Morok is a New-PM pass
plugin: it rewrites a module's IR into a behaviourally-identical but
harder-to-analyse form.

---

## Why this layout

The codebase is split into layers that depend strictly downward, so each can be
built and tested in isolation. The lower two layers have **no LLVM dependency**
at all and are verified by fast, exhaustive unit tests; only the upper layers
touch LLVM.

```
  morok::core      pure algorithms — PRNG, GF(2^8), Feistel, XOR sharing,
                   MBA & substitution identities, chaos map, Knuth hash.
                   Header-only, constexpr, zero LLVM, zero I/O.
        ▲
  morok::config    preset / policy / TOML configuration model + resolver.
                   Pure; name demangling injected so it needs no LLVM.
        ▲
  morok::ir        LLVM-IR helpers: annotations, PRNG↔IR adaptor.
        ▲
  morok::passes    the transformations (New-PM passes + testable free fns).
        ▲
  libMorok         the loadable pass plugin: scheduler + plugin entry point.
```

The guiding principle: **the security-critical math is proven once, in the pure
core, independently of any IR.** A pass then only has to *emit* the matching IR,
and the end-to-end differential tests confirm it did so without changing
behaviour.

```
include/morok/{core,config,ir,passes,pipeline}/   public headers
src/{core,config,ir,passes,pipeline}/             implementation
tests/{unit/core,unit/config,ir,e2e}/             test suites
third_party/{doctest,tomlplusplus}/               vendored, pinned
cmake/Morok{Warnings,LLVM,Test}.cmake             build policy modules
docs/algorithms.md                                per-pass algorithm reference
```

## Building

Requires a C++23 compiler, CMake ≥ 3.28, Ninja, and an LLVM that exposes the
New-PM plugin API. See [`cmake/MorokLLVM.cmake`](cmake/MorokLLVM.cmake) for the
exact validation performed at configure time.

```sh
cmake -S . -B build -G Ninja -DLLVM_DIR="$LLVM_PREFIX/lib/cmake/llvm"
cmake --build build
ctest --test-dir build -j
```

The pure layers (`morok::core`, `morok::config`) and their tests build even if
no usable LLVM is found; the IR/plugin layers are skipped in that case.

## Using the plugin

```sh
# Whole pipeline, driven by a preset:
clang -O2 -fpass-plugin=build/src/pipeline/libMorok.dylib \
      -mllvm -morok -mllvm -morok-preset=high -mllvm -morok-seed=1234 prog.c -o prog

# Or via opt on IR:
opt -load-pass-plugin build/src/pipeline/libMorok.dylib -passes=morok prog.ll -o out.ll

# Individual passes:
opt -load-pass-plugin … -passes=morok-substitution …
opt -load-pass-plugin … -passes=morok-mba …
opt -load-pass-plugin … -passes=morok-constenc …
```

Configuration can also come from a TOML file (`-morok-config=…`, `MOROK_CONFIG`),
with `[global]`, `[passes.*]`, and ordered `[[policy]]` rules; see
[`docs/algorithms.md`](docs/algorithms.md) and the config tests for the schema.
Per-function `__attribute__((annotate("sub")))` / `annotate("nosub")` overrides
are honoured.

The scheduler has hard instruction/block/module budgets and skips growth passes
once a function or module is too large.  The `high` preset is bounded-aggressive:
it enables small capped slices of VM lifting, hash self-decrypt, DFI,
self-checks, MQ, microcode stress, and call-site wrapping while keeping
adversarial clone/merge tuning as explicit opt-ins.  String encryption also has
direct byte caps so large global literals do not expand into unbounded
constructor IR.  Standalone growth-heavy passes have fixed local caps for table,
CFG-route, and call-site collection.

## Testing strategy

Coverage is layered to match the architecture:

| Layer            | Test kind                      | What it proves |
|------------------|--------------------------------|----------------|
| `core`           | exhaustive / property unit tests | every PRNG, field, cipher, and rewrite **identity** is mathematically correct (≈1.4×10⁸ assertions, e.g. all 65 536 8-bit operand pairs × every MBA/substitution variant) |
| `config`         | unit tests                     | preset tables, merge precedence, policy resolution order, TOML parsing & errors |
| `ir` / `passes`  | LLVM-linked IR tests           | each pass emits **well-formed IR** (`verifyModule`) and actually fires |
| whole stack      | e2e differential tests         | obfuscated binaries produce **identical output** to clean ones across presets/seeds |

`ctest` exposes each test module as its own entry (e.g. `ctest -R core/galois8`)
and runs them in parallel.

## Passes

Every obfuscation pass is implemented as a New-PM pass, each available standalone
(`-passes=morok-<name>`) and orchestrated by the scheduler (`-passes=morok`, or
`-morok` + a preset):

| Pass | `-passes` name | What it does |
|------|----------------|--------------|
| Split basic blocks | `morok-split` | cuts blocks into more dispatch targets |
| Stack coalescing | `morok-stackcoalesce` | locals → one opaque byte buffer |
| Stack delta games | `morok-stackdelta` | dynamic stack-pointer deltas with odd overlapping volatile slots |
| Pointer laundering | `morok-ptrlaunder` | pointer/scalar round trips and byte-vector value views |
| Type punning | `morok-typepun` | union-buffer scalar reinterpretation chains |
| PHI tangling | `morok-phitangle` | redundant cross-block PHI webs |
| Adversarial merge/outline | `morok-afm` | unrelated functions fused behind selector dispatchers and shared helpers |
| Adversarial self-tuning | `morok-selftune` | cloned-candidate hardness search with selected bundle replay |
| Per-build polymorphism | `morok-polymorph` | seed-driven function/block layout and neutral return anchors |
| Data-flow integrity | `morok-dfi` | narrow lookup tables decoded from runtime integrity hashes |
| Mutual guard graph | `morok-mutualguard` | overlapping checksum nodes whose aggregate diff poisons returns |
| Table arithmetic | `morok-tablearith` | narrow integer arithmetic lowered to encrypted lookup tables |
| Uniform primitive lowering | `morok-uniform` | narrow ops and direct branches lowered to table/memory dispatch |
| Virtualization | `morok-vm` | selected straight-line integer arithmetic/comparison functions lifted to encrypted threaded bytecode VMs |
| Hash-gated self-decrypt | `morok-selfdecrypt` | VM bytecode payloads hash/context-gated and lazily decrypted |
| Path explosion | `morok-pathexplode` | opaque-guarded input-derived decoy loops |
| Execution-trace keying | `morok-tracekey` | rolling trace accumulator guards and neutral data/control poisoning |
| Alias opaque predicates | `morok-aliasop` | pointer/alias invariant guarded decoy edges |
| External opaque predicates | `morok-extop` | IPO-blocked volatile context guards with scratch decoy arms |
| Coherent decoys | `morok-decoy` | opaque-dead alternate return implementations |
| Bogus control flow | `morok-bcf` | opaque-true (volatile-load) guarded junk edges |
| Optimizer amplification | `morok-optamp` | early input-selected equivalent forms for optimizer/backend lowering |
| Substitution | `morok-substitution` | integer ops → equivalent expression trees |
| Mixed Boolean-Arithmetic | `morok-mba` | layered MBA rewrites + zero-noise |
| Sub-threshold persistence | `morok-threshold` | volatile-seeded neutral terms tuned below optimizer fold thresholds |
| Flattening | `morok-flatten` | switch-dispatcher control-flow flattening |
| Data-entangled flattening | `morok-entfla` | dispatcher state updates fused with live data |
| Non-invertible state | `morok-nistate` | flattened next states hashed into encoded dispatcher IDs |
| Stateful opaque predicates | `morok-stateop` | MBA opaque guards over flattened dispatcher state |
| Interprocedural FSM | `morok-ifsm` | flattened state updates routed through recursive helper functions |
| Chaos state machine | `morok-csm` | flattening driven by logistic or T-function state maps |
| T-function flattening | `morok-tfa` | single-cycle nonlinear dispatcher-state generator |
| Dispatcherless routing | `morok-dispatchless` | branch/switch edges → state-entangled `indirectbr` DAG |
| Microcode stress | `morok-microstress` | oversized computed blockaddress tables with aliased decoy destinations |
| Vector obfuscation | `morok-vec` | scalar integer ops/comparisons/selects lifted to configurable SIMD |
| Self-checksum constants | `morok-selfcheck` | constants fused with runtime checksum diff so tamper corrupts data |
| Shamir threshold sharing | `morok-shamir` | selected integer literals reconstructed from GF(2^8) threshold shares |
| MQ opaque gate | `morok-mq` | planted GF(2) quadratic systems guarding input-derived branch sites |
| Constant encryption | `morok-constenc` | literals split into XOR shares |
| String encryption | `morok-strenc` | literals stored GF(2⁸)-encrypted, decrypted in a ctor |
| Indirect branch | `morok-indbr` | conditional edges → keyed `indirectbr` table |
| Function wrapper | `morok-funcwrap` | call sites routed through forwarder proxies |
| Function-call obfuscate | `morok-fco` | external calls resolved via `dlsym` |
| Anti-debugging | `morok-antidbg` | `ptrace`-based debugger denial at startup |
| Anti-hooking | `morok-antihook` | startup check for resident hooking frameworks |
| Anti-class-dump | `morok-antiacd` | scrambles Objective-C metadata (no-op without it) |

Every pass is exercised by an IR-validity test, and the value/control-flow
passes are additionally proven semantics-preserving by the end-to-end
differential tests across the `low`/`mid`/`high` presets.  The `high` preset
stacks the bounded aggressive pipeline and still reproduces the reference
output byte-for-byte.

Faithfulness note for the current LLVM: indirect-branch keys the table index
rather than multiplicatively encrypting the loaded pointer (modern LLVM forbids
the `ConstantExpr` arithmetic that required); the verified Knuth primitive
(`core/KnuthHash`) remains available.

## Licence

MIT — see [`LICENSE`](LICENSE).
