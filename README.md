# Morok

A modular LLVM-IR obfuscator, rewritten from scratch as a clean, layered,
test-first C++23 codebase. Morok is a New-PM pass plugin: it rewrites a module's
IR into a behaviourally-identical but harder-to-analyse form.

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
| Bogus control flow | `morok-bcf` | opaque-true (volatile-load) guarded junk edges |
| Substitution | `morok-substitution` | integer ops → equivalent expression trees |
| Mixed Boolean-Arithmetic | `morok-mba` | layered MBA rewrites + zero-noise |
| Flattening | `morok-flatten` | switch-dispatcher control-flow flattening |
| Chaos state machine | `morok-csm` | flattening driven by the logistic map |
| Vector obfuscation | `morok-vec` | scalar integer ops lifted to 2-lane SIMD |
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
differential tests across the `low`/`mid`/`high` presets — the `high` preset
stacks the full pipeline and still reproduces the reference output byte-for-byte.

Two faithfulness notes for the current LLVM: indirect-branch keys the table index
rather than multiplicatively encrypting the loaded pointer (modern LLVM forbids
the `ConstantExpr` arithmetic that required); the verified Knuth primitive
(`core/KnuthHash`) remains available. Vector obfuscation lifts to a fixed 2-lane
width rather than honouring the `width`/`shuffle` knobs.

## Licence

AGPL-3.0-or-later, consistent with the upstream project this descends from.
