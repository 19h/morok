# Morok objections and failure modes

This document is for people who will look at a protected binary with IDA,
Ghidra, Binary Ninja, `strings`, `objdump`, Frida, DBI, or a custom lifter and
try to remove the protection. It is not marketing copy and it is not a
third-party audit.

The short version: Morok is useful when it removes cheap static landmarks and
forces the attacker into slower, target-specific work. It is not useful if the
claim being made is "this cannot be reversed." A full dynamic trace at the right
place wins. Build and release policy have to assume that.

## Attacker model

Morok is evaluated against several different jobs. Mixing them is how weak
obfuscation claims become nonsense.

- **Bulk static triage.** The attacker scans many binaries and wants immediate
  strings, imports, direct calls, clean CFGs, recognizable switch dispatchers,
  and obvious authorization branches.
- **Targeted static reversing.** The attacker spends time on one binary with a
  decompiler, microcode/SSA cleanup, data-flow slicing, and manual patching.
- **Symbolic or concolic analysis.** The attacker uses angr, Triton, KLEE-class
  workflows, SMT queries, value-set analysis, and trace-guided simplification.
- **Concrete dynamic analysis.** The attacker can run the program under a
  debugger, DBI, emulator, or hook framework and can dump memory after a trigger
  condition fires.
- **Source-aware analysis.** Morok is open source. Assume the attacker has read
  the passes, knows the templates, and knows where runtime gates are emitted.

The first two are the main targets. The third should get more expensive. The
fourth is a hard ceiling: once the protected value exists in process memory, a
well-placed trace can observe it. Morok can make "well-placed" harder. It cannot
make it impossible on a hostile machine.

## What can be claimed

Good claims are narrow and falsifiable:

- Protected strings should not appear as real plaintext in the binary.
- There should not be one obvious global decryptor for all protected strings.
- Sensitive call sites should not decompile into direct import calls with clear
  symbol names on supported configurations.
- A quick call graph should not expose stable, obvious caller/callee
  relationships for protected paths.
- Control-flow recovery should require more than recognizing a stock flattened
  switch or running one generic cleanup pass.
- Runtime checks should feed protected values, not just branch to a failure
  block that can be patched out.
- Growth should be bounded and testable; runtime cost still needs measurement on
  the user's hot paths.

Bad claims are easy to disprove:

- "Dynamic analysis cannot recover the secret."
- "MBA prevents symbolic execution."
- "Opaque predicates are a hard problem by themselves."
- "Per-build randomization means a deobfuscator cannot generalize."
- "The source is public but that does not help attackers."
- "The test suite proves semantic equivalence for all inputs."

## Anchors and amplifiers

Some transforms are **anchors**: they try to remove or hide a value the static
attacker wants, or bind a value to runtime state. Examples are per-site string
materialization, function-call obfuscation on supported platforms, VM and
self-decrypting payload paths, post-link seals, runtime-seal folding, and
indirect routing that survives normal CFG recovery.

Other transforms are **amplifiers**: they add work, noise, or bad structure
around the anchors. MBA, substitution, bogus branches, opaque predicates,
splitting, PHI tangling, misleading metadata, decoys, and optimizer
amplification are in this category. A serious attacker will remove a lot of
this. That is acceptable only if the protected value or relationship is still
not cheap to recover after the cleanup.

Do not judge the system by whether every amplifier survives. Judge it by whether
the protected build still leaks the thing the operator cared about after the
attacker strips the easy noise.

## Common objections

### "`strings` still finds text"

Some text is intentionally left readable: decoys, platform strings, toolchain
metadata, diagnostics in unprotected code, and anything the configuration did
not select. That does not make the protected-string pass broken by itself.

The release question is narrower: do real protected application strings appear
as plaintext, and is there an obvious decrypt-all routine? If yes, that is a
failed configuration or a bug. If `strings` mostly finds bait and unrelated
metadata while real strings are recovered only near use sites, the pass is doing
the intended job.

### "IDA shows `dlsym(..., \"fprintf\")` and a direct call"

That is not an acceptable result for a protected sensitive call site on a
supported configuration. A decompiler should not be able to connect a clear
symbol string, a standard resolver call, and the sensitive call in one readable
snippet.

There are still ways this can happen: unsupported platform path, fallback
resolver, disabled function-call obfuscation, unprotected helper code, debug
build, or a missed call shape. Treat it as release-blocking for sensitive paths
until explained. The right check is binary inspection, not a source-level
argument that the pass "should" have handled it.

### "I can lift the binary back to IR and run `-O3`"

That will remove a lot of amplifier material. It should. MBA identities, simple
opaque predicates, and noisy arithmetic are not expected to beat an optimizer
plus a domain-specific cleanup pass.

The harder question is whether the lift preserves enough semantics to recover
the protected relationship: real string value, import target, call graph,
dispatcher edge, VM payload, or sealed constant. Indirect branches, volatile
state, per-site materialization, and post-link state are meant to make that
answer nontrivial in static bulk tooling. A concrete trace can still pin the
state.

### "Flattening is solved"

Stock switch flattening is solved. Morok should not rely on stock flattening.
The useful cases combine successor encoding, data-entangled state, indirect
routing, interprocedural transition helpers, and late caller/callee damage.

Even then, this is cost amplification. A trace that records concrete successors
can rebuild the executed CFG. Static recovery should be annoying and lossy; it
will not be impossible.

### "VM obfuscation is the most studied target in reversing"

Correct. VM transforms only buy value when the original code is no longer
available as normal code and when handler recovery, bytecode decoding, and
runtime keys are all made target-specific.

A DBI trace of a representative run can recover executed semantics. The VM path
is still useful if it forces the attacker to collect the right traces, model
state, and separate real behavior from decoys instead of reading a decompiler
listing.

### "Self-decrypting payloads are just run-and-dump"

At the ceiling, yes. If a payload is plaintext in memory, it can be dumped.

Morok can make static unpacking less useful by decrypting lazily, narrowing the
window, binding keys to runtime verdicts, and resealing or zeroing after use.
That changes timing and setup for the attacker. It does not remove the memory
dump limit.

### "Anti-debug and anti-hook checks are patched in minutes"

A standalone check that branches to failure is weak. The defensible pattern is
to fold verdicts into keys, constants, VM state, or return values so the patched
program computes wrong data rather than merely skipping an alarm.

This still depends on configuration and platform support. A clean emulator,
kernel-level trace, or hardware trace path that never trips the probes can
bypass the verdict. Treat anti-analysis as key material and tripwire pressure,
not as a root of trust.

### "MBA and opaque predicates are dead"

As standalone defenses, mostly yes. Modern simplifiers, decompiler plugins, and
SMT workflows handle many MBA identities and many opaque predicates.

Morok should use them as cover and cost multipliers. If a protected value
depends only on MBA or a tautological branch, the design is weak. If those
constructs sit around per-site recovery, sealed state, indirect dispatch, and
runtime-gated values, removing them is only the first pass of the attack.

### "MQ and Shamir sound academic"

The pure cores are real, but placement matters more than the name of the math.
An MQ predicate that is small, planted, and emitted as opaque-true does not force
the attacker to solve a meaningful MQ instance. Shamir reconstruction that is
co-located and ungated is vulnerable to constant recovery and dynamic tracing.

Use these only where the deployment actually imposes the claimed condition:
adequate parameters, shares or constraints separated across paths or contexts,
and reconstruction bound to application state. Otherwise they are engineering
scaffolding, not a hardness claim.

### "Per-build polymorphism is just reseeding"

Yes. Reseeding breaks byte-for-byte signatures and patch reuse. It does not
change the grammar of the transforms. A deobfuscator written against the grammar
can generalize across seeds.

Polymorphism is still useful operationally because it raises the cost of
building one universal patch or one exact signature. Do not sell it as a
hardness argument.

### "LLMs will clean up the pseudocode"

They will help. They are already useful for naming variables, summarizing messy
functions, spotting common transforms, and writing cleanup scripts.

The defense is not "LLMs cannot understand obfuscated code." The defense is to
make the available input worse: fewer real strings, worse call relationships,
less reliable CFG, missing original code for VM paths, and runtime values that
are not present in the static artifact. This is a moving target and should be
tested regularly.

### "A classifier can recognize Morok output"

Probably. Classification is not inversion. A model or signature that says "this
binary is Morok-protected" has not recovered the secret, call target, or
payload.

It still matters. Classification lowers the attacker's setup cost because they
can load Morok-specific tooling immediately. Per-build diversity and decoys
should make exact signatures brittle, but family-level detection is a conceded
risk.

### "The project is open source, so attackers can write the inverse"

For template transforms, yes. Openness gives the attacker the grammar and the
locations to inspect. That is why template-only protection is not enough.

The open-source posture is defensible only where the transform depends on
per-build seeds, runtime-gated values, platform state, or application-provided
material. Source knowledge should be assumed in every claim. If a claim fails
once the source is public, it was not a strong claim.

### "The post-link seal can be skipped"

Then seal-dependent claims do not hold. A placeholder or unsealed build should
fail closed when configured to require sealing, and release tooling should make
unsealed artifacts obvious.

For features that depend on final native bytes, the IR pass alone is not the
protection. The protection is the IR shape plus a completed post-link seal plus
a release gate that rejects retained bypass material.

### "This will break under LTO or a different optimizer"

The implementation avoids obvious UB tricks: volatile state, `indirectbr`,
well-defined integer wraparound, and poison-flag stripping are the right
direction. That is a construction argument, not a full proof.

The practical answer is to test the build modes the product ships: optimization
level, LTO/ThinLTO, target triple, sanitizer or hardening flags, and linker.
Current differential tests are necessary bug-finding evidence. They are not a
semantic proof for all inputs.

### "The overhead will hurt users more than attackers"

It can. Static growth budgets prevent unlimited IR expansion, but they do not
prove acceptable latency on a hot path. VM, self-decrypting payloads, table
initialization, function-call obfuscation, and indirect dispatch all need
product-specific measurement.

The sane deployment model is selective protection: annotate high-value code and
leave throughput-critical low-value code alone unless measurement says
otherwise.

### "There is no public benchmark against OLLVM, Tigress, or VMProtect"

Correct. The repo has correctness tests and release hygiene checks. That is not
the same as an independent resilience benchmark.

A serious benchmark would publish the corpus, configs, protected binaries,
attacker workflow, time budget, success criteria, and failures. Until that
exists, resilience claims should stay qualitative: what static landmarks are
removed, what dynamic ceiling remains, and what checks a release must pass.

### "Platform support is uneven"

Correct. LLVM IR transforms are broadly portable, but runtime anti-analysis,
manual import resolution, direct syscall work, object-format details, and
post-link sealing are platform-specific. macOS, Linux, and Windows should be
evaluated separately.

A feature being present in configuration does not mean every target triple gets
the same protection. Release documentation should say which platform path was
actually exercised.

## What would be damning in a protected release

The following findings should block a release or force a configuration change
for the affected path:

- Real application secrets appear in `strings -a`.
- A single generated function decrypts most or all protected strings.
- IDA/cdump shows a clear resolver call, clear symbol name, and sensitive import
  use in one direct chain.
- Sensitive helper names, tables, or Morok internals remain exported.
- The protected authorization or feature gate is still one clear conditional
  branch around a direct success path.
- A post-link-seal feature is enabled but the final artifact is unsealed or
  carries retained bypass material.
- The protected path fails clean-vs-obfuscated differential tests.
- A hot path regresses beyond the product's measured budget.

## Release inspection checklist

Run tests first:

```sh
./run_tests.sh
git diff --check
```

Then inspect the final binary, not only IR:

```sh
strings -a path/to/binary
nm -a path/to/binary
objdump -d path/to/binary
```

Use platform tools where relevant:

```sh
otool -Iv path/to/macho
readelf -Ws path/to/elf
```

If IDA automation is available in the environment, inspect the decompiler view:

```sh
cdump path/to/binary
```

For a sensitive path, record the answer to four questions:

1. Are the real strings still hidden from static string extraction?
2. Are sensitive imports and call targets disconnected from clear symbol names?
3. Does the decompiler still show the protected decision in a direct, patchable
   form?
4. Does a dynamic trace have to reach a real trigger condition to recover the
   value, or is the value available at startup or in a global table?

## Open evaluation gaps

These are known gaps, not footnotes:

- No independent public resilience benchmark is included.
- No test suite can prove semantic equivalence for all possible inputs.
- Runtime performance is bounded only by measurement, not by static growth caps.
- Some runtime protections are platform-specific and weaker on fallback paths.
- Dynamic tracing at the right point remains the ceiling.

Morok should be judged on whether a release binary passes the inspection above
and whether it makes the attacker's next step materially more expensive. Anything
stronger needs published break attempts and reproducible measurements.
