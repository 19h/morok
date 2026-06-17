# Insurance — Implementable Task List

Derived from [`insurance.md`](insurance.md), triaged against what Morok actually
is: a **compile-time LLVM New-PM IR pass plugin** that can emit arbitrary runtime
code, constructors, helper threads, inline asm, and direct syscalls into a target
binary — but has **no server, no code-signing keys, and no hardware-enclave
access**. Everything below is something Morok can *produce*. Techniques that
fundamentally require infrastructure Morok will never have are listed under
[Removed](#removed--cannot-implement) at the bottom, with the reason.

**Effort:** `S` ≤1 day (localized emitter / small extension) · `M` a few days
(new self-contained pass or substantial extension) · `L` 1–2 weeks (new subsystem
or cross-platform runtime support) · `XL` multi-week (new platform target or a
major engine). Sorted quickest-win first.

Tags: `[platform · extends <pass> | new]`. All `XL` Windows items presume the
**Windows/PE foundation** task (first `XL` entry) is done first.

---

## S — quick wins

- [x] Re-arm `ptrace(PTRACE_TRACEME)` where compatible and re-check `TracerPid` on a late cadence to catch late attach, not just at init `[linux · extends antidbg]`
- [x] Read `/proc/self/status` `TracerPid:` and `/proc/self/stat` field 4 directly as a debugger check `[linux · extends antidbg]`
- [x] Add `ptrace(PT_DENY_ATTACH)` debugger denial for macOS targets `[macos · extends antidbg]`
- [x] Check `sysctl(KERN_PROC_PID)` → `kinfo_proc.kp_proc.p_flag & P_TRACED` (harder to fake than ptrace) `[macos · new]`
- [x] Check `csops(pid, CS_OPS_STATUS)` → `CS_DEBUGGED` flag `[macos · new]`
- [x] Census `DYLD_INSERT_LIBRARIES` / `DYLD_PRINT_*` env vars — their presence under a hardened build is itself a tamper signal `[macos · new]`
- [x] Emit `prctl(PR_SET_DUMPABLE,0)` + `PR_SET_PTRACER` + `no_new_privs` at startup to block `/proc/pid/mem` and non-root ptrace `[linux · new]`
- [x] Constant-time the secret-dependent paths of environmental-keying crypto so the protection key doesn't leak via timing `[xplat · new]`
- [x] Raise MBA / opaque-predicate density specifically on sensitive functions to inflate IDA/Ghidra decompiler output `[xplat · extends mba/bcf/extop]`

## M — new passes / substantial extensions

- [x] Per-callsite stack-string materialization: decrypt each string lazily at its use site (never one ctor, never a readable global), unique cipher per string `[xplat · extends strenc]`
- [x] Insert anti-debug detectors at many randomized call sites and from multiple threads instead of a single startup check `[xplat · extends antidbg]`
- [x] Emit timing oracles: bracket short spans with serialized `RDTSCP` / `CLOCK_MONOTONIC_RAW` / `mach_absolute_time`, compare two independent clocks, judge by distribution; inflated Δ ⇒ single-step/DBI/EPT-step `[xplat · new]`
- [x] Embed `int3`/`icebp`/`INT 2Dh` traps and a single-step (TF) trap with your own SEH/VEH/`SIGTRAP`/Mach `EXC_BREAKPOINT` handler — handler not firing ⇒ a debugger swallowed it `[xplat · new]`
- [x] Install a `seccomp-BPF` kill-filter on `ptrace`/`process_vm_readv`/`process_vm_writev`/`PTRACE_*` for self and children (closes the whole ptrace class) `[linux · new]`
- [x] Self-sandbox the process with Landlock at startup `[linux · new]`
- [x] Emit direct syscalls for sensitive operations, bypassing libc/`dlsym` wrappers entirely `[posix · new]`
- [x] Clean-copy byte-diff: fresh-map the on-disk module, apply relocations, byte-compare executable sections to the in-memory image to flag every inline/EAT/IAT patch `[posix · new]`
- [x] Prologue-pattern hook detector on critical functions (`E9`/`FF25`/`68..C3`/`EB`/`jcc` as first bytes) `[xplat · new]`
- [x] Per-function keyed-MAC code baseline verified at runtime to catch mid-body patches `[xplat · extends selfcheck]`
- [x] Runtime GOT/PLT validator: verify each entry points inside its owning library's executable range, re-`mprotect` the GOT read-only, poison on deviation (pairs with `-z relro,-z now`) `[linux · new]`
- [x] Mach-O `__got`/`__la_symbol_ptr` fixup validator: verify each pointer lands in the expected dylib `__TEXT` `[macos · new]`
- [x] VTable integrity: store expected vptr + per-vtable hash and verify before virtual dispatch `[xplat C++ · new]`
- [x] Keep critical function pointers / imports XOR-/encode-obfuscated and decrypt only at the call site `[xplat · extends fco/constenc]`
- [x] DR-register sentinel thread: scan and continuously zero `Dr0–7` on all threads (detects HW breakpoints and wipes DR-based hooks) `[xplat · new]`
- [x] Address-space / module census: parse `/proc/self/maps` / `vm_region` / `VirtualQuery`, flag RWX or W^X-violating / `NOACCESS` / guard / unbacked pages, `.text` not RX, manually-mapped images absent from the loader list, and unexpected `LD_PRELOAD`/injected `.so` `[xplat · new]`
- [x] Self-enforce W^X on own pages (`mprotect` to RX, ban RWX) `[xplat · new]`
- [x] Call-stack origin validation at sensitive functions: every return frame must lie in a known module's executable range, never in private/unbacked RWX (defeats ROP / injected calls / DBI trampolines) `[xplat · new]`
- [x] Method-divergence oracle: call the same primitive two ways (direct syscall vs wrapper); divergent results ⇒ one path is hooked `[posix · new]`
- [x] Guard-network topology: ensure overlapping checksum guards cover every byte under ≥k guards (Chang–Atallah) `[xplat · extends mutualguard]`
- [x] Oblivious hashing: hash the runtime value/branch trace of a computation (not static bytes) to detect semantic tampering and emulation `[xplat · extends tracekey]`
- [x] Functional entanglement — derive real runtime values (crypto keys, jump-table indices, S-box bytes, next-block decryption keys) **from** the checksum / DR-state / watchdog-liveness so there is no `jz` to NOP `[xplat · extends selfcheck/dfi]`
- [ ] Delayed, probabilistic, decoupled failure: record tamper in obscure state, continue normally, degrade/crash much later at an unrelated site `[xplat · extends selfcheck/tracekey]`
- [ ] Plant realistic decoy checks whose patching flips hidden state that feeds the entanglement corruption `[xplat · extends decoy]`
- [ ] Code-as-data: compute a constant the program needs (S-box / dispatch table) by hashing a function's bytes, so patching that function yields a wrong constant `[xplat · extends selfcheck/dfi]`
- [ ] Anti-VM/sandbox heuristic battery: CPUID hypervisor leaf, Red Pill `sidt`/`sgdt`/`sldt`, VMware backdoor port, sleep-skip, CPU-count/RAM/uptime (decoy-grade, multi-signal) `[xplat · new]`
- [ ] Anti-DBI battery: code-cache return-address origin check, large-RWX-region scan, SMC tripwire, Frida thread/port/maps signatures (`gum-js-loop`, `27042`, `frida`/`gadget`) `[xplat · extends antihook]`
- [ ] Negative-space verification: assert the *absence* of tamper — no `0xCC` in `.text`, no extra modules, timing not slow, DR all zero `[xplat · new]`
- [ ] Multi-signal corroboration gate before any aggressive response, to avoid false-positive crashes on legitimate VMs/CI/new CPUs (anti-self-DoS) `[xplat · new]`
- [ ] Misleading metadata: plant bogus symbol names, fake function boundaries, and malformed-but-tolerated DWARF to mislead the auto-analyzer `[xplat · extends SymbolCloak]`
- [ ] Auto-analysis sabotage: computed `jmp` / oversized switch with runtime-only targets (no recoverable jump table), bogus `endbr64`, fake epilogues/prologues `[xplat · extends microstress/dispatchless]`
- [ ] API-call-via-exception: replace `call <import>` with a deliberate fault whose handler resolves and invokes the API by hash (defeats IAT hook + call-site inline hook + static call-graph at once) `[xplat · extends fco]`
- [ ] Anti-disasm control flow: signal/VEH-as-`goto`, `call $+5;pop` PIC, computed `jmp reg` `[xplat · new]`

## L — new subsystems

- [ ] Manual export-by-hash import resolver: walk ELF `.dynamic` (`DT_SYMTAB`/`DT_STRTAB`) and Mach-O chained fixups, match by hashed name, re-resolve+diff periodically — so no `dlsym`/GOT/`__la_symbol_ptr` entry exists to hook `[linux+macos · extends fco]`
- [ ] Buddy/triad mutual protection: a 2–3 process ring that occupies the debugger slot (`PTRACE_ATTACH`) and cross-verifies code + liveness; killing one cascades, external attach is blocked `[posix · new]`
- [ ] Watchdog orchestration thread/process: re-run the §2–§4 checks on a randomized cadence with a heartbeat; a missing heartbeat triggers entangled self-corruption (the backbone for "re-arm, don't one-shot") `[xplat · new]`
- [ ] JIT self-decrypt with re-encrypt-on-exit and a polymorphic stub so a static dump + one breakpoint reveals only one slice (macOS needs `MAP_JIT`) `[xplat · extends selfdecrypt]`
- [ ] Per-build-randomized VM ISA: permuted/duplicated handler tables, opaque dispatcher, optional nested VMs `[xplat · extends vm]`
- [ ] Run the anti-debug/anti-hook/integrity checkers themselves through the VM so the protection logic is never plaintext (highest-leverage composition) `[xplat · extends vm]`
- [ ] Stolen-code: physically remove critical instructions from the on-disk image and execute them only inside the VM `[xplat · extends vm]`
- [ ] Environmental keying / anti-transplant: code-block decryption key = `H(expected image bytes ∥ CPUID/RDTSCP fingerprint ∥ volume-serial/MAC)` (local fingerprint; the server-nonce variant is out of scope) `[xplat · extends selfdecrypt]`
- [ ] Heartbeat-entangled crypto: continuously re-derive the live session key from the running code-checksum + watchdog liveness, so stopping/patching either drifts the key and corrupts later crypto `[xplat · extends selfcheck/tracekey]`
- [ ] Disassembler desync via raw byte sleds (junk after unconditional jumps, overlapping/aliased instructions, jump-into-mid-instruction) emitted through inline asm `[xplat · new]`
- [ ] Execute from `memfd` only: re-exec self from `memfd_create` + `execveat` so the running image is unbacked by an on-disk file `[linux · new]`
- [ ] Schrödinger pages: keep code `NOACCESS`, made readable only by a fault handler that validates the faulting RIP is legitimate code; any external reader faults and trips a tripwire `[xplat · new]`
- [ ] Moving-target hot-rewrite: continuously relocate/re-encrypt hot functions to fresh addresses so fixed-address breakpoints/patches go stale (macOS W^X caveat) `[xplat · extends selfdecrypt/polymorph]`
- [ ] Anti-dump: corrupt the in-memory ELF/Mach-O header + section table after load, keep only the executing block decrypted, guard pages to trip `/proc/pid/mem` scans `[posix · new]`
- [ ] Nanomites: replace conditional branches with `int3`; an encrypted address→branch table held only by the self-debugger interprets them at runtime (needs the buddy/self-debugger infra) `[posix · new]`
- [ ] Page-fault/TLB-timing single-step oracle: spread code over many pages and detect anomalous fault pattern/latency under single-stepping incl. EPT (low confidence, FP-prone) `[xplat · new]`
- [ ] Cache-timing self-attestation: pseudo-random pointer-chase over own code per run under a cumulative-cycle bound (low confidence) `[xplat · new]`
- [ ] Microarchitectural/speculative single-step canaries via branch-predictor/speculation side effects (unreliable, CPU-specific — not a primary control) `[xplat · new]`

## XL — new platform / major engines

- [ ] **Windows/PE foundation:** add Windows as a target platform with a runtime helper layer (PEB/TEB access, indirect syscalls, SEH/VEH) — prerequisite for all Windows items below `[windows · new]`
- [ ] Windows PEB/heap debug-struct battery: `BeingDebugged`, `NtGlobalFlag`, `ProcessHeap` `Flags`/`ForceFlags`, via direct gs-relative reads (bypass API hooks) `[windows · new]`
- [ ] Windows debug-object battery: `NtQueryInformationProcess` (`ProcessDebugPort`/`DebugObjectHandle`/`DebugFlags`) + `NtQueryObject` `ObjectTypesInformation` count `[windows · new]`
- [ ] Windows `NtSetInformationThread(ThreadHideFromDebugger)` on all threads, then query it back to confirm it stuck `[windows · new]`
- [ ] Windows anti-attach: patch `DbgUiRemoteBreakin`→`ExitProcess` and `DbgBreakPoint`→`ret`, plus the `CloseHandle`/`NtClose` invalid-handle probe `[windows · new]`
- [ ] Windows kernel-debugger probes: `SharedUserData.KdDebuggerEnabled`, `NtQuerySystemInformation(SystemKernelDebuggerInformation)`, + driver/parent-PID/window-class census (decoy-grade) `[windows · new]`
- [ ] Windows direct + indirect syscalls (Hell's/Halo's/Tartarus' Gate, SysWhispers) to defeat all usermode ntdll hooks `[windows · new]`
- [ ] Windows unhook: map pristine ntdll/kernel32 `.text` from `KnownDlls` / a suspended sacrificial process (Perun's Fart) / disk and overwrite the hooked in-memory `.text` `[windows · new]`
- [ ] Windows VEH-list audit: decode `LdrpVectorHandlerList`, reject/strip handlers not inside your own modules `[windows · new]`
- [ ] Windows process-mitigation opt-ins via `SetProcessMitigationPolicy`: ACG (`ProcessDynamicCodePolicy`, no RWX) and CIG (`ProcessSignaturePolicy`, only signed images load) `[windows · new]`

---

## Removed — cannot implement

These need infrastructure Morok (a compile-time IR pass) fundamentally lacks.

| Technique (insurance.md) | Why Morok cannot produce it |
|---|---|
| §2.4 / §4.4 macOS hardened runtime, library validation, `CS_KILL`/`CS_HARD`, no `get-task-allow` | Kernel-enforced against a code signature + entitlements applied by `codesign` at build/sign time. Morok has no signing keys and cannot sign a Mach-O — it's a build/deploy step (document as a required build setting). |
| §4.4 Linux RELRO / PIE / `_FORTIFY_SOURCE` / stack canaries | Compiler/linker flags, not IR-pass output. (The *runtime* GOT validator that pairs with RELRO is kept above; the flags themselves are a build recommendation.) |
| §4.4 Windows CFG / XFG / CET shadow stack / `/GS` / `/INTEGRITYCHECK` | Compiler+linker codegen/signature switches a mid-pipeline IR pass does not control (build recommendation). |
| §4.4 Windows HVCI | System-wide OS/admin policy, not a per-binary property. |
| §4.4 Windows PPL (Protected Process Light) | Requires special Microsoft signing unavailable to third parties. |
| §4.4 ARM64 PAC / BTI / MTE | Backend codegen target features (`-mbranch-protection`, `+mte`), not IR-pass output (build recommendation). |
| §4.5 TPM 2.0 + measured boot + remote attestation | Needs TPM hardware and a remote verifier server as the trust root. |
| §4.5 Intel SGX | Needs the enclave SDK, provisioning, and attestation; an IR pass cannot lift arbitrary code into an enclave. |
| §4.5 ARM TrustZone secure world | Needs secure-world firmware/SDK; not reachable from a normal-world IR pass. |
| §4.5 AMD SEV / SEV-SNP | VM-level confidential compute requiring hypervisor/provisioning support. |
| §4.5 Apple Secure Enclave | Needs SEP key-custody APIs and provisioning, not arbitrary code execution. |
| §4.6 SWATT / Pioneer software attestation | A challenge-response protocol whose trust root is a remote verifier with a calibrated timing model — there is no server. (The *local* timing-traversal idea survives as the §5 cache-timing self-attestation task above.) |
