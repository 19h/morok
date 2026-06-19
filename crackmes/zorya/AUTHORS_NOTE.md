# ZORYA — author's note & security model

A hardened license-style crackme for x86-64 Linux. The shipped binary holds only
a public key and a pile of ciphertext; *correctness is the decryption key*, so
there is no boolean to flip and no keygen to write. The intended difficulty is a
gauntlet of four mutually-reinforcing anti-analysis layers, every one of which
is **load-bearing**: defeating it changes the key, and a wrong key yields a wrong
flag rather than an honest refusal.

## Files

```
src/         build it yourself
  zorya.c        verifier + (ifdef'd) minter/sealer
  zcommon.h      deterministic shared core (VM, key schedule, base64url, canon)
  tweetnacl.c/.h public-domain crypto (SHA-512, Ed25519, XSalsa20) + z_* helpers
  zpub.h         the embedded Ed25519 public key (generated)
  zbanner.h      XOR-masked grant/deny banners (generated)
  keygen.c       one-shot keypair generator
  build.sh       builds keygen, the stripped verifier, and the minter
challenge/     ready to play
  zorya          sealed, stripped verifier
  license.txt    a valid license for the winner name baked into this seal
  PLAYME.txt     how to run
issuer/        SECRET — never distribute
  zorya.sk       the Ed25519 secret key; whoever holds it can mint & seal
AUTHORS_NOTE.md  this file
```

## Threat model — why the usual moves fail

**No keygen.** A license is an Ed25519 *signed message* `base64url(R‖S‖msg)`, where
`msg` is the canonicalized name. The verifier carries only the public key and
recomputes the curve point `t = S·B − H(R,A,msg)·A`, which equals `R` iff the
signature is genuine. Forging a license is forging an Ed25519 signature. The
signing path is compiled out unless `-DZORYA_MINT`, and even then needs
`zorya.sk`.

**No magic patch.** There is no `if (valid) print(flag)` sink. The flag is
XSalsa20 ciphertext; its 32-byte key is

```
S0   = SHA512(DOM_PRE ‖ t ‖ msg_claimed ‖ name)            // pre-state
S    = VM(S0, bytecode)                                     // stack-VM mutation
key  = SHA512(DOM_POST ‖ S ‖ checksum ‖ LE64(tracer) ‖ LE64(ge))[:32]
flag = XSalsa20(key, ZN_SEAL) ⊕ ZSEAL
```

Every operand is real input: `t` (signature), `msg_claimed` (signed name),
`name` (entered name), `checksum` (the protected section), `tracer` (a word only
a cooperating tracer injects), `ge` (the single-step sensor). Perturb any one and
`key` diverges. The final 16-byte MAGIC compare is **cosmetic**: forcing it true
only prints the garbage plaintext, never the flag, because the flag bytes are
already wrong whenever the key is wrong.

## The four novel layers

1. **Self-checksum of a named code section.** The key glue lives in an ELF
   section `zoryatext`; the verifier SHA-512s `[__start_zoryatext,__stop_zoryatext)`
   at runtime and folds the digest into the key. A planted `0xCC` software
   breakpoint, an inline patch, or a hook anywhere in that section changes the
   digest → wrong bootstrap (below) and wrong post-key. Built `-no-pie` so the
   file bytes equal the runtime bytes, which is what lets the sealer predict the
   digest from the on-disk ELF.

2. **Single-step detection via context-switch counters, not timing.** A short
   pure-arithmetic loop is bracketed by `perf_event_open(PERF_COUNT_SW_CONTEXT_SWITCHES)`
   (fallback `getrusage(RUSAGE_THREAD)` voluntary+involuntary switches). Honest
   execution costs ~0 switches; `PTRACE_SINGLESTEP` traps every instruction and
   inflates the count by orders of magnitude. The branchless bit `ge = (Δ ≥ 4)`
   is folded into the key — a stepping debugger silently corrupts the result
   instead of being told it was caught. rdtsc deltas are deliberately avoided
   (too noisy, too obvious, trivially hooked).

3. **Self-ptrace fork with a key-bearing handshake.** `main` forks: the child
   `PTRACE_TRACEME`s and the parent becomes its tracer. This both blocks an
   external `PTRACE_ATTACH` (a task may have only one tracer) and is load-bearing:
   the child executes `int3` with `&slot` in `rdi`; the parent reads `rdi` via
   `GETREGS` and `POKEDATA`s `ZORYA_TRACER_WORD` into the slot, then continues
   with signal 0. No cooperating parent ⇒ the slot stays 0 ⇒ `tracer = 0` ⇒ wrong
   key. An external debugger that follows the child (e.g. `strace -f`, gdb) makes
   the child's `TRACEME` fail and the `int3` deliver as an un-handled `SIGTRAP`,
   killing the worker before it can leak anything.

4. **userfaultfd-delivered encrypted bytecode.** The key schedule *is* a program
   for a tiny stack VM (`zcommon.h`). It is never stored in cleartext: `ZBC` is
   `XSalsa20(bootstrap) ⊕ bytecode`, `bootstrap = SHA512(DOM_VM ‖ checksum)[:32]`.
   The verifier maps an anonymous region, registers it with `userfaultfd`
   (`MODE_MISSING`), and a handler thread supplies each page — decrypted — only
   when the VM first faults on it. Spanning two pages forces multiple faults.
   Tamper with the code section → wrong `checksum` → wrong `bootstrap` → the
   "decrypted" bytecode is garbage; the VM still runs (its unknown-opcode path is
   a defined diffusion step) and produces a wrong-but-deterministic `S`.

## Building, minting, sealing

```sh
cd src && sh build.sh          # -> keygen (run once), zorya (stripped), zorya-mint
```

`build.sh` runs `keygen` once to emit `zpub.h` (compiled into the verifier) and
`zorya.sk` (kept by you, the issuer). Sealing is intrinsically **two-pass**: the
flag key depends on the finished binary's `checksum`, so you seal *after* linking.
The sealer patches only data sections (`zoryabc`, `zoryaseal`); it never touches
`zoryatext`, so the checksum it measured stays valid.

```sh
./zorya-mint seal ./zorya "Winner Name" flag.txt   # patches zorya in place, prints the license
./zorya-mint license "Winner Name"                 # re-print the license any time
```

Seal/runtime entropy is honest-run-constant and reproducible by the sealer:
`ge = 0`, `tracer = ZORYA_TRACER_WORD`, and the checksum is read from the ELF's
`zoryatext` bytes (== runtime bytes under `-no-pie`). Plaintext bytecode and the
plaintext flag exist only transiently inside the sealer, never in the shipped
verifier.

## Playing

```sh
./zorya "Winner Name" "<license>"     # args, or run with no args for prompts
```

An honest run prints the flag. **Every standard dynamic shortcut poisons it:**
attaching a debugger, single-stepping, breakpointing the key math, or patching
any protected byte all yield the SEALED banner with no usable output.

## Intended solution & difficulty knobs

This is an **anti-analysis** challenge, not a keygenme — keygenning is
cryptographically closed on purpose. Two ways to "win", both fair:

* **Survive the gauntlet dynamically.** Neutralize each sensor *consistently*
  (no external trace of the worker thread, no single-step, no breakpoints in
  `zoryatext`, no patches) so the honest key is reproduced and the flag prints.
  This forces the solver to understand each layer well enough to leave it intact.
* **Reconstruct the schedule statically.** Parse the license, re-implement the
  Ed25519 recompute for `t`, hash `zoryatext` from the ELF for `checksum`, derive
  the bootstrap, decrypt + emulate the VM bytecode, fold the post-key with the
  honest constants, and XSalsa-decrypt `zoryaseal`. Everything needed is present
  in the binary + license; nothing is hidden behind a missing secret.

Difficulty knobs: enlarge `ZBC_PAGES` for more faults and a longer VM program;
raise the VM opcode count / add opcodes in `zcommon.h`; tighten the single-step
threshold `T`; add decoy sections; ship the binary for an architecture the
solver must emulate (kills the "just run it" path and pushes toward static recon).

A purist variant is to **withhold the license** entirely: this turns ZORYA into a
pure tamper-proofing artifact (no one can produce the flag without `zorya.sk`),
at the cost of being unsolvable as a CTF puzzle. Shipping the license keeps it
solvable; the difficulty then lives entirely in the four layers above.

## Graceful degradation

* `userfaultfd` unavailable (older kernel, or `vm.unprivileged_userfaultfd=0`
  for a non-root player): the verifier eagerly decrypts the whole bytecode buffer
  in place and runs the VM over it. Bit-identical key, identical flag.
* `perf_event_open` denied (`perf_event_paranoid`): falls back to
  `getrusage(RUSAGE_THREAD)`; if that too fails, `ge = 0` (the honest default),
  so honest players are never falsely denied.

## Crypto provenance

TweetNaCl (Bernstein et al.), public domain. Added in `tweetnacl.c`:
`z_ed25519_recompute` (packs the verification point `t` without branching on
validity) and `z_ed25519_keypair`. No primitive was modified.
