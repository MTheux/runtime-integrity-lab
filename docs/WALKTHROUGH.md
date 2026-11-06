# Walkthrough — reversing and defeating a toy self-protection, step by step

> A hands-on reverse-engineering walkthrough on a **toy target built for this lab**.
> Everything below operates on the lab's own `victim` binary and its own process.
> No real product is analysed, named or involved. The goal is to teach the *method*
> and, above all, the *defensive* lesson — not to weaponise anything.

If you just want to run it, see the [README](../README.md). This document is the
long version: we build the target, map its kill-chain, read the disassembly
instruction by instruction, decode the one branch that matters, neutralise it in a
live process, and then watch the mitigation catch us.

---

## 0. The shape of the problem

Anti-tamper / RASP layers vary wildly in *how* they detect a hostile environment
(root, emulator, debugger, hooks, repackaging). But the *enforcement* almost always
collapses into one shape:

```
    detect  ->  verdict  ->  react (kill / exit / crash)
```

The "react" step is, at the CPU level, a **call** to a routine that ends the
process. No matter how clever the detection is, enforcement funnels through a small
number of call sites. This walkthrough shows why that funnel is fragile when (1) the
attacker can write process memory, and (2) the protection never checks its own code.

Our toy makes the pattern explicit and deterministic so we can study it.

---

## 1. Build the target and watch it die

```bash
gcc -O0 -fno-inline -no-pie -o victim src/victim.c
./victim
```

```
[victim] pid=20
[victim] &security_verdict   = 0x400a14
[victim] &enforce_termination= 0x400904
[victim] self-CRC DISABLED (vulnerable build)
[victim] arming window: 6s -- run the patcher now
[toy-rasp] verdict=HOSTILE (environment-check) -> terminating process
```

Ground truth: the process reaches its verdict and terminates itself. The program
*wants* to die when it believes the environment is hostile. Our job is to understand
exactly **how** it dies, and then to stop that one action without touching anything
else.

> The binary helpfully prints two addresses. In a real analysis you would recover
> these from the symbol table, from static analysis, or by pattern-scanning the
> code; printing them just keeps the lab deterministic.

---

## 2. Map the kill-chain with `objdump`

Three functions implement the pattern. Disassemble them:

```bash
objdump -d victim
```

**The detection** — returns a fixed "hostile" verdict (a real one would probe the
device here):

```asm
0000000000400950 <environment_is_hostile>:
  400950:  52800020   mov  w0, #0x1       // #1  -> "hostile"
  400954:  d65f03c0   ret
```

**The kill routine** — prints a line and raises `SIGKILL` (standing in for a real
`panic!`/`abort()`/`kill()` path):

```asm
0000000000400904 <enforce_termination>:
  400904:  a9be7bfd   stp  x29, x30, [sp, #-32]!
  400908:  910003fd   mov  x29, sp
  ...
  40092c:  97ffffb1   bl   4007f0 <fprintf@plt>
  ...        (then raise(SIGKILL))
```

**The verdict** — glues them together. This is where the interesting instruction
lives:

```asm
0000000000400a14 <security_verdict>:
  400a14:  a9bf7bfd   stp  x29, x30, [sp, #-16]!
  400a18:  910003fd   mov  x29, sp
  400a1c:  97ffffcd   bl   400950 <environment_is_hostile>   ; run detection
  400a20:  7100001f   cmp  w0, #0x0
  400a24:  54000080   b.eq 400a34 <security_verdict+0x20>    ; verdict == safe? skip
  400a28:  90000000   adrp x0, 400000
  400a2c:  912d6000   add  x0, x0, #0xb58                    ; "environment-check"
  400a30:  97ffffb5   bl   400904 <enforce_termination>      ; <<< THE ENFORCEMENT CALL
  400a34:  d503201f   nop
  400a38:  a8c17bfd   ldp  x29, x30, [sp], #16
  400a3c:  d65f03c0   ret
```

Read `security_verdict` as prose: *call the detector; if it returned non-zero
(hostile), call `enforce_termination`; otherwise fall through to `ret`.*

The entire life-or-death decision reduces to the single instruction at `0x400a30`.
If that `bl` never executes, the function simply returns — as if the check had
passed — even though the detector still said "hostile". **That one branch is the
target.**

---

## 3. Decode the enforcement `bl` by hand

The instruction at `0x400a30` disassembles as `bl 400904`. Let's verify that from
the raw bytes, because the patcher has to find it with no symbols.

AArch64 `bl` is encoded as:

```
 31      26 25                             0
+----------+--------------------------------+
| 1 0 0 1 0 1 |          imm26               |
+----------+--------------------------------+
   opcode            signed word offset
```

The instruction word is `0x97ffffb5` (in memory, little-endian: `b5 ff ff 97`).

1. **Is it a `bl`?** Top 6 bits: `0x97ffffb5 >> 26 = 0b100101`. ✔ yes.
2. **Immediate:** `imm26 = 0x97ffffb5 & 0x03FFFFFF = 0x3FFFFB5`. Bit 25 is set, so
   it's negative: `0x3FFFFB5 - 0x4000000 = -75` (words).
3. **Target:** `pc + (imm26 << 2) = 0x400a30 + (-75 × 4) = 0x400a30 - 0x12C = 0x400904`.

`0x400904` is exactly `enforce_termination`. Confirmed without symbols.

That is all the patcher does to locate the call: scan the verdict function for a
4-byte word whose top six bits are `100101` and whose decoded target equals the kill
routine's address. (See `find_enforcement_bl()` in
[`patcher/nop_enforcement.py`](../patcher/nop_enforcement.py).)

---

## 4. The memory primitive: `/proc/<pid>/mem`, no ptrace

Now we need to *change* that instruction in a running process. Look at the live
memory map:

```bash
grep victim /proc/<pid>/maps
```

```
00400000-00401000 r-xp 00000000 00:73 988979  /tmp/victim    <- code: READ + EXEC, not writable
0041f000-00420000 r--p 0000f000 00:73 988979  /tmp/victim
00420000-00421000 rw-p 00010000 00:73 988979  /tmp/victim
```

The code page is `r-xp` — **not** writable by the process itself. And yet we can
still change it, because `/proc/<pid>/mem` is written by the **kernel** on our
behalf. With sufficient privilege, a write through that file takes the kernel's
forced path (copy-on-write) and lands even on a read-only, executable page. The
on-disk binary is never touched; only this process's private copy changes.

The decisive property: **this uses no `ptrace`.** We never attach. Compare the
target's tracer state before and after the patch:

```
--- TracerPid before ---
TracerPid:  0
--- (patch happens) ---
--- TracerPid after ---
TracerPid:  0
```

`TracerPid` stays `0`. There is no debugger, no `LD_PRELOAD` entry, no extra library
in `/proc/<pid>/maps`, no injected `.so`. This matters enormously: a protection
whose anti-instrumentation watches for debuggers, preloads, hooking frameworks
(Frida/Xposed) or new modules is **blind** to a plain `/proc/<pid>/mem` write. It is
looking for the wrong thing.

```
 technique              TracerPid   new module in maps   defeats "anti-instrumentation"?
 ptrace / debugger       != 0         no                  detected
 LD_PRELOAD shim          0           yes (the shim)      detected (new .so)
 Frida / Xposed           0           yes (agent/gum)     detected (known signatures)
 /proc/pid/mem write      0           no                  INVISIBLE to all of the above
```

The only thing that can catch it is the program checking **its own bytes**. Which
the vulnerable build does not do.

---

## 5. Apply the patch: `bl` → `nop`

The AArch64 `NOP` is the word `0xD503201F` (bytes `1f 20 03 d5`). We overwrite the
4 bytes of the enforcement `bl` with it:

```bash
python3 patcher/nop_enforcement.py --pid <pid> \
        --verdict 0x400a14 --enforce 0x400904
```

```
[patcher] target pid=20  TracerPid(before)=0
[patcher] scanning security_verdict @ 0x400a14 for a bl to 0x400904
[patcher] found enforcement bl at 0x400a30: b5 ff ff 97
[patcher] after patch:  1f 20 03 d5  (nop)
[patcher] enforcement bl neutralised. TracerPid(after)=0
[patcher] done -- the verdict now returns instead of killing the process.
```

Before: `b5 ff ff 97` (`bl 400904`). After: `1f 20 03 d5` (`nop`). One aligned 4-byte
store. `security_verdict` now runs the detector, learns the environment is "hostile",
and then... does nothing, falling straight through to `ret`.

---

## 6. Result: the differential

```
[victim] tick=0 survived (verdict did not terminate us)
[victim] tick=1 survived (verdict did not terminate us)
```

The process that terminated itself in §1 now survives indefinitely. Nothing about the
*detection* changed — it still fires, still says "hostile". We removed only the
*consequence*. That is the whole trick, and it is why "the app still detects root but
no longer reacts" is such a common observation against in-process protections on
rooted devices.

The three lab scenarios make the before/after explicit:

```
A) baseline    vulnerable, no patch      -> DEAD   (toy RASP terminates the process)
B) attack      vulnerable + NOP patch    -> ALIVE  (this walkthrough)
C) mitigation  hardened self-CRC + patch -> DEAD   (next section)
```

---

## 7. Why it worked — the trust model that failed

The vulnerable build implicitly trusts that **its own code cannot change under it.**
On a device where the attacker holds the ability to write process memory, that
assumption is simply false. Every subsequent instruction after the detector — the
`cmp`, the `b.eq`, the `bl` — treats the detector's result as authoritative, but the
code that *acts* on that result is sitting in writable-by-the-kernel memory with no
guard on it.

Detection strength is irrelevant here. You can make `environment_is_hostile()` as
clever as you like; the single `bl` that turns its verdict into an action is the
soft spot.

---

## 8. Hardening: make the program check its own bytes

The mitigated build (`-DWITH_SELFCRC`) adds exactly one idea — **runtime
self-integrity**. At startup it hashes its own verdict code and remembers the value;
before enforcing, it re-hashes and compares:

```c
/* captured once at startup, over clean bytes */
g_text_baseline = crc32_region((const void *)security_verdict, GUARD_LEN);

/* inside security_verdict(), before acting */
if (crc32_region((const void *)security_verdict, GUARD_LEN) != g_text_baseline)
    enforce_termination("code-integrity-mismatch");
```

Our NOP changes bytes inside the guarded window, so the CRC no longer matches, and
enforcement fires regardless of the patched branch. Scenario **C** is `DEAD` for this
reason. The single most important control the vulnerable build lacked was *verifying
its own `.text` in memory at runtime* — not on disk, not at install time, where an
in-memory COW patch is invisible.

### The arms race it starts

A self-CRC is necessary, not sufficient. An attacker who hits scenario C will try:

- **Patch the second site too.** The integrity check has *its own*
  `bl enforce_termination`. NOP both and you're alive again. → Defence: many,
  redundant, mutually-checking verdict sites, generated dynamically, so there is no
  small fixed set to neutralise.
- **Patch data, not code.** Flip the stored baseline or the boolean the verdict
  reads instead of the branch. → Defence: keep integrity state in registers / derived
  values, recompute instead of storing, cross-check across threads.
- **Win the timing.** Patch before the first check. → Defence: continuous re-checks
  on independent, jittered timers, not one check at startup.
- **Go under the process.** The whole in-process model assumes the attacker is not
  already root with arbitrary memory write — which, on a rooted device, they are.

That last bullet is the real conclusion.

---

## 9. Takeaways for defenders

On a device where the attacker holds root, **in-process** self-protection raises cost
— it is not a boundary. Concretely, in priority order:

1. **Add runtime self-integrity** (hash the native `.text` in memory, over protected
   copies, on jittered timers) so the trivial single-NOP patch is caught — this lab's
   scenario C.
2. **Make enforcement diffuse**, not a single call site, so neutralisation isn't a
   4-byte edit.
3. **Move the trust decision server-side.** Bind sensitive operations to a signed
   attestation of device/app state (plus hardware attestation such as Play Integrity),
   so a locally-defeated client still cannot reach the sensitive flows. A local bypass
   should cost the attacker a working app, not your backend.

---

## Appendix — reproduce every step

```bash
# build
gcc -O0 -fno-inline -no-pie -o victim          src/victim.c
gcc -O0 -fno-inline -no-pie -DWITH_SELFCRC -o victim_hardened src/victim.c

# map the kill-chain
objdump -d victim | sed -n '/<security_verdict>:/,/ret/p'

# run + patch (vulnerable) -> survives
./victim & PID=$!
python3 patcher/nop_enforcement.py --pid $PID --verdict 0x... --enforce 0x...
grep TracerPid /proc/$PID/status      # stays 0

# or just run all three scenarios end to end
./run_demo.sh          # (use the Dockerfile on non-Linux hosts)
```

See also: [`README.md`](../README.md) · [`WRITEUP.md`](WRITEUP.md) ·
[`sample-run.txt`](sample-run.txt).
