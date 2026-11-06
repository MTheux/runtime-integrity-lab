# In-memory neutralisation of a self-protection that doesn't guard its own code

> A defensive study. The lab targets its own toy process only; no shipping product
> is named or involved.

## 1. The pattern every RASP shares

Runtime Application Self-Protection and anti-tamper layers differ enormously in how
they *detect* a hostile environment (root, emulator, debugger, hooking frameworks,
repackaging, …), but they converge on the same *enforcement* shape:

```
    detect  ->  verdict  ->  react (kill / exit / corrupt state)
```

The "react" step is, at the machine level, a **call** to some routine that ends the
process: a `panic!`/`abort()`, a `kill()`, a deliberate crash. However elaborate the
detection, enforcement eventually funnels through one or a few call sites.

That funnel is the weak point when two conditions hold:

1. the attacker can **write the process's code in memory**, and
2. the protection does **not verify its own code** at runtime.

On a rooted device both the kernel primitive (write `/proc/<pid>/mem`) and the
missing check are common. This lab isolates that situation.

## 2. The primitive: writing code via `/proc/<pid>/mem`

`/proc/<pid>/mem` exposes a process's address space as a file. With sufficient
privilege (root, or same-user under a permissive `yama/ptrace_scope`), a writer can
`seek` to a virtual address and `write` — and the kernel's forced-write path
(copy-on-write) lets that store land even on a **read-only, executable** page. The
original file on disk is untouched; only the private in-memory copy changes.

Crucially this needs **no `ptrace`**. We never attach. Therefore the target's
`/proc/<pid>/status` keeps `TracerPid: 0`, there is no `LD_PRELOAD` entry, no extra
library in `/proc/<pid>/maps`, and no injected `.so`. A protection whose
anti-instrumentation looks for debuggers, preloads or new modules sees nothing.

The lab prints `TracerPid` before and after the patch to make this explicit.

## 3. The target: one `bl`

`src/victim.c` reduces the pattern to its essence:

```c
static void security_verdict(void) {
    if (environment_is_hostile())
        enforce_termination("environment-check");   // the enforcement call
}
```

Compiled for AArch64 (`-O0 -fno-inline -no-pie`) the enforcement call is a single
branch-with-link:

```asm
0000000000400a14 <security_verdict>:
  400a1c:  bl  <environment_is_hostile>
  400a20:  cmp w0, #0x0
  400a24:  b.eq <skip>
  400a30:  bl  400904 <enforce_termination>    ; <-- b5 ff ff 97
  400a34:  nop
  400a38:  ldp x29, x30, [sp], #16
  400a3c:  ret
```

### AArch64 `bl` → `nop`

`bl` is encoded as `0b100101` in the top 6 bits followed by a signed 26-bit
immediate (the word-offset to the target). To find *the* enforcement call we scan the
verdict function for a `bl` whose decoded destination equals `enforce_termination`:

```
dest = bl_addr + (sign_extend(imm26) << 2)
```

Then we overwrite those 4 bytes with the canonical AArch64 `NOP`:

```
0xD503201F   ->   little-endian bytes: 1f 20 03 d5
```

`bl → nop` makes the kill routine unreachable; `security_verdict()` falls through to
its `ret` and returns to the caller as if the check had passed. Detection still ran
and still said "hostile" — only the consequence is gone. One aligned 4-byte store.

(The same idea on x86-64 targets the `call rel32` at opcode `0xE8` and writes `0x90`
bytes. The arch differs; the lesson doesn't.)

## 4. Captured result

```
A) baseline    vulnerable, no patch      -> DEAD   (toy RASP terminates the process)
B) attack      vulnerable + NOP patch    -> ALIVE  (tick=0 survived, tick=1 survived; TracerPid=0)
C) mitigation  hardened self-CRC + patch -> DEAD   (code change detected, enforced anyway)
```

Full log: [`sample-run.txt`](sample-run.txt).

## 5. The mitigation: runtime self-integrity

The hardened build (`-DWITH_SELFCRC`) captures a CRC32 of its own verdict code at
startup and re-checks it before enforcing:

```c
if (crc32_region(security_verdict, GUARD_LEN) != g_text_baseline)
    enforce_termination("code-integrity-mismatch");
```

The NOP changes bytes inside the guarded window, the CRC diverges, and enforcement
fires despite the patched branch. Scenario **C** is `DEAD` for this reason.

This is the single most important control the vulnerable build lacked: **verify your
own `.text` in memory at runtime**, not just at install time and not just on disk —
an in-memory COW patch is invisible to a disk/APK checksum.

## 6. Where it stops being a 4-byte problem (the arms race)

A self-CRC is necessary, not sufficient. An attacker who sees scenario C will:

- **patch the second site too** — the integrity check has *its own* `bl
  enforce_termination`; NOP both and you're back to alive. Defence answer: many,
  redundant, mutually-checking verdict sites, spawned dynamically, so there is no
  small fixed set to neutralise.
- **patch data, not code** — flip the stored baseline, or the boolean the verdict
  reads, instead of the branch. Defence answer: keep integrity state in registers /
  derived values, recompute rather than store, and cross-check across threads.
- **win the timing** — patch before the first check. Defence answer: continuous
  re-checks on independent timers with jitter, not a single startup check.
- **go under the process** — the whole in-process model assumes the attacker isn't
  already root with arbitrary memory write, which on a rooted device they are.

That last point is the real conclusion.

## 7. Conclusion for defenders

On a device where the attacker holds root, **in-process** self-protection is a
cost-raising measure, not a boundary. Concretely:

1. **Add runtime self-integrity** (self-CRC/hash of the native `.text`, over
   protected copies, on jittered timers) so the trivial single-NOP patch is caught —
   this lab's scenario C.
2. **Make enforcement diffuse**, not a single call site, so neutralisation isn't a
   4-byte edit.
3. **Move the trust decision server-side.** Bind sensitive operations to a signed
   attestation of device/app state (and hardware attestation such as Play Integrity),
   so a locally-defeated client still cannot reach the sensitive flows. A local
   bypass should cost the attacker a working app, not the backend.

## References

- OWASP MASTG — [Runtime Application Self-Protection (RASP)](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0118/)
- OWASP MASTG — [Android anti-tampering techniques](https://mas.owasp.org/MASTG/techniques/android/)
- OWASP MASVS — [MASVS-RESILIENCE](https://mas.owasp.org/MASVS/09-MASVS-RESILIENCE/)
- `proc(5)` — [`/proc/<pid>/mem`](https://man7.org/linux/man-pages/man5/proc.5.html)
- Public prior art on analysing a commercial anti-tamper SDK (third-party, not this lab):
  [Appsealing-Reversal](https://github.com/ARandomPerson7/Appsealing-Reversal) — notes, among other things, a gap in memory-manipulation detection.
