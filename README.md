# runtime-integrity-lab

A tiny, self-contained lab that shows **why a runtime self-protection (RASP /
anti-tamper) that does not verify its own code can be neutralised in memory**, and
how a runtime **self-integrity check** mitigates it.

It ships a *toy* protection of ~120 lines and a ~110-line patcher. Everything
targets nothing but the lab's own `victim` process. No real product is involved.

---

## The idea in one picture

Real anti-tamper products enforce a verdict with the same shape:

```
detect hostile environment  ->  reach a verdict  ->  CALL a kill routine
```

If the protected code can be **written in memory** by an attacker (e.g. root +
`/proc/<pid>/mem`), that single enforcement **CALL** can be replaced with a `NOP`.
The detection still fires — the environment is still "hostile" — but the process
is no longer terminated. The defence never notices, **unless it checksums its own
`.text` at runtime.**

This lab demonstrates exactly that, and the fix.

---

## Quickstart

### With Docker (any host, incl. macOS / Apple Silicon)

```bash
docker build -t runtime-integrity-lab .
docker run --rm runtime-integrity-lab
```

### Native (Linux, arm64)

```bash
./run_demo.sh
```

You should see:

```
   A baseline   : DEAD    (want DEAD)
   B attack     : ALIVE   (want ALIVE)
   C mitigation : DEAD    (want DEAD)
   PASS
```

(Full captured output: [`docs/sample-run.txt`](docs/sample-run.txt).)

---

## The three scenarios

| # | Build | Patcher | Outcome | What it proves |
|---|-------|---------|---------|----------------|
| **A** | vulnerable | — | process **terminated** | the toy RASP works: hostile verdict kills the process |
| **B** | vulnerable | yes | process **survives** | the enforcement `bl` NOPed in memory via `/proc/pid/mem`; `TracerPid` stays `0` |
| **C** | hardened (`-DWITH_SELFCRC`) | yes | process **terminated** | the self-CRC detects the modified code and enforces anyway |

The attacker in **B** uses **no ptrace, no `LD_PRELOAD`, no hooks** — only a write
to `/proc/<pid>/mem`. That is why the target's `TracerPid` remains `0`: there is no
tracer. A protection that only looks for debuggers/instrumentation cannot see this.

---

## Why it works (and the AArch64 detail)

The verdict function contains a branch-with-link to the kill routine:

```asm
security_verdict:
    ...
    bl   enforce_termination      ; 4 bytes, e.g. b5 ff ff 97  <-- the enforcement call
    ...
    ret
```

The patcher finds that `bl` (top 6 bits `0b100101`, target == `enforce_termination`)
and overwrites its 4 bytes with the AArch64 `NOP`, `1f 20 03 d5` (`0xD503201F`).
`bl` → `nop` means the kill routine is simply never called; the function returns
normally. A single aligned 4-byte store is all it takes.

## Why the mitigation works

The hardened build captures a CRC32 of its own verdict code at startup, then
re-checks it before acting. The NOP changes those bytes, the CRC no longer
matches, and enforcement fires regardless. See
[`docs/WRITEUP.md`](docs/WRITEUP.md) for the full discussion — including the
arms race it starts (the integrity check's *own* enforcement site, data-vs-code
patching, and where this stops being a 4-byte problem).

---

## Scope & ethics

This is **educational**. It deliberately uses a toy target so the technique can be
studied without weaponising it against any shipping product. The point is the
**defensive** lesson: *RASP without runtime code self-integrity is a NOP away from
defeat on a rooted device — add self-CRC (and move trust server-side).*

- Requires privileges to write another process's memory (root, or same-user with a
  permissive `yama/ptrace_scope`). It only ever touches this lab's `victim`.
- Do not use these ideas against software you are not explicitly authorised to test.

## Layout

```
src/victim.c                  toy program + toy RASP (vulnerable / -DWITH_SELFCRC)
patcher/nop_enforcement.py    find the enforcement bl, NOP it via /proc/pid/mem
run_demo.sh                   build + run scenarios A/B/C
Dockerfile                    reproducible Linux env
docs/WRITEUP.md               the long explanation
docs/sample-run.txt           captured output of a passing run
```

## References

- OWASP MASTG — [Runtime Application Self-Protection (RASP)](https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0118/)
- OWASP MASVS — [MASVS-RESILIENCE](https://mas.owasp.org/MASVS/09-MASVS-RESILIENCE/)
- `proc(5)` — [`/proc/<pid>/mem`](https://man7.org/linux/man-pages/man5/proc.5.html)

## License

MIT — see [LICENSE](LICENSE).
