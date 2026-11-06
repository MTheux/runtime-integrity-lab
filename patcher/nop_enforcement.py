#!/usr/bin/env python3
"""
nop_enforcement.py - neutralise a toy RASP's enforcement CALL in a live process.

Teaching tool for the runtime-integrity-lab. It demonstrates the generic
"in-memory code patch" primitive that defeats any self-protection which does NOT
verify its own code at runtime:

  1. locate the enforcement branch (the `bl` that invokes the kill routine)
     inside the verdict function, and
  2. overwrite it with a NOP by writing to /proc/<pid>/mem.

It uses NO ptrace, NO LD_PRELOAD and installs NO hooks: it is a plain write to
/proc/<pid>/mem, so the target's /proc/<pid>/status keeps TracerPid: 0. That is
the whole point -- the defence is blind to it unless it checksums its own .text.

Architecture: AArch64 (arm64), the arch real Android RASP ships on. The
enforcement site is a `bl` (branch-with-link): a 4-byte word whose top 6 bits are
0b100101. The AArch64 NOP is the word 0xD503201F (bytes 1f 20 03 d5).

Requires privileges to write the target's memory (root, or same-user with a
permissive yama ptrace_scope). This only ever targets the lab's own `victim`.
"""
import argparse
import sys

AARCH64_NOP = (0xD503201F).to_bytes(4, "little")  # 1f 20 03 d5
INSN = 4


def read_mem(pid: int, addr: int, length: int) -> bytes:
    with open(f"/proc/{pid}/mem", "rb", 0) as f:
        f.seek(addr)
        return f.read(length)


def write_mem(pid: int, addr: int, data: bytes) -> None:
    # r+b so the read-only executable page is reached via the kernel's forced
    # write path (copy-on-write); no ptrace involved.
    with open(f"/proc/{pid}/mem", "r+b", 0) as f:
        f.seek(addr)
        f.write(data)


def tracer_pid(pid: int) -> str:
    try:
        for line in open(f"/proc/{pid}/status"):
            if line.startswith("TracerPid:"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return "?"


def bl_target(word: int, pc: int):
    """If `word` (a 32-bit AArch64 instruction at address `pc`) is a `bl`, return
    its branch target, else None."""
    if (word >> 26) & 0x3F != 0b100101:  # bl opcode
        return None
    imm26 = word & 0x03FFFFFF
    if imm26 & (1 << 25):               # sign-extend 26-bit immediate
        imm26 -= (1 << 26)
    return pc + (imm26 << 2)


def find_enforcement_bl(code: bytes, base: int, target: int):
    """Return (offset, target) of the `bl` in `code` whose destination is
    `target`, or None. `base` is the virtual address of code[0]."""
    for off in range(0, len(code) - INSN + 1, INSN):
        word = int.from_bytes(code[off:off + INSN], "little")
        if bl_target(word, base + off) == target:
            return off
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="NOP a toy RASP enforcement bl via /proc/pid/mem (AArch64)")
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--verdict", required=True, help="address of security_verdict (hex, e.g. 0x400a14)")
    ap.add_argument("--enforce", required=True, help="address of enforce_termination (hex)")
    ap.add_argument("--scan-len", type=lambda x: int(x, 0), default=160,
                    help="bytes of the verdict function to scan (default 160)")
    args = ap.parse_args()

    verdict = int(args.verdict, 16)
    enforce = int(args.enforce, 16)

    print(f"[patcher] target pid={args.pid}  TracerPid(before)={tracer_pid(args.pid)}")
    print(f"[patcher] scanning security_verdict @ {verdict:#x} for a bl to {enforce:#x}")

    code = read_mem(args.pid, verdict, args.scan_len)
    off = find_enforcement_bl(code, verdict, enforce)
    if off is None:
        print("[patcher] ERROR: enforcement bl not found in scanned window", file=sys.stderr)
        return 2

    site = verdict + off
    original = code[off:off + INSN]
    print(f"[patcher] found enforcement bl at {site:#x}: "
          f"{' '.join(f'{b:02x}' for b in original)}")

    write_mem(args.pid, site, AARCH64_NOP)

    check = read_mem(args.pid, site, INSN)
    print(f"[patcher] after patch:  {' '.join(f'{b:02x}' for b in check)}  (nop)")
    if check != AARCH64_NOP:
        print("[patcher] ERROR: verification failed (write did not stick)", file=sys.stderr)
        return 3

    print(f"[patcher] enforcement bl neutralised. TracerPid(after)={tracer_pid(args.pid)}")
    print("[patcher] done -- the verdict now returns instead of killing the process.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
