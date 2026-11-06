#!/usr/bin/env bash
# run_demo.sh - build the toy RASP and run the three lab scenarios end to end.
#
#   A) baseline    : vulnerable build, no patch        -> process is TERMINATED
#   B) attack      : vulnerable build + patcher        -> process SURVIVES
#   C) mitigation  : hardened build (self-CRC) + patcher -> process is TERMINATED
#
# Must run on Linux (needs /proc/<pid>/mem). Use the provided Dockerfile on macOS.
set -u
cd "$(dirname "$0")"

CC=${CC:-gcc}
CFLAGS="-O0 -fno-inline -fno-omit-frame-pointer -no-pie"
mkdir -p build out

echo "== building =="
$CC $CFLAGS                -o build/victim          src/victim.c || exit 1
$CC $CFLAGS -DWITH_SELFCRC -o build/victim_hardened src/victim.c || exit 1
echo "ok"

# run $1=binary, $2=do_patch(0/1), log to $3; returns victim exit reason
run_scenario() {
  local bin="$1" patch="$2" log="$3"
  : > "$log"
  "$bin" > "$log" 2>&1 &
  local pid=$!
  # wait for the victim to print its addresses
  local verdict="" enforce=""
  for _ in $(seq 1 50); do
    verdict=$(grep -oE '&security_verdict   = 0x[0-9a-f]+'  "$log" | grep -oE '0x[0-9a-f]+')
    enforce=$(grep -oE '&enforce_termination= 0x[0-9a-f]+' "$log" | grep -oE '0x[0-9a-f]+')
    [ -n "$verdict" ] && [ -n "$enforce" ] && break
    sleep 0.1
  done
  if [ "$patch" = "1" ] && [ -n "$verdict" ] && [ -n "$enforce" ]; then
    python3 patcher/nop_enforcement.py --pid "$pid" --verdict "$verdict" --enforce "$enforce" \
      >> "$log" 2>&1
  fi
  # let the arming window close and a few ticks elapse
  sleep 8
  if kill -0 "$pid" 2>/dev/null; then
    echo "ALIVE"
    kill -9 "$pid" 2>/dev/null
  else
    echo "DEAD"
  fi
  wait "$pid" 2>/dev/null
}

echo; echo "== A) baseline: vulnerable, NO patch =="
A=$(run_scenario build/victim 0 out/A_baseline.log); sed 's/^/   /' out/A_baseline.log; echo "   => $A (expected DEAD)"

echo; echo "== B) attack: vulnerable + /proc/pid/mem NOP =="
B=$(run_scenario build/victim 1 out/B_attack.log); sed 's/^/   /' out/B_attack.log; echo "   => $B (expected ALIVE)"

echo; echo "== C) mitigation: hardened self-CRC + same patch =="
C=$(run_scenario build/victim_hardened 1 out/C_mitigation.log); sed 's/^/   /' out/C_mitigation.log; echo "   => $C (expected DEAD)"

echo; echo "== RESULT =="
echo "   A baseline   : $A   (want DEAD)"
echo "   B attack     : $B   (want ALIVE)"
echo "   C mitigation : $C   (want DEAD)"
[ "$A" = DEAD ] && [ "$B" = ALIVE ] && [ "$C" = DEAD ] && { echo "   PASS"; exit 0; }
echo "   FAIL"; exit 1
