#!/bin/bash
# Timed lifecycle run for dev family 3 (RC1-646 cost measurement).
#
# Full per-case lifecycle for the difficult case - storage writable at
# install, full later - against the live customer app (cik-esp), with
# per-stage elapsed times. The write probe flushes and fsyncs inside the
# try block (the ENOSPC-at-flush lesson from the 0B capture).
#
# Usage: bash spike/lifecycle_family3.sh
set -u
APP=cik-esp

# Write probe: must report errno 28 when full, "write ok" when not.
PROBE=$(printf '%s' '
import os, sys
try:
    f = open("/data/probe", "w")
    f.write("x" * 4096)
    f.flush()
    os.fsync(f.fileno())
    f.close()
    print("write ok")
except OSError as e:
    print(f"write failed errno={e.errno}")
os.path.exists("/data/probe") and os.remove("/data/probe")
' | base64)

remote() { flyctl ssh console -a "$APP" -C "$1" 2>&1 | grep -v '^Connecting to'; }
probe()  { remote "/bin/sh -c 'echo $PROBE | base64 -d | python3'"; }

declare -a LABELS TIMES
run_stage() {
  local label=$1; shift
  local t0 t1 out
  t0=$(date +%s.%N)
  out=$("$@")
  t1=$(date +%s.%N)
  LABELS+=("$label"); TIMES+=("$(echo "$t1 - $t0" | bc)")
  printf '  %-30s %7.2fs  %s\n' "$label" "$(echo "$t1 - $t0" | bc)" "$out"
}

health() { curl -s -o /dev/null -w '%{http_code}' https://cik-esp.fly.dev/healthz; }

wake() {
  local i
  for i in $(seq 1 30); do
    [ "$(health)" = "200" ] && { echo "healthz 200 after ${i} tries"; return 0; }
    sleep 1
  done
  echo "machine did not wake"; return 1
}

echo "family 3 lifecycle (timed stages):"
run_stage "wake (scale-to-zero start)" wake
run_stage "baseline write"         probe
run_stage "inject (fill volume)"   remote "/bin/sh -c 'dd if=/dev/zero of=/data/fill bs=1M 2>&1 | tail -1; df -h /data | tail -1'"
run_stage "trigger + collect"      probe
run_stage "health during fault"    health
run_stage "remedy (rm fill)"       remote "rm /data/fill"
run_stage "verify recovery"        probe
run_stage "cleanup check (df)"     remote "/bin/sh -c 'df -h /data | tail -1'"

total=0
for t in "${TIMES[@]}"; do total=$(echo "$total + $t" | bc); done
printf '  %-30s %7.2fs\n' "TOTAL" "$total"
