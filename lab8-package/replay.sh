#!/usr/bin/env bash
# Replay labeled probes (label<TAB>prompt), one session per probe.
# Usage: MODEL=test-model AUDIT_LOG=run.jsonl ROUNDS=3 bash replay.sh [probes.tsv]
# Lab 8: PROBE_GROUPS=5,6 runs only the groups whose header line is "# --- 5. ..." (a probe file without headers: all)
set -e
export QUIET=1
ROUNDS="${ROUNDS:-1}"
for r in $(seq 1 "$ROUNDS"); do
  group=""
  while IFS=$'\t' read -r label p || [ -n "$label" ]; do
    if [[ "$label" =~ ^\#\ ---\ ([0-9]+)\. ]]; then group="${BASH_REMATCH[1]}"; continue; fi
    p="${p%$'\r'}"                       # tolerate Windows line endings
    [ -z "$p" ] && continue              # skip blank lines
    case "$label" in \#*) continue;; esac  # skip comment lines
    if [ -n "${PROBE_GROUPS:-}" ] && [[ ",$PROBE_GROUPS," != *",$group,"* ]]; then continue; fi
    PROBE_LABEL="$label" python3 "${CHAT:-chat.py}" "$p"
  done < "${1:-probes.tsv}"
done
