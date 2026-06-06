#!/usr/bin/env bash
# Continuous driver for hallucination_guard.py.
# Runs the guard every INTERVAL_SEC (default 300 = 5min) until killed.
# Appends one JSON summary per run to logs/hallucination_guard.jsonl
# AND writes a rolling human-readable log to logs/hallucination_guard.log.

set -u
FINDEVIL_ROOT="${FINDEVIL_ROOT:-/home/sansforensics/findevil}"
INTERVAL_SEC="${INTERVAL_SEC:-300}"
LOG_FILE="${FINDEVIL_ROOT}/logs/hallucination_guard.log"

mkdir -p "${FINDEVIL_ROOT}/logs"

echo "[$(date -u +%FT%TZ)] hallucination guard loop starting — interval=${INTERVAL_SEC}s" | tee -a "${LOG_FILE}"

while true; do
    ts="$(date -u +%FT%TZ)"
    {
        echo "==== ${ts} ===="
        FINDEVIL_ROOT="${FINDEVIL_ROOT}" \
            "${FINDEVIL_ROOT}/.venv/bin/python" \
            "${FINDEVIL_ROOT}/tests/harness/hallucination_guard.py" 2>&1
        rc=$?
        echo "---- exit=${rc} ----"
    } | tee -a "${LOG_FILE}"
    sleep "${INTERVAL_SEC}"
done
