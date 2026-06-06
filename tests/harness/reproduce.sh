#!/usr/bin/env bash
# One-command reproducibility check.
#
# What a judge or reviewer would run to verify findevil is in a
# working state without running any Claude API calls:
#
#     bash tests/harness/reproduce.sh
#
# Exit 0 means:
#   - Unit tests pass (parser + scanner correctness over bundled samples)
#   - Grader calibration passes (the hallucination-harness grader fails
#     when it should fail and passes when it should pass)
#   - Security suite passes (path validation, symlink safety, audit
#     completeness, no unauthorized writes, MITRE coverage)
#   - Tool-layer guard passes (MCP-client smoke test against every
#     findevil tool with the bundled scenarios)
#
# Does NOT run any Claude agent investigations. Those cost API credits
# and need ANTHROPIC_API_KEY + claude CLI; keep them out of a
# reproducibility check so the same command works on any machine.

set -e

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VENV="${ROOT}/.venv"

if [ ! -x "${VENV}/bin/python" ]; then
    echo ">>> creating virtualenv at ${VENV}"
    python3 -m venv "${VENV}"
    "${VENV}/bin/pip" install -q -e "${ROOT}[dev]"
fi

PY="${VENV}/bin/python"

echo
echo ">>> 1/4: pytest unit + security suites"
"${PY}" -m pytest "${ROOT}/tests/" -q

echo
echo ">>> 2/4: grader calibration"
FINDEVIL_ROOT="${ROOT}" "${PY}" "${ROOT}/tests/harness/grader_calibration.py"
FINDEVIL_ROOT="${ROOT}" "${PY}" "${ROOT}/tests/harness/citation_grader.py" --self-test

echo
echo ">>> 3/4: tool-layer hallucination guard (MCP client smoke test)"
# Needs evidence/ staged from samples/ — do it idempotently.
mkdir -p "${ROOT}/evidence" "${ROOT}/logs"
for s in "${ROOT}"/samples/attack-scenario-*; do
    name="$(basename "$s")"
    if [ ! -d "${ROOT}/evidence/${name}" ]; then
        cp -r "$s" "${ROOT}/evidence/"
    fi
done
FINDEVIL_ROOT="${ROOT}" "${PY}" "${ROOT}/tests/harness/hallucination_guard.py"

echo
echo ">>> 4/4: summary"
echo "  scenarios:              $(ls -d "${ROOT}"/samples/attack-scenario-* | wc -l)"
echo "  agent-guard scenarios:  $(grep -c '^    "[0-9]' "${ROOT}/tests/harness/agent_guard.py" 2>/dev/null || echo '?')"
echo "  mitre techniques:       $(grep -c '^    ("T' "${ROOT}/tests/security/test_mitre_coverage.py" 2>/dev/null || echo '?')"
echo "  OK"
