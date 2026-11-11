"""Run the actual final-gate script, including skipped and cancelled predecessors."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _gate_script() -> str:
    text = (ROOT / ".github/workflows/ci.yml").read_text()
    job = text.split("  integrity-required-ci:\n", 1)[1]
    assert "if: ${{ always() }}" in job
    assert "needs: [repository-hygiene, python-tests]" in job
    script = job.split("python - <<'PY'\n", 1)[1].rsplit("          PY", 1)[0]
    return "\n".join(line[10:] for line in script.splitlines())


def _run_gate(jobs: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-I", "-c", _gate_script()],
        env={**os.environ, "JOB_RESULTS": json.dumps(jobs)},
        capture_output=True, text=True, timeout=5,
    )


def test_actual_gate_requires_explicit_success_from_both_jobs():
    assert _run_gate({
        "repository-hygiene": {"result": "success"},
        "python-tests": {"result": "success"},
    }).returncode == 0


@pytest.mark.parametrize("job", ["repository-hygiene", "python-tests"])
@pytest.mark.parametrize("state", ["failure", "cancelled", "skipped", "neutral", None, ""])
def test_actual_gate_rejects_every_unsuccessful_dependency(job, state):
    jobs = {
        "repository-hygiene": {"result": "success"},
        "python-tests": {"result": "success"},
    }
    jobs[job]["result"] = state
    assert _run_gate(jobs).returncode == 1


@pytest.mark.parametrize("jobs", [
    {},
    {"python-tests": {"result": "success"}},
    {"repository-hygiene": {"result": "success"}, "python-tests": {}},
    {"repository-hygiene": {"result": "success"}, "python-tests": {"result": "success"},
     "unexpected": {"result": "success"}},
])
def test_actual_gate_rejects_missing_or_unknown_evidence(jobs):
    assert _run_gate(jobs).returncode == 1


def test_controller_never_executes_the_pr_checkout_or_skips_drafts():
    text = (ROOT / ".github/workflows/pre-merge-integrity-guard.yml").read_text()
    assert "pull_request_target:" in text
    assert "ref: ${{ github.event.pull_request.base.sha }}" in text
    assert "github.event.pull_request.head.sha" not in text
    assert "if:" not in text
    assert "continue-on-error" not in text
    assert "statuses: write" not in text
    assert "permissions: {}" in text
    assert "--require-hashes" in text
    assert "persist-credentials: false" in text
    assert "name: Integrity Guard Controller" in text
