"""Public check output uses fixed templates, never scanner free text or source lines."""

from __future__ import annotations

from collections.abc import Iterator

from .semantic_validation import validate_result

CHECK_NAME = "Pre-Merge Integrity Guard"
LABEL_PASS = "Integrität: Bestätigt"
LABEL_FAIL = "Integrität: Blockiert"

_MESSAGES = {
    "INT-001": "Credential pattern detected. Remove and rotate any real exposed credential.",
    "INT-002": "Private key material detected. Remove it and replace any real exposed key.",
    "INT-010": "A protected guard component was removed. Independent maintenance review required.",
    "INT-011": "A protected component changed. Independent maintenance review required.",
    "INT-012": "A mandatory check could not be completed.",
    "INT-013": "A mandatory scanner failed.",
    "INT-014": "A mandatory scanner exceeded its time limit.",
    "INT-020": "A required build failed.",
    "INT-021": "A required test failed.",
    "INT-030": "Workflow configuration violates the configured security policy.",
    "INT-040": "A high-confidence critical security finding requires remediation.",
    "INT-041": "A security candidate requires human review.",
    "INT-050": "Dependency changes require human review.",
    "INT-060": "A development marker requires human review.",
    "INT-061": "An unusually large change requires human review.",
}


def check_output(result: dict) -> dict:
    validate_result(result)
    context = result["context"]
    count = len(result["findings"])
    return {
        "title": CHECK_NAME,
        "summary": (
            f"Configured static checks: {result['status']}; exit {result['exit_code']}; "
            f"complete={str(result['complete']).lower()}; findings={count}.\n\n"
            f"Head: `{context['head_sha']}`. Base: `{context['base_sha']}`.\n\n"
            f"Policy digest: `{context['policy_digest']}`.\n\n"
            "Scope: complete changed Git blobs, protected paths, configured credential patterns "
            "and workflow policy. Build/test CI is a separate required check. "
            "This result is not a guarantee that code is free of vulnerabilities."
        ),
    }


def annotation_batches(result: dict, *, size: int = 50) -> Iterator[list[dict]]:
    """Preserve every locatable finding; GitHub accepts at most 50 per request."""
    validate_result(result)
    if type(size) is not int or not 1 <= size <= 50:
        raise ValueError("Invalid annotation batch size.")
    batch: list[dict] = []
    for finding in result["findings"]:
        if "path" not in finding or "line" not in finding:
            continue
        batch.append({
            "path": finding["path"],
            "start_line": finding["line"],
            "end_line": finding.get("end_line", finding["line"]),
            "annotation_level": (
                "failure" if finding["blocking"] else
                "notice" if finding["severity"] == "info" else "warning"
            ),
            "title": finding["rule_id"],
            "message": _MESSAGES[finding["rule_id"]],
        })
        if len(batch) == size:
            yield batch
            batch = []
    if batch:
        yield batch
