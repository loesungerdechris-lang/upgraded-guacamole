#!/usr/bin/env python3
"""Run the synthetic SENTINEL Core pilot and print a compact JSON result."""

from __future__ import annotations

import json

from sentinel_core.pilot import run_synthetic_pilot


def main() -> int:
    pilot = run_synthetic_pilot(role="auditor", decision="allow")
    output = {
        "ok": pilot.verification.ok,
        "digest": pilot.verification.digest,
        "actor_role": pilot.verification.actor_role,
        "key_id": pilot.verification.key_id,
        "errors": list(pilot.verification.errors),
        "warnings": list(pilot.verification.warnings),
        "record": pilot.record,
    }
    print(json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if pilot.verification.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
