#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Walk through one fictional dividend round. No data or network access required."""

from pathlib import Path
from tempfile import TemporaryDirectory

from ki_dividende_modell import Anspruch, DemoRegister, Reject, verteilen


def euros(cents):
    return f"EUR {cents // 100}.{cents % 100:02d}"


def main():
    people = [Anspruch("DEMO-A", "route-1"), Anspruch("DEMO-B", "route-2"),
              Anspruch("DEMO-C")]
    plan = verteilen(500_000, 200, 10_000, people, personenkreis_geklaert=True)
    print("2% of EUR 5,000.00 in fictional receipts funds a EUR 100.00 round.")
    for position in plan.zahlbar:
        print(f"{position.person}: {euros(position.cent)} payable")
    for position in plan.reserviert:
        print(f"{position.person}: {euros(position.cent)} reserved")
    print(f"Carry-forward: {euros(plan.rest_cent)}")

    with TemporaryDirectory() as temporary:
        ledger = Path(temporary) / "claims.sqlite"
        desk_a, desk_b = DemoRegister(ledger), DemoRegister(ledger)
        program, period = "pilot", "round-1"
        first = desk_a.scan("DEMO-A", program, period)
        second = desk_b.scan("DEMO-A", program, period)
        print(f"Two distinct demo tokens: {first != second}")
        desk_a.einloesen(first, program, period)
        try:
            desk_b.einloesen(second, program, period)
        except Reject:
            print("Redemptions on the shared ledger: first accepted, second rejected.")
        else:
            raise RuntimeError("Expected the shared ledger to reject the second claim.")


if __name__ == "__main__":
    main()
