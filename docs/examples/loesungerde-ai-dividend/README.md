# LoesungErde · The Open AI Dividend

**One living person has one personal, inalienable right to an equal share of the distributable AI proceeds for each accounting period.** The founder, a newborn and the person who finances the computers have the same weight under the proposed rule. Participants decide how to use money they receive.

Version 0.2.0 is an independent LoesungErde research release. You can test how a funded pool is divided and how two desks sharing a ledger handle a repeated claim. The program runs offline using three fictional people. It collects no personal information. The global dividend is a proposal. Enrollment, real revenue, banking, liveness measurement and privacy-preserving proofs remain outside this demonstration.

## Try one round

From the directory containing this README, run these commands with Python 3. Tested with Python 3.12 and its built-in SQLite library. No package installation or account is required.

```sh
python3 -B demo.py
python3 -B -m unittest -v ki_dividende_modell test_claims
```

The first command pays out **on paper**. A fictional service commits 2% of €5,000, so €100 enters the pool. Two people have a payment route. The third person's entitlement is settled in the calculation while their payment waits. The program reports:

| Payable now | Reserved for the third person | Carry-forward |
| --- | --- | --- |
| €66.66 | €33.33 | €0.01 |

The second command runs 20 tests. These include a founder asking for double weight, a missing €200 from the agreed contribution, a shared payment destination, a restart and two simultaneous attempts to redeem the same entitlement.

## A fresh token and a unique person are different claims

A fresh token changes what a person presents. Something must still remember that this program and period have already paid that entitlement. Two desks in the demo issue different random tokens for the same fictional participant. Both map to one claim marker. SQLite records the first redemption atomically and rejects the second. The operator can link these records. Independent ledgers do not share this protection.

The example sometimes described as a “rolling biometric hash” combines a fixed input and a timestamp with a shared-key authenticator. Within the same clock second the same inputs yield the same value. It supplies neither a liveness measurement nor a zero-knowledge proof of unique enrollment. The release uses random demo tickets and an explicit ledger so reviewers can see exactly where the one-claim property comes from. [HMAC, RFC 2104](https://www.rfc-editor.org/rfc/rfc2104) · [Semaphore v4 membership and scoped nullifiers](https://docs.semaphore.pse.dev/technical-reference/circuits)

## Help test the hard part

- **Developers and cryptographers.** Review the two-desk case. What evidence could two independently operated issuers accept to prevent a second enrollment while allowing a mistaken exclusion to be appealed? Specify who sees what and what happens after a lost credential.
- **Community organizations.** Walk through a fictional applicant with no official ID, phone or bank account. Identify where a free alternative route, representation for a child or a funded correction would be needed. The World Bank estimates about 800 million people lacked official ID in 2024. Those figures measure ID coverage. [World Bank ID4D](https://id4d.worldbank.org/global-dataset)
- **Hardware contributors.** Compare complete, costed designs against a staffed, non-biometric route. Include accessibility, error rates, maintenance and independent optical safety assessment. A €20–30 complete terminal and field equivalence to other devices are unverified targets.

Use synthetic cases in public contributions. Include the code version, starting state, expected decision and observed result. Omit identity documents, photos, scans, payment information and live credentials.

## Read and reuse

[Concept brief (PDF)](docs/open-ai-dividend.pdf) · [Editable brief (HTML)](docs/open-ai-dividend.html) · [Privacy, enrollment and two-terminal research protocol](docs/privacy-and-enrollment.md)

The Python files use AGPL-3.0-only. The README and original documentation use CC BY-SA 4.0. Credit LoesungErde contributors. These licenses apply to the files in this example directory. Third-party materials retain their own terms. The SHA-256 manifest can be checked with `sha256sum -c SHA256SUMS` from this directory. It checks file integrity against a trusted copy of the manifest. [License details](LICENSE.md)
