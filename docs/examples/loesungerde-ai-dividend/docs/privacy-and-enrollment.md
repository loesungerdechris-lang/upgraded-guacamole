# Privacy and enrollment

**Research specification · 20 November 2026.** The proposed right belongs to the person. A lost credential, an unavailable terminal or a disputed match must have a correction path. The tests below use synthetic participants and simulated entitlements. They describe acceptance criteria for future work.

## What each check establishes

| Check | Evidence it can supply | Assumption still open |
| --- | --- | --- |
| Presence or liveness | Evidence about the presentation at one session, subject to measurement error | Eligibility, identity and earlier enrollments remain separate questions. |
| Enrollment | An issuer accepted a person under stated rules for a defined population and period | Different issuers can issue to the same person. The joint duplicate-resolution process needs independent validation and an appeal route. |
| Zero-knowledge membership proof | In a protocol such as Semaphore, a holder proves possession of a secret associated with an admitted member, without revealing which member | A valid proof inherits the issuer's admission decisions. Control of a credential can change hands. |
| Once-per-period claim | A verifier can derive or verify a scoped, one-use tag called a nullifier. Both terminals must use the same program and period scope and atomically record its use against a payment instruction. | Two separately issued credentials can produce different valid tags for the same person. Timing, payment details and device metadata can still connect claims across periods. |

Scope definitions and approved group roots must be versioned and independently reproducible. A nullifier belongs to a claim scope. Deriving a global identifier from an iris image would give organizations a durable means to track people. [Semaphore v4 circuit](https://docs.semaphore.pse.dev/technical-reference/circuits) · [W3C Verifiable Credentials 2.0, verification and privacy](https://www.w3.org/TR/vc-data-model-2.0/)

## Access and data handling

The World Bank's 2025 dataset estimates that in 2024 about 800 million people lacked official identification. More than half were children whose births were unregistered. A phone, government ID or successful iris scan as the only entry route would exclude intended participants. [World Bank ID4D data](https://id4d.worldbank.org/global-dataset)

Offer a free, staffed, accessible route with documented alternative evidence and an independent reviewer, including for applicants without government ID or a smartphone. Test a representative acting for a child and a person recovering a lost credential. A successful alternative enrollment carries the same entitlement, fee and terms. Record whether the alternative can actually be reached, how long it takes and what the applicant spends. Publish aggregate delays and appeals. A disputed case gets a case receipt, review and a funded correction mechanism. [World Bank ID4D principles](https://id4d.worldbank.org/guide/1-principles) · [NIST identity proofing requirements, including manual review of biometric duplicate matches](https://pages.nist.gov/800-63-4/sp800-63a/ial-general/)

Separate enrollment, payout and appeals. Publish rule versions and aggregate accounting. Give individuals their own private receipt. Keep raw images, biometric templates, identity numbers, payment addresses and stable personal identifiers out of public evidence and telemetry. Small aggregates can identify people too. For any later EU trial involving real people, document purpose, necessity, minimization, retention, erasure, access controls, applicable legal basis, any required Article 9 condition and the Article 35 impact assessment where applicable before collection. Hashing a biometric template does not establish anonymity. [GDPR, Articles 4, 5, 6, 9, 25 and 35](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng)

## Two-terminal research gates

Use independently operated terminals A and B, with separate administrators and signing keys. Record each operator, hardware model, firmware, software version and all shared services or vendors. Distinguish administrative independence from independent hardware or software implementations. Each test needs a versioned synthetic input, expected outcome, both terminals' receipts where applicable, and the reconciled ledger. Results from two terminals describe only the tested configuration.

| Research question | Acceptance evidence |
| --- | --- |
| Can A and B issue twice to the same synthetic participant? | Simultaneous applications for one fixture produce one active entitlement. Two distinct fixtures with a simulated false match retain separate entitlements after independent review. Unavailable duplicate checks leave a recoverable pending case. |
| Can both terminals settle the same period? | For one credential, concurrent claims, retries and a disconnect after payment produce one recorded settlement and one amount paid. A disconnected terminal may queue a claim. Settlement waits for shared spent-state reconciliation. |
| Does recovery preserve rights and control disclosure? | A replacement or change of enrollment route preserves accrued and claimed periods and disables the old credential. A new period uses a different tag. Inspect public outputs, receipts and diagnostics for stable cross-period identifiers and unnecessary metadata. Distinct tags alone cannot prove anonymity. |
| Can someone decline the iris route? | Test synthetic cases for no ID, no phone, unavailable network, a guardian, inability to scan, and an erroneous rejection. Each case reaches payment on the same terms or a reasoned, appealable decision. Record elapsed time and costs for each route. |
| Would optical performance support a later trial? | Agree a target population, realistic comparison gallery size, maximum error rates and confidence bounds before human evaluation. Independently measure failure to acquire, false matches, false nonmatches and manual-review burden across intended groups. Synthetic tests establish workflow behavior only. |

## Hardware cost and eye safety

The Galaxy S9 included an iris scanner, and Microsoft documented iris unlock on the Lumia 950. These examples establish that iris authentication shipped in consumer handsets. They provide no tested population-scale duplicate-detection rate, supported cross-vendor enrollment interface or current terminal price. Samsung's own S9 manual includes specific operating restrictions. [Samsung Galaxy S9 specification](https://news.samsung.com/us/samsung-galaxy-s9-enterprise-fact-sheet/) · [Samsung S9 user guide, p. 224](https://images.samsung.com/is/content/samsung/assets/ca/support/mobile-devices/galaxy-s9-plus-how-do-i-access-the-user-manual-on-my-samsung-galaxy-s9-plus/pdf/SM-G96X_UG_EN4.pdf) · [Microsoft Devices Blog, Lumia 950](https://blogs.windows.com/devices/2015/11/20/surprise-fan-review-lumia-950/)

Obtain dated, itemized supplier quotes for two complete stations. State currency, quantity, tax and support assumptions. Compare installed cost and cost per completed enrollment against the staffed non-iris route, including accessibility, power, connectivity, maintenance, staff, independent testing and appeals. Component prices alone cannot establish either measure. No complete-station quote or measured unit cost is available in this specification. [World Bank ID4D cost guidance](https://id4d.worldbank.org/guide/evaluate-costs-and-benefits)

Keep the present demonstration synthetic. Before any human-facing optical trial, obtain a qualified assessment covering the complete device, optical source, operating modes, intended population and foreseeable exposure. A supplier's classification for another device or an individual component does not establish safety after integration. IEC 62471 covers applicable LED lamp systems and excludes lasers. IEC TR 62471-4 describes optical measurement methods. Have the assessor identify the standards that apply to the actual design. [IEC 62471](https://webstore.iec.ch/en/publication/7076) · [IEC TR 62471-4](https://webstore.iec.ch/en/publication/33225)
