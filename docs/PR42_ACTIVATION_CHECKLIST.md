# PR #42 activation checklist

- [x] Seven Ruff findings corrected in code
- [x] Two exact non-security Ruff compatibility waivers recorded; no global rule disabled
- [x] Workflow pin validator hardened and shared by CI and release gate
- [x] Unsupported and ambiguous `uses` syntax fails closed
- [x] Checkout credentials disabled exactly once as a direct `with` input
- [x] Safe deterministic hashing for every Git-tracked filename
- [x] Release gate emits `CANDIDATE_VALIDATED`, never `RC_VERIFIED`
- [x] Temporary diagnostic workflows removed
- [ ] Python tests green on final head
- [ ] Receipt verifier red-team tests green on final head
- [ ] Go formatting, tests, build, and vulnerability scan green on final head
- [ ] Secret and security scans green on final head
- [ ] Security review threads resolved
- [ ] Protected-branch requirements satisfied
- [ ] Merge performed without bypass
- [ ] Post-merge `main` workflows green
