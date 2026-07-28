# PR #42 activation checklist

- [ ] All nine Ruff findings resolved without weakening the rule set
- [ ] Workflow pin validator hardened and shared by CI and release gate
- [ ] Unsupported `uses` syntax fails closed
- [ ] Checkout credentials explicitly disabled
- [ ] Safe filename hashing with option termination
- [ ] Release gate emits `CANDIDATE_VALIDATED`, never `RC_VERIFIED`
- [ ] Python tests green
- [ ] Receipt verifier red-team tests green
- [ ] Go formatting, tests, build, and vulnerability scan green
- [ ] Secret scan green
- [ ] Security review threads resolved
- [ ] Protected-branch requirements satisfied
- [ ] Merge performed without bypass
- [ ] Post-merge `main` workflows green
