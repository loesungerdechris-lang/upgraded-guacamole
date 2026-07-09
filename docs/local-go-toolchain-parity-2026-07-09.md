# Local Go Toolchain Availability

Date: 2026-07-09  
Branch: sentinel/local-go-toolchain-parity  
Repository: loesungerdechris-lang/upgraded-guacamole

## Local Toolchain

- Go local: go version go1.26.5 windows/amd64
- Python local: Python 3.12.10
- Go install mode: user-local portable install
- Go root: C:\Users\meyer\tools\go
- MSI installer status: winget/MSI failed with exit code 1603, portable install used as safe fallback

## CI Toolchain Boundary

This document confirms that Go can now be executed locally for developer-side smoke testing.

It does not claim exact CI parity.

GitHub Actions remains the source of truth for the pinned CI Go version, operating system, and required repository checks.

The local environment currently runs on Windows. The CI workflow runs on GitHub-hosted Linux runners and uses the Go version configured in the workflow and go.mod.

## Verification Performed Locally

- go test ./...: passed
- python -m pytest -q: passed
- python -m ruff check .: passed

## Assessment

The previous local blocker was that the Go command was unavailable.

That blocker is now closed.

Exact Go version and OS parity with CI remain separate from local smoke-test capability.
