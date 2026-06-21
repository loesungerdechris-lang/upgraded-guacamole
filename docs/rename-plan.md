# Rename Plan: upgraded-guacamole → sentinel-core

## Decision

This repository is now treated as the bootstrap implementation of `sentinel-core`.

## Reason

The repository was empty and therefore safe to use as the clean core workspace. The name `upgraded-guacamole` is not suitable for a serious security, governance, and evidence-chain project.

## Target name

`sentinel-core`

## Manual GitHub step

When ready, rename the repository in GitHub:

1. Open repository settings.
2. Go to **General**.
3. Use **Repository name**.
4. Rename from `upgraded-guacamole` to `sentinel-core`.
5. Confirm that redirects work.
6. Update local remotes if needed:

```bash
git remote set-url origin https://github.com/loesungerdechris-lang/sentinel-core.git
```

## Post-rename checks

- CI still runs on `main`.
- README links are valid.
- Package metadata still uses `sentinel-core`.
- No external documentation points to the old name unless intentionally archived.
