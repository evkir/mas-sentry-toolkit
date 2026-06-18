# MAS-Sentry Audit - mas-sentry-toolkit

**Generated:** 2026-06-18T06:14:23+00:00  
**Findings:** 0  
**Breakdown:** CRITICAL: 0 - HIGH: 0 - MEDIUM: 0 - LOW: 0 - INFO: 0

## Methodology

This is a dogfooding self-audit: MAS-Sentry's own ASI08 (Supply Chain) scanner run against this repository's hash-pinned lockfile, which is the artifact CI installs from in `supply-chain.yml`.

```bash
mas-sentry agentic scan --target mas-sentry-toolkit \
  --requirements requirements-lock.txt --asi asi08 \
  --out reports/self-supply.json
mas-sentry report convert reports/self-supply.json \
  --format md --target mas-sentry-toolkit --out reports/SELF-AUDIT.md
```

Zero findings against the lockfile means every install pin is exact and hash-verified, with no floating ranges or direct git installs.

`requirements.txt` deliberately mirrors the `>=` ranges declared in `pyproject.toml` for human readability; it is not the install-of-record. The hash-pinned `requirements-lock.txt` is the verified install path, and a drift-guard test keeps both in sync with `pyproject.toml`.

## Summary

| # | Severity | Module | Title |
|---|----------|--------|-------|

## Detail
