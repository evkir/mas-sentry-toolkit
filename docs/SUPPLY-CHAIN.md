# Supply Chain Security

How MAS-Sentry Toolkit keeps its dependency chain auditable, reproducible, and
continuously verified. This is the process the toolkit itself runs against its
own dependencies (see "Self-audit" below).

## Dependency artifacts

The chain has one source of truth and two derived files:

| File | Role | Pinning | Audience |
| --- | --- | --- | --- |
| `pyproject.toml` `[project.dependencies]` | Source of truth | Ranges (`>=`) | Maintainers |
| `requirements.txt` | Human-readable mirror | Ranges (`>=`) | Quick install, tooling |
| `requirements-lock.txt` | Reproducible install | Exact `==` + `--hash` | Production, CI |

`requirements.txt` mirrors the source of truth exactly; drift between the two
fails the test suite (`tests/unit/test_requirements_sync.py`), so the mirror can
never silently lie. The lock file is generated from the same source and carries
a SHA-256 hash for every distribution.

## Reproducible / production install

Install runtime dependencies with hash enforcement, then the package itself:

```bash
pip install --require-hashes -r requirements-lock.txt
pip install . --no-deps
```

`--require-hashes` makes pip refuse any artifact whose download does not match
the recorded hash, which blocks a compromised mirror or a tampered package from
being installed.

## Regenerating the lock file

Regenerate whenever `[project.dependencies]` changes. Run on the lowest
supported interpreter to keep markers conservative:

```bash
pip install pip-tools
pip-compile --generate-hashes --strip-extras \
    --output-file=requirements-lock.txt pyproject.toml
```

The guard test then confirms every runtime dependency is present in the lock; a
forgotten regeneration fails `pytest` rather than surfacing later at install
time.

## Continuous verification (`supply-chain.yml`)

Runs on dependency changes, on every pull request, and weekly (to catch newly
disclosed CVEs in unchanged dependencies):

- **Lockfile integrity** - installs the lock with `--require-hashes`; proves the
  lock is complete and untampered.
- **CVE audit** - `pip-audit` against the lock; fails on any known
  vulnerability in a pinned dependency.
- **Self-audit (ASI04)** - the toolkit scans its own lock file for supply-chain
  weakness and fails the build on any finding (see below).
- **Dependency review** - on pull requests, flags newly introduced
  dependencies at `high` severity or above before merge.

This is distinct from the `Security scan` job in `ci.yml`, which runs Bandit
SAST over first-party source. Supply-chain verification covers the external
dependency surface; Bandit covers the code we write.

## Self-audit (dogfooding ASI04)

MAS-Sentry implements OWASP Agentic Top 10 **ASI04 (Agentic Supply Chain)** as a
scanner. CI points that scanner at the toolkit's own lock file:

```bash
mas-sentry agentic scan --target self-audit \
    --requirements requirements-lock.txt --asi asi08 \
    --out reports/self-asi08.json
```

A hash-pinned lock yields zero findings. If the lock ever regresses to floating
versions, the scanner reports `ASI04_Supply_Chain` and the build fails. The
product is its own regression test, and the run demonstrates the scanner on a
real target.

## Updating dependencies

1. Edit `[project.dependencies]` in `pyproject.toml`.
2. Mirror the change into `requirements.txt`.
3. Regenerate `requirements-lock.txt` (command above).
4. Run the gate: `ruff check . && mypy mas_sentry && pytest`.

Renovate proposes dependency bumps automatically; each bump must pass the full
supply-chain workflow before merge.
