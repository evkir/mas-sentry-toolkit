# Contributing

Thanks for considering a contribution. A few principles up front:

1. **Scope.** This is a defensive/offensive security toolkit. We accept code
   that helps detect, audit, or document risks against multi-agent systems.
   We do not accept weaponised payloads or anything that helps attack systems
   the operator does not own.
2. **License.** All contributions land under AGPL-3.0-or-later. By opening a
   PR you agree to license your contribution under this license. The author
   retains copyright; commercial dual-licensing remains possible.
3. **Style.** Run `ruff check . && ruff format . && mypy mas_sentry` before
   pushing.
4. **Tests.** New modules require unit tests. Targeted coverage minimum: 80%.
5. **Commits.** Conventional Commits: `feat:`, `fix:`, `docs:`, `test:`,
   `chore:`, `ci:`, `build:`, `refactor:`. Scope tags: `(core)`, `(mqtt)`,
   `(amqp)`, `(mcp)`, `(a2a)`, `(abfp)`, `(agentic)`, `(threat)`,
   `(reporting)`, `(cli)`, `(lab)`.
6. **Active probes.** Any active-probe module must respect the scope guard
   (`--confirm-scope` outside lab) and log to `~/.mas-sentry/audit.jsonl`.

## Local dev

    git clone https://github.com/evkir/mas-sentry-toolkit
    cd mas-sentry-toolkit
    python -m venv .venv && source .venv/bin/activate
    pip install -e ".[dev,docs]"
    pytest
    ruff check .
    mypy mas_sentry

## Reporting security issues

Do not open a public issue. Email `ekiriyak@gmail.com` with subject
`[mas-sentry security]`.
