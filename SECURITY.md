# Security policy

## Supported versions

The `main` branch and the latest tagged release receive security fixes. Older tags are best-effort only.

## Reporting a vulnerability

Email `ekiriyak@gmail.com` with subject prefix `[mas-sentry security]`. Include:

- A clear description.
- Reproduction steps (CLI invocation, target, expected vs actual).
- Affected version (`mas-sentry --version` or commit hash).
- Whether you intend to publish a writeup. If so, propose a coordinated date.

You will get an acknowledgement within 72 hours. We aim for a fix within 14 days for HIGH/CRITICAL issues.

## Scope of "security issue" for this project

- Vulnerabilities in the toolkit itself (RCE in our parser, path-traversal in our file I/O, code-execution via crafted scan input).
- False-positive or false-negative classes that materially mislead users.
- Cryptographic weakness in our own modules.

**Out of scope:**

- Findings the toolkit produces against intentional lab targets.
- Issues in dependencies - please report upstream first. We will fast-track an update once a fix lands.

## Researcher recognition

Reporters who follow this policy will be credited in the release notes and in `SECURITY-HALL-OF-FAME.md` once any fix ships, unless they prefer otherwise.

## Operational guarantees we make

- Active probes write to `~/.mas-sentry/audit.jsonl` (append-only, owner-only perms 0600).
- Active probes refuse non-lab targets unless `--confirm-scope` is set or `MAS_SENTRY_SCOPE_CONFIRMED=1`.
- Probes never deliver destructive payloads; canaries are benign (touch a tempfile, request a public URL, etc.).

