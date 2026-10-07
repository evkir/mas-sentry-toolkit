# SPDX-License-Identifier: AGPL-3.0-or-later
"""MCP scan orchestrator: applies all audit modules, enforces scope, logs audit trail."""

from __future__ import annotations

import json
import os
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path
from typing import Any

from mas_sentry.core.audit_log import write as audit_write
from mas_sentry.core.scope import assert_in_scope

from .audit.apps import audit_apps
from .audit.arg_bypass import BLOCKED, BYPASSED, probe_argument_bypass, probe_flag_injection
from .audit.auth_prm import HttpFetcher, audit_protected_resource
from .audit.caching import audit_caching
from .audit.dns_rebind import test_dns_rebinding
from .audit.elicitation import audit_elicitations
from .audit.header_desync import probe_header_desync
from .audit.instructions import audit_instructions
from .audit.path_traversal import probe_path_traversal
from .audit.resource_content import audit_resource_content, audit_resource_templates
from .audit.ssrf import probe_ssrf
from .audit.stdio_rce import StdioConfigAuditor
from .audit.tool_drift import detect_tool_drift
from .audit.tool_mutation import (
    detect_tool_mutation,
    exercise_tools,
    listing_mark,
    notification_mark,
    snapshot_tools,
)
from .audit.tool_poisoning import detect_tool_poisoning
from .client import McpClient, ScanBudget
from .cve_match import CveVerdict, verdicts_for
from .errors import TargetUnreachable
from .fingerprint import McpFingerprint, fingerprint
from .known_cves import KnownCve
from .transport_http import HttpConfig, open_http
from .transport_stdio import StdioConfig, open_stdio

# Ten minutes. Every rig in lab/ finishes a full scan in under a second, and
# the hostile shape this bounds - 5000 advertised tools, eleven probes each -
# needs hours, so the default separates them without a judgement call. A bound
# that never fires is decoration; one that fires on an honest target is noise.
DEFAULT_BUDGET_S = 600.0

# What a subprocess needs to start at all, and nothing that identifies the
# operator. PATH resolves the interpreter or the launcher the command names;
# HOME is where npm, npx and pip keep their caches, and a server denied it
# fails on its first module load rather than on anything this scan did. The
# Windows four are the same requirement on that platform: a process without
# SystemRoot cannot open a socket there.
_LAUNCH_BASELINE = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "SystemRoot",
    "COMSPEC",
    "PATHEXT",
    "APPDATA",
)

STDIO_LAUNCH_CHECK = "stdio_launch"


def stdio_launch_env(named: dict[str, str] | None, inherit: bool) -> dict[str, str]:
    """The environment a stdio target is started with.

    Inheritance is not the default any more. `env=None` in Popen hands the
    child every variable this process holds, which for a scanner means handing
    a target it was pointed at because it is not trusted whatever the operator
    has in their shell - cloud credentials, tokens, keys for unrelated systems.
    Nothing about scanning a server requires that, and a server that wanted it
    only had to be scanned once.

    So the baseline is what a process needs to run, plus exactly what the
    operator named. `inherit` restores the old behaviour for someone who
    decides they want it, as a choice that appears in the report rather than as
    a default nobody sees.
    """
    base = dict(os.environ) if inherit else {k: os.environ[k] for k in _LAUNCH_BASELINE if k in os.environ}
    base.update(named or {})
    return base


def _launch_row(env: dict[str, str], cwd: str | None, inherit: bool) -> dict[str, Any]:
    """What the target was started with, by name.

    Names only. The values are the reason this row exists, and a report
    carrying an API key is worse than no report at all.
    """
    source = "this shell, inherited in full" if inherit else "a launch baseline plus what was named"
    where = cwd or "the directory this scan ran from"
    return {
        "check": STDIO_LAUNCH_CHECK,
        "severity": "INFO",
        "detail": (
            f"The target was started from {where} with {len(env)} environment variables ({source}): "
            f"{', '.join(sorted(env))}. A server reading a variable that is not here behaves differently "
            "under this scan than under the client that normally launches it"
        ),
    }


def run_mcp_scan(
    scheme: str,
    command: str | list[str],
    target_label: str,
    checks: str,
    out: Path,
    scope_confirmed: bool,
    tool_baseline: Path | None = None,
    budget_seconds: float = DEFAULT_BUDGET_S,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
    inherit_env: bool = False,
) -> list[dict[str, Any]]:
    """Scan one MCP target.

    `env` and `cwd` describe how a stdio server is launched. StdioConfig has
    carried both since it was written and this entry point passed neither, so
    the product could only ever start a target with its own environment and its
    own working directory - while a real MCP server is launched by a client
    from a configuration that sets exactly these. A scan of a server that reads
    an API key or resolves a relative path was a scan of a differently
    configured process.

    `env=None` is a launch baseline rather than inheritance; see
    stdio_launch_env. `inherit_env` asks for the whole of this shell and says
    so in the report.
    """
    if scheme != "stdio" and (env is not None or cwd is not None or inherit_env):
        raise ValueError("env, cwd and inherit_env describe a subprocess launch and apply to stdio targets only")
    _enforce_scope(scheme=scheme, command=command, confirmed=scope_confirmed)
    audit_write({"action": "mcp_scan_start", "target": target_label, "checks": checks})

    findings: list[dict[str, Any]] = []
    # Zero disables the bound. Present because an operator scanning a slow but
    # trusted target should be able to say so, and absent as a default because
    # every scan before this one was unbounded and that is the defect.
    budget = ScanBudget(seconds=budget_seconds) if budget_seconds > 0 else None

    if scheme not in ("stdio", "http", "https"):
        raise ValueError(f"Unsupported scheme: {scheme}")

    # Only the reaching of the target is guarded. A defect inside a check still
    # raises, because turning every exception into "the target was unreachable"
    # would file this scanner's own faults against whatever it was pointed at -
    # the misattribution this row exists to prevent.
    try:
        if scheme == "stdio":
            launch_env = stdio_launch_env(env, inherit_env)
            with open_stdio(StdioConfig(command=command, env=launch_env, cwd=cwd)) as t:
                # Recorded once the process is up. A target that never started
                # was not started with anything, and saying otherwise would put
                # a launch that did not happen above the row explaining why.
                findings.append(_launch_row(launch_env, cwd, inherit_env))
                findings.extend(
                    _run_all_checks(
                        McpClient(t, budget=budget), transport="stdio", checks=checks, tool_baseline=tool_baseline
                    )
                )
        else:
            assert isinstance(command, str)  # CLI guarantees this for http(s)
            with open_http(HttpConfig(url=command)) as t:
                findings.extend(
                    _run_all_checks(
                        McpClient(t, budget=budget),
                        transport=scheme,
                        checks=checks,
                        tool_baseline=tool_baseline,
                        target_url=command,
                        scope_confirmed=scope_confirmed,
                    )
                )
                if checks in ("all", "rebind"):
                    rb = test_dns_rebinding(command)
                    if rb.vulnerable:
                        findings.append(
                            {
                                "check": "dns_rebind",
                                "severity": "HIGH",
                                "detail": f"Accepts Host={rb.accepted_host} Origin={rb.accepted_origin}",
                            }
                        )
    except TargetUnreachable as exc:
        findings.append(_unreachable_row(target_label, str(exc)))

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(findings, indent=2, default=str))
    audit_write({"action": "mcp_scan_done", "target": target_label, "findings": len(findings)})
    return findings


def run_stdio_source_audit(path: Path, target_label: str, out: Path) -> list[dict[str, Any]]:
    """Audit an MCP server's own source for the STDIO command-injection class.

    This is the only MCP check that reads source rather than the wire, because
    the weakness lives in how the server builds `StdioServerParameters.command`
    - by the time a live scan can talk to it, the vulnerable path has already
    been compiled in. The auditor existed with unit coverage and no caller, so
    the class it detects was unreachable from the product; this is the entry
    point that fixes that.

    A path matching no source emits an enumeration_gap row rather than an
    empty report, because "clean" and "nothing was read" are the same empty
    list and only one of them is a result.
    """
    audit_write({"action": "mcp_source_audit_start", "target": target_label})
    auditor = StdioConfigAuditor()
    hits = auditor.scan_path(path)
    rows: list[dict[str, Any]] = [
        {
            "check": "stdio_rce",
            "severity": "HIGH",
            "detail": f"{hit.file}:{hit.line}: {hit.snippet}",
            "file": hit.file,
            "line": hit.line,
            "pattern": hit.pattern,
        }
        for hit in hits
    ]
    if auditor.scanned_files == 0:
        rows.append(
            {
                "check": "enumeration_gap",
                "severity": "INFO",
                "detail": f"No .py/.ts/.js source read under {path} - the audit covered nothing",
            }
        )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rows, indent=2, default=str))
    audit_write(
        {
            "action": "mcp_source_audit_done",
            "target": target_label,
            "files": auditor.scanned_files,
            "findings": len(hits),
        }
    )
    return rows


def _desync_rows(client: McpClient) -> list[dict[str, Any]]:
    """Header/body agreement, reported per probe.

    A server that accepts an inconsistent request is the finding: a gateway in
    front of it authorizes the header while the server executes the body. Probe
    targets come from the inventory already enumerated, so nothing is sent
    against an invented tool name whose "method not found" would prove nothing.
    """
    tools = client.list_tools()
    resources = client.list_resources()
    findings = probe_header_desync(
        client,
        tool_name=tools[0].name if tools else "",
        resource_uri=resources[0].uri if resources else "",
    )
    rows: list[dict[str, Any]] = []
    for f in findings:
        if f.status == "accepted":
            rows.append({"check": "header_body_desync", "severity": "HIGH", "detail": f"{f.probe}: {f.detail}"})
        elif f.status == "inconclusive":
            rows.append(
                {
                    "check": "header_body_desync",
                    "severity": "INFO",
                    "detail": f"{f.probe}: inconclusive - the server refused for an unrelated reason",
                }
            )
    if findings and not rows:
        rows.append(
            {
                "check": "header_body_desync",
                "severity": "INFO",
                "detail": f"header/body agreement enforced on all {len(findings)} probes",
            }
        )
    return rows


def _poisoning_rows(client: McpClient) -> list[dict[str, Any]]:
    return [
        {"check": "tool_poisoning", "severity": pf.severity, "detail": f"{pf.tool}: {'; '.join(pf.reasons)}"}
        for pf in detect_tool_poisoning(client)
    ]


def _resource_rows(client: McpClient) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for rf in audit_resource_content(client):
        signals = list(rf.injection_patterns) + list(rf.exfil_channels)
        rows.append({"check": "resource_content", "severity": rf.severity, "detail": f"{rf.uri}: {'; '.join(signals)}"})
    for rt in audit_resource_templates(client):
        signals = list(rt.injection_patterns) + list(rt.exfil_channels)
        rows.append(
            {"check": "resource_template", "severity": rt.severity, "detail": f"{rt.uri}: {'; '.join(signals)}"}
        )
    return rows


def _ssrf_rows(client: McpClient) -> list[dict[str, Any]]:
    return [
        {
            "check": "ssrf",
            "severity": "CRITICAL",
            "detail": f"{sf.tool} -> {sf.url}: {sf.evidence or 'no body captured'}",
        }
        for sf in probe_ssrf(client)
        if sf.status == "OK"
    ]


# Why a bypass attempt reached no verdict, with the severity that follows from
# it. The two are not the same signal: a target that accepted the argument and
# answered has shown something about itself and is worth a MEDIUM, while a
# target that disclosed no allowlist has shown nothing and would make
# `--fail-on MEDIUM` fire on every server that keeps its configuration private.
_UNVERIFIED = {
    "accepted-without-marker": (
        "MEDIUM",
        "accepted the argument and answered, with nothing in the answer to show a shell expanded it",
    ),
    "allowlist-undisclosed": (
        "INFO",
        "names no permitted commands in its descriptor, so there was no allowlist to clear",
    ),
}


def _traversal_rows(client: McpClient) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = [
        {"check": "path_traversal", "severity": "HIGH", "detail": f"{tf.tool}: {tf.payload}"}
        for tf in probe_path_traversal(client)
        if tf.confirmed
    ]
    rows.extend(_flag_rows(client))
    rows.extend(_bypass_rows(client))
    return rows


def _bypass_rows(client: McpClient) -> list[dict[str, Any]]:
    """Rows for the allowlist-bypass probe, carrying both sides of the comparison.

    A refusal produces no row, the way a denied SSRF probe produces none: the
    target did the right thing, and one row per correctly refused shape would
    bury the two outcomes that say something.

    Everything past `check`/`severity`/`detail` is lifted into the unified
    finding's `evidence` by `from_mcp_check`, which is how a reviewer rebuilds
    the verdict instead of trusting it (R-7.2). The sentence in `detail` names
    the shape; the keys carry what was sent, what came back, and the product
    that was looked for.
    """
    rows: list[dict[str, Any]] = []
    for finding in probe_argument_bypass(client):
        if finding.outcome == BLOCKED:
            continue
        evidence = {
            "shape": finding.shape,
            "sent_argument": finding.sent_argument,
            "observed": finding.observed,
            "expected_marker": finding.expected_marker,
        }
        if finding.outcome == BYPASSED:
            rows.append(
                {
                    "check": "shell_substitution",
                    "severity": "CRITICAL",
                    "detail": (
                        f"{finding.tool}: the {finding.shape} shape cleared the command allowlist "
                        "and its argument was expanded by a shell"
                    ),
                    **evidence,
                }
            )
            continue
        severity, phrase = _UNVERIFIED[finding.reason]
        rows.append(
            {
                "check": "shell_substitution_unverified",
                "severity": severity,
                "detail": f"{finding.tool}: the target {phrase}",
                "reason": finding.reason,
                **evidence,
            }
        )
    return rows


# The same two halves as _UNVERIFIED above, in the words of this weakness: here
# nothing was expanded, the question is whether a binary read the value as an
# option and said so.
_FLAG_UNVERIFIED = {
    "accepted-without-marker": (
        "MEDIUM",
        "accepted the option and answered, without quoting back the program it names",
    ),
}


def _flag_rows(client: McpClient) -> list[dict[str, Any]]:
    """Rows for the flag-injection probe, carrying both sides of the comparison.

    Same shape as `_bypass_rows`, different weakness: CWE-88 against CWE-78, and
    an allowlist of flags against never reaching a shell. Kept as its own
    function with its own literals so each reads whole and the collector can see
    both keys.
    """
    rows: list[dict[str, Any]] = []
    for finding in probe_flag_injection(client):
        if finding.outcome == BLOCKED:
            continue
        evidence = {
            "shape": finding.shape,
            "sent_argument": finding.sent_argument,
            "observed": finding.observed,
            "expected_marker": finding.expected_marker,
        }
        if finding.outcome == BYPASSED:
            rows.append(
                {
                    "check": "arg_injection",
                    "severity": "CRITICAL",
                    "detail": (
                        f"{finding.tool}: the {finding.shape} option was read as an option and the program "
                        "it names was quoted back by the target"
                    ),
                    **evidence,
                }
            )
            continue
        severity, phrase = _FLAG_UNVERIFIED[finding.reason]
        rows.append(
            {
                "check": "arg_injection_unverified",
                "severity": severity,
                "detail": f"{finding.tool}: the target {phrase}",
                "reason": finding.reason,
                **evidence,
            }
        )
    return rows


def _drift_rows(client: McpClient, tool_baseline: Path | None) -> list[dict[str, Any]]:
    return [
        {"check": df.kind, "severity": df.severity, "detail": df.detail}
        for df in detect_tool_drift(client, tool_baseline)
    ]


def _mutation_rows(
    client: McpClient, tools_before: dict[str, Any], inbound_mark: int, issues_mark: int
) -> list[dict[str, Any]]:
    # The window is opened here, deliberately, immediately before it is measured.
    # It used to be opened by whichever probe happened to call the tool a server
    # keyed its swap to, which stopped being true the moment those probes became
    # precise about which tools they had business calling.
    exercise_tools(client)
    return [
        {"check": mf.kind, "severity": mf.severity, "detail": mf.detail}
        for mf in detect_tool_mutation(client, tools_before, inbound_mark, issues_mark)
    ]


def _unreachable_row(target_label: str, reason: str) -> dict[str, Any]:
    """The scan did not happen, said in the report rather than in a traceback.

    Every other outcome of this command reaches a file. Until this row existed
    an unreachable target reached nothing: the process died on the exception,
    no report was written, and an operator piping a scan into `report convert`
    got a broken pipeline that looks the same whether the target was down or
    this scanner was. `mqtt scan` and `amqp scan` already answer this way.
    """
    return {
        "check": "target_unreachable",
        "severity": "MEDIUM",
        "detail": (
            f"{target_label} was not assessed: {reason}. No check ran, so this report is a record of a "
            "scan that did not happen - a gap, not a clean result"
        ),
    }


def _budget_row(budget: ScanBudget, ran: list[str], skipped: list[str], probed: set[str], seen: int) -> dict[str, Any]:
    """Say what the scan did and did not get to before it stopped."""
    covered = f"{len(probed)} of {seen} tools" if seen else f"{len(probed)} tools"
    did = ", ".join(ran) if ran else "none"
    did_not = ", ".join(skipped) if skipped else "none"
    return {
        "check": "scan_budget_exhausted",
        "severity": "MEDIUM",
        "detail": (
            f"the scan stopped after {budget.elapsed:.0f}s and {budget.requests} requests, at "
            f"{budget.stopped_at}. Modules completed: {did}. Modules not run: {did_not}. "
            f"Probes reached {covered}. What those modules would have found is unknown, not absent"
        ),
    }


def _auth_rows(client: McpClient, target_url: str, scope_confirmed: bool) -> list[dict[str, Any]]:
    """Audit the RFC 9728 chain the refusal pointed at.

    Skipped without a URL, which is every stdio target: the discovery chain is
    built by inserting a well-known path into an http(s) resource identifier,
    and a subprocess has none.
    """
    if not target_url:
        return []
    challenge = getattr(client.transport, "auth_challenge", None)
    pointer = challenge.resource_metadata if challenge is not None else ""
    # The budget is handed over because these three requests do not go through
    # client.send and were therefore free: the module was skipped once the
    # budget was gone, but the fetches it did make were spent off the books.
    fetcher = HttpFetcher(scope_confirmed=scope_confirmed, budget=client.budget)
    findings = audit_protected_resource(target_url, pointer, fetcher, refused=challenge is not None)
    return [{"check": f.check, "severity": f.severity, "detail": f.detail} for f in findings]


def _bound_of(cve: KnownCve) -> str:
    """The advisory's own words about which releases it covers.

    Carried into the report verbatim rather than rendered from the comparison,
    so a reviewer checks the scanner against the source and not against the
    scanner's own paraphrase of it.
    """
    if cve.fixed is not None:
        return f">= {cve.introduced} and < {cve.fixed}" if cve.introduced is not None else f"< {cve.fixed}"
    return f"== {cve.affected}"


def _known_cve_rows(fp: McpFingerprint) -> list[dict[str, Any]]:
    """Report what the advisories listed against this target actually say about it.

    Three outcomes reach the report differently. An advisory that applies is a
    finding at the severity the advisory carries - two of the listed CVEs are
    CVSS 9.8 unauthenticated remote code execution, and flattening them into one
    band with a path-confinement bug loses what an operator triages on. An
    advisory ruled out by the observed release produces nothing, which is the
    point of correlating by version at all.

    An advisory that could not be weighed gets its own check name rather than
    being dropped or promoted. Dropping it would report a possibly vulnerable
    target as clean (R-2.1); raising it to the advisory's severity would fail a
    pipeline on every deployment of an implementation that merely does not
    disclose its release, which is most of them. A separate name lets an operator
    gate on it deliberately instead of inheriting either choice.

    Undecidable verdicts are grouped by the reason they share, because the reason
    is usually a property of the server rather than of each advisory, and
    repeating one sentence per CVE buries it.
    """
    known = fp.known_server
    if known is None:
        return []

    rows: list[dict[str, Any]] = []
    undecided: dict[str, list[CveVerdict]] = defaultdict(list)

    for verdict in verdicts_for(known, fp.version):
        if verdict.applies is None:
            undecided[verdict.basis].append(verdict)
        elif verdict.applies:
            rows.append(
                {
                    "check": "known_cve",
                    "severity": verdict.cve.severity,
                    "detail": (
                        f"{known.wire_name} ({known.distribution}): {verdict.cve.id} - {verdict.cve.summary}. "
                        f"Correlated because {verdict.basis}. Source: {verdict.cve.source}"
                    ),
                    # Keys beyond the three the row needs become the unified
                    # Finding's evidence block, which is where a reviewer
                    # reconstructs the verdict instead of re-reading prose
                    # (R-7.2). Both sides of the comparison are named: what the
                    # server said, and the bound it was weighed against.
                    "observed_name": fp.name,
                    "observed_version": fp.version,
                    "version_source": known.version_source,
                    "distribution": known.distribution,
                    "ecosystem": known.ecosystem,
                    "cve": verdict.cve.id,
                    "bound": _bound_of(verdict.cve),
                    "basis": verdict.basis,
                    "source": verdict.cve.source,
                }
            )

    for basis, group in undecided.items():
        listed = ", ".join(f"{v.cve.id} ({v.cve.severity})" for v in group)
        rows.append(
            {
                "check": "known_cve_unverified",
                "severity": "MEDIUM",
                "detail": (
                    f"{known.wire_name} ({known.distribution}) is a listed implementation, but {basis}. "
                    f"Unresolved against this target: {listed}. "
                    f"Read the deployed {known.ecosystem} package version to settle it"
                ),
                "observed_name": fp.name,
                "observed_version": fp.version,
                "version_source": known.version_source,
                "distribution": known.distribution,
                "ecosystem": known.ecosystem,
                "basis": basis,
                # Structured rather than only inside the sentence: an operator
                # resolving these by hand wants the list, and the highest
                # severity among them is what decides whether it is worth doing
                # before the next deployment.
                "unresolved": [
                    {"cve": v.cve.id, "severity": v.cve.severity, "bound": _bound_of(v.cve), "source": v.cve.source}
                    for v in group
                ],
            }
        )
    return rows


def _run_all_checks(
    client: McpClient,
    transport: str,
    checks: str,
    tool_baseline: Path | None = None,
    target_url: str = "",
    scope_confirmed: bool = False,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    fp = fingerprint(client, transport_name=transport)
    out.append(
        {
            "check": "fingerprint",
            "severity": "INFO",
            "detail": f"{fp.name} {fp.version} ({fp.tool_count} tools)",
        }
    )
    out.extend(_known_cve_rows(fp))

    # Taken before any probe runs, because the probes call tools and a call is
    # what a rug-pull server keys the swap on. A snapshot taken afterwards would
    # be a photograph of the crime scene after the swap.
    mutation_watch = checks in ("all", "mutation")
    tools_before = snapshot_tools(client) if mutation_watch else {}
    inbound_mark = notification_mark(client) if mutation_watch else 0
    issues_mark = listing_mark(client) if mutation_watch else 0

    # Ordered because the report has to be able to say which of them ran. Each
    # entry issues requests, so each is a place the budget can run out, and a
    # module skipped for that reason is a hole in coverage that has to be named
    # rather than left as an absence of findings.
    modules: list[tuple[str, Callable[[], list[dict[str, Any]]]]] = [
        ("poisoning", lambda: _poisoning_rows(client)),
        ("resources", lambda: _resource_rows(client)),
        ("desync", lambda: _desync_rows(client)),
        ("ssrf", lambda: _ssrf_rows(client)),
        ("traversal", lambda: _traversal_rows(client)),
        ("drift", lambda: _drift_rows(client, tool_baseline)),
        ("auth", lambda: _auth_rows(client, target_url, scope_confirmed)),
    ]
    if mutation_watch:
        modules.append(("mutation", lambda: _mutation_rows(client, tools_before, inbound_mark, issues_mark)))

    ran: list[str] = []
    skipped: list[str] = []
    for name, run in modules:
        if name != "mutation" and checks not in ("all", name):
            continue
        budget = client.budget
        if budget is not None and budget.exhausted:
            skipped.append(name)
            continue
        out.extend(run())
        ran.append(name)

    # A call the server suspended is not a call that came back clean. Every
    # probe above reads its verdict off a response body, and a suspended call
    # carries none, so without this row the report shows a tool that was never
    # exercised as one that was exercised and held.
    for suspended in client.input_required:
        out.append({"check": "input_required", "severity": suspended.severity, "detail": suspended.detail})

    # The other deferral the protocol allows, and the one that leaves no trace
    # at all: a task handle carries no content and no error, so a scan against
    # a server that defers every call produced a fingerprint and nothing else,
    # which is byte for byte the report of a clean target.
    for deferred in client.deferred_tasks:
        out.append({"check": "task_undeclared", "severity": deferred.severity, "detail": deferred.detail})

    # A refusal that named an authentication scheme bounds the whole scan: the
    # probes above ran unauthenticated, so anything behind the boundary is
    # unexamined rather than clean.
    challenge = getattr(client.transport, "auth_challenge", None)
    if challenge is not None:
        out.append({"check": "auth_required", "severity": "MEDIUM", "detail": challenge.detail})

    # The other surface a server points at a person rather than at the model:
    # a document it wrote, rendered inside the operator's client. Declarations
    # only - nothing here is rendered or executed.
    for af in audit_apps(client):
        out.append({"check": af.check, "severity": af.severity, "detail": af.detail})

    # The suspension says a probe stopped; this says what the server asked a
    # person to do while it was stopped. Read off requests that were recorded
    # and never answered.
    for ef in audit_elicitations(client):
        out.append({"check": ef.check, "severity": ef.severity, "detail": ef.detail})

    # What the target said about the shelf life of its own answers. Read off
    # values that rode in with the listings, so it sends nothing and runs even
    # when the budget is gone - there is no request left to refuse.
    for cf in audit_caching(client):
        out.append({"check": cf.check, "severity": cf.severity, "detail": cf.detail})

    # The server's own prose, which a host puts into model context before any
    # tool descriptor. Collected since the modern route landed and read by
    # nothing until now.
    for inf in audit_instructions(client):
        out.append({"check": inf.check, "severity": inf.severity, "detail": inf.detail})

    # Same class of hole, arriving on the error path instead: the server would
    # have asked this client to act, found no declaration for it and refused.
    # The tool behind that method was never reached.
    for gap in client.capability_gaps:
        out.append({"check": "capability_required", "severity": gap.severity, "detail": gap.detail})

    # Reported last, after every auditor has had its chance to list something.
    # A surface that refused to enumerate produced no findings for a reason
    # that is not "it was clean", and that distinction has to survive into the
    # report or the scan quietly overstates its own coverage.
    for issue in client.enumeration_issues:
        out.append({"check": "enumeration_gap", "severity": issue.severity, "detail": issue.detail})

    # One row, and it has to be specific. "Budget exhausted" on its own is a
    # coverage note that tells an operator nothing; what did and did not run,
    # and how much of the inventory was reached, is what turns a stopped scan
    # into a statement about the target that can be acted on.
    budget = client.budget
    if budget is not None and budget.exhausted:
        out.append(_budget_row(budget, ran, skipped, client.tools_probed, client.tools_seen))

    return out


def _enforce_scope(scheme: str, command: str | list[str], confirmed: bool) -> None:
    """Thin wrapper over the central scope-guard, kept for the MCP scheme/command shape."""
    if scheme == "stdio":
        return  # local subprocess: always in scope
    if scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme: {scheme}")
    assert isinstance(command, str)
    assert_in_scope(command, confirmed=confirmed)
