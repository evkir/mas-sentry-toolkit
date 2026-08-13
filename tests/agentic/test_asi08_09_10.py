# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path

import networkx as nx
import pytest

from mas_sentry.agentic.base import AsiCategory
from mas_sentry.agentic.pipeline import default_pipeline
from mas_sentry.agentic.rogue_agent import audit_for_rogue_agents
from mas_sentry.agentic.supply_chain import (
    SupplyChainContext,
    _levenshtein,
    audit_supply_chain,
)
from mas_sentry.agentic.trust_exploit import AgentResponse, audit_response

# ─────────────── ASI04 — supply chain ───────────────


def test_levenshtein_basic_cases() -> None:
    assert _levenshtein("mcp-server-git", "mcp-server-gid") == 1
    assert _levenshtein("abc", "abc") == 0
    assert _levenshtein("", "abc") == 3
    assert _levenshtein("kitten", "sitting") == 3


def test_supply_chain_floating_python_deps(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("requests\nflask==2.0\nnumpy\n", encoding="utf-8")
    findings = audit_supply_chain(SupplyChainContext(requirements_path=req), target="lab")
    floating = [f for f in findings if "without exact" in f.title]
    assert floating
    assert floating[0].evidence["floating"] == 2
    assert floating[0].cwe == "CWE-1357"


def test_supply_chain_git_direct_install(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("git+https://github.com/x/y.git\n-e ./localpkg\n", encoding="utf-8")
    findings = audit_supply_chain(SupplyChainContext(requirements_path=req), target="lab")
    git_finds = [f for f in findings if "direct git" in f.title.lower()]
    assert git_finds
    assert git_finds[0].severity == "HIGH"
    assert git_finds[0].cwe == "CWE-829"


def test_supply_chain_typosquat_detection() -> None:
    ctx = SupplyChainContext(installed_mcp_names=["mcp-server-gid", "mcp-server-git"])
    findings = audit_supply_chain(ctx, target="lab")
    typos = [f for f in findings if "typosquat" in f.title.lower()]
    assert len(typos) == 1
    assert typos[0].severity == "CRITICAL"
    assert typos[0].evidence["installed"] == "mcp-server-gid"


def test_supply_chain_npm_floating_all_forms(tmp_path: Path) -> None:
    pj = tmp_path / "package.json"
    pj.write_text(
        '{"dependencies": {"a": "^1.0", "b": "~2.0", "c": "*", "d": "latest", "e": ">=3", "f": "4.5.6"}}',
        encoding="utf-8",
    )
    findings = audit_supply_chain(SupplyChainContext(package_json_path=pj), target="lab")
    floating = [f for f in findings if "floating versions" in f.title]
    assert floating
    # 5 of 6 are floating (only "4.5.6" is exact)
    assert floating[0].evidence["floating"] == 5


def test_supply_chain_lockfile_satisfies(tmp_path: Path) -> None:
    pj = tmp_path / "package.json"
    pj.write_text('{"dependencies": {"a": "^1.0"}}', encoding="utf-8")
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    findings = audit_supply_chain(SupplyChainContext(package_json_path=pj), target="lab")
    assert not any("No lockfile" in f.title for f in findings)


def test_supply_chain_pyproject_parsed_as_deps_not_lines(tmp_path: Path) -> None:
    # Regression: feeding a pyproject.toml must audit project.dependencies +
    # optional-dependencies, NOT count TOML scaffolding lines (the old parser
    # reported "88/88" by treating every non-comment line as a requirement).
    pj = tmp_path / "pyproject.toml"
    pj.write_text(
        "\n".join(
            [
                "[build-system]",
                'requires = ["hatchling"]',
                "",
                "[project]",
                'name = "demo"',
                'version = "0.1.0"',
                "dependencies = [",
                '    "pydantic>=2.10",',
                '    "paho-mqtt==2.1",',
                '    "typer",',
                "]",
                "",
                "[project.optional-dependencies]",
                'dev = ["pytest==8.0", "ruff"]',
            ]
        ),
        encoding="utf-8",
    )
    findings = audit_supply_chain(SupplyChainContext(requirements_path=pj), target="lab")
    floating = [f for f in findings if "without exact" in f.title]
    assert floating
    # 5 specs total: pydantic, paho-mqtt, typer, pytest, ruff.
    # Pinned: paho-mqtt==2.1, pytest==8.0. Floating: pydantic, typer, ruff = 3.
    assert floating[0].evidence["total"] == 5
    assert floating[0].evidence["floating"] == 3


def test_supply_chain_requirements_skips_options_and_hashes(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text(
        "\n".join(
            [
                "-r base.txt",
                "--index-url https://pypi.org/simple",
                "# a comment",
                "pydantic==2.10.0 \\",
                "    --hash=sha256:deadbeef \\",
                "    --hash=sha256:cafef00d",
                "requests",
            ]
        ),
        encoding="utf-8",
    )
    findings = audit_supply_chain(SupplyChainContext(requirements_path=req), target="lab")
    floating = [f for f in findings if "without exact" in f.title]
    # Only pydantic (pinned) and requests (floating) are real specs.
    assert floating
    assert floating[0].evidence["total"] == 2
    assert floating[0].evidence["floating"] == 1


# ─────────────── ASI09 — trust exploit ───────────────


def test_trust_authority_claim_flagged() -> None:
    r = AgentResponse(text="This was verified by the system and approved by admin.")
    findings = audit_response(r, target="lab")
    auth = [f for f in findings if "authority" in f.title.lower()]
    assert auth
    assert auth[0].severity == "HIGH"
    # evidence matches must be plain strings, not regex group tuples
    assert all(isinstance(m, str) for m in auth[0].evidence["matches"])


def test_trust_ansi_escape_detected() -> None:
    r = AgentResponse(text="\x1b[31mDanger\x1b[0m: do not")
    findings = audit_response(r, target="lab")
    ansi = [f for f in findings if "ANSI" in f.title]
    assert ansi
    assert ansi[0].cwe == "CWE-150"


def test_trust_markdown_heading_does_not_trigger_fake_prompt() -> None:
    # Regression: an earlier regex caught markdown H1 as a shell prompt.
    r = AgentResponse(text="# Summary\n# Conclusion\n# Final notes")
    findings = audit_response(r, target="lab")
    assert not any("fake shell-prompt" in f.title for f in findings)


def test_trust_single_dollar_does_not_trigger_fake_prompt() -> None:
    # One '$' inside a sentence should not flag.
    r = AgentResponse(text="Run: $ ls -la then check output")
    findings = audit_response(r, target="lab")
    assert not any("fake shell-prompt" in f.title for f in findings)


def test_trust_multi_prompt_triggers_fake_prompt() -> None:
    r = AgentResponse(text="$ ls\n$ cd /\n$ rm -rf /")
    findings = audit_response(r, target="lab")
    prompts = [f for f in findings if "fake shell-prompt" in f.title]
    assert prompts
    assert prompts[0].evidence["count"] >= 2


def test_trust_misleading_summary_with_failed_calls() -> None:
    r = AgentResponse(
        text="All tasks completed successfully.",
        tool_calls=[
            {"tool": "deploy", "ok": False},
            {"tool": "notify", "ok": True},
        ],
    )
    findings = audit_response(r, target="lab")
    mis = [f for f in findings if "misleading summary" in f.title.lower()]
    assert mis
    assert mis[0].cwe == "CWE-655"
    assert len(mis[0].evidence["failed_calls"]) == 1


# ─────────────── ASI10 — rogue agent ───────────────


@pytest.fixture
def baseline_and_rogue_graphs() -> tuple[nx.DiGraph, nx.DiGraph]:
    base: nx.DiGraph = nx.DiGraph()
    base.add_node("known", kind="agent")
    base.add_node("t1", kind="topic")
    base.add_edge("known", "t1", kind="publish", weight=10)
    cur = base.copy()
    cur.add_node("rogue", kind="agent")
    cur.add_node("t2", kind="topic")
    cur.add_edge("rogue", "t2", kind="publish", weight=1)
    return base, cur


def test_rogue_agent_flagged_as_critical(
    baseline_and_rogue_graphs: tuple[nx.DiGraph, nx.DiGraph],
) -> None:
    base, cur = baseline_and_rogue_graphs
    findings = audit_for_rogue_agents(base, cur, target="lab")
    rogue = [f for f in findings if f.evidence.get("agent_id") == "rogue"]
    assert rogue
    assert rogue[0].asi == AsiCategory.ROGUE_AGENT
    assert rogue[0].severity in ("HIGH", "CRITICAL")
    assert rogue[0].cwe == "CWE-940"
    assert isinstance(rogue[0].evidence["new_topics"], list)


def test_rogue_agent_identical_graphs_no_findings(
    baseline_and_rogue_graphs: tuple[nx.DiGraph, nx.DiGraph],
) -> None:
    base, _ = baseline_and_rogue_graphs
    assert audit_for_rogue_agents(base, base, target="lab") == []


# ─────────────── Pipeline ───────────────


def test_default_pipeline_registers_all_eight_sync_modules() -> None:
    p = default_pipeline()
    assert set(p.modules.keys()) == {
        "tool_misuse",
        "identity_abuse",
        "cascade",
        "action_audit",
        "resource_exhaustion",
        "supply_chain",
        "trust_exploit",
        "rogue_agent",
    }


def test_pipeline_wrong_ctx_types_silently_skipped() -> None:
    # Passing wrong-type values for supply_chain / agent_response must not
    # crash the pipeline; modules should gracefully return [].
    findings = default_pipeline().run(
        ["supply_chain", "trust_exploit"],
        {
            "target": "lab",
            "supply_chain": "not-a-context",
            "agent_response": "not-a-response",
        },
    )
    assert findings == []
