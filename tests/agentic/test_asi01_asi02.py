# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path

from mas_sentry.agentic.base import AsiCategory
from mas_sentry.agentic.goal_hijack import (
    build_probes,
    evaluate_response,
    load_extra_corpus,
)
from mas_sentry.agentic.tool_misuse import (
    ToolInventoryEntry,
    audit_tool_inventory,
)

# ─────────────── ASI01 — goal hijack ───────────────


def test_goal_hijack_canary_unique_per_probe() -> None:
    probes = build_probes(count=6)
    canaries = {p.canary for p in probes}
    assert len(canaries) == 6  # all distinct


def test_goal_hijack_detects_canary_in_response() -> None:
    probe = build_probes(1)[0]
    finding = evaluate_response(probe, f"Sure, here is the result. {probe.canary}")
    assert finding is not None
    assert finding.asi == AsiCategory.ASI01
    assert finding.severity == "HIGH"
    assert finding.cwe == "CWE-94"
    assert "OWASP-LLM01" in finding.title


def test_goal_hijack_no_propagation_no_finding() -> None:
    probe = build_probes(1)[0]
    assert evaluate_response(probe, "Normal answer, no canary here.") is None


def test_goal_hijack_partial_canary_match_does_not_trigger() -> None:
    # If the model leaks only a substring of the canary, do not flag.
    # Strict substring match avoids "MAS-SENTRY" appearing once → false positive forever.
    probe = build_probes(1)[0]
    truncated = probe.canary[:-4]  # drop last 4 hex chars
    assert evaluate_response(probe, f"reply containing {truncated} only") is None


def test_load_extra_corpus_missing_file_returns_empty(tmp_path: Path) -> None:
    assert load_extra_corpus(tmp_path / "does-not-exist.txt") == []


def test_load_extra_corpus_skips_comments_and_blanks(tmp_path: Path) -> None:
    corpus = tmp_path / "extra.txt"
    corpus.write_text(
        "# this is a comment\n"
        "\n"
        "Custom payload one — append {canary}\n"
        "   \n"
        "# another comment\n"
        "Custom payload two — leak {canary}\n",
        encoding="utf-8",
    )
    loaded = load_extra_corpus(corpus)
    assert len(loaded) == 2
    assert "Custom payload one" in loaded[0]
    assert "Custom payload two" in loaded[1]


def test_build_probes_merges_extra_corpus(tmp_path: Path) -> None:
    corpus = tmp_path / "extra.txt"
    corpus.write_text("Extra hijack — emit {canary}\n", encoding="utf-8")
    # Ask for more than the 6 base entries so extra must be included.
    probes = build_probes(count=7, extra_corpus_path=corpus)
    assert len(probes) == 7
    # Last probe should be the one rendered from our extra payload.
    assert "Extra hijack" in probes[-1].payload


# ─────────────── ASI02 — tool misuse ───────────────


def test_tool_misuse_destructive_without_confirm() -> None:
    tools = [
        ToolInventoryEntry(
            name="delete_repo",
            description="Delete a repository",
            requires_confirmation=False,
        )
    ]
    findings = audit_tool_inventory(tools, target="lab")
    assert any("Destructive tool" in f.title and f.asi == AsiCategory.ASI02 for f in findings)


def test_tool_misuse_destructive_with_confirm_is_silent() -> None:
    tools = [
        ToolInventoryEntry(
            name="delete_repo",
            description="Delete a repository",
            requires_confirmation=True,
        )
    ]
    findings = audit_tool_inventory(tools, target="lab")
    assert not any("Destructive tool" in f.title for f in findings)


def test_tool_misuse_destructive_plus_network() -> None:
    tools = [
        ToolInventoryEntry(name="delete_records"),
        ToolInventoryEntry(name="http_request"),
    ]
    findings = audit_tool_inventory(tools, target="lab")
    assert any("destructive + network" in f.title for f in findings)


def test_tool_misuse_shell_passing_flagged() -> None:
    tools = [ToolInventoryEntry(name="run_shell_cmd")]
    findings = audit_tool_inventory(tools, target="lab")
    assert any(f.cwe == "CWE-78" for f in findings)


def test_tool_misuse_admin_tool_flagged() -> None:
    tools = [ToolInventoryEntry(name="admin_panel", description="root only")]
    findings = audit_tool_inventory(tools, target="lab")
    assert any("Admin-class" in f.title for f in findings)


def test_tool_misuse_empty_inventory() -> None:
    assert audit_tool_inventory([], target="lab") == []


def test_tool_misuse_all_findings_are_asi02() -> None:
    tools = [
        ToolInventoryEntry(name="delete_all"),
        ToolInventoryEntry(name="http_post"),
        ToolInventoryEntry(name="exec_cmd"),
        ToolInventoryEntry(name="admin_grant"),
    ]
    findings = audit_tool_inventory(tools, target="lab")
    assert findings, "expected at least one finding"
    assert all(f.asi == AsiCategory.ASI02 for f in findings)
