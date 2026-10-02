# SPDX-License-Identifier: AGPL-3.0-or-later
"""Recognising a credential by its documented form, and reporting it without carrying it.

Only formats whose prefix the issuer documents are recognised (GitHub token
types, AWS IAM unique ID prefixes), plus the JWT, which is identified by
decoding its header rather than from a table. A key with no documented prefix
is a stated bound, not an oversight: an entropy test would fire on commit
hashes and base64 blobs.

Every test that asserts a finding also asserts the value is absent from it.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from mas_sentry.core.finding import Severity
from mas_sentry.host import classify, credential_findings, locate, read, shape_of

_GH = "ghp_aBcDeFgHiJkLmNoPqRsT012345678901"
_AWS = "AKIAIOSFODNN7EXAMPLE"


def _jwt(alg: str = "HS256") -> str:
    def seg(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    return f"{seg({'alg': alg, 'typ': 'JWT'})}.{seg({'sub': '1'})}.c2lnbmF0dXJl"


# --- the classifier ---------------------------------------------------------


def test_every_documented_prefix_is_recognised() -> None:
    for prefix in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "AKIA", "ASIA"]:
        assert classify(prefix + "0123456789abcdef") == f"prefix:{prefix}", prefix


def test_a_jwt_is_recognised_by_its_header(tmp_path: Path) -> None:
    assert classify(_jwt()) == "jwt"
    assert classify(f"Bearer {_jwt()}") == "jwt"


def test_three_dotted_segments_without_a_jws_header_are_not_a_jwt() -> None:
    """The header is the discriminator; dotted base64 alone describes much else."""
    assert classify("x.y.z") is None
    assert classify("aGVsbG8.d29ybGQ.c2ln") is None


def test_an_unknown_prefix_and_a_generic_key_are_not_labelled() -> None:
    """The stated bound: no entropy test, so no row on a hash or a blob."""
    assert classify("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4") is None
    assert classify("sk-unknown-vendor-0123456789abcdef") is None
    assert classify("/usr/local/bin:/usr/bin:/bin") is None


def test_a_placeholder_carries_no_credential() -> None:
    assert shape_of("${GITHUB_TOKEN}").credential is None
    assert shape_of("${input:api-key}").credential is None


def test_a_mixed_value_is_still_classified_when_it_starts_with_a_prefix() -> None:
    mixed = shape_of(f"{_GH}${{SUFFIX}}")
    assert mixed.form == "mixed"
    assert mixed.credential == "prefix:ghp_"


def test_an_empty_value_has_no_credential() -> None:
    assert shape_of("").credential is None


# --- the detector -----------------------------------------------------------


def _inv(tmp_path: Path, *, project: dict | None = None, user: dict | None = None, settings: dict | None = None):
    home, repo = tmp_path / "home", tmp_path / "repo"
    home.mkdir(parents=True, exist_ok=True)
    repo.mkdir(parents=True, exist_ok=True)
    if project is not None:
        (repo / ".mcp.json").write_text(json.dumps(project))
    if user is not None:
        (home / ".claude.json").write_text(json.dumps(user))
    if settings is not None:
        (repo / ".claude").mkdir(exist_ok=True)
        (repo / ".claude" / "settings.json").write_text(json.dumps(settings))
    configs = locate(home=home, project_root=repo, system="Linux")
    return [read(c) for c in configs if c.exists]


def _findings(inventories: list) -> list:
    return [f for inv in inventories for f in credential_findings(inv)]


def test_a_literal_token_in_a_repository_server_env_is_high(tmp_path: Path) -> None:
    findings = _findings(_inv(tmp_path, project={"mcpServers": {"gh": {"command": "uvx", "env": {"T": _GH}}}}))
    (f,) = findings
    assert f.module == "host.credential_literal"
    assert f.severity == Severity.HIGH
    assert f.evidence["variable"] == "T"
    assert f.evidence["credential_format"] == "prefix:ghp_"
    assert f.evidence["value_length"] == len(_GH)
    assert _GH not in repr(f)
    assert "rotating" in f.detail


def test_the_same_token_in_user_scope_is_medium(tmp_path: Path) -> None:
    findings = _findings(_inv(tmp_path, user={"mcpServers": {"gh": {"command": "uvx", "env": {"T": _GH}}}}))
    (f,) = findings
    assert f.severity == Severity.MEDIUM
    assert "plaintext on disk" in f.detail
    assert _GH not in repr(f)


def test_an_aws_key_is_named_by_its_issuer(tmp_path: Path) -> None:
    findings = _findings(_inv(tmp_path, project={"mcpServers": {"a": {"command": "n", "env": {"K": _AWS}}}}))
    assert "AWS access key ID" in findings[0].title
    assert _AWS not in repr(findings[0])


def test_a_jwt_in_a_settings_env_block_is_reported(tmp_path: Path) -> None:
    token = _jwt()
    findings = _findings(_inv(tmp_path, settings={"env": {"CI_TOKEN": token}}))
    (f,) = findings
    assert f.evidence["where"] == "the settings env block"
    assert f.evidence["credential_format"] == "jwt"
    assert "JSON Web Token" in f.title
    assert token not in repr(f)


def test_several_literals_each_get_their_own_row(tmp_path: Path) -> None:
    findings = _findings(_inv(tmp_path, project={"mcpServers": {"s": {"command": "n", "env": {"A": _GH, "B": _AWS}}}}))
    assert sorted(f.evidence["variable"] for f in findings) == ["A", "B"]


# --- the cases that must stay quiet -----------------------------------------


def test_a_reference_to_the_environment_is_not_a_finding(tmp_path: Path) -> None:
    """The ordinary way a server is given a token; a row here would hit honest projects."""
    assert (
        _findings(
            _inv(
                tmp_path,
                project={
                    "mcpServers": {
                        "gh": {"command": "uvx", "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}", "K": "${input:key}"}}
                    }
                },
            )
        )
        == []
    )


def test_a_credential_reference_in_remote_headers_is_not_a_finding(tmp_path: Path) -> None:
    """The host reads covered credential variables in headers as empty."""
    assert (
        _findings(
            _inv(
                tmp_path,
                project={
                    "mcpServers": {
                        "r": {
                            "url": "https://api.test/mcp",
                            "headers": {"Authorization": "Bearer ${ANTHROPIC_API_KEY}"},
                        }
                    }
                },
            )
        )
        == []
    )


def test_an_ordinary_env_value_is_not_a_finding(tmp_path: Path) -> None:
    assert (
        _findings(
            _inv(
                tmp_path,
                project={"mcpServers": {"s": {"command": "n", "env": {"PATH": "/usr/bin:/bin", "TZ": "UTC"}}}},
            )
        )
        == []
    )


# --- what is hidden rather than absent --------------------------------------


def test_an_env_file_is_an_info_gap(tmp_path: Path) -> None:
    """Secrets outside the documented config set are unassessed, not absent (R-2.1)."""
    findings = _findings(_inv(tmp_path, project={"mcpServers": {"s": {"command": "n", "envFile": ".env.local"}}}))
    (f,) = findings
    assert f.module == "host.credential_unread"
    assert f.severity == Severity.INFO
    assert f.evidence["env_file"] == ".env.local"


def test_an_env_file_alongside_a_literal_gives_both_rows(tmp_path: Path) -> None:
    findings = _findings(
        _inv(tmp_path, project={"mcpServers": {"s": {"command": "n", "env": {"T": _GH}, "envFile": ".env"}}})
    )
    assert {f.module for f in findings} == {"host.credential_literal", "host.credential_unread"}


def test_a_config_with_nothing_to_report_is_quiet(tmp_path: Path) -> None:
    assert _findings(_inv(tmp_path, project={"mcpServers": {"s": {"command": "uvx"}}})) == []
