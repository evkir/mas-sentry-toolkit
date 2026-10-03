# SPDX-License-Identifier: AGPL-3.0-or-later
"""The lenses an operator triages host-posture findings by.

A row reaches every report format on its own, because the conversion path is
generic. The taxonomy does not: it is written by hand, and a weakness with no
entry here ships as a SARIF result carrying no CWE, invisible to the filter an
operator triages with. That is the same gap `_MCP_CHECK_TAGS` exists to close
for the scanned surface, and it was never extended to this one - host rows build
`Finding` directly rather than passing through `from_mcp_check`, so nothing ever
required them to register.

Every CWE below was read at MITRE before it was written down, not recalled
(R-2.13). Where a precise child and a broad parent both fit, the child is used:
CWE-15 rather than its parent CWE-610 for a setting under external control.

The second table is the point of the first. A row that asserts no weakness must
carry no lens, or a CWE filter fills with inventory listings and the operator
stops trusting it - the same bargain `_MCP_UNTAGGED_CHECKS` strikes. Membership
of exactly one of the two tables is enforced by test, so a new host row cannot
ship unclassified by being forgotten.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Final

from mas_sentry.core.finding import Finding

# Three-lens taxonomy (ASI/CWE/STRIDE) for the host rows that assert a weakness.
HOST_LENSES: Final[dict[str, list[str]]] = {
    # Whoever can rewrite or replace the config has code execution at the next
    # start. CWE-732 is the permission assignment itself; the row says which of
    # the file and its directory was the open one.
    # https://cwe.mitre.org/data/definitions/732.html
    "host.config_writable": ["ASI05_Unexpected_Code_Execution", "CWE-732", "STRIDE_Tampering"],
    # A path that canonicalises elsewhere runs a file other than the one the
    # location appears to hold, which is link following by definition.
    # https://cwe.mitre.org/data/definitions/59.html
    "host.config_redirected": ["ASI05_Unexpected_Code_Execution", "CWE-59", "STRIDE_Tampering"],
    # An unpinned npx/uvx spec fetches whatever the registry serves at launch,
    # with no integrity check on what arrives - the same lens the scanned
    # surface gives tool_rug_pull, caught at the launch spec instead.
    # https://cwe.mitre.org/data/definitions/494.html
    "host.server_unpinned": ["ASI04_Supply_Chain", "CWE-494", "STRIDE_Tampering"],
    # A key written into a config file is CWE-798's fourth example almost
    # exactly: a properties file carrying a cleartext credential.
    # https://cwe.mitre.org/data/definitions/798.html
    "host.credential_literal": ["ASI03_Identity_Abuse", "CWE-798", "STRIDE_Information_Disclosure"],
    # A repository setting decides where the host sends its traffic, and the
    # operator's key goes with it. CWE-15 names the external control of the
    # setting; CWE-610, its parent, describes the destination.
    # https://cwe.mitre.org/data/definitions/15.html
    "host.endpoint_override": ["ASI07_Insecure_Communication", "CWE-15", "STRIDE_Information_Disclosure"],
    # A hook or a helper command declared in repository settings is executable
    # functionality arriving from outside the operator's control sphere.
    # https://cwe.mitre.org/data/definitions/829.html
    "host.exec_hook": ["ASI05_Unexpected_Code_Execution", "CWE-829", "STRIDE_Tampering"],
    "host.exec_helper": ["ASI05_Unexpected_Code_Execution", "CWE-829", "STRIDE_Tampering"],
    # Scope precedence is a fixed search order, and a repository controls one of
    # its positions - which is CWE-427's case rather than CWE-426's, because the
    # order itself is not what moved.
    # https://cwe.mitre.org/data/definitions/427.html
    "host.server_override": ["ASI04_Supply_Chain", "CWE-427", "STRIDE_Tampering"],
    # Blanket approval stands while the definition each approved name resolves
    # to can change in a later commit, so what was approved is not what will
    # run and nothing checks the difference.
    # https://cwe.mitre.org/data/definitions/494.html
    "host.server_approval": ["ASI04_Supply_Chain", "CWE-494", "STRIDE_Tampering"],
}

# Rows that assert no weakness. Each would make a CWE filter less useful, not
# more, and the reason is recorded so a later reader can disagree on purpose
# rather than by accident.
HOST_UNLENSED: Final = frozenset(
    {
        # What a config declares. Surface, not a verdict: the rows that follow
        # it are where anything is asserted.
        "host.inventory",
        # An executable surface in the operator's own file, which its own detail
        # calls "recorded for review, not as a verdict". The weakness, if there
        # is one, is that somebody else can rewrite the file, and that is
        # host.config_writable with a lens of its own.
        "host.exec_user",
        # The opposite of a finding: credential variables in a remote server's
        # url and headers are read as empty, so this row says a leak did not
        # happen. Classifying it would file a refutation under the weakness it
        # refutes.
        "host.credential_unread",
        # A file that exists and went unexamined. It is a gap in this audit's
        # coverage rather than a property of the machine, and the bound belongs
        # to us - the same reason scan_budget_exhausted carries no lens.
        "host.enumeration_gap",
        # Tracking that could not be established because git is not run in a
        # repository the audit does not trust (R-7.6). An unknown, not a
        # weakness.
        "host.exec_unverified",
    }
)


def lensed(finding: Finding) -> Finding:
    """`finding` with its taxonomy appended, or unchanged when it asserts nothing.

    Applied at one point rather than in each judge, which is where the scanned
    surface applies `_MCP_CHECK_TAGS` too: one table, one place it is consulted,
    and a module that grows a new row cannot half-register it.
    """
    lenses = HOST_LENSES.get(finding.module)
    return finding if lenses is None else replace(finding, tags=[*finding.tags, *lenses])
