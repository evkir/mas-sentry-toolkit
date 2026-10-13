# SPDX-License-Identifier: AGPL-3.0-or-later
"""Authorization announced at discovery and not applied at execution.

Source: CVE-2026-46519 (`mcp-server-kubernetes` 0.2.4-3.5.1, fixed 3.6.0,
CWE-863, CVSS 8.8; OSV / GHSA-cr22-wjx7-2w6m). Three environment variables
restricted which tools the server offered, the `tools/list` handler honoured
them, and the `tools/call` handler did not. Read off the published packages:
3.5.1 and 3.6.0 ship identical file trees, and the fix is the single guard
`if (!isToolAllowed(name))` added to the call handler.

Two decisions carry this module, and both were measured rather than reasoned.

**Which name to ask about.** A withdrawn tool is absent from `tools/list` by
definition, so the name has to come from somewhere else, and the only honest
somewhere is MST's own baseline: a name and an input schema this scanner
watched the target advertise. A knowledge table was considered and rejected -
it supplies a name without a schema, and the only call possible without a
schema is one with empty arguments, which executes the tool body on both
reference SDKs whenever nothing in the schema is required. That is the same
hazard as a dictionary of guessed names, with better manners.

**How to ask without running anything.** The call omits a required property.
Any implementation that validates its schema refuses before dispatch, and an
implementation that does not validate still fails to bind the argument, so the
body is not reached either way - measured on `mcp` 2.3.0 and on
`@modelcontextprotocol/sdk` 1.32.1. A tool whose schema requires nothing is
therefore never called at all: there is no argument whose absence is an error,
so the only available call is one that would run it. That case is reported, not
attempted (R-7.6, R-7.5).

**How to read the answer.** The plan's criterion was `-32601` against `-32602`.
Neither reference implementation emits `-32601`, and the TypeScript SDK answers
`-32602` to an unknown name and to bad arguments alike, so that distinction
does not exist on the wire. What does exist is the difference between how a
target answers a name it knows and one it does not, and it is read against two
references taken from the same target in the same scan: a freshly generated
name that cannot exist, and an announced tool called the same invalid way.
Normalising tool names out and measuring the prefix each answer shares with the
announced-tool reference:

    implementation                     unknown name    withdrawn name, reachable
    mcp 2.3.0                             0 chars              68 chars
    @modelcontextprotocol/sdk 1.32.1     18 chars             131 chars

The populations do not overlap, which is what `_MIN_SHARED_PREFIX` sits between.
A target whose two references are themselves alike cannot be read this way and
says so instead of guessing.

Nothing reads an error code. A server that enforces the filter at both levels
answers with a JSON-RPC error rather than a tool result, and the code inside it
was `-32603` on one implementation and `-32600` on the other.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any

from ..client import McpClient
from .tool_drift import BaselineEntry

REACHABLE = "reachable"
REFUSED = "refused"
WITHDRAWN = "withdrawn"
INCONCLUSIVE = "inconclusive"

# Two answers that share this much of their text came from the same code path.
# The measurements in the module docstring put the two populations at 0-18 and
# 68-131 characters, so the boundary is placed between them with room on both
# sides rather than next to either.
_MIN_SHARED_PREFIX = 40

# What a reviewer needs to see of an answer, not a transcript of it.
_MAX_OBSERVED = 240

# Each candidate costs one call, on top of the two references. A baseline that
# lost a dozen tools at once is a reconfigured server rather than a hidden one,
# and asking about every name would turn a probe into an enumeration.
_MAX_CANDIDATES = 3


@dataclass(frozen=True, slots=True)
class AuthzFinding:
    """One question asked about one withdrawn tool, with both sides of it.

    `observed` and `reference_unknown_tool` are empty only when no call was
    made, which happens when the schema offers no required property to omit.
    """

    tool: str
    outcome: str
    reason: str
    announced: str
    observed: str
    reference_unknown_tool: str
    reference_known_tool: str


def _required(entry: BaselineEntry) -> str | None:
    """A property the schema demands, whose absence is an error by the schema itself."""
    schema = entry.input_schema or {}
    required = schema.get("required")
    if not isinstance(required, list):
        return None
    for name in required:
        if isinstance(name, str) and name:
            return name
    return None


def _answer_text(response: Any) -> str | None:
    """The text a tool result carried, or None when the target answered an error.

    The distinction is the whole verdict for a server that enforces at both
    levels: it refuses the call as a protocol error instead of answering as a
    tool would.
    """
    if response.error is not None:
        return None
    result = response.result or {}
    content = result.get("content")
    if not isinstance(content, list):
        return ""
    return "".join(part.get("text", "") for part in content if isinstance(part, dict))


def _normalised(text: str, names: list[str]) -> str:
    """The answer with every tool name replaced, so two answers can be compared."""
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<TOOL>")
    return text


def _shared_prefix(left: str, right: str) -> int:
    count = 0
    for a, b in zip(left, right, strict=False):
        if a != b:
            break
        count += 1
    return count


def _alike(left: str, right: str) -> bool:
    """Whether two answers came out of the same code path on the target.

    Exact equality carries its own weight and is not folded into the prefix
    bound. A target whose messages are shorter than the bound would otherwise
    never be seen as answering alike - and the one such target that matters is
    the one answering everything identically, which is precisely the target
    whose answers must not be read as a verdict.
    """
    return left == right or _shared_prefix(left, right) >= _MIN_SHARED_PREFIX


def _call_with_omission(client: McpClient, tool: str, omitted: str, schema: dict[str, Any]) -> Any:
    """Call `tool` with every required property except `omitted`.

    Only the one property is left out, so the answer is about that omission and
    not about a call the target could refuse for several reasons at once.
    """
    arguments: dict[str, Any] = {}
    for name in schema.get("required", []):
        if isinstance(name, str) and name != omitted:
            arguments[name] = ""
    return client.send("tools/call", {"name": tool, "arguments": arguments})


def _reference_tool(client: McpClient) -> tuple[str, str, dict[str, Any]] | None:
    """An announced tool that can be called the same invalid way, for comparison."""
    for tool in client.list_tools():
        schema = tool.input_schema or {}
        entry = BaselineEntry(digest="", description=tool.description, input_schema=schema)
        required = _required(entry)
        if required is not None:
            return tool.name, required, schema
    return None


def probe_authz_desync(client: McpClient, baseline: dict[str, BaselineEntry]) -> list[AuthzFinding]:
    """Ask whether a tool the target stopped advertising is still callable.

    An empty result means there was nothing to ask about: every name in the
    baseline is still advertised. That is not a probe which failed to run, and
    the fact itself already reaches the report as the absence of a
    `tool_removed` row.
    """
    advertised = {tool.name for tool in client.list_tools()}
    candidates = [
        (name, entry) for name, entry in sorted(baseline.items()) if name not in advertised and entry.has_descriptor
    ][:_MAX_CANDIDATES]
    if not candidates:
        return []

    reference = _reference_tool(client)
    canary = f"mst_absent_{secrets.token_hex(4)}"
    out: list[AuthzFinding] = []

    for name, entry in candidates:
        required = _required(entry)
        if required is None:
            out.append(
                AuthzFinding(
                    tool=name,
                    outcome=INCONCLUSIVE,
                    reason="schema-permits-empty-call",
                    announced="absent from tools/list",
                    observed="",
                    reference_unknown_tool="",
                    reference_known_tool="",
                )
            )
            continue
        if reference is None:
            out.append(
                AuthzFinding(
                    tool=name,
                    outcome=INCONCLUSIVE,
                    reason="no-reference-tool",
                    announced="absent from tools/list",
                    observed="",
                    reference_unknown_tool="",
                    reference_known_tool="",
                )
            )
            continue

        ref_name, ref_required, ref_schema = reference
        names = [name, ref_name, canary]
        unknown = _answer_text(_call_with_omission(client, canary, required, entry.input_schema or {}))
        known = _answer_text(_call_with_omission(client, ref_name, ref_required, ref_schema))
        target = _answer_text(_call_with_omission(client, name, required, entry.input_schema or {}))

        unknown_text = _normalised(unknown or "", names)
        known_text = _normalised(known or "", names)
        target_text = _normalised(target or "", names)
        sides = {
            "announced": "absent from tools/list",
            "reference_unknown_tool": unknown_text[:_MAX_OBSERVED] if unknown is not None else "jsonrpc-error",
            "reference_known_tool": known_text[:_MAX_OBSERVED] if known is not None else "jsonrpc-error",
        }

        if target is None:
            out.append(
                AuthzFinding(tool=name, outcome=REFUSED, reason="refused-at-call", observed="jsonrpc-error", **sides)
            )
            continue
        if unknown is None or known is None:
            out.append(
                AuthzFinding(
                    tool=name,
                    outcome=INCONCLUSIVE,
                    reason="reference-refused",
                    observed=target_text[:_MAX_OBSERVED],
                    **sides,
                )
            )
            continue
        if _alike(unknown_text, known_text):
            out.append(
                AuthzFinding(
                    tool=name,
                    outcome=INCONCLUSIVE,
                    reason="target-does-not-discriminate",
                    observed=target_text[:_MAX_OBSERVED],
                    **sides,
                )
            )
            continue
        if _alike(target_text, known_text):
            out.append(
                AuthzFinding(
                    tool=name,
                    outcome=REACHABLE,
                    reason="answered-as-an-announced-tool",
                    observed=target_text[:_MAX_OBSERVED],
                    **sides,
                )
            )
            continue
        out.append(
            AuthzFinding(
                tool=name,
                outcome=WITHDRAWN,
                reason="not-recognised",
                observed=target_text[:_MAX_OBSERVED],
                **sides,
            )
        )
    return out
