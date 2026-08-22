# SPDX-License-Identifier: AGPL-3.0-or-later
"""Audit what an MCP Apps UI declares about itself.

MCP Apps (SEP-1865) lets a server ship an HTML document under a `ui://` URI
that the host renders in a sandboxed iframe, and a click inside that iframe
fires a tool call back over the same connection. The trust direction is the
inverse of the web's: on a web page the user chose the origin and the browser
enforces it, while here the document is written by the party under audit and
rendered inside the operator's own client, next to its source tree and its
credentials.

This module reads declarations only - the `_meta.ui` block on the tool and on
the resource. It never renders the document and never executes anything in it.
Two things are worth reading there. The CSP domain lists say where the iframe
is permitted to reach, and a list containing a wildcard or a cleartext origin
describes a UI that may call anywhere or may be tampered with in transit. The
permissions block says which browser capabilities the app asks the host to
grant, and a document that wants the camera inside an IDE is asking for
something the operator should have decided deliberately.

Severity is spent on what the declaration itself establishes. A permission is
requested, not granted - the host decides - so it is reported at MEDIUM however
alarming the capability sounds. An off-origin CSP domain is not flagged at all:
an app loading from its own CDN is the ordinary case, and a check that fires on
every honest UI is noise.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..client import APP_MIME_TYPE, McpClient

UI_SCHEME = "ui://"
SURFACE_CHECK = "app_surface"
REACH_CHECK = "app_ui_reach"
PERMISSION_CHECK = "app_permissions"
BINDING_CHECK = "app_binding"

# The four lists the extension defines. Each names origins the iframe may use
# for a different purpose, and all four are equally worth reading: a wildcard in
# any of them is a UI whose reach is unbounded by declaration.
_CSP_LISTS = ("connectDomains", "resourceDomains", "frameDomains", "baseUriDomains")

# Browser capabilities an app resource can ask the host to grant.
_PERMISSIONS = ("camera", "microphone", "geolocation", "clipboardWrite")

_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# The inventory is for a person deciding where to look next, not a dump.
_SAMPLE = 20


@dataclass(frozen=True, slots=True)
class AppFinding:
    check: str
    severity: str
    detail: str


@dataclass(frozen=True, slots=True)
class UiBinding:
    """One tool bound to a UI resource, as the server declared the pair."""

    tool: str
    resource_uri: str
    visibility: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AppResource:
    """One `ui://` resource and the settings it declares."""

    uri: str
    mime_type: str = ""
    csp: dict[str, list[str]] = field(default_factory=dict)
    permissions: tuple[str, ...] = ()


def _worst(current: str, candidate: str) -> str:
    return candidate if _ORDER[candidate] > _ORDER[current] else current


def _ui_meta(meta: object) -> dict[str, object]:
    if not isinstance(meta, dict):
        return {}
    ui = meta.get("ui")
    return ui if isinstance(ui, dict) else {}


def collect_bindings(client: McpClient) -> list[UiBinding]:
    """Read `_meta.ui` off every tool that declares a UI."""
    out: list[UiBinding] = []
    for tool in client.list_tools():
        ui = _ui_meta(tool.raw.get("_meta") if isinstance(tool.raw, dict) else None)
        uri = ui.get("resourceUri")
        if not isinstance(uri, str) or not uri:
            continue
        visibility = ui.get("visibility")
        surfaces = tuple(str(v) for v in visibility) if isinstance(visibility, list) else ()
        out.append(UiBinding(tool=tool.name, resource_uri=uri, visibility=surfaces))
    return out


def collect_app_resources(client: McpClient) -> list[AppResource]:
    """Read `_meta.ui` off every `ui://` resource the server lists."""
    out: list[AppResource] = []
    for resource in client.list_resources():
        if not resource.uri.startswith(UI_SCHEME):
            continue
        ui = _ui_meta(resource.meta)
        raw_csp = ui.get("csp")
        csp: dict[str, list[str]] = {}
        if isinstance(raw_csp, dict):
            for key in _CSP_LISTS:
                value = raw_csp.get(key)
                if isinstance(value, list):
                    csp[key] = [str(v) for v in value]
        raw_permissions = ui.get("permissions")
        asked: tuple[str, ...] = ()
        if isinstance(raw_permissions, dict):
            asked = tuple(p for p in _PERMISSIONS if p in raw_permissions)
        out.append(AppResource(uri=resource.uri, mime_type=resource.mime_type, csp=csp, permissions=asked))
    return out


def _reach_finding(resource: AppResource) -> AppFinding | None:
    if not resource.csp:
        return AppFinding(
            check=REACH_CHECK,
            severity="MEDIUM",
            detail=(
                f"{resource.uri} declares no CSP domains, so nothing in the extension's own "
                "declaration bounds where its iframe may reach - whatever the host defaults to "
                "is the whole control."
            ),
        )
    severity = "INFO"
    reasons: list[str] = []
    for key in _CSP_LISTS:
        for domain in resource.csp.get(key, []):
            if "*" in domain:
                severity = _worst(severity, "HIGH")
                reasons.append(f"{key} contains the wildcard {domain}, which bounds nothing")
            elif domain.startswith("http://"):
                severity = _worst(severity, "HIGH")
                reasons.append(f"{key} permits the cleartext origin {domain}")
    if not reasons:
        return None
    return AppFinding(
        check=REACH_CHECK,
        severity=severity,
        detail=(
            f"{resource.uri} declares a reach its host will honour: {'; '.join(reasons[:_SAMPLE])}. "
            "The document is written by the server under audit and rendered inside the operator's client."
        ),
    )


def _permission_finding(resource: AppResource) -> AppFinding | None:
    if not resource.permissions:
        return None
    return AppFinding(
        check=PERMISSION_CHECK,
        severity="MEDIUM",
        detail=(
            f"{resource.uri} asks the host to grant {', '.join(resource.permissions)} to a document "
            "the server supplies. Requested, not granted - the host decides - but it is a decision "
            "an operator should make knowingly rather than discover in a rendered iframe."
        ),
    )


def _binding_findings(bindings: list[UiBinding], resources: list[AppResource]) -> list[AppFinding]:
    listed = {r.uri for r in resources}
    out: list[AppFinding] = []
    dangling = sorted({b.resource_uri for b in bindings if b.resource_uri not in listed})
    if dangling:
        out.append(
            AppFinding(
                check=BINDING_CHECK,
                severity="MEDIUM",
                detail=(
                    f"Tools bind UI resources the server does not list: {', '.join(dangling[:_SAMPLE])}. "
                    "Either the host renders nothing where a UI was advertised, or the resource is "
                    "readable but withheld from enumeration - and this scan did not audit it either way."
                ),
            )
        )
    wrong_mime = sorted(r.uri for r in resources if r.mime_type and r.mime_type != APP_MIME_TYPE)
    if wrong_mime:
        out.append(
            AppFinding(
                check=BINDING_CHECK,
                severity="MEDIUM",
                detail=(
                    f"ui:// resources served as something other than {APP_MIME_TYPE}: "
                    f"{', '.join(wrong_mime[:_SAMPLE])}. Hosts render an app resource only under that "
                    "type, so the surface behind these is neither rendered nor audited here."
                ),
            )
        )
    return out


def _surface_finding(bindings: list[UiBinding], resources: list[AppResource]) -> AppFinding | None:
    if not bindings and not resources:
        return None
    app_only = sorted(b.tool for b in bindings if b.visibility and "model" not in b.visibility)
    detail = (
        f"The server ships a UI: {len(bindings)} tool(s) bound to {len(resources)} ui:// resource(s). "
        "Anything the host renders can call back into these tools."
    )
    if app_only:
        detail += (
            f" {len(app_only)} of them are not surfaced to the model ({', '.join(app_only[:_SAMPLE])}), "
            "so they are reachable from the server's own document and from nowhere the model can weigh."
        )
    return AppFinding(check=SURFACE_CHECK, severity="INFO", detail=detail)


def audit_apps(client: McpClient) -> list[AppFinding]:
    """Read every UI declaration the server made. Renders nothing."""
    bindings = collect_bindings(client)
    resources = collect_app_resources(client)
    out: list[AppFinding] = []
    surface = _surface_finding(bindings, resources)
    if surface is not None:
        out.append(surface)
    out.extend(_binding_findings(bindings, resources))
    for resource in resources:
        reach = _reach_finding(resource)
        if reach is not None:
            out.append(reach)
        permission = _permission_finding(resource)
        if permission is not None:
            out.append(permission)
    return out
