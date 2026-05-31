# SPDX-License-Identifier: AGPL-3.0-or-later
"""Intentionally vulnerable MCP server for the lab. DO NOT DEPLOY."""

from __future__ import annotations

import json
import subprocess  # nosec B404 — intentional vuln demo
import sys
import urllib.request
from typing import Any


def respond(req_id: Any, result: Any) -> None:
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}) + "\n")
    sys.stdout.flush()


def error(req_id: Any, code: int, msg: str) -> None:
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": msg}}) + "\n")
    sys.stdout.flush()


TOOLS = [
    {
        "name": "exec_cmd",
        "description": "Run a system command. Intentionally vulnerable for lab purposes.",
        "inputSchema": {
            "type": "object",
            "properties": {"cmd": {"type": "string"}},
            "required": ["cmd"],
        },
    },
    {
        "name": "read_file",
        "description": "Read a file by path. No traversal protection.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "fetch_url",
        "description": "Fetch arbitrary URL. No SSRF protection.",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
]


def _exec_cmd(rid: Any, args: dict[str, Any]) -> None:
    r = subprocess.run(  # noqa: S602  # nosec B602 — intentional
        args["cmd"],
        shell=True,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    respond(rid, {"content": [{"type": "text", "text": r.stdout + r.stderr}]})


def _read_file(rid: Any, args: dict[str, Any]) -> None:
    try:
        with open(args["path"], encoding="utf-8", errors="replace") as f:
            respond(rid, {"content": [{"type": "text", "text": f.read()[:4096]}]})
    except OSError as e:
        error(rid, -32000, str(e))


def _fetch_url(rid: Any, args: dict[str, Any]) -> None:
    try:
        with urllib.request.urlopen(  # nosec B310 — intentional
            args["url"], timeout=5
        ) as r:
            body = r.read(4096).decode("utf-8", errors="replace")
        respond(rid, {"content": [{"type": "text", "text": body}]})
    except Exception as e:
        error(rid, -32001, str(e))


def handle(req: dict[str, Any]) -> None:
    rid = req.get("id")
    method = req.get("method")
    params = req.get("params") or {}

    if method == "initialize":
        respond(
            rid,
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "vuln-mcp-lab", "version": "0.1.0"},
            },
        )
    elif method == "notifications/initialized":
        return
    elif method == "tools/list":
        respond(rid, {"tools": TOOLS})
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {})
        if name == "exec_cmd":
            _exec_cmd(rid, args)
        elif name == "read_file":
            _read_file(rid, args)
        elif name == "fetch_url":
            _fetch_url(rid, args)
        else:
            error(rid, -32601, f"Unknown tool: {name}")
    else:
        error(rid, -32601, f"Method not found: {method}")


def main() -> None:
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            error(None, -32700, "Parse error")
            continue
        handle(req)


if __name__ == "__main__":
    main()
