# SPDX-License-Identifier: AGPL-3.0-or-later
"""STDIO transport. Owns the subprocess; line-delimited JSON framing."""

from __future__ import annotations

import os
import shlex
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from .jsonrpc import JsonRpcRequest, JsonRpcResponse


@dataclass(slots=True)
class StdioConfig:
    command: str | list[str]
    env: dict[str, str] | None = None
    cwd: str | None = None
    timeout: float = 10.0


class StdioTransport:
    def __init__(self, config: StdioConfig) -> None:
        self.config = config
        self._proc: subprocess.Popen[bytes] | None = None

    def open(self) -> None:
        cmd = self.config.command if isinstance(self.config.command, list) else shlex.split(self.config.command)
        # Pentest-tool note: we deliberately use list-form Popen (no shell=True)
        # to avoid laundering an injection in our OWN tooling. Server-side
        # config-injection RCE is what we DETECT, not what we ship.
        self._proc = subprocess.Popen(  # noqa: S603
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.config.env,
            cwd=self.config.cwd,
            bufsize=0,
        )
        # Non-blocking stderr: a chatty/dead server must never deadlock us
        # while we wait on stdout.readline().
        if self._proc.stderr is not None:
            os.set_blocking(self._proc.stderr.fileno(), False)

    def close(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None

    def send(self, req: JsonRpcRequest) -> JsonRpcResponse:
        if not self._proc or not self._proc.stdin or not self._proc.stdout:
            raise RuntimeError("Transport not open")
        line = req.encode() + b"\n"
        self._proc.stdin.write(line)
        self._proc.stdin.flush()
        if req.id is None:  # notification
            return JsonRpcResponse(id=None, result=None)
        raw = self._proc.stdout.readline()
        return JsonRpcResponse.decode(raw)

    def stderr_lines(self) -> Iterator[str]:
        """Drain whatever stderr has buffered. Non-blocking: returns on empty."""
        if not self._proc or not self._proc.stderr:
            return
        while True:
            line = self._proc.stderr.readline()
            if not line:
                return
            yield line.decode("utf-8", errors="replace").rstrip()


@contextmanager
def open_stdio(config: StdioConfig) -> Iterator[StdioTransport]:
    t = StdioTransport(config)
    t.open()
    try:
        yield t
    finally:
        t.close()
