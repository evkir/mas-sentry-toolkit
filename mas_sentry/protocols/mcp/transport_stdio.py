# SPDX-License-Identifier: AGPL-3.0-or-later
"""STDIO transport. Owns the subprocess; line-delimited JSON framing.

Reads are bounded. `StdioConfig.timeout` existed from the start and was never
applied: the transport called a blocking readline, so a server that accepted a
request and answered nothing stopped the scan for good. That is not a rare
shape - a misconfigured server that starts on the wrong transport, one that
crashes mid-handshake, or one that simply chooses not to answer all produce it,
and the last of those is under the control of the host being scanned. A tool
pointed at untrusted infrastructure that the target can hang is a denial of
service on its own operator, and in CI it is a job that runs until the runner
is killed.

Neither a timeout nor a dead server raises here. Both come back as a JSON-RPC
error, so a stalled listing is recorded as an enumeration gap and the rest of
the scan continues instead of taking the process down with it.
"""

from __future__ import annotations

import contextlib
import os
import select
import shlex
import subprocess
import threading
import time
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from .jsonrpc import JsonRpcRequest, JsonRpcResponse

READ_CHUNK = 65536
# A server may legitimately interleave notifications with responses, and a
# hostile one may emit them without end. Reading is bounded by the same
# deadline as before plus a message count, so a chatty target costs one
# request rather than the scan.
MAX_MESSAGES_PER_SEND = 100
STDERR_TAIL_CHARS = 400

# Lines of server stderr kept for diagnostics. Enough to carry a traceback,
# bounded because the volume is the target's to choose.
STDERR_TAIL_LINES = 200

# How long to wait for the reader to finish once the process is gone.
STDERR_DRAIN_WAIT_S = 2.0
# select() on a pipe is POSIX-only. Elsewhere we fall back to a blocking read,
# which is the old behaviour: worse, but honest about being unbounded.
_CAN_POLL = os.name == "posix"


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
        self._buf = bytearray()
        # Route state the client sets on every transport. Stdio frames requests
        # without headers, so the routing headers have nowhere to go and the
        # flag is accepted and ignored; the negotiated version is still tracked
        # because the client reads it back.
        self.emit_routing_headers = False
        self.protocol_version: str | None = None
        # Server-initiated traffic that is not an answer to anything we asked.
        # Kept rather than discarded: a mid-session tools/list_changed is the
        # rug-pull signal, and it only exists here.
        self.notifications: list[dict[str, Any]] = []
        # Responses that arrived before the request that asked for them was
        # the one waiting. JSON-RPC does not promise ordering.
        self._pending: dict[Any, JsonRpcResponse] = {}
        # The tail of whatever the server wrote to stderr, drained by a reader
        # thread. Bounded: this is diagnostic context for a failure, not a log.
        self._stderr_tail: deque[str] = deque(maxlen=STDERR_TAIL_LINES)
        self._stderr_reader: threading.Thread | None = None

    # STDIO frames requests without headers, so the header/body desync audit
    # has nothing to measure here and skips this transport rather than
    # reporting its inapplicability as a pass.
    supports_headers = False

    def send_with_extra_headers(self, req: Any, overrides: dict[str, str]) -> JsonRpcResponse:
        """Not expressible on STDIO: there are no headers to set."""
        raise NotImplementedError("STDIO frames requests without headers")

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
        # A pipe nobody reads fills up, and a server whose stderr buffer is
        # full blocks on write and stops answering on stdout. Marking our end
        # non-blocking - which is what this used to do - reads nothing and
        # empties nothing, so the guarantee in that comment was never held.
        #
        # Seen against the reference lab server: each refused tool call logged
        # a formatted traceback, roughly sixty kilobytes accumulated over one
        # probe pass, and every request after that timed out. A server that
        # logs is more common than one that does not.
        self._start_stderr_reader()

    def _start_stderr_reader(self) -> None:
        """Drain stderr for as long as the process lives, keeping the tail."""
        stream = self._proc.stderr if self._proc else None
        if stream is None:
            return

        def drain() -> None:
            try:
                for line in iter(stream.readline, b""):
                    self._stderr_tail.append(line.decode("utf-8", errors="replace").rstrip())
            except (OSError, ValueError):
                # The pipe closed under us while the process was shutting down.
                return

        self._stderr_reader = threading.Thread(target=drain, daemon=True)
        self._stderr_reader.start()

    def close(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None
        self._buf = bytearray()
        self._pending = {}

    def send(self, req: JsonRpcRequest) -> JsonRpcResponse:
        if not self._proc or not self._proc.stdin or not self._proc.stdout:
            raise RuntimeError("Transport not open")
        line = req.encode() + b"\n"
        try:
            self._proc.stdin.write(line)
            self._proc.stdin.flush()
        except OSError:
            # The far end is already gone. Writing to a dead pipe raises, and a
            # scanner that dies because its target did is no better than one
            # that hangs.
            return JsonRpcResponse(id=req.id, error={"message": self._exit_reason(req.method)})
        if req.id is None:  # notification
            return JsonRpcResponse(id=None, result=None)
        held = self._pending.pop(req.id, None)
        if held is not None:
            return held
        return self._await_answer(req)

    def _await_answer(self, req: JsonRpcRequest) -> JsonRpcResponse:
        """Read until the answer to `req` arrives, filing everything else.

        The previous version returned the first line that came back. That is
        correct only for a server that answers one request at a time and says
        nothing else, and the reference `everything` server breaks it on the
        first exchange: it emits `notifications/tools/list_changed` before the
        response to `initialize`, so every later answer was off by one and
        `tools/list` came back holding nothing while `prompts/list` came back
        holding the tools. Nothing errored - the scan simply reported an empty
        inventory for a server with thirteen tools, and attributed results to
        methods that never produced them.

        A message carrying `method` is inbound traffic (a notification, or a
        request the server is making of us) and can never be our answer. A
        response bearing someone else's id is held: JSON-RPC allows answers out
        of order, and discarding one would turn a later read into another
        mismatch.
        """
        deadline = time.monotonic() + self.config.timeout
        for _ in range(MAX_MESSAGES_PER_SEND):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return JsonRpcResponse(
                    id=req.id,
                    error={"message": f"no response to {req.method} within {self.config.timeout}s"},
                )
            try:
                raw = self._read_line(remaining)
            except TimeoutError:
                return JsonRpcResponse(
                    id=req.id,
                    error={"message": f"no response to {req.method} within {self.config.timeout}s"},
                )
            except EOFError:
                return JsonRpcResponse(id=req.id, error={"message": self._exit_reason(req.method)})
            resp = JsonRpcResponse.decode(raw)
            if "method" in resp.raw:
                self.notifications.append(resp.raw)
                continue
            if resp.id == req.id:
                return resp
            if resp.id is not None:
                self._pending[resp.id] = resp
                continue
            # No id and no method: an unframeable body, including the decoder's
            # own parse error. Surfacing it beats looping on garbage.
            return resp
        return JsonRpcResponse(
            id=req.id,
            error={"message": f"server sent {MAX_MESSAGES_PER_SEND} messages without answering {req.method}"},
        )

    def _read_line(self, timeout: float) -> bytes:
        """Read one framed line, or give up.

        Buffers across calls because a single read can span several responses
        or stop mid-line; framing is by newline, not by read boundary.
        """
        stdout = self._proc.stdout if self._proc else None
        if stdout is None:
            raise EOFError
        if not _CAN_POLL:
            line = stdout.readline()
            if not line:
                raise EOFError
            return line
        fd = stdout.fileno()
        deadline = time.monotonic() + timeout
        while b"\n" not in self._buf:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            ready, _, _ = select.select([fd], [], [], remaining)
            if not ready:
                continue
            chunk = os.read(fd, READ_CHUNK)
            if not chunk:
                raise EOFError
            self._buf += chunk
        line, _, rest = bytes(self._buf).partition(b"\n")
        self._buf = bytearray(rest)
        return line

    def _exit_reason(self, method: str) -> str:
        """Explain a closed pipe with whatever the server said on its way out.

        The child is given a bounded moment to finish exiting first. Its last
        line is usually the traceback that explains the closed pipe, and
        reading the tail while the process is still writing it returns nothing -
        which is how this looked before: a closed pipe reported with no reason.
        """
        if self._proc is not None:
            with contextlib.suppress(subprocess.TimeoutExpired):
                self._proc.wait(timeout=STDERR_DRAIN_WAIT_S)
        code = self._proc.poll() if self._proc else None
        tail = " | ".join(self.stderr_lines())[-STDERR_TAIL_CHARS:]
        status = "exited" if code is None else f"exited with code {code}"
        suffix = f": {tail}" if tail else ""
        return f"server closed stdout during {method} and {status}{suffix}"

    def stderr_lines(self) -> Iterator[str]:
        """Whatever the reader thread has collected, oldest first.

        Reading is non-destructive: the same tail explains every failure in a
        session, and a diagnostic that empties itself on first use is one that
        is missing by the time a second error asks for it.

        When the process has already exited its stderr is finite, so the reader
        is given a bounded moment to finish. Without that wait the last thing a
        crashing server said - which is the whole reason to keep a tail - races
        the caller asking for it.
        """
        reader = self._stderr_reader
        if reader is not None and self._proc is not None and self._proc.poll() is not None:
            reader.join(timeout=STDERR_DRAIN_WAIT_S)
        yield from list(self._stderr_tail)


@contextmanager
def open_stdio(config: StdioConfig) -> Iterator[StdioTransport]:
    t = StdioTransport(config)
    t.open()
    try:
        yield t
    finally:
        t.close()
