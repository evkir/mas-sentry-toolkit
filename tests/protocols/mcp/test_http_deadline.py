# SPDX-License-Identifier: AGPL-3.0-or-later
"""One HTTP request must not be able to hold the scan open.

Driven against a real socket rather than a mock. The defect these cases pin is
in how bytes arrive over time, and a mock hands the whole body over at once -
it cannot express a server that sends a byte, waits, and sends another. Under
the transport as it was, the first case here ran for over half a minute with a
two second timeout configured, because the httpx timeout bounds the gap
between reads and nothing bounds their number.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Callable, Iterator

import pytest

from mas_sentry.protocols.mcp.jsonrpc import JsonRpcCodec
from mas_sentry.protocols.mcp.transport_http import (
    DEADLINE_ERROR,
    HttpConfig,
    StreamableHttpTransport,
)

CHUNK_GAP_S = 0.05


def _chunk(payload: bytes) -> bytes:
    return f"{len(payload):x}\r\n".encode() + payload + b"\r\n"


def _serve(handler: Callable[[socket.socket, int], None]) -> Iterator[int]:
    """Run a one-shot HTTP server that frames its own chunks, and hand back its port."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = int(srv.getsockname()[1])
    stop = threading.Event()

    def accept_loop() -> None:
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            threading.Thread(target=_run_handler, args=(conn, handler), daemon=True).start()

    def _run_handler(conn: socket.socket, fn: Callable[[socket.socket, int], None]) -> None:
        try:
            raw = conn.recv(65536).decode("utf-8", "replace")
            body = raw.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in raw else "{}"
            try:
                req_id = int(json.loads(body).get("id", 1))
            except (ValueError, TypeError, AttributeError):
                req_id = 1
            fn(conn, req_id)
        except OSError:
            pass
        finally:
            conn.close()

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        stop.set()
        thread.join(timeout=2)
        srv.close()


def _sse_headers(conn: socket.socket) -> None:
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")


def _dribble(conn: socket.socket, req_id: int) -> None:
    """Never answer, but never fall silent either. Every gap is inside the timeout."""
    _sse_headers(conn)
    while True:
        conn.sendall(_chunk(b": keep-alive\n\n"))
        time.sleep(CHUNK_GAP_S)


def _answer_then_hold(conn: socket.socket, req_id: int) -> None:
    """Answer, then keep the stream open - which a server is permitted to do."""
    _sse_headers(conn)
    frame = "data: " + json.dumps({"jsonrpc": "2.0", "id": req_id, "result": {"tools": []}}) + "\n\n"
    conn.sendall(_chunk(frame.encode()))
    while True:
        conn.sendall(_chunk(b": keep-alive\n\n"))
        time.sleep(CHUNK_GAP_S)


@pytest.fixture()
def dribbling_port() -> Iterator[int]:
    yield from _serve(_dribble)


@pytest.fixture()
def holding_port() -> Iterator[int]:
    yield from _serve(_answer_then_hold)


def _send(port: int, deadline: float):
    transport = StreamableHttpTransport(HttpConfig(url=f"http://127.0.0.1:{port}/mcp", timeout=10.0, deadline=deadline))
    transport.open()
    try:
        return transport.send(JsonRpcCodec.request("tools/list", {}, req_id=1))
    finally:
        transport.close()


def test_a_server_that_never_answers_is_given_up_on(dribbling_port: int) -> None:
    start = time.monotonic()
    resp = _send(dribbling_port, deadline=1.0)
    elapsed = time.monotonic() - start
    assert elapsed < 8.0, f"the request ran for {elapsed:.1f}s against a 1.0s deadline"
    assert resp.error is not None
    assert resp.error["code"] == DEADLINE_ERROR


def test_giving_up_says_it_was_us_and_not_the_target(dribbling_port: int) -> None:
    """A bound of ours filed as the target's error is a finding we invented."""
    resp = _send(dribbling_port, deadline=1.0)
    assert resp.error is not None
    assert "scanner bound" in resp.error["message"]
    assert resp.error["code"] < -32768, "must sit outside the JSON-RPC reserved band"


def test_an_answer_is_taken_without_waiting_for_the_stream_to_end(holding_port: int) -> None:
    """Pinned in both directions: the deadline must not swallow a served answer.

    This server answers immediately and then holds the stream, which the spec
    allows. A reader that waits for the body to end reaches the deadline and
    reports a target that answered correctly as one that never answered.
    """
    start = time.monotonic()
    resp = _send(holding_port, deadline=30.0)
    elapsed = time.monotonic() - start
    assert resp.result == {"tools": []}
    assert elapsed < 5.0, f"the answer arrived at once but the read took {elapsed:.1f}s"
