# SPDX-License-Identifier: AGPL-3.0-or-later
import os

from mas_sentry.agents.abfp import MessageEvent
from mas_sentry.agents.abfp.encoding import detect_encoding
from mas_sentry.agents.abfp.payload import PayloadSignature, shannon_entropy
from mas_sentry.agents.abfp.schema_infer import infer_schema


def test_entropy_uniform_high_random_low_zeros():
    assert shannon_entropy(b"\x00" * 1024) == 0.0
    assert shannon_entropy(os.urandom(2048)) > 7.5


def test_payload_signature_bucketing():
    payloads = [b"a" * 32, b"a" * 200, b"a" * 800, b"a" * 3000, b"a" * 8000]
    events = [MessageEvent.now("a", "t", p) for p in payloads]
    sig = PayloadSignature.from_events_and_payloads(events, payloads)
    assert sig is not None
    assert sig.size_histogram == {"0-64": 1, "65-256": 1, "257-1024": 1, "1025-4096": 1, "4097+": 1}


def test_schema_inference_basic():
    payloads = [b'{"id": 1, "temp": 22.5, "ok": true}', b'{"id": 2, "temp": 21.0, "ok": false}']
    schema = infer_schema(payloads)
    assert schema["samples"] == 2
    assert "id" in schema["keys"] and "int" in schema["keys"]["id"]
    assert "temp" in schema["keys"]


def test_encoding_detect_json_binary_base64():
    assert detect_encoding(b'{"x":1}') == "json"
    assert detect_encoding(b"YWJjZGVmZ2g=") == "base64"
    assert detect_encoding(b"plain text") == "utf8"
    assert detect_encoding(b"\xff\xfe\xfd\xfc") in {"binary", "msgpack", "cbor", "protobuf"}
