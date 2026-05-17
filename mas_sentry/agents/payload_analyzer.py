# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Payload analysis utilities for ABFP.
Entropy calculation, encoding detection, sensitive data patterns.
"""

import base64
import json
import math
import re

SENSITIVE_PATTERNS = [
    (r"password", "password field detected"),
    (r"passwd", "password field detected"),
    (r"secret", "secret field detected"),
    (r"token", "auth token detected"),
    (r"api_key", "API key detected"),
    (r"private", "private key reference"),
    (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "IP address in payload"),
]


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of bytes (0=uniform, 8=random)"""
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def detect_encoding(data: bytes) -> str:
    """Detect payload encoding: json / base64 / plaintext / binary"""
    try:
        text = data.decode("utf-8")
        try:
            json.loads(text)
            return "json"
        except Exception:
            pass
        try:
            decoded = base64.b64decode(text, validate=True)
            if len(decoded) > 4:
                return "base64"
        except Exception:
            pass
        if text.isprintable():
            return "plaintext"
    except UnicodeDecodeError:
        pass
    return "binary"


def scan_sensitive(data: bytes) -> list:
    """Scan payload for sensitive data patterns"""
    findings = []
    try:
        text = data.decode("utf-8", errors="ignore").lower()
        for pattern, label in SENSITIVE_PATTERNS:
            if re.search(pattern, text):
                findings.append(label)
    except Exception:
        pass
    return findings
