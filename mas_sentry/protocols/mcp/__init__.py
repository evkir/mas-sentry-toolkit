# SPDX-License-Identifier: AGPL-3.0-or-later
"""Model Context Protocol — independent implementation for offensive testing.

Critical: this is intentionally NOT built on the official `mcp` SDK. A pentest
tool must be able to send malformed traffic; the official SDK validates and
refuses. Schemas may be referenced for design, never imported at runtime.
"""

from .jsonrpc import JsonRpcCodec, JsonRpcError, JsonRpcRequest, JsonRpcResponse

__all__ = ["JsonRpcCodec", "JsonRpcError", "JsonRpcRequest", "JsonRpcResponse"]
