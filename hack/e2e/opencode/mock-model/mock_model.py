#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Deterministic OpenAI-compatible model for the opencode browser E2E test.

The test intentionally exercises a real ACP agent and a real blipchat MCP
call. It does not need a real model: this server answers the prompts the
browser harness sends, emits the two spawn_agent tool calls, and echoes the
nonces it is given. It is served over TLS because the Blip endpoint requires
an HTTPS origin.

The script runs inside the kind cluster on the dev image. Keep it dependency
free (standard library only).
"""

from __future__ import annotations

import json
import os
import re
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8443
TLS_CERT_PATH = "/tls/tls.crt"
TLS_KEY_PATH = "/tls/tls.key"

TITLE = "E2E OpenCode"
CHILD_NONCE_RE = re.compile(r"E2E_SUBAGENT_[A-Z0-9]+")
WARMUP_RE = re.compile(r"E2E_WARMUP_[A-Z0-9]+")
FINAL_RE = re.compile(r"E2E_OPENCODE_[A-Z0-9]+")

COUNTER = 0
COUNTER_LOCK = threading.Lock()


def next_id(prefix: str) -> str:
    global COUNTER
    with COUNTER_LOCK:
        COUNTER += 1
        return f"{prefix}_{COUNTER}"


def text_content(message: dict) -> str:
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict) and isinstance(part.get("text"), str):
                parts.append(part["text"])
        return "\n".join(parts)
    return ""


def sse_chunk(model: str, delta: dict, finish_reason: str | None) -> bytes:
    body = {
        "id": "chatcmpl-e2e",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": model,
        "choices": [
            {
                "index": 0,
                "delta": delta,
                "finish_reason": finish_reason,
            }
        ],
    }
    return ("data: " + json.dumps(body, separators=(",", ":")) + "\n\n").encode()


def sse_text(model: str, text: str) -> bytes:
    return (
        sse_chunk(model, {"role": "assistant", "content": text}, None)
        + sse_chunk(model, {}, "stop")
        + b"data: [DONE]\n\n"
    )


def tool_call(model: str, calls: list[dict]) -> bytes:
    deltas = []
    for index, call in enumerate(calls):
        deltas.append(
            {
                "index": index,
                "id": next_id("call_spawn"),
                "type": "function",
                "function": {
                    "name": "blipchat_spawn_agent",
                    "arguments": json.dumps(call, separators=(",", ":")),
                },
            }
        )
    return (
        sse_chunk(model, {"role": "assistant", "tool_calls": deltas}, None)
        + sse_chunk(model, {}, "tool_calls")
        + b"data: [DONE]\n\n"
    )


def response_for(payload: dict) -> bytes:
    """Return the SSE body for a chat completion request."""
    model = str(payload.get("model") or "e2e")
    messages = payload.get("messages")
    if not isinstance(messages, list):
        messages = []

    # OpenCode asks for a short title with tools disabled. Give it a stable
    # title so the browser can wait for the header to settle.
    if not payload.get("tools"):
        return sse_text(model, TITLE)

    last_user = -1
    for index, message in enumerate(messages):
        if isinstance(message, dict) and message.get("role") == "user":
            last_user = index
    prompt = text_content(messages[last_user]) if last_user >= 0 else ""

    warmup = WARMUP_RE.search(prompt)
    if warmup:
        return sse_text(model, warmup.group(0))

    child = CHILD_NONCE_RE.search(prompt)
    if child and not FINAL_RE.search(prompt):
        return sse_text(model, child.group(0))

    final = FINAL_RE.search(prompt)
    if final:
        tool_results = sum(
            1
            for message in messages[last_user + 1 :]
            if isinstance(message, dict) and message.get("role") == "tool"
        )
        if tool_results:
            return sse_text(model, final.group(0))

        child_nonces = CHILD_NONCE_RE.findall(prompt)
        if len(child_nonces) >= 2:
            calls = [
                {
                    "profile": "opencode",
                    "title": "E2E child A",
                    "prompt": f"Reply with exactly: {child_nonces[0]}. Do not use any tools.",
                },
                {
                    "profile": "opencode",
                    "title": "E2E child B",
                    "prompt": f"Reply with exactly: {child_nonces[1]}. Do not use any tools.",
                },
            ]
            return tool_call(model, calls)

        # A plain turn (for example the first or second prompt) also uses the
        # E2E_OPENCODE_ prefix. Echo it instead of returning the fallback.
        return sse_text(model, final.group(0))

    return sse_text(model, "OK")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "e2e-mock-model"
    sys_version = ""

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.log_date_time_string(), fmt % args))
        sys.stderr.flush()

    def do_GET(self):
        if self.path == "/healthz":
            self._plain(200, b"ok\n")
        else:
            self._plain(404, b"not found\n")

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._plain(400, b"bad content length\n")
            return
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw or b"{}")
        except ValueError:
            self._plain(400, b"bad json\n")
            return

        body = response_for(payload)
        self.send_response_only(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        self.close_connection = True

    def _plain(self, status: int, body: bytes):
        self.send_response_only(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(TLS_CERT_PATH, TLS_KEY_PATH)
    server = Server((LISTEN_HOST, LISTEN_PORT), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    sys.stderr.write(f"e2e mock model listening on https://{LISTEN_HOST}:{LISTEN_PORT}\n")
    sys.stderr.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
