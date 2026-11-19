#!/usr/bin/env python3
"""Deterministic OpenAI-compatible LLM for the blipchat end-to-end test.

The server distinguishes the engineer-facing chat prompt from the coordinator
prompt and plays a tiny scripted conversation. It uses only the Python
standard library, keeps no conversation state (every decision comes from the
messages the caller sends), and emits one tool call per response so the
coordinator exercises its tool loop.
"""

import json
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# The agent command is appended to `sh -c`. The guest supplies BLIP_REPORT_URL;
# the first sleep keeps the open task observable, and the second gives the
# report turn time to be sequenced before the blip finishes.
AGENT_PROMPT = (
    "echo agent-ran; sleep 2; "
    "curl -fsS -X POST --data-binary "
    "'{\"summary\":\"agent done\",\"outcome\":\"success\"}' "
    "\"$BLIP_REPORT_URL\"; sleep 2"
)

TASK_LINE = re.compile(r"^- t1 (open|closed)\b", re.MULTILINE)

_lock = threading.Lock()
_requests = 0
_recent = []


def _assistant(content="", tool_calls=None):
    message = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return message


def _tool_call(call_id, name, arguments):
    return {
        "id": call_id,
        "type": "function",
        "function": {
            "name": name,
            "arguments": json.dumps(arguments, sort_keys=True, separators=(",", ":")),
        },
    }


def _contents(messages):
    return [m.get("content") or "" for m in messages if isinstance(m, dict)]


def _has_tool(messages, name):
    for message in messages:
        for call in message.get("tool_calls") or []:
            if call.get("function", {}).get("name") == name:
                return True
    return False


def _tool_names(message):
    return [call.get("function", {}).get("name", "") for call in message.get("tool_calls") or []]


def _chat(messages):
    """One send proposal, then a final answer after the tool result."""
    if any(message.get("role") == "tool" for message in messages):
        return _assistant("I sent that to the coordinator.")
    return _assistant(
        tool_calls=[
            _tool_call(
                "chat-send",
                "send",
                {"topic": "chat.propose", "text": "please run the e2e agent"},
            )
        ]
    )


def _board_state(messages):
    for content in _contents(messages):
        match = TASK_LINE.search(content)
        if match:
            return match.group(1)
    return None


def _saw_report(messages):
    return any("blip.report" in c or "blip.finished" in c for c in _contents(messages))


def _coordinator(messages):
    """Create and start t1, then close it after the report arrives."""
    state = _board_state(messages)
    if state == "open" and _saw_report(messages):
        if not _has_tool(messages, "task_update"):
            return _assistant(
                tool_calls=[
                    _tool_call(
                        "coord-close",
                        "task_update",
                        {"id": "t1", "open": False, "note": "agent completed"},
                    )
                ]
            )
        if not _has_tool(messages, "reply"):
            return _assistant(
                tool_calls=[_tool_call("coord-reply", "reply", {"text": "agent completed"})]
            )
        if not _has_tool(messages, "idle"):
            return _assistant(tool_calls=[_tool_call("coord-idle-done", "idle", {})])
        return _assistant("agent completed")
    if state is not None:
        # t1 already exists (a heartbeat or retry); do not start more work.
        if not _has_tool(messages, "idle"):
            return _assistant(tool_calls=[_tool_call("coord-idle-existing", "idle", {})])
        return _assistant("idle")
    if not _has_tool(messages, "task_create"):
        return _assistant(
            tool_calls=[
                _tool_call(
                    "coord-create",
                    "task_create",
                    {
                        "id": "t1",
                        "title": "run the e2e agent",
                        "note": "requested by the engineer",
                    },
                )
            ]
        )
    if not _has_tool(messages, "start_task"):
        return _assistant(
            tool_calls=[
                _tool_call(
                    "coord-start",
                    "start_task",
                    {"task": "t1", "prompt": AGENT_PROMPT},
                )
            ]
        )
    if not _has_tool(messages, "idle"):
        return _assistant(tool_calls=[_tool_call("coord-idle", "idle", {})])
    return _assistant("idle")


def _respond(messages):
    system = "\n".join(
        m.get("content") or "" for m in messages if m.get("role") == "system"
    )
    if "engineer-facing assistant" in system:
        return _chat(messages), "chat"
    if "You are the coordinator" in system:
        return _coordinator(messages), "coordinator"
    return _assistant("fake-llm: unrecognized system prompt"), "unknown"


class Handler(BaseHTTPRequestHandler):
    server_version = "fake-llm/1.0"

    def log_message(self, _format, *_args):
        # Requests are logged explicitly in do_GET/do_POST.
        pass

    def _write(self, status, payload, content_type):
        body = payload if isinstance(payload, bytes) else payload.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status, value):
        self._write(status, json.dumps(value, sort_keys=True), "application/json")

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        print("fake-llm: GET %s" % path, flush=True)
        if path == "/healthz":
            self._write(200, "ok\n", "text/plain; charset=utf-8")
            return
        if path == "/requests":
            with _lock:
                self._json(200, {"requests": _requests, "recent": list(_recent)})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if path != "/v1/chat/completions":
            print("fake-llm: POST %s (not found)" % path, flush=True)
            self._json(404, {"error": "not found"})
            return
        try:
            request = json.loads(raw.decode("utf-8"))
            messages = request["messages"]
            if not isinstance(messages, list):
                raise ValueError("messages must be a list")
        except (ValueError, KeyError, UnicodeDecodeError) as err:
            print("fake-llm: POST %s bad request: %s" % (path, err), flush=True)
            self._json(400, {"error": "bad request: %s" % err})
            return

        message, kind = _respond(messages)
        tools = _tool_names(message)
        with _lock:
            global _requests
            _requests += 1
            number = _requests
            _recent.append({"n": number, "kind": kind, "tools": tools})
            del _recent[:-20]
        print(
            "fake-llm: POST %s kind=%s messages=%d tools=%s"
            % (path, kind, len(messages), ",".join(tools) or "-"),
            flush=True,
        )

        self._json(
            200,
            {
                "id": "fake-%d" % number,
                "object": "chat.completion",
                "choices": [
                    {
                        "index": 0,
                        "message": message,
                        "finish_reason": "tool_calls" if tools else "stop",
                    }
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            },
        )


def main():
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print("fake-llm: listening on :%d" % port, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("fake-llm: shutting down", flush=True)
        server.server_close()
        return 0


if __name__ == "__main__":
    sys.exit(main())
