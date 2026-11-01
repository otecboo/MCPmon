#!/usr/bin/env python3
"""Minimal MCP server used as the *upstream* for the sequence-guardrail evaluation.

The replay harness must exercise the real Rust detector, so the mock only has to be a
well-behaved MCP endpoint: it answers `initialize`, `tools/list` and `tools/call`, and it
never decides anything about policy. Decisions come from the gateway.

Protocol notes (matching what the gateway's upstream client expects):

* `initialize` echoes the client's `protocolVersion` and advertises the `tools` capability.
* `server/discover` answers with a JSON-RPC error, which is exactly how a legacy server
  signals "no modern protocol": the gateway falls back to `initialize`.
* `tools/list` and `tools/call` include `resultType: "complete"`, the modern field the
  gateway strips again for legacy downstream clients.
* No `Mcp-Session-Id` is issued: the upstream is sessionless, and the gateway supports
  that (each call carries a self-contained request).
* Notifications (`notifications/initialized`, ...) get `202 Accepted` with no body.

Standard library only; no dependencies.

Usage:
    python eval/mcp_mock.py --port 9099 --delay-ms 0
"""

import argparse
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Tools referenced by the generated dataset. Descriptions and schemas are irrelevant to
# the detector, but a real client may list them, so keep them plausible.
TOOL_CATALOG = {
    "fs.read": "Read a file from the workspace",
    "fs.list": "List a directory",
    "cache.get": "Read a key from the session cache",
    "cache.set": "Write a key to the session cache",
    "log.write": "Append a line to the audit log",
    "time.now": "Return the current timestamp",
    "http.get": "Fetch a URL",
    "http.post": "Upload a payload to a URL",
    "archive.create": "Create a tar archive",
    "shell.exec": "Run a shell command",
}


def tool_schema() -> dict:
    return {"type": "object", "additionalProperties": True}


class MockHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mcp-eval-mock/0.1"
    # `http.server` writes status/headers and the body separately; with Nagle enabled the second
    # small write waits for a delayed ACK (~40ms on loopback), which would pollute latency
    # measurements. This flag makes socketserver set TCP_NODELAY on accepted sockets.
    disable_nagle_algorithm = True

    # -- plumbing ---------------------------------------------------------------
    def log_message(self, fmt, *args):  # keep stdout for structured lines only
        if not self.server.quiet:
            sys.stderr.write("[mock] %s\n" % (fmt % args))

    def handle_one_request(self):
        # Clients (and health checks) close keep-alive connections at will; that is not an
        # error worth a traceback in the middle of an experiment log.
        try:
            super().handle_one_request()
        except (ConnectionResetError, BrokenPipeError):
            self.close_connection = True

    def _send(self, status: int, payload=None) -> None:
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        self.send_response(status)
        if payload is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _event(self, **fields) -> None:
        if self.server.quiet:
            return
        record = {"ts": round(time.time(), 6), "event": "upstream", **fields}
        sys.stdout.write(json.dumps(record, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    # -- HTTP verbs -------------------------------------------------------------
    def do_GET(self):
        if self.path.rstrip("/") == "/health":
            return self._send(200, {"status": "ok"})
        # Streamable HTTP servers may reject GET when they do not offer a stream.
        return self._send(405, {"error": "method not allowed"})

    def do_DELETE(self):
        return self._send(200, {})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            message = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._send(400, {"error": "invalid JSON"})
        if not isinstance(message, dict):
            return self._send(400, {"error": "expected a single JSON-RPC message"})

        request_id = message.get("id")
        method = message.get("method") or ""
        params = message.get("params") or {}

        if method.startswith("notifications/"):
            self._event(method=method, notification=True)
            return self._send(202, None)

        if method == "server/discover":
            # Legacy server: the gateway retries with `initialize`.
            self._event(method=method, error="unsupported")
            return self._send(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": "Method not found: server/discover"},
                },
            )

        if method == "initialize":
            result = {
                "protocolVersion": params.get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mcp-eval-mock", "version": "0.1.0"},
            }
            self._event(method=method)
            return self._send(200, {"jsonrpc": "2.0", "id": request_id, "result": result})

        if method == "tools/list":
            tools = [
                {"name": name, "description": description, "inputSchema": tool_schema()}
                for name, description in sorted(self.server.tools.items())
            ]
            self._event(method=method, tools=len(tools))
            return self._send(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"resultType": "complete", "tools": tools},
                },
            )

        if method == "tools/call":
            tool = params.get("name", "")
            if self.server.delay_ms:
                time.sleep(self.server.delay_ms / 1000.0)
            self._event(method=method, tool=tool)
            return self._send(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "resultType": "complete",
                        "content": [{"type": "text", "text": f"ok:{tool}"}],
                        "isError": False,
                    },
                },
            )

        if method == "ping":
            self._event(method=method)
            return self._send(200, {"jsonrpc": "2.0", "id": request_id, "result": {}})

        if method in ("resources/list", "prompts/list", "resources/templates/list"):
            key = {"resources/list": "resources", "prompts/list": "prompts"}.get(
                method, "resourceTemplates"
            )
            self._event(method=method, empty=True)
            return self._send(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"resultType": "complete", key: []},
                },
            )

        self._event(method=method, error="method_not_found")
        return self._send(
            200,
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            },
        )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=9099, help="listen port (default: 9099)")
    parser.add_argument("--host", default="127.0.0.1", help="listen address (default: 127.0.0.1)")
    parser.add_argument(
        "--delay-ms",
        type=int,
        default=0,
        help="artificial latency added to tools/call, for throughput experiments",
    )
    parser.add_argument("--quiet", action="store_true", help="suppress structured request logs")
    args = parser.parse_args(argv)

    server = ThreadingHTTPServer((args.host, args.port), MockHandler)
    server.tools = dict(TOOL_CATALOG)
    server.delay_ms = args.delay_ms
    server.quiet = args.quiet
    print(
        f"mcp mock listening on http://{args.host}:{args.port}/mcp "
        f"({len(server.tools)} tools, delay={args.delay_ms}ms)",
        file=sys.stderr,
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
