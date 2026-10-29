# Sequence guardrails over `mcp.history`

`mcp.history` is a bounded, per-principal record of the `tools/call` requests that were
already authorized for the current MCP backend. Guardrail expressions can read it during
the request phase, which makes order-dependent policies expressible:

```yaml
condition: mcp.params.name == 'echo' && mcp.history.exists(h, h.tool == 'increment')
```

## Shape

`mcp.history` is a list, oldest first. Each element is an object:

| field | type | meaning |
|---|---|---|
| `target` | string | MCP target that served the call |
| `tool` | string | tool name in the target's own namespace (never mux-prefixed) |
| `timestamp` | int | milliseconds since the Unix epoch |

The call currently being evaluated is **not** in the list; it is `mcp.params`. A call is
appended only after it passes authorization, so a rejected attempt cannot become part of
the chain.

## Identity and bounds

A history bucket is keyed by backend + principal, where the principal is, in order of
preference: `jwt.iss` + `jwt.sub`, a truncated SHA-256 of an API key, the legacy
`mcp-session-id`, or `anonymous`. MCP `2026-07-28`+ has no protocol sessions, so a client
that wants a stable chain across stateless requests should either authenticate or set
`_meta: {"agentsecuregateway.dev/conversationId": "..."}`.

Defaults: 64 calls per bucket, 4096 buckets, 15-minute idle TTL. Raise them in code
(`McpHistoryStore::with_limits`) rather than in config: M1 records history for every
`tools/call` on the backend and has no per-policy enable flag yet.

## Try it

```bash
cargo run -p agentgateway-app -- -f examples/mcp-guardrails/history/config.yaml
```

Then call `increment` and afterwards `echo` from any MCP client: the second call is
rejected with `increment then echo is not allowed in one session`.
