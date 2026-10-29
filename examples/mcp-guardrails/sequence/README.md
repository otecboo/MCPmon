# Declarative sequence guardrails

`kind: sequence` evaluates rules in Rust against the `tools/call` chain recorded by
`mcp.history` (see `../history/README.md` for the identity and retention model).

```yaml
- kind: sequence
  methods: {"tools/call": request}
  action: reject          # or flag
  rules:
  - denyTool: shell_exec
  - denyAfter: {before: fs.read, after: http.post}
  - denyPattern: [fs.read, archive.create, http.post]
```

Rules are tried in order and the first match decides. `denyPattern` matches the **tail**
of the chain, so the call is denied at the step that completes the pattern; earlier
occurrences would already have been denied, which keeps the detection step equal to the
first step that proves the violation.

`action: flag` never blocks: it logs a warning and publishes
`mcpGuardrails.anomaly = {rule, tool, step, historyLength}` for access-log CEL:

```yaml
frontendPolicies:
  accessLog:
    add:
      anomaly.rule: 'has(mcpGuardrails.anomaly) ? string(mcpGuardrails.anomaly.rule) : ""'
```

Without a Rust change this does not exist in the Kubernetes/xDS schema: `mcpGuardrails`
is standalone-YAML only for now.
