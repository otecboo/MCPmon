# Runbook

Everything below assumes the repository root (`MCPmon`) and a Linux/WSL shell with the Rust
toolchain from `rust-toolchain.toml` and `python3`.

## 0. One-time setup

```bash
cargo build -p agentgateway-app                 # first build compiles the workspace (slow once)
python3 eval/generate_dataset.py --count 400 --seed 42 --out eval/data/synthetic.jsonl
```

The dataset is reproducible: `<dataset>.meta.json` records the seed, counts and rule list.

## 1. Rust checks (no gateway needed)

```bash
cargo fmt --check
cargo test -p agentgateway --lib mcp::                    # history + sequence + guardrails
cargo test -p agentgateway --test validate_examples        # validates every examples/**/config.yaml
cargo xtask schema && git diff --stat schema/              # only if a config field changed
```

`validate_examples` is the cheap way to catch a typo in `examples/mcp-guardrails/*/config.yaml`
before starting a gateway.

### Faster builds on WSL

If the checkout lives on `/mnt/d`, every build writes through the Windows filesystem, which is
slow (the binary is over 1 GB). Point cargo at a Linux-native target directory once:

```bash
export CARGO_TARGET_DIR="$HOME/target-mcpmon"
cargo build -p agentgateway-app
```

`run_experiment.sh` honours `CARGO_TARGET_DIR` and runs the binary from there.

## 2. Evaluation runs

One command per configuration. The script starts its own mock and gateway, waits for readiness,
asserts that the live policy is the expected one, replays the dataset and cleans up:

```bash
bash eval/run_experiment.sh enforce  eval/data/synthetic.jsonl   # target policy
bash eval/run_experiment.sh naive    eval/data/synthetic.jsonl   # early-rule ablation
bash eval/run_experiment.sh baseline eval/data/synthetic.jsonl   # no guardrails: latency reference
```

Outputs:

| file | content |
|---|---|
| `eval/results/<mode>.json` | every trajectory verdict + aggregate summary + `policy_probe` |
| `eval/results/<mode>.md` | the same as a table, ready to paste into the thesis |
| `eval/results/<mode>.gateway.log` | gateway log for that run |
| `eval/results/<mode>.mock.log` | upstream mock log |

`eval/data/` and `eval/results/` are git-ignored: they are reproducible from the seed.

### Manual mode (three terminals)

Useful when debugging, but remember: **the gateway keeps the policy it was started with**.

```bash
# terminal 1
python3 eval/mcp_mock.py --port 9099

# terminal 2 — one config at a time
cargo run -p agentgateway-app -- -f examples/mcp-guardrails/enforce/config.yaml

# terminal 3
python3 eval/replay.py --dataset eval/data/synthetic.jsonl --expect deny --out eval/results/enforce.json
```

`--expect deny` (evaluation configs) or `--expect allow` (baseline) makes the replayer probe
`shell.exec` first and abort with a clear message if the running gateway does not match. Without
the restart this is exactly the mistake that silently produces a "baseline" identical to the
enforcement run.

## 3. What the runs should show

| mode | TPR | FPR | mean IG | notes |
|---|---|---|---|---|
| `enforce` | 1.00 | 0.00 | ~1.17 | conformance: rules match the dataset generator |
| `naive` | 1.00 | ~0.25 | ~0.83 | earlier detection, but blocks the legitimate read→archive prefix |
| `baseline` | — | — | — | nothing fires; only latency is meaningful |

Latency: compare p50/p95 of `enforce` against `baseline` (same dataset, same mock). The delta is
the detector cost; if it is inside the noise, report it as such rather than inventing
milliseconds.

### If the gateway does not become ready

`run_experiment.sh` builds first and only then starts a timer, so a slow link step is no
longer mistaken for a failed start. If it still fails, the script prints the tail of the
gateway log; typical causes are a config error (the process exits immediately) or a port
already taken. For a hands-on look, use the three-terminal mode above and start the binary
directly, bypassing cargo:

```bash
cargo build -p agentgateway-app          # once; prints progress
target/debug/agentgateway -f examples/mcp-guardrails/enforce/config.yaml
```

## 4. Audit (`flag`) run

Requires JSON logs — already set in `examples/mcp-guardrails/eval/config.yaml`.

```bash
python3 eval/mcp_mock.py --port 9099 &
cargo run -p agentgateway-app -- -f examples/mcp-guardrails/eval/config.yaml > eval/results/audit.log 2>&1 &
python3 eval/replay.py --mode flag --log-file eval/results/audit.log \
  --dataset eval/data/synthetic.jsonl --out eval/results/audit.json
```

Use it to verify that the same rules fire without blocking and that `mcpGuardrails.anomaly`
reaches the log. The replayer warns if it parsed the log but saw no flag line.

## 5. Troubleshooting

| symptom | cause / fix |
|---|---|
| `406 client must accept both application/json and text/event-stream` | the client must send `accept: application/json, text/event-stream`; `replay.py` does |
| `port 3000 is already in use` | an old gateway is running: `pkill -f agentgateway` |
| `gateway denies shell.exec, but --expect allow was given` | wrong config is running: restart with `baseline/config.yaml` |
| results of two modes are byte-identical | the gateway was not restarted (the probe now prevents this) |
| flag mode found nothing | the gateway is logging text, not JSON: add `logging: {format: json}` |
| `EIR@k` shows `—` | nothing was detected; check the `policy probe:` line printed at startup |

## 6. Where things live

| path | role |
|---|---|
| `crates/agentgateway/src/mcp/history.rs` | call history + identity |
| `crates/agentgateway/src/mcp/guardrails/sequence.rs` | rule engine |
| `examples/mcp-guardrails/{enforce,naive,baseline,eval}/config.yaml` | gateway configs |
| `eval/generate_dataset.py` | dataset generator |
| `eval/mcp_mock.py` | upstream MCP server |
| `eval/replay.py` | MCP client, decisions, metrics |
| `eval/RESULTS.md` | log of the runs |
