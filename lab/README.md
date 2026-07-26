# MAS-Sentry Lab

Vulnerable targets for exercising every module in `mas-sentry-toolkit`.

> **Localhost only — do not expose any of these to a real network.**
> Targets matching `localhost / .lab / .test / .local` bypass `--confirm-scope`.

## Services

| Service | Type | Endpoint | Vulnerabilities exercised |
|---|---|---|---|
| `mosquitto` | docker-compose, top-level | `localhost:1883` | Anonymous access, retained-message poisoning |
| `victim/agents/{sensor,logger,controller}` | docker-compose, top-level | MQTT clients | Plaintext command topic, no auth |
| `vuln-mcp` | local python (or `docker build` lab/vuln-mcp) | `stdio://python3 ./lab/vuln-mcp/server.py` | STDIO RCE (`exec_cmd`), SSRF (`fetch_url`), path traversal (`read_file`), tool-poisoning (prompt-injection markers in tool description) |

`vuln-mcp` is intentionally NOT wired into `docker-compose.yml`: MCP STDIO needs a live client session, so a backgrounded container is meaningless. Launch it on demand from your scanner.

## Quick start

Start the MQTT lab (mosquitto + 3 agents):

```bash
docker compose up -d
```

Run the canned MCP scenario end-to-end (all 4 checks):

```bash
pip install -e ".[lab]"        # pulls in pyyaml for the runner
python lab/scenarios/run.py lab/scenarios/mcp-stdio-rce.yaml
```

Or scan manually:

```bash
# MCP — stdio:// requires a command, not a path
mas-sentry mcp scan -t 'stdio://python3 ./lab/vuln-mcp/server.py' --checks all --out reports/mcp_all.json

# MQTT broker
mas-sentry mqtt scan --target localhost:1883

# Behavioural fingerprinting on live MQTT traffic
mas-sentry abfp scan --target mqtt://localhost:1883 --duration 30
```

## Expected findings — `mcp-stdio-rce.yaml`

The scenario asserts these via per-step `expect_check` + `expect_severity` (see `lab/scenarios/run.py`):

| Step | `--checks` flag | Finding `check` | Min severity | Why it fires |
|---|---|---|---|---|
| 1 | `fingerprint` | `fingerprint` | `INFO` | Server identifies as `vuln-mcp-lab 0.1.0 (3 tools)` |
| 2 | `poisoning` | `tool_poisoning` | `MEDIUM` (observed: CRITICAL) | `exec_cmd` description contains EchoLeak/Windsurf/Cursor prompt-injection markers (`Ignore previous instructions`, `New task:`, `System: you must`, tool-call hijack pattern) |
| 3 | `ssrf` | `ssrf` | `CRITICAL` | `fetch_url` happily fetches `file:///etc/passwd` |
| 4 | `traversal` | `path_traversal` | `HIGH` | `read_file` accepts `../../../../etc/passwd` |

> Note: the CLI flag name (`poisoning`, `traversal`) does NOT always match the `check` field in JSON output (`tool_poisoning`, `path_traversal`). Match by JSON `check` when writing assertions.

## File layout

```
lab/
├── README.md                       # this file
├── docker-compose.yml              # (lives at repo root, not here)
├── victim/                         # MQTT victim agents (Day 14)
│   ├── mosquitto.conf
│   └── agents/{sensor,logger,controller}/
├── a2a/                            # intentional-vuln A2A agent (Day 76)
│   ├── agent.py                    # built on the reference a2a-sdk
│   └── Dockerfile
├── vuln-mcp/                       # intentional-vuln MCP server (Day 28)
│   ├── server.py
│   └── Dockerfile                  # optional, for `docker run -i`
└── scenarios/
    ├── insecure_command_topic.py   # MQTT scenario (Day 17)
    ├── mcp-stdio-rce.yaml          # MCP scenario (Day 28)
    └── run.py                      # YAML scenario runner with expect-validation
```

## A2A lab agent

`lab/a2a/agent.py` runs a deliberately weak A2A agent on the reference
`a2a-sdk`. Using the reference implementation is the point: a hand-written
victim would only echo back the scanner's own assumptions about the wire,
so it could never catch a divergence between what MAS-Sentry emits and
what a real A2A server accepts.

```bash
pip install -e '.[lab]'
python -m lab.a2a.agent                     # 127.0.0.1:9700, strict v1.0
A2A_LAB_COMPAT=1 python -m lab.a2a.agent    # also accept legacy v0.3.x
mas-sentry a2a scan --target http://127.0.0.1:9700
```

The published card is built to trigger the passive audit: no security
requirement, wildcard and admin-family OAuth2 scopes, no signature,
cleartext transport, and skill descriptions carrying an injection
directive and a selection-steering directive.
