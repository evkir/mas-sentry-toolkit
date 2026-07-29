# MQTT Scanning

`mas-sentry mqtt scan` audits an MQTT broker that agents use as their message
bus. It reads only: it subscribes, it tries credential pairs, and it never
publishes.

```bash
mas-sentry mqtt scan --target mqtt://localhost:1883 --duration 20
```

## Options

| Flag | Default | Meaning |
|---|---|---|
| `--target` / `-t` | required | `mqtt://host[:port]`, `host[:port]`, or a bare host (port 1883) |
| `--checks` | `all` | Comma-separated subset of `auth`, `fingerprint`, `topics`, `retained` |
| `--duration` / `-d` | `20` | Seconds spent collecting topics and retained messages |
| `--out` / `-o` | `reports/mqtt.json` | Where the unified findings are written |
| `--confirm-scope` | off | Required for anything outside `localhost` / `.lab` / `.test` / `.local` |

## What it checks

**`auth`** - connects with no credentials, then with `guest:guest` and
`admin:admin`.

**`fingerprint`** - reads the `$SYS` tree to identify the broker product and
version.

**`topics`** - subscribes with wildcards and records what is delivered.

**`retained`** - reads the retained payload on every topic and scans the content
for injection directives and auto-fetch beacons. The topic walk and the retained
read share one subscription, so `topics,retained` costs one connection, not two.

## Findings it produces

| Module | Severity | Fires when |
|---|---|---|
| `mqtt.anonymous_access` | CRITICAL | A CONNECT with no credentials was accepted |
| `mqtt.default_credentials` | HIGH | Authentication is enforced but a well-known pair works |
| `mqtt.topic_exposure` | HIGH | Live traffic was delivered to an unauthenticated subscriber |
| `mqtt.retained_injection` | HIGH / MEDIUM | A retained payload carries injection directives |
| `mqtt.retained_exfil` | HIGH | A retained payload embeds an auto-fetch beacon |
| `mqtt.sys_exposure` | MEDIUM | The `$SYS` tree was readable without credentials |
| `mqtt.fingerprint`, `mqtt.topic_inventory`, `mqtt.retained_state`, `mqtt.auth` | INFO | Inventory and posture |
| `mqtt.enumeration_gap` | INFO / MEDIUM | A probe did not run - see below |

## Two results that look alike and are not

**An empty topic inventory is not a quiet broker.** A broker enforcing
authentication refuses the subscription, and a broker with a topic ACL grants
the subscription and then withholds the messages - Mosquitto answers a `#`
SUBSCRIBE with `Granted QoS 0` and delivers nothing. All three cases used to end
as an empty list. Now a refused connection produces an `mqtt.enumeration_gap`
finding instead, and `mqtt.topic_exposure` is raised only on traffic that
actually arrived, never on a subscription merely being accepted.

**Default credentials on an open broker mean nothing.** A broker allowing
anonymous access accepts every username and password it is handed, so
`guest:guest` and `admin:admin` both "work" against it. That is one weakness -
`mqtt.anonymous_access` - not three. The credential result is recorded as INFO
explaining why it could not be assessed separately.

## Reading the gaps

`mqtt.enumeration_gap` marks a surface that was **not** examined:

- **INFO** - the broker answered and refused us. Authentication is enforced,
  which is the desired posture, but whatever sits behind it went unaudited.
- **MEDIUM** - the broker was unreachable. Nothing was assessed at all.

A scan of a hardened broker is mostly gaps, and that is the correct output. It
must not be read as a clean bill of health.

## Against the lab

```bash
docker compose up -d
mas-sentry mqtt scan --target mqtt://localhost:1883 --duration 10
mas-sentry report convert reports/mqtt.json --format html --out reports/mqtt.html
```

## Scope

Non-lab targets require `--confirm-scope` or `MAS_SENTRY_SCOPE_CONFIRMED=1`, and
every run appends to `~/.mas-sentry/audit.jsonl`.
