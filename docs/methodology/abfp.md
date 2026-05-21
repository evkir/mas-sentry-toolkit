# ABFP — Phase 3: Topic Graph

The topic graph captures **structural** behavior: which agents publish to which topics, and which topics route to which subscribers. Two snapshots taken at different times reveal **behavioral drift**.

## Nodes

- `kind=agent` — derived via `infer_agent_id(client_id, topic)`.
- `kind=topic` — exact topic strings observed in PUBLISH packets.

## Edges

- `agent → topic`, `kind=publish`, `weight=count`
- `topic → agent`, `kind=subscribe`, `weight=count`

## Metrics

Per-agent: `pub_degree`, `sub_degree`, `betweenness`, `eigenvector_centrality`, `distinct_topics`.

## Drift signals

Returned by `diff_graphs(baseline, current)`:

- `new_agents` — never seen in baseline (potential rogue agent → ASI10).
- `new_topics_per_agent` — agent now publishes to a topic outside its profile (potential privilege escalation → ASI03).
- `removed_topics_per_agent` — silenced agent (potential DoS or compromise → ASI05).

## Why a directed multi-mode graph

Pub/sub is fundamentally directional; collapsing it to an undirected graph loses the "who publishes vs who consumes" asymmetry that drives all privilege analysis.
