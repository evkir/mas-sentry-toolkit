# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unified HTML report rendering all Finding objects across modules."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, select_autoescape

from mas_sentry.core.finding import Finding, Severity, max_severity

_SEV_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

# autoescape is mandatory: findings carry attacker-controllable strings
# (tool names, payloads, evidence). Without it the report is an XSS sink.
_ENV = Environment(autoescape=select_autoescape(default=True, default_for_string=True))

_TEMPLATE_SRC = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><title>MAS-Sentry Report - {{ target }}</title>
<style>
:root{color-scheme:dark}
body{font-family:-apple-system,system-ui,sans-serif;background:#0f172a;color:#e2e8f0;
     padding:2rem;max-width:1200px;margin:auto;line-height:1.5}
h1,h2,h3{color:#f1f5f9}
h1{border-bottom:2px solid #334155;padding-bottom:.5rem}
.meta{color:#94a3b8;font-size:.9rem}
.counts{display:flex;gap:1rem;margin:1.5rem 0}
.count{background:#1e293b;padding:.8rem 1.2rem;border-radius:6px;flex:1;text-align:center}
.count strong{font-size:1.6rem;display:block}
.f{background:#1e293b;padding:1rem 1.2rem;margin:.8rem 0;border-radius:6px;
   border-left:4px solid #64748b}
.sev-CRITICAL{border-left-color:#ef4444}
.sev-HIGH{border-left-color:#f97316}
.sev-MEDIUM{border-left-color:#eab308}
.sev-LOW{border-left-color:#3b82f6}
.sev-INFO{border-left-color:#64748b}
.tag{display:inline-block;background:#334155;color:#cbd5e1;padding:.1rem .5rem;
     border-radius:3px;font-size:.8rem;margin-right:.3rem}
.tag.asi{background:#7f1d1d;color:#fee}
.tag.cwe{background:#1e3a8a;color:#dbeafe}
.tag.stride{background:#065f46;color:#d1fae5}
code{background:#0b1220;padding:.1rem .3rem;border-radius:3px;font-size:.85rem}
.drivers{margin:.5rem 0}
.drivers ul{margin:.3rem 0 0 1.1rem;padding:0}
.drv-name{color:#a78bfa;font-weight:bold}
.drv-raw{color:#94a3b8;font-size:.85rem;margin-left:.3rem}
table{border-collapse:collapse;width:100%;margin:.5rem 0}
th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #334155}
th{color:#94a3b8;font-weight:600}
pre{background:#0b1220;padding:.8rem;border-radius:4px;overflow-x:auto;font-size:.8rem}
footer{margin-top:3rem;color:#64748b;font-size:.85rem;border-top:1px solid #334155;padding-top:1rem}
</style></head><body>
<h1>MAS-Sentry Audit Report</h1>
<p class="meta">
  <strong>Target:</strong> <code>{{ target }}</code> &middot;
  <strong>Generated:</strong> {{ generated_at }} &middot;
  <strong>Findings:</strong> {{ findings|length }} &middot;
  <strong>Max severity:</strong> <span class="tag sev-{{ max_sev }}">{{ max_sev }}</span>
</p>

<div class="counts">
  {% for sev in severities %}
  <div class="count sev-{{ sev }}" style="border-left:4px solid">
    <strong>{{ counts[sev] }}</strong>
    <span>{{ sev }}</span>
  </div>
  {% endfor %}
</div>

{% if graph and graph.agents %}
<h2>ABFP Graph Centrality</h2>
<p class="meta">
  {% if graph.summary %}
  <strong>Agents:</strong> {{ graph.summary.get('agents', '?') }} &middot;
  <strong>Topics:</strong> {{ graph.summary.get('topics', '?') }} &middot;
  <strong>Edges:</strong> {{ graph.summary.get('edges', '?') }}
  {% endif %}
</p>
<table class="centrality"><thead><tr>
  <th>Agent</th><th>Pub&deg;</th><th>Sub&deg;</th><th>Topics</th>
  <th>Betweenness</th><th>Eigenvector</th>
</tr></thead><tbody>
{% for aid, m in graph.agents.items() %}
<tr>
  <td>{{ aid }}</td>
  <td>{{ m.get('pub_degree', 0) }}</td>
  <td>{{ m.get('sub_degree', 0) }}</td>
  <td>{{ m.get('distinct_topics', 0) }}</td>
  <td>{{ '%.3f'|format(m.get('betweenness', 0)) }}</td>
  <td>{{ '%.3f'|format(m.get('eigenvector', 0)) }}</td>
</tr>
{% endfor %}
</tbody></table>
{% endif %}

{% for sev in severities %}{% if counts[sev] %}
<h2>{{ sev }} ({{ counts[sev] }})</h2>
{% for f in by_sev[sev] %}
<div class="f sev-{{ f.severity.value }}">
  <h3>{{ f.title }}</h3>
  <p>{{ f.detail }}</p>
  <p>
    <span class="tag">{{ f.module }}</span>
    {% for t in f.tags %}
      {% if t.startswith('ASI') %}<span class="tag asi">{{ t }}</span>
      {% elif t.startswith('CWE') %}<span class="tag cwe">{{ t }}</span>
      {% elif t.startswith('STRIDE') %}<span class="tag stride">{{ t }}</span>
      {% else %}<span class="tag">{{ t }}</span>{% endif %}
    {% endfor %}
  </p>
  {% if f.evidence.dimensions %}
  <div class="drivers"><strong>Drivers</strong>
  <ul>
    {% for dim in f.evidence.dimensions %}
    <li>
      <span class="drv-name">{{ dim.get('name', '?') }}</span>
      <span class="drv-raw">{{ '%.2f'|format(dim.get('raw', 0)) }}</span>
      &mdash; {{ dim.get('reason', '') }}
    </li>
    {% endfor %}
  </ul></div>
  {% endif %}
  {% if f.evidence %}<details><summary>Evidence</summary>
  <pre>{{ f.evidence | tojson(indent=2) }}</pre></details>{% endif %}
</div>
{% endfor %}
{% endif %}{% endfor %}

<footer>
  Generated by <a href="https://github.com/evkir/mas-sentry-toolkit">mas-sentry-toolkit</a> &middot;
  AGPL-3.0-or-later &middot; OWASP Agentic Top 10 (2026)
</footer>
</body></html>"""

_TEMPLATE = _ENV.from_string(_TEMPLATE_SRC)


def render_unified_html(
    findings: list[Finding], target: str, out_path: Path, graph: dict[str, Any] | None = None
) -> None:
    counts = Counter(f.severity.value for f in findings)
    by_sev: dict[Severity, list[Finding]] = {sev: [] for sev in _SEV_ORDER}
    for f in findings:
        by_sev[f.severity].append(f)
    max_sev = max_severity(findings)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        _TEMPLATE.render(
            target=target,
            findings=findings,
            counts={s.value: counts.get(s.value, 0) for s in _SEV_ORDER},
            by_sev=by_sev,
            severities=[s.value for s in _SEV_ORDER],
            max_sev=max_sev.value,
            generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
            graph=graph,
        )
    )
