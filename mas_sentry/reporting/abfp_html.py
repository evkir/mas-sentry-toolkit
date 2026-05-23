# SPDX-License-Identifier: AGPL-3.0-or-later
"""Standalone HTML report for ABFP findings."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Template

_TEMPLATE = Template("""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><title>ABFP Report — {{ target }}</title>
<style>
body{font-family:system-ui;background:#0f172a;color:#e2e8f0;padding:2rem;}
.f{background:#1e293b;border-left:4px solid #ef4444;padding:1rem;margin:1rem 0;border-radius:4px;}
.s-CRITICAL{border-left-color:#ef4444}.s-HIGH{border-left-color:#f97316}
.s-MEDIUM{border-left-color:#eab308}.s-LOW{border-left-color:#3b82f6}.s-INFO{border-left-color:#64748b}
code{background:#0b1220;padding:.1rem .3rem;border-radius:3px;}
</style></head><body>
<h1>🛡️ ABFP Report</h1><p><b>Target:</b> <code>{{ target }}</code></p>
<h2>Findings ({{ findings|length }})</h2>
{% for f in findings %}
<div class="f s-{{ f.score.severity.value }}">
  <h3>{{ f.agent_id }} — score {{ f.score.total }}/100 [{{ f.score.severity.value }}]</h3>
  <p>Rogue: {{ f.is_rogue }}</p>
  <p>New topics: {{ f.diff_summary.new_topics }}</p>
</div>
{% endfor %}
</body></html>""")


def render_abfp_html(findings, target: str, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(_TEMPLATE.render(findings=findings, target=target))
