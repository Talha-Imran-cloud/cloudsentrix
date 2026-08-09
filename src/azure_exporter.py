"""
azure_exporter.py
-----------------
Exports Azure scan results to JSON, CSV, SARIF, and interactive HTML dashboard.

Public API
  export_azure(findings, score_result, blast_results, iam, output_path)
"""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path

from azure_blast_radius import AzureBlastResult
from azure_detection import AzureFinding
from azure_parser import AzureIAMData
from azure_risk_score import AzureScoreResult


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def _to_json(
    findings: list[AzureFinding],
    score: AzureScoreResult,
    blast: list[AzureBlastResult],
    output_path: str,
) -> None:
    data = {
        "score": {
            "value": score.score,
            "grade": score.grade,
            "summary": score.summary,
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "principal": f.principal_name,
                "principal_type": f.principal_type,
                "role": f.role,
                "scope": f.scope,
                "scope_level": f.scope_level,
                "mitre_technique": f.mitre_technique,
                "mitre_tactic": f.mitre_tactic,
                "description": f.description,
                "remediation": f.remediation_steps,
            }
            for f in findings
        ],
        "blast_radius": [
            {
                "principal": b.principal_name,
                "type": b.principal_type,
                "blast_score": b.blast_score,
                "blast_level": b.blast_level,
                "roles": b.roles,
                "reachable_scopes": b.reachable_scope_levels,
            }
            for b in blast
        ],
    }
    Path(output_path).write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"[azure-export] JSON saved: {output_path}")


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

def _to_csv(findings: list[AzureFinding], output_path: str) -> None:
    fieldnames = [
        "rule_id", "title", "severity", "principal_name", "principal_type",
        "role", "scope", "scope_level", "mitre_technique", "mitre_tactic",
        "description",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for f in findings:
            writer.writerow({
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "principal_name": f.principal_name,
                "principal_type": f.principal_type,
                "role": f.role,
                "scope": f.scope,
                "scope_level": f.scope_level,
                "mitre_technique": f.mitre_technique,
                "mitre_tactic": f.mitre_tactic,
                "description": f.description,
            })
    print(f"[azure-export] CSV saved: {output_path}")


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------

def _to_sarif(findings: list[AzureFinding], output_path: str) -> None:
    rules = {}
    for f in findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title.replace(" ", ""),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "helpUri": f"https://attack.mitre.org/techniques/{f.mitre_technique.replace('.', '/')}/",
                "properties": {
                    "tags": ["security", "azure", "rbac", f.severity.lower()],
                    "precision": "high",
                    "problem.severity": f.severity.lower(),
                },
            }

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CloudSentrix-Azure",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/Talha-Imran-cloud/cloudsentrix",
                        "rules": list(rules.values()),
                    }
                },
                "results": [
                    {
                        "ruleId": f.rule_id,
                        "level": "error" if f.severity == "CRITICAL" else "warning",
                        "message": {"text": f.description},
                        "locations": [
                            {
                                "logicalLocations": [
                                    {
                                        "name": f.principal_name,
                                        "kind": "azure-principal",
                                        "decoratedName": f"{f.principal_name} @ {f.scope}",
                                    }
                                ]
                            }
                        ],
                        "properties": {
                            "principal_type": f.principal_type,
                            "role": f.role,
                            "scope": f.scope,
                            "mitre_technique": f.mitre_technique,
                        },
                    }
                    for f in findings
                ],
            }
        ],
    }
    Path(output_path).write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    print(f"[azure-export] SARIF saved: {output_path}")


# ---------------------------------------------------------------------------
# HTML Dashboard
# ---------------------------------------------------------------------------

_SEVERITY_COLOR = {
    "CRITICAL": "#e53935",
    "HIGH": "#fb8c00",
    "MEDIUM": "#fdd835",
    "LOW": "#43a047",
}

_BLAST_COLOR = {
    "Critical": "#e53935",
    "High": "#fb8c00",
    "Medium": "#fdd835",
    "Low": "#43a047",
}


def _to_html(
    findings: list[AzureFinding],
    score: AzureScoreResult,
    blast: list[AzureBlastResult],
    iam: AzureIAMData,
    output_path: str,
) -> None:
    # Build findings rows
    findings_rows = ""
    for f in findings:
        color = _SEVERITY_COLOR.get(f.severity, "#999")
        findings_rows += f"""
        <tr>
          <td><span class="badge" style="background:{color}">{f.rule_id}</span></td>
          <td>{f.title}</td>
          <td><span class="badge" style="background:{color}">{f.severity}</span></td>
          <td>{f.principal_name}</td>
          <td>{f.principal_type}</td>
          <td>{f.role}</td>
          <td>{f.scope_level}</td>
          <td><code>{f.mitre_technique}</code></td>
        </tr>"""

    # Build blast rows
    blast_rows = ""
    for b in blast[:20]:   # top 20
        color = _BLAST_COLOR.get(b.blast_level, "#999")
        blast_rows += f"""
        <tr>
          <td>{b.principal_name}</td>
          <td>{b.principal_type}</td>
          <td>{', '.join(b.roles[:3])}</td>
          <td><span class="badge" style="background:{color}">{b.blast_level} ({b.blast_score})</span></td>
          <td>{', '.join(b.reachable_scope_levels)}</td>
        </tr>"""

    # Score colour
    score_color = (
        "#e53935" if score.score < 40
        else "#fb8c00" if score.score < 70
        else "#43a047"
    )

    # Graph nodes / edges (D3-style)
    nodes_js = []
    edges_js = []
    seen_nodes: set[str] = set()

    for f in findings:
        if f.principal_name not in seen_nodes:
            nodes_js.append(
                f'{{"id":"{f.principal_name}","type":"{f.principal_type}",'
                f'"severity":"{f.severity}"}}'
            )
            seen_nodes.add(f.principal_name)
        role_node = f"role:{f.role}"
        if role_node not in seen_nodes:
            nodes_js.append(f'{{"id":"{role_node}","type":"Role","severity":"INFO"}}')
            seen_nodes.add(role_node)
        edges_js.append(
            f'{{"source":"{f.principal_name}","target":"{role_node}",'
            f'"label":"{f.scope_level}"}}'
        )

    nodes_str = "[" + ",".join(nodes_js) + "]"
    edges_str = "[" + ",".join(edges_js) + "]"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CloudSentrix — Azure RBAC Dashboard</title>
<style>
  :root {{
    --bg: #0f1117; --card: #1a1d27; --border: #2a2d3a;
    --text: #e0e0e0; --muted: #888; --accent: #4fc3f7;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', sans-serif; }}
  header {{ background: linear-gradient(135deg,#1565c0,#0d47a1);
            padding: 24px 32px; display: flex; align-items: center; gap: 16px; }}
  header h1 {{ font-size: 1.6rem; font-weight: 700; color: #fff; }}
  header span {{ font-size: .9rem; color: #90caf9; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(180px,1fr));
           gap: 16px; padding: 24px 32px; }}
  .card {{ background: var(--card); border: 1px solid var(--border);
           border-radius: 10px; padding: 20px; text-align: center; }}
  .card .val {{ font-size: 2.4rem; font-weight: 800; }}
  .card .lbl {{ font-size: .8rem; color: var(--muted); margin-top: 4px; }}
  section {{ padding: 0 32px 32px; }}
  h2 {{ font-size: 1.1rem; margin-bottom: 12px; color: var(--accent); }}
  table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
  th {{ background: var(--card); padding: 10px 12px; text-align: left;
        border-bottom: 2px solid var(--border); color: var(--muted); }}
  td {{ padding: 9px 12px; border-bottom: 1px solid var(--border); }}
  tr:hover td {{ background: rgba(255,255,255,.03); }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px;
            font-size: .75rem; font-weight: 700; color: #fff; }}
  code {{ background: #252830; padding: 2px 6px; border-radius: 4px; font-size: .8rem; }}
  #graph-container {{ background: var(--card); border: 1px solid var(--border);
                      border-radius: 10px; height: 400px; margin-bottom: 32px;
                      display: flex; align-items: center; justify-content: center; }}
  svg.graph {{ width: 100%; height: 100%; }}
  .node circle {{ stroke: #fff; stroke-width: 1.5px; }}
  .node text {{ fill: var(--text); font-size: 11px; }}
  .link {{ stroke: #444; stroke-opacity: 0.7; stroke-width: 1.5px; }}
</style>
</head>
<body>
<header>
  <div>
    <h1>🔐 CloudSentrix — Azure RBAC Analyzer</h1>
    <span>Security posture dashboard · {len(iam.assignments)} assignments scanned</span>
  </div>
</header>

<div class="grid">
  <div class="card">
    <div class="val" style="color:{score_color}">{score.score}</div>
    <div class="lbl">Security Score (Grade {score.grade})</div>
  </div>
  <div class="card">
    <div class="val" style="color:#e53935">{score.critical_count}</div>
    <div class="lbl">Critical Findings</div>
  </div>
  <div class="card">
    <div class="val" style="color:#fb8c00">{score.high_count}</div>
    <div class="lbl">High Findings</div>
  </div>
  <div class="card">
    <div class="val">{score.total_assignments}</div>
    <div class="lbl">Total Assignments</div>
  </div>
  <div class="card">
    <div class="val">{score.total_principals}</div>
    <div class="lbl">Unique Principals</div>
  </div>
</div>

<section>
  <h2>🕸️ Attack Path Graph</h2>
  <div id="graph-container">
    <svg class="graph" id="graph-svg"></svg>
  </div>
</section>

<section>
  <h2>🔍 Findings ({len(findings)} total)</h2>
  <table>
    <thead>
      <tr>
        <th>Rule</th><th>Title</th><th>Severity</th><th>Principal</th>
        <th>Type</th><th>Role</th><th>Scope Level</th><th>MITRE</th>
      </tr>
    </thead>
    <tbody>{findings_rows}</tbody>
  </table>
</section>

<section style="margin-top:32px">
  <h2>💥 Blast Radius (Top 20 Principals)</h2>
  <table>
    <thead>
      <tr><th>Principal</th><th>Type</th><th>Roles</th><th>Blast Level</th><th>Reachable Scopes</th></tr>
    </thead>
    <tbody>{blast_rows}</tbody>
  </table>
</section>

<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<script>
const nodes = {nodes_str};
const links = {edges_str};

const severityColor = {{
  CRITICAL:"#e53935", HIGH:"#fb8c00", MEDIUM:"#fdd835",
  LOW:"#43a047", INFO:"#4fc3f7", Role:"#7e57c2"
}};

const svg = d3.select("#graph-svg");
const container = document.getElementById("graph-container");
const W = container.clientWidth || 800;
const H = 400;
svg.attr("viewBox", `0 0 ${{W}} ${{H}}`);

const sim = d3.forceSimulation(nodes)
  .force("link", d3.forceLink(links).id(d => d.id).distance(100))
  .force("charge", d3.forceManyBody().strength(-200))
  .force("center", d3.forceCenter(W/2, H/2));

const link = svg.append("g").selectAll("line")
  .data(links).join("line").attr("class","link");

const node = svg.append("g").selectAll("g")
  .data(nodes).join("g").attr("class","node")
  .call(d3.drag()
    .on("start", (e,d) => {{ if(!e.active) sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; }})
    .on("drag",  (e,d) => {{ d.fx=e.x; d.fy=e.y; }})
    .on("end",   (e,d) => {{ if(!e.active) sim.alphaTarget(0); d.fx=null; d.fy=null; }}));

node.append("circle").attr("r", d => d.type==="Role"?10:14)
  .attr("fill", d => severityColor[d.severity] || severityColor[d.type] || "#888");

node.append("text").attr("dy","0.35em").attr("x",18)
  .text(d => d.id.length > 28 ? d.id.slice(0,26)+".." : d.id);

node.append("title").text(d => `${{d.id}}\\nType: ${{d.type}}\\nSeverity: ${{d.severity}}`);

sim.on("tick", () => {{
  link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y)
      .attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);
  node.attr("transform",d=>`translate(${{d.x}},${{d.y}})`);
}});
</script>
</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")
    print(f"[azure-export] HTML dashboard saved: {output_path}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def export_azure(
    findings: list[AzureFinding],
    score_result: AzureScoreResult,
    blast_results: list[AzureBlastResult],
    iam: AzureIAMData,
    output_path: str,
) -> None:
    """Detect format from extension and export accordingly."""
    ext = Path(output_path).suffix.lower()
    if ext == ".json":
        _to_json(findings, score_result, blast_results, output_path)
    elif ext == ".csv":
        _to_csv(findings, output_path)
    elif ext == ".sarif":
        _to_sarif(findings, output_path)
    elif ext in (".html", ".htm"):
        _to_html(findings, score_result, blast_results, iam, output_path)
    else:
        raise ValueError(
            f"Unsupported export format: '{ext}'. "
            "Use .json, .csv, .sarif, or .html"
        )
