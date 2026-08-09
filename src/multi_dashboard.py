"""
multi_dashboard.py
------------------
Generates a single animated interactive HTML dashboard comparing
GCP, AWS, and Azure IAM/RBAC security posture side by side.

Public API
  generate_multi_dashboard(gcp_file, aws_file, azure_file, output_path) -> tuple
"""

from __future__ import annotations
import json
from pathlib import Path


def _collect_gcp(file_path: str) -> dict:
    try:
        from parser import GCPIAMParser
        from graph import IAMGraph
        from detection import DetectionEngine
        from risk_score import RiskScorer

        policy   = GCPIAMParser().parse_file(file_path)
        graph    = IAMGraph.from_policy(policy)
        findings = DetectionEngine().run(graph)
        risk     = RiskScorer().score(findings)

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        finding_list = []
        for f in findings:
            counts[f.severity.name] += 1
            finding_list.append({
                "rule_id": f.rule_id, "title": f.title,
                "severity": f.severity.name, "principal": f.principal_id,
                "mitre": f.mitre_technique_id, "description": f.description,
            })
        return {
            "cloud": "GCP", "icon": "☁️", "color": "#4285f4",
            "score": risk.score, "rating": risk.rating.value,
            "counts": counts, "total": len(findings),
            "findings": finding_list, "principals": len(graph.principal_ids()),
            "file": file_path, "error": None,
        }
    except Exception as exc:
        return _err("GCP", "☁️", "#4285f4", file_path, str(exc))


def _collect_aws(file_path: str) -> dict:
    try:
        from aws_parser import AWSIAMParser
        from aws_graph import AWSIAMGraph
        from aws_detection import AWSDetectionEngine
        from risk_score import RiskScorer
        from detection import Finding as GF, Severity as GS

        policy   = AWSIAMParser().parse_file(file_path)
        graph    = AWSIAMGraph.from_policy(policy)
        findings = AWSDetectionEngine().run(graph)

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        finding_list, gcp_f = [], []
        for f in findings:
            counts[f.severity.name] += 1
            finding_list.append({
                "rule_id": f.rule_id, "title": f.title,
                "severity": f.severity.name, "principal": f.principal_id,
                "mitre": f.mitre_technique_id, "description": f.description,
            })
            gcp_f.append(GF(rule_id=f.rule_id, title=f.title,
                             severity=GS(int(f.severity)),
                             principal_id=f.principal_id,
                             description=f.description,
                             mitre_technique_id=f.mitre_technique_id,
                             mitre_technique_name=f.mitre_technique_name,
                             evidence=f.evidence))
        risk  = RiskScorer().score(gcp_f)
        stats = policy.summary()
        return {
            "cloud": "AWS", "icon": "🟡", "color": "#ff9900",
            "score": risk.score, "rating": risk.rating.value,
            "counts": counts, "total": len(findings),
            "findings": finding_list, "principals": stats["total_principals"],
            "file": file_path, "error": None,
        }
    except Exception as exc:
        return _err("AWS", "🟡", "#ff9900", file_path, str(exc))


def _collect_azure(file_path: str) -> dict:
    try:
        from azure_parser import parse_azure_file
        from azure_detection import run_azure_detections
        from azure_risk_score import score_azure

        iam      = parse_azure_file(file_path)
        findings = run_azure_detections(iam)
        score    = score_azure(findings, iam)

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        finding_list = []
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
            finding_list.append({
                "rule_id": f.rule_id, "title": f.title,
                "severity": f.severity, "principal": f.principal_name,
                "mitre": f.mitre_technique, "description": f.description,
            })
        unique = {a.principal_name for a in iam.assignments}
        return {
            "cloud": "Azure", "icon": "🔷", "color": "#0078d4",
            "score": score.score, "rating": score.grade,
            "counts": counts, "total": len(findings),
            "findings": finding_list, "principals": len(unique),
            "file": file_path, "error": None,
        }
    except Exception as exc:
        return _err("Azure", "🔷", "#0078d4", file_path, str(exc))


def _err(cloud, icon, color, file, error):
    return {"cloud": cloud, "icon": icon, "color": color,
            "score": 0, "rating": "Error",
            "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "total": 0, "findings": [], "principals": 0,
            "file": file, "error": error}


def _build_html(clouds: list[dict]) -> str:
    active = [c for c in clouds if not c["error"]]

    # Score cards
    score_cards = ""
    for i, c in enumerate(clouds):
        if c["error"]:
            score_cards += f'<div class="score-card" style="border-top:4px solid {c["color"]};animation-delay:{i*0.15}s"><div class="cloud-label" style="color:{c["color"]}">{c["icon"]} {c["cloud"]}</div><div class="score-val" style="color:#888">N/A</div><div class="score-sub">{c["error"][:60]}</div></div>'
            continue
        sc = "#e53935" if c["score"] < 40 else "#fb8c00" if c["score"] < 70 else "#43a047"
        score_cards += f"""
        <div class="score-card fade-up" style="border-top:4px solid {c['color']};animation-delay:{i*0.15}s">
          <div class="cloud-label" style="color:{c['color']}">{c['icon']} {c['cloud']}</div>
          <div class="score-val counter" style="color:{sc}" data-target="{c['score']}" data-suffix="/100">0/100</div>
          <div class="score-bar-bg"><div class="score-bar" style="background:{sc}" data-width="{c['score']}"></div></div>
          <div class="score-sub">Rating: {c['rating']}</div>
          <div class="score-meta">
            <span style="color:#e53935">🔴 {c['counts'].get('CRITICAL',0)} Critical</span>&nbsp;
            <span style="color:#fb8c00">🟠 {c['counts'].get('HIGH',0)} High</span>
          </div>
          <div class="score-meta" style="color:#888;margin-top:4px">{c['total']} finding(s) · {c['principals']} principal(s)</div>
        </div>"""

    # Severity table
    cloud_headers = "".join(f'<th style="color:{c["color"]}">{c["icon"]} {c["cloud"]}</th>' for c in clouds)
    sev_rows = ""
    for sev, color in [("CRITICAL","#e53935"),("HIGH","#fb8c00"),("MEDIUM","#fdd835"),("LOW","#43a047")]:
        total = sum(c["counts"].get(sev, 0) for c in active)
        cells = "".join(f'<td style="text-align:center;color:{color};font-weight:700">{c["counts"].get(sev,0)}</td>' for c in clouds)
        sev_rows += f'<tr><td><span class="badge" style="background:{color}">{sev}</span></td>{cells}<td style="text-align:center;font-weight:700">{total}</td></tr>'

    # All findings
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sev_color = {"CRITICAL":"#e53935","HIGH":"#fb8c00","MEDIUM":"#fdd835","LOW":"#43a047"}
    all_f = []
    for c in clouds:
        for f in c["findings"]:
            f["_cloud"] = c["cloud"]; f["_color"] = c["color"]; f["_icon"] = c["icon"]
            all_f.append(f)
    all_f.sort(key=lambda f: sev_order.get(f["severity"], 9))

    finding_rows = ""
    for f in all_f:
        sc = sev_color.get(f["severity"], "#999")
        finding_rows += f"""<tr class="finding-row">
          <td><span class="badge" style="background:{f['_color']}">{f['_icon']} {f['_cloud']}</span></td>
          <td><span class="badge" style="background:{sc}">{f['rule_id']}</span></td>
          <td>{f['title']}</td>
          <td><span class="badge" style="background:{sc}">{f['severity']}</span></td>
          <td style="font-size:.8rem;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{f['principal'][:45]}</td>
          <td><code>{f['mitre']}</code></td>
        </tr>"""

    total_findings = sum(c["total"] for c in active)
    total_critical = sum(c["counts"].get("CRITICAL", 0) for c in active)

    chart_labels   = json.dumps([c["cloud"] for c in clouds])
    chart_scores   = json.dumps([c["score"] for c in clouds])
    chart_colors   = json.dumps([c["color"] for c in clouds])
    chart_critical = json.dumps([c["counts"].get("CRITICAL", 0) for c in clouds])
    chart_high     = json.dumps([c["counts"].get("HIGH", 0) for c in clouds])
    chart_medium   = json.dumps([c["counts"].get("MEDIUM", 0) for c in clouds])
    chart_low      = json.dumps([c["counts"].get("LOW", 0) for c in clouds])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>CloudSentrix — Multi-Cloud Dashboard</title>
<style>
:root{{--bg:#0f1117;--card:#1a1d27;--border:#2a2d3a;--text:#e0e0e0;--muted:#888;--accent:#4fc3f7;}}
*{{box-sizing:border-box;margin:0;padding:0;}}
html{{scroll-behavior:smooth;}}
body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',sans-serif;overflow-x:hidden;}}

/* ── Animations ── */
@keyframes fadeUp{{from{{opacity:0;transform:translateY(30px)}}to{{opacity:1;transform:translateY(0)}}}}
@keyframes fadeIn{{from{{opacity:0}}to{{opacity:1}}}}
@keyframes slideLeft{{from{{opacity:0;transform:translateX(-40px)}}to{{opacity:1;transform:translateX(0)}}}}
@keyframes pulse{{0%,100%{{box-shadow:0 0 0 0 rgba(79,195,247,.4)}}50%{{box-shadow:0 0 0 12px rgba(79,195,247,0)}}}}
@keyframes gradientShift{{0%{{background-position:0% 50%}}50%{{background-position:100% 50%}}100%{{background-position:0% 50%}}}}
@keyframes scanLine{{0%{{top:0}}100%{{top:100%}}}}
@keyframes countUp{{from{{opacity:0}}to{{opacity:1}}}}
@keyframes barGrow{{from{{width:0}}to{{width:var(--bar-w,0%)}}}};
@keyframes float{{0%,100%{{transform:translateY(0)}}50%{{transform:translateY(-8px)}}}}
@keyframes shimmer{{0%{{background-position:-200% center}}100%{{background-position:200% center}}}}
@keyframes ringPulse{{0%{{transform:scale(1);opacity:1}}100%{{transform:scale(1.6);opacity:0}}}}

.fade-up{{opacity:0;animation:fadeUp .7s ease forwards;}}
.fade-in{{opacity:0;animation:fadeIn .8s ease forwards;}}
.slide-left{{opacity:0;animation:slideLeft .6s ease forwards;}}

/* ── Header ── */
header{{
  background:linear-gradient(135deg,#0d1b4b,#0d47a1,#01579b,#006064);
  background-size:300% 300%;
  animation:gradientShift 8s ease infinite;
  padding:36px 48px;
  position:relative;overflow:hidden;
}}
header::before{{
  content:'';position:absolute;top:0;left:-100%;width:60%;height:100%;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.05),transparent);
  animation:shimmer 3s infinite;
}}
.header-scan-line{{
  position:absolute;left:0;width:100%;height:2px;
  background:linear-gradient(90deg,transparent,rgba(79,195,247,.8),transparent);
  animation:scanLine 4s linear infinite;pointer-events:none;
}}
header h1{{font-size:2rem;font-weight:900;color:#fff;letter-spacing:1px;animation:fadeUp .6s ease both;}}
header p{{color:#90caf9;font-size:.95rem;margin-top:6px;animation:fadeUp .6s .1s ease both;}}
.header-stats{{display:flex;gap:40px;animation:fadeUp .6s .2s ease both;}}
.hstat{{text-align:center;}}
.hstat .val{{font-size:2.4rem;font-weight:900;color:#fff;}}
.hstat .lbl{{font-size:.75rem;color:#90caf9;text-transform:uppercase;letter-spacing:1px;}}
.hstat .val.danger{{color:#ff5252;animation:pulse 2s infinite;}}

/* ── Sections ── */
.section{{padding:32px 48px;}}
h2{{font-size:1rem;color:var(--accent);margin-bottom:20px;
    letter-spacing:1px;text-transform:uppercase;
    display:flex;align-items:center;gap:8px;}}
h2::before{{content:'';display:inline-block;width:3px;height:18px;
            background:var(--accent);border-radius:2px;}}

/* ── Score cards ── */
.score-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:24px;}}
.score-card{{
  background:var(--card);border:1px solid var(--border);
  border-radius:16px;padding:28px;
  transition:transform .3s,box-shadow .3s;
  position:relative;overflow:hidden;
}}
.score-card::after{{
  content:'';position:absolute;top:-50%;right:-50%;
  width:100%;height:100%;
  background:radial-gradient(circle,rgba(255,255,255,.03),transparent 70%);
  pointer-events:none;
}}
.score-card:hover{{transform:translateY(-6px);box-shadow:0 20px 40px rgba(0,0,0,.4);}}
.cloud-label{{font-size:1.05rem;font-weight:700;margin-bottom:16px;}}
.score-val{{font-size:3.2rem;font-weight:900;line-height:1;}}
.score-bar-bg{{background:#252830;border-radius:6px;height:8px;margin:14px 0;overflow:hidden;}}
.score-bar{{height:8px;border-radius:6px;width:0;transition:width 1.5s cubic-bezier(.4,0,.2,1);}}
.score-sub{{font-size:.82rem;color:var(--muted);margin-top:8px;}}
.score-meta{{font-size:.82rem;margin-top:10px;}}

/* ── Charts ── */
.charts-grid{{display:grid;grid-template-columns:1fr 1fr;gap:24px;}}
.chart-card{{
  background:var(--card);border:1px solid var(--border);
  border-radius:16px;padding:24px;
  transition:transform .3s;
}}
.chart-card:hover{{transform:translateY(-4px);}}
canvas{{max-height:280px;}}

/* ── Tables ── */
.table-wrap{{background:var(--card);border:1px solid var(--border);border-radius:16px;overflow:hidden;}}
table{{width:100%;border-collapse:collapse;font-size:.85rem;}}
th{{background:#13161f;padding:12px 14px;text-align:left;
    border-bottom:2px solid var(--border);color:var(--muted);
    font-size:.73rem;text-transform:uppercase;letter-spacing:.8px;}}
td{{padding:10px 14px;border-bottom:1px solid var(--border);transition:background .2s;}}
.finding-row{{opacity:0;animation:fadeUp .5s ease forwards;}}
.finding-row:hover td{{background:rgba(255,255,255,.04);}}
.badge{{display:inline-block;padding:3px 9px;border-radius:12px;
        font-size:.72rem;font-weight:700;color:#fff;}}
code{{background:#252830;padding:2px 7px;border-radius:4px;font-size:.78rem;}}

/* ── Floating particles ── */
.particles{{position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:0;overflow:hidden;}}
.particle{{position:absolute;border-radius:50%;animation:float linear infinite;opacity:.15;}}

/* ── Scroll reveal ── */
.reveal{{opacity:0;transform:translateY(24px);transition:opacity .7s ease,transform .7s ease;}}
.reveal.visible{{opacity:1;transform:translateY(0);}}

/* ── Ring badge ── */
.ring{{position:relative;display:inline-block;}}
.ring::after{{content:'';position:absolute;top:50%;left:50%;
              transform:translate(-50%,-50%);
              width:100%;height:100%;border-radius:50%;
              border:2px solid currentColor;
              animation:ringPulse 2s ease-out infinite;}}

@media(max-width:768px){{
  .charts-grid{{grid-template-columns:1fr;}}
  header{{flex-direction:column;gap:20px;padding:24px;}}
  .section{{padding:20px 24px;}}
}}
</style>
</head>
<body>

<!-- Floating particles -->
<div class="particles" id="particles"></div>

<header style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:24px;">
  <div class="header-scan-line"></div>
  <div>
    <h1>🔐 CloudSentrix</h1>
    <p>Multi-Cloud Security Dashboard · GCP · AWS · Azure</p>
  </div>
  <div class="header-stats">
    <div class="hstat">
      <div class="val counter" data-target="{len(active)}">{len(active)}</div>
      <div class="lbl">Clouds</div>
    </div>
    <div class="hstat">
      <div class="val danger counter" data-target="{total_critical}">0</div>
      <div class="lbl">Critical</div>
    </div>
    <div class="hstat">
      <div class="val counter" data-target="{total_findings}">0</div>
      <div class="lbl">Findings</div>
    </div>
  </div>
</header>

<!-- Score Cards -->
<div class="section reveal">
  <h2>Security Score by Cloud</h2>
  <div class="score-grid">{score_cards}</div>
</div>

<!-- Charts -->
<div class="section reveal">
  <h2>Risk Comparison</h2>
  <div class="charts-grid">
    <div class="chart-card fade-up" style="animation-delay:.1s">
      <h2 style="font-size:.9rem;margin-bottom:14px">Security Scores</h2>
      <canvas id="scoreChart"></canvas>
    </div>
    <div class="chart-card fade-up" style="animation-delay:.2s">
      <h2 style="font-size:.9rem;margin-bottom:14px">Findings by Severity</h2>
      <canvas id="severityChart"></canvas>
    </div>
  </div>
</div>

<!-- Severity Table -->
<div class="section reveal">
  <h2>Severity Breakdown</h2>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Severity</th>{cloud_headers}<th style="text-align:center">Total</th></tr></thead>
      <tbody>{sev_rows}</tbody>
    </table>
  </div>
</div>

<!-- All Findings -->
<div class="section reveal">
  <h2>All Findings ({total_findings} total)</h2>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Cloud</th><th>Rule</th><th>Title</th><th>Severity</th><th>Principal</th><th>MITRE</th></tr></thead>
      <tbody>{finding_rows}</tbody>
    </table>
  </div>
</div>

<div style="padding:24px 48px;color:var(--muted);font-size:.8rem;text-align:center;animation:fadeIn 1s 1s both">
  Generated by <strong style="color:var(--accent)">CloudSentrix</strong> —
  <a href="https://github.com/Talha-Imran-cloud/cloudsentrix" style="color:var(--accent)">github.com/Talha-Imran-cloud/cloudsentrix</a>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<script>
/* ── Particles ── */
(function(){{
  const c=['#4285f4','#ff9900','#0078d4','#4fc3f7','#e53935'];
  const p=document.getElementById('particles');
  for(let i=0;i<28;i++){{
    const el=document.createElement('div');
    el.className='particle';
    const s=Math.random()*6+2;
    el.style.cssText=`width:${{s}}px;height:${{s}}px;background:${{c[i%c.length]}};`+
      `left:${{Math.random()*100}}%;top:${{Math.random()*100}}%;`+
      `animation-duration:${{Math.random()*12+8}}s;`+
      `animation-delay:-${{Math.random()*10}}s;`;
    p.appendChild(el);
  }}
}})();

/* ── Scroll reveal ── */
const observer=new IntersectionObserver(entries=>{{
  entries.forEach(e=>{{if(e.isIntersecting){{e.target.classList.add('visible');observer.unobserve(e.target);}}}});
}},{{threshold:0.15}});
document.querySelectorAll('.reveal').forEach(el=>observer.observe(el));

/* ── Counter animation ── */
function animateCounter(el){{
  const target=parseInt(el.dataset.target)||0;
  const suffix=el.dataset.suffix||'';
  const dur=1400;
  const start=performance.now();
  (function tick(now){{
    const p=Math.min((now-start)/dur,1);
    const ease=1-Math.pow(1-p,3);
    el.textContent=Math.round(ease*target)+suffix;
    if(p<1) requestAnimationFrame(tick);
  }})(start);
}}
const cObserver=new IntersectionObserver(entries=>{{
  entries.forEach(e=>{{
    if(e.isIntersecting){{
      animateCounter(e.target);
      cObserver.unobserve(e.target);
    }}
  }});
}},{{threshold:0.5}});
document.querySelectorAll('.counter').forEach(el=>cObserver.observe(el));

/* ── Score bars ── */
const bObserver=new IntersectionObserver(entries=>{{
  entries.forEach(e=>{{
    if(e.isIntersecting){{
      const bar=e.target.querySelector('.score-bar');
      if(bar){{
        const w=bar.dataset.width+'%';
        setTimeout(()=>bar.style.width=w,200);
      }}
      bObserver.unobserve(e.target);
    }}
  }});
}},{{threshold:0.3}});
document.querySelectorAll('.score-card').forEach(el=>bObserver.observe(el));

/* ── Finding rows stagger ── */
document.querySelectorAll('.finding-row').forEach((r,i)=>{{
  r.style.animationDelay=(i*0.04)+'s';
}});

/* ── Charts ── */
Chart.defaults.color='#888';
Chart.defaults.borderColor='#2a2d3a';
const labels={chart_labels};
const scores={chart_scores};
const colors={chart_colors};

new Chart(document.getElementById('scoreChart'),{{
  type:'bar',
  data:{{labels,datasets:[{{
    label:'Security Score',data:scores,
    backgroundColor:colors.map(c=>c+'cc'),
    borderColor:colors,borderWidth:2,
    borderRadius:8,borderSkipped:false,
  }}]}},
  options:{{
    responsive:true,animation:{{duration:1200,easing:'easeOutQuart'}},
    plugins:{{legend:{{display:false}}}},
    scales:{{
      y:{{min:0,max:100,grid:{{color:'#2a2d3a'}},ticks:{{color:'#888'}}}},
      x:{{grid:{{display:false}},ticks:{{color:'#ccc'}}}}
    }}
  }}
}});

new Chart(document.getElementById('severityChart'),{{
  type:'bar',
  data:{{labels,datasets:[
    {{label:'Critical',data:{chart_critical},backgroundColor:'#e5393588',borderColor:'#e53935',borderWidth:2,borderRadius:6}},
    {{label:'High',    data:{chart_high},   backgroundColor:'#fb8c0088',borderColor:'#fb8c00',borderWidth:2,borderRadius:6}},
    {{label:'Medium',  data:{chart_medium}, backgroundColor:'#fdd83588',borderColor:'#fdd835',borderWidth:2,borderRadius:6}},
    {{label:'Low',     data:{chart_low},    backgroundColor:'#43a04788',borderColor:'#43a047',borderWidth:2,borderRadius:6}},
  ]}},
  options:{{
    responsive:true,animation:{{duration:1400,easing:'easeOutQuart'}},
    plugins:{{legend:{{labels:{{color:'#ccc'}}}}}},
    scales:{{
      y:{{grid:{{color:'#2a2d3a'}},ticks:{{color:'#888'}}}},
      x:{{grid:{{display:false}},ticks:{{color:'#ccc'}}}}
    }}
  }}
}});
</script>
</body>
</html>"""


def generate_multi_dashboard(
    gcp_file: str | None,
    aws_file: str | None,
    azure_file: str | None,
    output_path: str,
) -> tuple[int, int]:
    clouds: list[dict] = []
    if gcp_file:
        print(f"  [dashboard] Scanning GCP   : {gcp_file}")
        clouds.append(_collect_gcp(gcp_file))
    if aws_file:
        print(f"  [dashboard] Scanning AWS   : {aws_file}")
        clouds.append(_collect_aws(aws_file))
    if azure_file:
        print(f"  [dashboard] Scanning Azure : {azure_file}")
        clouds.append(_collect_azure(azure_file))
    if not clouds:
        raise ValueError("At least one cloud file must be provided.")

    Path(output_path).write_text(_build_html(clouds), encoding="utf-8")
    active = [c for c in clouds if not c["error"]]
    return len(active), sum(c["total"] for c in active)


if __name__ == "__main__":
    s, f = generate_multi_dashboard(
        "sample_data/sample_gcp_iam.json",
        "sample_data/sample_aws_iam.json",
        "sample_data/sample_azure_rbac.json",
        "multi_cloud_dashboard.html",
    )
    print(f"\n✅ Dashboard generated: {s} cloud(s), {f} finding(s)")
    print("   Open: multi_cloud_dashboard.html")
