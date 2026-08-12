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
    cloud_colors = {"GCP": "#4285f4", "AWS": "#ff9900", "Azure": "#0078d4"}
    for i, c in enumerate(clouds):
        color = cloud_colors.get(c["cloud"], "#888888")
        if c["error"]:
            score_cards += (
                f'<div class="score-card" style="--card-color:{color}">' +
                f'<div class="cloud-label">{c["icon"]} {c["cloud"]}</div>' +
                f'<div class="score-val" style="color:var(--w4)">N/A</div>' +
                f'<div class="score-sub">Error: {c["error"][:50]}</div></div>'
            )
            continue
        sc = "#FF4444" if c["score"] < 40 else "#FF8800" if c["score"] < 70 else "#44CC44"
        crit = c["counts"].get("CRITICAL", 0)
        high = c["counts"].get("HIGH", 0)
        crit_cls = " crit" if crit else ""
        high_cls = " high" if high else ""
        score_cards += (
            f'<div class="score-card" style="--card-color:{color};--score-color:{sc}">' +
            f'<div class="cloud-label">{c["icon"]} {c["cloud"]}</div>' +
            f'<div class="score-val"><span class="counter" data-target="{c["score"]}">0</span>' +
            f'<span class="score-suffix">/100</span></div>' +
            f'<div class="score-bar-bg"><div class="score-bar" data-width="{c["score"]}"></div></div>' +
            f'<div class="score-sub">Rating: {c["rating"]} &nbsp;·&nbsp; {c["total"]} finding(s)</div>' +
            f'<div class="score-meta">' +
            f'<span class="score-badge{crit_cls}">🔴 {crit} Critical</span>' +
            f'<span class="score-badge{high_cls}">🟠 {high} High</span></div></div>'
        )

    # Severity table
    cloud_headers = "".join(f'<th style="color:{c["color"]}">{c["icon"]} {c["cloud"]}</th>' for c in clouds)
    sev_colors = {"CRITICAL":"#FF4444","HIGH":"#FF8800","MEDIUM":"#FFCC00","LOW":"#44CC44"}
    sev_rows = ""
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW"]:
        color = sev_colors[sev]
        total = sum(c["counts"].get(sev, 0) for c in active)
        cells = "".join(
            f'<td style="text-align:center;font-family:JetBrains Mono,monospace;font-weight:700;color:{color}">{c["counts"].get(sev,0)}</td>'
            for c in clouds
        )
        sev_rows += f'<tr class="sev-row-{sev}"><td><span class="badge {sev}">{sev}</span></td>{cells}<td style="text-align:center;font-weight:700">{total}</td></tr>'

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
<title>CloudSentrix — Multi-Cloud Security Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@100..900&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet"/>
<style>
:root{{
  --bg:#070707;--s0:#0B0B0B;--s1:#101010;--s2:#161616;--s3:#1E1E1E;--s4:#272727;
  --bd:#202020;--bdb:#303030;--bdc:#3E3E3E;
  --w:#F4F4F4;--w2:#C0C0C0;--w3:#888888;--w4:#505050;--w5:#333333;
  --crit:#FF4444;--high:#FF8800;--med:#FFCC00;--low:#44CC44;
  --gcp:#4285f4;--aws:#ff9900;--azure:#0078d4;
}}
*{{box-sizing:border-box;margin:0;padding:0;}}
html{{scroll-behavior:smooth;}}
body{{
  background:var(--bg);color:var(--w);
  font-family:'Inter',system-ui,sans-serif;
  line-height:1.6;overflow-x:hidden;cursor:none;
}}
::-webkit-scrollbar{{width:3px;}}
::-webkit-scrollbar-track{{background:var(--bg);}}
::-webkit-scrollbar-thumb{{background:var(--bdb);border-radius:2px;}}

/* Trail canvas */
#trail{{position:fixed;top:0;left:0;pointer-events:none;z-index:9990;}}

/* Cursor */
#cur{{
  position:fixed;width:8px;height:8px;
  background:var(--w);border-radius:50%;
  pointer-events:none;z-index:9999;
  transform:translate(-50%,-50%);
  transition:transform .15s,background .2s;
  mix-blend-mode:difference;
}}

/* Grid background */
.grid-bg{{
  position:fixed;inset:0;pointer-events:none;z-index:0;
  background-image:
    linear-gradient(rgba(255,255,255,.018) 1px,transparent 1px),
    linear-gradient(90deg,rgba(255,255,255,.018) 1px,transparent 1px);
  background-size:72px 72px;
  mask-image:radial-gradient(ellipse 80% 80% at 50% 0%,black 0%,transparent 100%);
}}

/* Header */
header{{
  position:relative;z-index:10;
  padding:48px 56px 40px;
  border-bottom:1px solid var(--bd);
  background:var(--s0);
  display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:32px;
}}
.hlogo{{display:flex;align-items:center;gap:16px;}}
.hlogo-icon{{
  width:40px;height:40px;background:var(--s3);
  border:1px solid var(--bdb);border-radius:10px;
  display:flex;align-items:center;justify-content:center;
  animation:float 4s ease-in-out infinite;
}}
@keyframes float{{0%,100%{{transform:translateY(0)}}50%{{transform:translateY(-6px)}}}}
.hlogo-text h1{{font-size:22px;font-weight:900;letter-spacing:-1px;color:var(--w);}}
.hlogo-text p{{font-size:12px;color:var(--w4);font-weight:500;letter-spacing:.5px;text-transform:uppercase;margin-top:2px;}}
.hstats{{display:flex;gap:40px;}}
.hstat{{text-align:center;}}
.hstat .val{{
  font-size:36px;font-weight:900;letter-spacing:-2px;
  color:var(--w);display:block;line-height:1;
}}
.hstat .val.danger{{color:var(--crit);animation:pulse 2s infinite;}}
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.6}}}}
.hstat .lbl{{font-size:11px;font-weight:600;color:var(--w4);letter-spacing:.5px;text-transform:uppercase;margin-top:6px;}}

/* Section */
.section{{padding:56px;position:relative;z-index:10;}}
.section-title{{
  font-size:11px;font-weight:700;letter-spacing:3px;
  text-transform:uppercase;color:var(--w4);margin-bottom:28px;
  display:flex;align-items:center;gap:12px;
}}
.section-title::after{{content:'';flex:1;height:1px;background:var(--bd);}}

/* Score cards */
.score-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1px;background:var(--bd);border:1px solid var(--bd);border-radius:16px;overflow:hidden;}}
.score-card{{
  background:var(--s1);padding:40px;
  transition:background .25s;position:relative;overflow:hidden;
  cursor:none;
}}
.score-card:hover{{background:var(--s2);}}
.score-card::before{{
  content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:var(--card-color,var(--w4));
}}
.cloud-label{{
  font-size:11px;font-weight:700;letter-spacing:3px;
  text-transform:uppercase;color:var(--w4);margin-bottom:24px;
  display:flex;align-items:center;gap:8px;
}}
.cloud-label::before{{
  content:'';width:6px;height:6px;border-radius:50%;
  background:var(--card-color,var(--w4));
  animation:pd 2.5s ease-in-out infinite;
}}
@keyframes pd{{0%,100%{{opacity:.5}}50%{{opacity:1}}}}
.score-val{{
  font-size:72px;font-weight:900;letter-spacing:-5px;line-height:1;
  color:var(--score-color,var(--w));margin-bottom:16px;
}}
.score-suffix{{font-size:24px;font-weight:400;color:var(--w4);}}
.score-bar-bg{{background:var(--s3);border-radius:2px;height:3px;margin:16px 0;overflow:hidden;}}
.score-bar{{height:3px;border-radius:2px;width:0;transition:width 1.5s cubic-bezier(.4,0,.2,1);background:var(--score-color,var(--w3));}}
.score-sub{{font-size:12px;color:var(--w4);font-weight:600;letter-spacing:.5px;text-transform:uppercase;}}
.score-meta{{display:flex;gap:16px;margin-top:16px;}}
.score-badge{{
  font-size:11px;font-weight:700;font-family:'JetBrains Mono',monospace;
  padding:4px 10px;border-radius:4px;
  background:var(--s3);border:1px solid var(--bd);color:var(--w4);
}}
.score-badge.crit{{background:rgba(255,68,68,.1);border-color:rgba(255,68,68,.2);color:var(--crit);}}
.score-badge.high{{background:rgba(255,136,0,.1);border-color:rgba(255,136,0,.2);color:var(--high);}}

/* Charts */
.charts-grid{{display:grid;grid-template-columns:1fr 1fr;gap:1px;background:var(--bd);border:1px solid var(--bd);border-radius:16px;overflow:hidden;}}
.chart-card{{background:var(--s1);padding:40px;transition:background .25s;}}
.chart-card:hover{{background:var(--s2);}}
.chart-title{{font-size:12px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:var(--w4);margin-bottom:24px;}}
canvas{{max-height:240px;}}

/* Tables */
.table-wrap{{background:var(--s1);border:1px solid var(--bd);border-radius:16px;overflow:hidden;}}
table{{width:100%;border-collapse:collapse;font-size:13px;}}
th{{
  background:var(--s0);padding:12px 16px;text-align:left;
  border-bottom:1px solid var(--bd);
  font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:var(--w4);
}}
td{{padding:12px 16px;border-bottom:1px solid var(--bd);transition:background .15s;}}
tr:last-child td{{border-bottom:none;}}
tr:hover td{{background:var(--s2);}}
.badge{{
  display:inline-block;padding:2px 8px;border-radius:4px;
  font-size:10px;font-weight:700;font-family:'JetBrains Mono',monospace;
  background:var(--s3);border:1px solid var(--bd);color:var(--w4);
}}
.badge.CRITICAL{{background:rgba(255,68,68,.1);border-color:rgba(255,68,68,.2);color:var(--crit);}}
.badge.HIGH{{background:rgba(255,136,0,.1);border-color:rgba(255,136,0,.2);color:var(--high);}}
.badge.MEDIUM{{background:rgba(255,204,0,.1);border-color:rgba(255,204,0,.2);color:var(--med);}}
.badge.LOW{{background:rgba(68,204,68,.1);border-color:rgba(68,204,68,.2);color:var(--low);}}
code{{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--w3);}}

/* Severity rows */
.sev-row-CRITICAL td{{background:rgba(255,68,68,.03);}}
.sev-row-HIGH td{{background:rgba(255,136,0,.03);}}

/* Finding row animation */
.finding-row{{opacity:0;animation:fadeUp .5s ease forwards;}}
@keyframes fadeUp{{from{{opacity:0;transform:translateY(12px)}}to{{opacity:1;transform:translateY(0)}}}}

/* Reveal */
.reveal{{opacity:0;transform:translateY(24px);transition:opacity .7s ease,transform .7s ease;}}
.reveal.visible{{opacity:1;transform:translateY(0);}}

/* Particles */
.particles{{position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:1;}}
.particle{{position:absolute;border-radius:50%;animation:pfloat linear infinite;opacity:.06;}}
@keyframes pfloat{{0%{{transform:translateY(100vh) rotate(0deg)}}100%{{transform:translateY(-100vh) rotate(360deg)}}}}

/* Footer */
footer{{
  position:relative;z-index:10;
  padding:32px 56px;
  border-top:1px solid var(--bd);
  background:var(--s0);
  text-align:center;
  font-size:12px;color:var(--w4);
}}
footer a{{color:var(--w3);text-decoration:none;}}
footer a:hover{{color:var(--w);}}

@media(max-width:768px){{
  .charts-grid{{grid-template-columns:1fr;}}
  header{{padding:32px 24px;}}
  .section{{padding:32px 24px;}}
  .hstats{{gap:20px;}}
}}
</style>
</head>
<body>
<canvas id="trail"></canvas>
<div id="cur"></div>
<div class="grid-bg"></div>
<div class="particles" id="particles"></div>

<header>
  <div class="hlogo">
    <div class="hlogo-icon">
      <svg width="20" height="14" viewBox="0 0 100 68" fill="none">
        <path d="M78 58H26C14.4 58 5 48.6 5 37s9.4-21 21-21c1.4 0 2.8.14 4.1.4C34.2 8.8 43.8 2 55 2c14.6 0 26.6 10.8 27.8 24.6C83.8 26.2 84.9 26 86 26c7.7 0 14 6.3 14 14s-6.3 14-14 14H78z" fill="url(#hg)"/>
        <defs><linearGradient id="hg" x1="5" y1="2" x2="100" y2="68" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#888"/><stop offset="1" stop-color="#444"/></linearGradient></defs>
      </svg>
    </div>
    <div class="hlogo-text">
      <h1>CloudSentrix</h1>
      <p>Multi-Cloud Security Dashboard</p>
    </div>
  </div>
  <div class="hstats">
    <div class="hstat">
      <span class="val counter" data-target="{len(active)}">{len(active)}</span>
      <div class="lbl">Clouds</div>
    </div>
    <div class="hstat">
      <span class="val danger counter" data-target="{total_critical}">0</span>
      <div class="lbl">Critical</div>
    </div>
    <div class="hstat">
      <span class="val counter" data-target="{total_findings}">0</span>
      <div class="lbl">Findings</div>
    </div>
  </div>
</header>

<!-- Score Cards -->
<div class="section reveal">
  <div class="section-title">Security Score by Cloud</div>
  <div class="score-grid">{score_cards}</div>
</div>

<!-- Charts -->
<div class="section reveal">
  <div class="section-title">Risk Comparison</div>
  <div class="charts-grid">
    <div class="chart-card">
      <div class="chart-title">Security Scores</div>
      <canvas id="scoreChart"></canvas>
    </div>
    <div class="chart-card">
      <div class="chart-title">Findings by Severity</div>
      <canvas id="severityChart"></canvas>
    </div>
  </div>
</div>

<!-- Severity Table -->
<div class="section reveal">
  <div class="section-title">Severity Breakdown</div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Severity</th>{cloud_headers}<th>Total</th></tr></thead>
      <tbody>{sev_rows}</tbody>
    </table>
  </div>
</div>

<!-- All Findings -->
<div class="section reveal">
  <div class="section-title">All Findings — {total_findings} total</div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Cloud</th><th>Rule</th><th>Title</th><th>Severity</th><th>Principal</th><th>MITRE</th></tr></thead>
      <tbody>{finding_rows}</tbody>
    </table>
  </div>
</div>

<footer>
  Generated by <strong>CloudSentrix</strong> &nbsp;·&nbsp;
  <a href="https://github.com/Talha-Imran-cloud/cloudsentrix" target="_blank">github.com/Talha-Imran-cloud/cloudsentrix</a>
  &nbsp;·&nbsp; Built by <a href="https://www.linkedin.com/in/talha-imran-583a44420" target="_blank">Talha Imran</a>
</footer>

<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<script>
/* Mouse Trail */
const canvas=document.getElementById('trail');
const ctx=canvas.getContext('2d');
function resize(){{canvas.width=window.innerWidth;canvas.height=window.innerHeight;}}
resize();window.addEventListener('resize',resize);
const pts=[];
document.addEventListener('mousemove',e=>{{pts.push({{x:e.clientX,y:e.clientY,t:Date.now()}});document.getElementById('cur').style.left=e.clientX+'px';document.getElementById('cur').style.top=e.clientY+'px';}});
(function draw(){{
  ctx.clearRect(0,0,canvas.width,canvas.height);
  const now=Date.now();
  while(pts.length>0&&now-pts[0].t>600)pts.shift();
  if(pts.length>1){{
    for(let i=1;i<pts.length;i++){{
      const prog=i/pts.length,alpha=prog*0.35,w=prog*2;
      ctx.beginPath();ctx.moveTo(pts[i-1].x,pts[i-1].y);ctx.lineTo(pts[i].x,pts[i].y);
      ctx.strokeStyle=`rgba(220,220,220,${{alpha}})`;ctx.lineWidth=w;
      ctx.lineCap='round';ctx.stroke();
    }}
  }}
  requestAnimationFrame(draw);
}})();

/* Particles */
(function(){{
  const colors=['#4285f4','#ff9900','#0078d4','#F4F4F4','#888888'];
  const p=document.getElementById('particles');
  for(let i=0;i<20;i++){{
    const el=document.createElement('div');
    el.className='particle';
    const s=Math.random()*4+2;
    el.style.cssText=`width:${{s}}px;height:${{s}}px;background:${{colors[i%colors.length]}};left:${{Math.random()*100}}%;animation-duration:${{Math.random()*20+15}}s;animation-delay:-${{Math.random()*15}}s;`;
    p.appendChild(el);
  }}
}})();

/* Scroll reveal */
const obs=new IntersectionObserver(e=>{{e.forEach(x=>{{if(x.isIntersecting){{x.target.classList.add('visible');obs.unobserve(x.target);}}}});}},{{threshold:.12}});
document.querySelectorAll('.reveal').forEach(el=>obs.observe(el));

/* Counter */
const cobs=new IntersectionObserver(e=>{{e.forEach(x=>{{if(x.isIntersecting){{animCounter(x.target);cobs.unobserve(x.target);}}}});}},{{threshold:.5}});
document.querySelectorAll('.counter').forEach(el=>cobs.observe(el));
function animCounter(el){{
  const target=parseInt(el.dataset.target)||0;
  const dur=1600,s=performance.now();
  (function go(now){{
    const p=Math.min((now-s)/dur,1),e=1-Math.pow(1-p,3);
    el.textContent=Math.round(e*target);
    if(p<1)requestAnimationFrame(go);
  }})(s);
}}

/* Score bars */
const bobs=new IntersectionObserver(e=>{{e.forEach(x=>{{if(x.isIntersecting){{const b=x.target.querySelector('.score-bar');if(b)setTimeout(()=>b.style.width=b.dataset.width+'%',200);bobs.unobserve(x.target);}}}});}},{{threshold:.3}});
document.querySelectorAll('.score-card').forEach(el=>bobs.observe(el));

/* Finding rows stagger */
document.querySelectorAll('.finding-row').forEach((r,i)=>{{r.style.animationDelay=(i*0.03)+'s';}});

/* Charts */
Chart.defaults.color='#505050';
Chart.defaults.borderColor='#202020';
Chart.defaults.font.family='Inter';

new Chart(document.getElementById('scoreChart'),{{
  type:'bar',
  data:{{
    labels:{chart_labels},
    datasets:[{{
      label:'Score',data:{chart_scores},
      backgroundColor:{chart_colors}.map(c=>c+'22'),
      borderColor:{chart_colors},
      borderWidth:1.5,borderRadius:4,borderSkipped:false,
    }}]
  }},
  options:{{
    responsive:true,
    animation:{{duration:1200,easing:'easeOutQuart'}},
    plugins:{{legend:{{display:false}}}},
    scales:{{
      y:{{min:0,max:100,grid:{{color:'#161616'}},ticks:{{color:'#505050',font:{{size:11}}}}}},
      x:{{grid:{{display:false}},ticks:{{color:'#888888',font:{{size:11}}}}}}
    }}
  }}
}});

new Chart(document.getElementById('severityChart'),{{
  type:'bar',
  data:{{
    labels:{chart_labels},
    datasets:[
      {{label:'Critical',data:{chart_critical},backgroundColor:'rgba(255,68,68,.15)',borderColor:'#FF4444',borderWidth:1.5,borderRadius:3}},
      {{label:'High',    data:{chart_high},   backgroundColor:'rgba(255,136,0,.15)', borderColor:'#FF8800',borderWidth:1.5,borderRadius:3}},
      {{label:'Medium',  data:{chart_medium}, backgroundColor:'rgba(255,204,0,.15)', borderColor:'#FFCC00',borderWidth:1.5,borderRadius:3}},
      {{label:'Low',     data:{chart_low},    backgroundColor:'rgba(68,204,68,.15)', borderColor:'#44CC44',borderWidth:1.5,borderRadius:3}},
    ]
  }},
  options:{{
    responsive:true,
    animation:{{duration:1400,easing:'easeOutQuart'}},
    plugins:{{legend:{{labels:{{color:'#888888',font:{{size:11}}}}}}}},
    scales:{{
      y:{{grid:{{color:'#161616'}},ticks:{{color:'#505050',font:{{size:11}}}}}},
      x:{{grid:{{display:false}},ticks:{{color:'#888888',font:{{size:11}}}}}}
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
