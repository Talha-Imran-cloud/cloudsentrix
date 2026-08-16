"""
web_server.py
-------------
CloudSentrix Local Web Dashboard — Flask Server

Serves an interactive browser-based dashboard for CloudSentrix.
Users can upload IAM files, scan them, and view results in browser.

Usage:
    cloudsentrix serve
    cloudsentrix serve --port 8080
    cloudsentrix serve --host 0.0.0.0 --port 5000

Then open: http://localhost:5000
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import webbrowser
from pathlib import Path

# ---------------------------------------------------------------------------
# Check Flask
# ---------------------------------------------------------------------------

def _check_flask():
    try:
        import flask
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Scan helper
# ---------------------------------------------------------------------------

def _run_scan(file_path: str, cloud: str) -> dict:
    """Run scan and return JSON-serializable results."""
    _here = os.path.dirname(os.path.abspath(__file__))
    if _here not in sys.path:
        sys.path.insert(0, _here)

    try:
        if cloud == "aws":
            from aws_parser import AWSIAMParser
            from aws_graph import AWSIAMGraph
            from aws_detection import AWSDetectionEngine
            from aws_blast_radius import calculate_aws_blast_radius
            from risk_score import RiskScorer
            from detection import Finding as GF, Severity as GS

            policy   = AWSIAMParser().parse_file(file_path)
            graph    = AWSIAMGraph.from_policy(policy)
            findings = AWSDetectionEngine().run(graph)
            gcp_f    = [GF(rule_id=f.rule_id, title=f.title,
                           severity=GS(int(f.severity)),
                           principal_id=f.principal_id,
                           description=f.description,
                           mitre_technique_id=f.mitre_technique_id,
                           mitre_technique_name=f.mitre_technique_name,
                           evidence=f.evidence) for f in findings]
            risk     = RiskScorer().score(gcp_f)
            blast    = calculate_aws_blast_radius(graph, findings)
            stats    = policy.summary()
            principals = stats["total_principals"]

        elif cloud == "azure":
            from azure_parser import parse_azure_file
            from azure_detection import run_azure_detections
            from azure_risk_score import score_azure
            from azure_blast_radius import calculate_azure_blast_radius
            from risk_score import RiskScorer
            from detection import Finding as GF, Severity as GS

            iam      = parse_azure_file(file_path)
            az_f     = run_azure_detections(iam)
            score    = score_azure(az_f, iam)
            blast    = calculate_azure_blast_radius(iam)
            sev_map  = {"CRITICAL": GS.CRITICAL, "HIGH": GS.HIGH,
                        "MEDIUM": GS.MEDIUM, "LOW": GS.LOW}
            gcp_f    = [GF(rule_id=f.rule_id, title=f.title,
                           severity=sev_map.get(f.severity, GS.LOW),
                           principal_id=f.principal_name,
                           description=f.description,
                           mitre_technique_id=f.mitre_technique,
                           mitre_technique_name=f.mitre_tactic,
                           evidence=(f.role,)) for f in az_f]
            risk     = RiskScorer().score(gcp_f)
            unique   = {a.principal_name for a in iam.assignments}
            principals = len(unique)
            findings = gcp_f

        elif cloud == "azure-ad":
            from azure_ad_parser import parse_azure_ad_file
            from azure_ad_detection import run_azure_ad_detections
            from risk_score import RiskScorer
            from detection import Finding as GF, Severity as GS

            sev_map = {"CRITICAL": GS.CRITICAL, "HIGH": GS.HIGH,
                       "MEDIUM": GS.MEDIUM, "LOW": GS.LOW}

            ad_data    = parse_azure_ad_file(file_path)
            ad_findings = run_azure_ad_detections(ad_data)

            gcp_f = []
            for f in ad_findings:
                gcp_f.append(GF(
                    rule_id=f.rule_id,
                    title=f.title,
                    severity=sev_map.get(f.severity, GS.LOW),
                    principal_id=f.principal_name,
                    description=f.description,
                    mitre_technique_id=f.mitre_technique,
                    mitre_technique_name=f.mitre_tactic,
                    evidence=f.evidence,
                ))
            risk     = RiskScorer().score(gcp_f)
            blast    = []
            findings = gcp_f
            principals = (len(ad_data.apps) if hasattr(ad_data, "apps") else
                          len(ad_data.service_principals) if hasattr(ad_data, "service_principals") else
                          len(gcp_f))

        else:  # gcp
            from parser import GCPIAMParser
            from graph import IAMGraph
            from detection import DetectionEngine
            from risk_score import RiskScorer
            from blast_radius import BlastRadiusCalculator

            policy   = GCPIAMParser().parse_file(file_path)
            graph    = IAMGraph.from_policy(policy)
            findings = DetectionEngine().run(graph)
            risk     = RiskScorer().score(findings)
            blast    = BlastRadiusCalculator(graph, findings).calculate_all()
            principals = len(graph.principal_ids())
            gcp_f    = findings

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        finding_list = []
        for f in gcp_f:
            sev = f.severity.name if hasattr(f.severity, "name") else str(f.severity)
            counts[sev] = counts.get(sev, 0) + 1
            finding_list.append({
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": sev,
                "principal": f.principal_id if hasattr(f, "principal_id") else getattr(f, "principal_name", ""),
                "mitre": f.mitre_technique_id if hasattr(f, "mitre_technique_id") else "",
                "description": f.description,
            })

        blast_list = []
        for b in (blast or [])[:10]:
            if hasattr(b, "blast_score"):
                pct = getattr(b, "percentage", None) or getattr(b, "blast_score", 0)
                blast_list.append({"principal": getattr(b, "principal_name", getattr(b, "principal_id", "")),
                                   "score": b.blast_score,
                                   "level": getattr(b, "blast_level", "High" if pct > 50 else "Medium"),
                                   "percentage": pct})
            else:
                pct = getattr(b, "percentage", 0)
                blast_list.append({"principal": getattr(b, "principal_id", ""),
                                   "score": int(pct),
                                   "level": "High" if pct > 50 else "Medium",
                                   "percentage": pct})

        return {
            "success": True,
            "cloud": cloud.upper(),
            "score": risk.score,
            "rating": risk.rating.value if hasattr(risk.rating, "value") else str(risk.rating),
            "principals": principals,
            "total_findings": len(finding_list),
            "counts": counts,
            "findings": finding_list,
            "blast_radius": blast_list,
        }

    except Exception as exc:
        return {"success": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

def create_app() -> "flask.Flask":
    from flask import Flask, request, jsonify, send_from_directory

    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50MB

    DASHBOARD_HTML = _build_dashboard_html()

    @app.route("/")
    def index():
        from flask import Response
        return Response(DASHBOARD_HTML, mimetype="text/html")

    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        if "file" not in request.files:
            return jsonify({"success": False, "error": "No file uploaded"}), 400

        f    = request.files["file"]
        cloud= request.form.get("cloud", "gcp").lower()

        if not f.filename:
            return jsonify({"success": False, "error": "Empty filename"}), 400

        # Save to temp file
        suffix = ".json"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            f.save(tmp.name)
            tmp_path = tmp.name

        try:
            result = _run_scan(tmp_path, cloud)
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

        return jsonify(result)

    @app.route("/api/health")
    def health():
        return jsonify({"status": "ok", "version": "2.0.0"})

    return app


# ---------------------------------------------------------------------------
# HTML Dashboard
# ---------------------------------------------------------------------------

def _build_dashboard_html() -> str:
    return '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>CloudSentrix — Local Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@100..900&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<style>
:root{--bg:#070707;--s0:#0B0B0B;--s1:#101010;--s2:#161616;--s3:#1E1E1E;--bd:#202020;--bdb:#303030;--w:#F4F4F4;--w2:#C0C0C0;--w3:#888888;--w4:#505050;--crit:#FF4444;--high:#FF8800;--med:#FFCC00;--low:#44CC44;}
*{box-sizing:border-box;margin:0;padding:0;}
html{scroll-behavior:smooth;}
body{background:var(--bg);color:var(--w);font-family:'Inter',sans-serif;min-height:100vh;cursor:none;overflow-x:hidden;}
::-webkit-scrollbar{width:3px;}::-webkit-scrollbar-track{background:var(--bg);}::-webkit-scrollbar-thumb{background:var(--bdb);}
#trail{position:fixed;top:0;left:0;pointer-events:none;z-index:9990;}
#cur{position:fixed;width:8px;height:8px;background:var(--w);border-radius:50%;pointer-events:none;z-index:9999;transform:translate(-50%,-50%);mix-blend-mode:difference;transition:transform .1s;}
.grid-bg{position:fixed;inset:0;pointer-events:none;z-index:0;background-image:linear-gradient(rgba(255,255,255,.015) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.015) 1px,transparent 1px);background-size:72px 72px;}

/* Header */
header{position:relative;z-index:10;padding:32px 48px;border-bottom:1px solid var(--bd);background:var(--s0);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:20px;}
.logo{display:flex;align-items:center;gap:14px;}
.logo-icon{width:36px;height:36px;background:var(--s3);border:1px solid var(--bdb);border-radius:10px;display:flex;align-items:center;justify-content:center;animation:float 4s ease-in-out infinite;}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-5px)}}
.logo h1{font-size:18px;font-weight:900;letter-spacing:-1px;}
.logo p{font-size:10px;color:var(--w4);font-weight:600;letter-spacing:.5px;text-transform:uppercase;margin-top:2px;}
.version-badge{font-size:10px;font-family:'JetBrains Mono',monospace;background:var(--s3);border:1px solid var(--bd);color:var(--w4);padding:4px 10px;border-radius:4px;}

/* Upload Zone */
.upload-zone{position:relative;z-index:10;margin:48px;border:1px dashed var(--bdb);border-radius:20px;padding:64px 48px;text-align:center;background:var(--s0);transition:all .3s;cursor:pointer;}
.upload-zone:hover,.upload-zone.drag-over{border-color:var(--w4);background:var(--s1);}
.upload-zone.drag-over{border-color:var(--w3);transform:scale(1.01);}
.upload-icon{font-size:48px;margin-bottom:20px;animation:float 3s ease-in-out infinite;}
.upload-zone h2{font-size:20px;font-weight:800;letter-spacing:-1px;margin-bottom:8px;}
.upload-zone p{font-size:13px;color:var(--w4);margin-bottom:28px;}
.cloud-tabs{display:flex;gap:8px;justify-content:center;margin-bottom:28px;flex-wrap:wrap;}
.cloud-tab{padding:8px 20px;border-radius:8px;font-size:12px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;cursor:pointer;border:1px solid var(--bd);background:var(--s2);color:var(--w4);transition:all .2s;}
.cloud-tab.active{background:var(--w);color:var(--bg);border-color:var(--w);}
.upload-btn{background:var(--w);color:var(--bg);border:none;padding:12px 32px;border-radius:8px;font-size:13px;font-weight:800;letter-spacing:.5px;cursor:pointer;transition:all .2s;}
.upload-btn:hover{opacity:.85;transform:translateY(-1px);}
#file-input{display:none;}
.file-name{font-size:11px;color:var(--w4);font-family:'JetBrains Mono',monospace;margin-top:12px;min-height:16px;}

/* Loading */
.loading{display:none;position:relative;z-index:10;text-align:center;padding:64px;margin:0 48px;}
.loading.show{display:block;}
.spinner{width:40px;height:40px;border:2px solid var(--s3);border-top-color:var(--w);border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 24px;}
@keyframes spin{to{transform:rotate(360deg)}}
.loading p{color:var(--w4);font-size:13px;font-family:'JetBrains Mono',monospace;}

/* Results */
.results{display:none;position:relative;z-index:10;}
.results.show{display:block;}

/* Score row */
.score-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1px;background:var(--bd);margin:0 48px;border:1px solid var(--bd);border-radius:16px;overflow:hidden;}
.score-card{background:var(--s1);padding:32px 28px;transition:background .2s;}
.score-card:hover{background:var(--s2);}
.score-card .lbl{font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:var(--w4);margin-bottom:12px;}
.score-card .val{font-size:40px;font-weight:900;letter-spacing:-2px;line-height:1;}
.score-card .sub{font-size:11px;color:var(--w4);margin-top:8px;}
.score-bar-bg{background:var(--s3);border-radius:2px;height:2px;margin-top:14px;overflow:hidden;}
.score-bar-fill{height:2px;border-radius:2px;width:0;transition:width 1.5s cubic-bezier(.4,0,.2,1);}

/* Section */
.section{padding:40px 48px 0;}
.section-title{font-size:10px;font-weight:700;letter-spacing:3px;text-transform:uppercase;color:var(--w4);margin-bottom:20px;display:flex;align-items:center;gap:12px;}
.section-title::after{content:'';flex:1;height:1px;background:var(--bd);}

/* Findings table */
.table-wrap{background:var(--s1);border:1px solid var(--bd);border-radius:14px;overflow:hidden;}
table{width:100%;border-collapse:collapse;font-size:12px;}
th{background:var(--s0);padding:10px 16px;text-align:left;border-bottom:1px solid var(--bd);font-size:10px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:var(--w4);}
td{padding:10px 16px;border-bottom:1px solid var(--bd);transition:background .15s;}
tr:last-child td{border-bottom:none;}
tr:hover td{background:var(--s2);}
.badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:10px;font-weight:700;font-family:'JetBrains Mono',monospace;}
.badge.CRITICAL{background:rgba(255,68,68,.1);border:1px solid rgba(255,68,68,.2);color:var(--crit);}
.badge.HIGH{background:rgba(255,136,0,.1);border:1px solid rgba(255,136,0,.2);color:var(--high);}
.badge.MEDIUM{background:rgba(255,204,0,.1);border:1px solid rgba(255,204,0,.2);color:var(--med);}
.badge.LOW{background:rgba(68,204,68,.1);border:1px solid rgba(68,204,68,.2);color:var(--low);}
code{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--w3);}

/* Blast radius */
.blast-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:1px;background:var(--bd);border:1px solid var(--bd);border-radius:14px;overflow:hidden;}
.blast-card{background:var(--s1);padding:20px 24px;transition:background .2s;}
.blast-card:hover{background:var(--s2);}
.blast-name{font-size:12px;font-family:'JetBrains Mono',monospace;color:var(--w2);margin-bottom:8px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.blast-score-bar{background:var(--s3);border-radius:2px;height:3px;margin:6px 0;}
.blast-score-fill{height:3px;border-radius:2px;transition:width 1s ease;}
.blast-meta{font-size:10px;color:var(--w4);}

/* New scan button */
.new-scan-btn{background:var(--s1);border:1px solid var(--bd);color:var(--w3);padding:10px 24px;border-radius:8px;font-size:12px;font-weight:700;cursor:pointer;transition:all .2s;margin:40px 48px;display:inline-block;}
.new-scan-btn:hover{background:var(--s2);color:var(--w);}

/* Error */
.error-box{background:rgba(255,68,68,.05);border:1px solid rgba(255,68,68,.15);border-radius:14px;padding:24px;margin:0 48px;color:var(--crit);font-size:13px;display:none;}
.error-box.show{display:block;}

footer{position:relative;z-index:10;padding:24px 48px;border-top:1px solid var(--bd);background:var(--s0);text-align:center;font-size:11px;color:var(--w4);margin-top:48px;}
footer a{color:var(--w3);text-decoration:none;}
footer a:hover{color:var(--w);}

.reveal{opacity:0;transform:translateY(16px);transition:opacity .6s ease,transform .6s ease;}
.reveal.visible{opacity:1;transform:translateY(0);}
</style>
</head>
<body>
<canvas id="trail"></canvas>
<div id="cur"></div>
<div class="grid-bg"></div>

<header>
  <div class="logo">
    <div class="logo-icon">
      <svg width="18" height="12" viewBox="0 0 100 68" fill="none">
        <path d="M78 58H26C14.4 58 5 48.6 5 37s9.4-21 21-21c1.4 0 2.8.14 4.1.4C34.2 8.8 43.8 2 55 2c14.6 0 26.6 10.8 27.8 24.6C83.8 26.2 84.9 26 86 26c7.7 0 14 6.3 14 14s-6.3 14-14 14H78z" fill="url(#g)"/>
        <defs><linearGradient id="g" x1="5" y1="2" x2="100" y2="68" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#888"/><stop offset="1" stop-color="#444"/></linearGradient></defs>
      </svg>
    </div>
    <div>
      <h1>CloudSentrix</h1>
      <p>Local Security Dashboard</p>
    </div>
  </div>
  <span class="version-badge">v2.0.0 · localhost</span>
</header>

<!-- Upload Zone -->
<div class="upload-zone reveal" id="upload-zone">
  <div class="upload-icon">🔐</div>
  <h2>Drop your IAM file here</h2>
  <p>Upload a GCP, AWS, or Azure IAM policy export to scan for privilege-escalation risks</p>
  <div class="cloud-tabs">
    <div class="cloud-tab active" onclick="selectCloud('gcp', this)">☁️ GCP</div>
    <div class="cloud-tab" onclick="selectCloud('aws', this)">🟡 AWS</div>
    <div class="cloud-tab" onclick="selectCloud('azure', this)">🔷 Azure</div>
    <div class="cloud-tab" onclick="selectCloud('azure-ad', this)">🔷 Azure AD</div>
  </div>
  <input type="file" id="file-input" accept=".json" onchange="fileSelected(this)"/>
  <button class="upload-btn" onclick="document.getElementById('file-input').click()">Choose File</button>
  <div class="file-name" id="file-name">No file selected</div>
</div>

<!-- Loading -->
<div class="loading" id="loading">
  <div class="spinner"></div>
  <p>Scanning for privilege-escalation risks...</p>
</div>

<!-- Error -->
<div class="error-box" id="error-box"></div>

<!-- Results -->
<div class="results" id="results">
  <button class="new-scan-btn" onclick="resetScan()">← New Scan</button>

  <div class="score-row reveal" id="score-row"></div>

  <div class="section reveal">
    <div class="section-title">Findings</div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Rule</th><th>Title</th><th>Severity</th><th>Principal</th><th>MITRE</th></tr></thead>
        <tbody id="findings-body"></tbody>
      </table>
    </div>
  </div>

  <div class="section reveal" id="blast-section">
    <div class="section-title">Blast Radius</div>
    <div class="blast-grid" id="blast-grid"></div>
  </div>

  <div style="height:48px;"></div>
</div>

<footer>
  CloudSentrix v2.0.0 · Running locally ·
  <a href="https://github.com/Talha-Imran-cloud/cloudsentrix" target="_blank">GitHub</a> ·
  <a href="https://cloudsentrix.netlify.app" target="_blank">Website</a>
</footer>

<script>
/* Trail */
const canvas=document.getElementById("trail"),ctx=canvas.getContext("2d");
function resize(){canvas.width=innerWidth;canvas.height=innerHeight;}
resize();window.addEventListener("resize",resize);
const pts=[];
document.addEventListener("mousemove",e=>{
  pts.push({x:e.clientX,y:e.clientY,t:Date.now()});
  document.getElementById("cur").style.left=e.clientX+"px";
  document.getElementById("cur").style.top=e.clientY+"px";
});
(function draw(){
  ctx.clearRect(0,0,canvas.width,canvas.height);
  const now=Date.now();
  while(pts.length&&now-pts[0].t>600)pts.shift();
  if(pts.length>1){
    for(let i=1;i<pts.length;i++){
      const p=i/pts.length;
      ctx.beginPath();ctx.moveTo(pts[i-1].x,pts[i-1].y);ctx.lineTo(pts[i].x,pts[i].y);
      ctx.strokeStyle=`rgba(200,200,200,${p*.3})`;ctx.lineWidth=p*2;ctx.lineCap="round";ctx.stroke();
    }
  }
  requestAnimationFrame(draw);
})();

/* Scroll reveal */
const obs=new IntersectionObserver(e=>{e.forEach(x=>{if(x.isIntersecting){x.target.classList.add("visible");obs.unobserve(x.target);}});},{threshold:.1});
document.querySelectorAll(".reveal").forEach(el=>obs.observe(el));

/* Drag & drop */
const zone=document.getElementById("upload-zone");
zone.addEventListener("dragover",e=>{e.preventDefault();zone.classList.add("drag-over");});
zone.addEventListener("dragleave",()=>zone.classList.remove("drag-over"));
zone.addEventListener("drop",e=>{
  e.preventDefault();zone.classList.remove("drag-over");
  const f=e.dataTransfer.files[0];
  if(f){document.getElementById("file-input").files=e.dataTransfer.files;fileSelected({files:[f]});}
});

/* Cloud selection */
let selectedCloud="gcp";
function selectCloud(cloud,el){
  selectedCloud=cloud;
  document.querySelectorAll(".cloud-tab").forEach(t=>t.classList.remove("active"));
  el.classList.add("active");
}

/* File selected */
let selectedFile=null;
function fileSelected(input){
  const f=input.files[0];
  if(!f)return;
  selectedFile=f;
  document.getElementById("file-name").textContent=f.name+" ("+Math.round(f.size/1024)+" KB)";
  scanFile();
}

/* Scan */
async function scanFile(){
  if(!selectedFile)return;

  document.getElementById("upload-zone").style.display="none";
  document.getElementById("loading").classList.add("show");
  document.getElementById("error-box").classList.remove("show");
  document.getElementById("results").classList.remove("show");

  const form=new FormData();
  form.append("file",selectedFile);
  form.append("cloud",selectedCloud);

  try{
    const res=await fetch("/api/scan",{method:"POST",body:form});
    const data=await res.json();

    document.getElementById("loading").classList.remove("show");

    if(!data.success){
      document.getElementById("error-box").textContent="Error: "+data.error;
      document.getElementById("error-box").classList.add("show");
      document.getElementById("upload-zone").style.display="block";
      return;
    }

    renderResults(data);
  }catch(err){
    document.getElementById("loading").classList.remove("show");
    document.getElementById("error-box").textContent="Connection error: "+err.message;
    document.getElementById("error-box").classList.add("show");
    document.getElementById("upload-zone").style.display="block";
  }
}

/* Render */
function renderResults(d){
  const sc=d.score<40?"#FF4444":d.score<70?"#FF8800":"#44CC44";

  document.getElementById("score-row").innerHTML=`
    <div class="score-card"><div class="lbl">Security Score</div>
      <div class="val" style="color:${sc}" id="score-val">0</div>
      <div class="score-bar-bg"><div class="score-bar-fill" style="background:${sc}" id="score-bar"></div></div>
      <div class="sub">Rating: ${d.rating}</div></div>
    <div class="score-card"><div class="lbl">Total Findings</div>
      <div class="val">${d.total_findings}</div><div class="sub">Cloud: ${d.cloud}</div></div>
    <div class="score-card"><div class="lbl">Critical</div>
      <div class="val" style="color:#FF4444">${d.counts.CRITICAL||0}</div><div class="sub">Immediate action</div></div>
    <div class="score-card"><div class="lbl">High</div>
      <div class="val" style="color:#FF8800">${d.counts.HIGH||0}</div><div class="sub">Address soon</div></div>
    <div class="score-card"><div class="lbl">Principals</div>
      <div class="val">${d.principals}</div><div class="sub">Scanned</div></div>
  `;

  /* Animate score */
  let cur=0;const target=d.score;const dur=1500;const s=Date.now();
  (function go(){
    const p=Math.min((Date.now()-s)/dur,1),e=1-Math.pow(1-p,3);
    document.getElementById("score-val").textContent=Math.round(e*target);
    if(p<1)requestAnimationFrame(go);
    else setTimeout(()=>document.getElementById("score-bar").style.width=target+"%",100);
  })();

  /* Findings */
  const SEV=["CRITICAL","HIGH","MEDIUM","LOW"];
  const sorted=[...d.findings].sort((a,b)=>SEV.indexOf(a.severity)-SEV.indexOf(b.severity));
  document.getElementById("findings-body").innerHTML=sorted.map(f=>`
    <tr>
      <td><span class="badge ${f.severity}">${f.rule_id}</span></td>
      <td style="font-weight:600">${f.title}</td>
      <td><span class="badge ${f.severity}">${f.severity}</span></td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#888;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${f.principal||"-"}</td>
      <td><code>${f.mitre||"-"}</code></td>
    </tr>`).join("")||"<tr><td colspan='5' style='color:#505050;padding:20px'>No findings detected ✅</td></tr>";

  /* Blast radius */
  if(d.blast_radius&&d.blast_radius.length){
    document.getElementById("blast-section").style.display="block";
    document.getElementById("blast-grid").innerHTML=d.blast_radius.map(b=>`
      <div class="blast-card">
        <div class="blast-name">${b.principal}</div>
        <div class="blast-score-bar"><div class="blast-score-fill" style="width:${b.percentage}%;background:${b.percentage>75?"#FF4444":b.percentage>50?"#FF8800":"#888"}"></div></div>
        <div class="blast-meta">${b.level} · ${b.percentage}% reachable</div>
      </div>`).join("");
  }else{
    document.getElementById("blast-section").style.display="none";
  }

  document.getElementById("results").classList.add("show");
  setTimeout(()=>{
    document.querySelectorAll(".results .reveal").forEach(el=>{
      el.classList.add("visible");obs.observe(el);
    });
  },100);
}

function resetScan(){
  selectedFile=null;
  document.getElementById("upload-zone").style.display="block";
  document.getElementById("results").classList.remove("show");
  document.getElementById("file-name").textContent="No file selected";
  document.getElementById("file-input").value="";
  window.scrollTo(0,0);
}
</script>
</body>
</html>'''


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def run_server(host: str = "127.0.0.1", port: int = 5000, debug: bool = False) -> None:
    if not _check_flask():
        print("\n[cloudsentrix] Flask not installed. Run:")
        print("    pip install flask")
        print("Then run: cloudsentrix serve\n")
        sys.exit(1)

    app = create_app()

    url = f"http://{host}:{port}"
    print(f"\n  🔐 CloudSentrix Local Dashboard")
    print(f"  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"  Running at: {url}")
    print(f"  Press Ctrl+C to stop\n")

    # Auto-open browser after short delay
    def _open():
        import time
        time.sleep(1.2)
        webbrowser.open(url)

    threading.Thread(target=_open, daemon=True).start()

    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    run_server()
