# CloudSentrix 🔐

**GCP IAM Privilege-Escalation Attack-Path Analyzer**

CloudSentrix is a free, open-source command-line tool that scans Google Cloud Platform IAM policy exports for privilege-escalation risks, generates interactive attack-path graphs, scores your security posture, and produces client-ready PDF reports — all without any paid APIs.

[![CI](https://github.com/Talha-Imran-cloud/cloudsentrix/actions/workflows/ci.yml/badge.svg)](https://github.com/Talha-Imran-cloud/cloudsentrix/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/cloudsentrix)](https://pypi.org/project/cloudsentrix/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-144%20passed-brightgreen)](tests/)

---

## What It Does

- **Detects** 5 GCP IAM privilege-escalation patterns (mapped to MITRE ATT&CK Cloud Matrix)
- **Scores** your project's security posture from 0–100
- **Calculates blast radius** — if one account is compromised, how much can an attacker reach?
- **Generates remediation** — exact `gcloud` CLI commands to fix each finding
- **Exports** results as JSON, CSV, SARIF, Interactive HTML Dashboard, or client-ready PDF
- **Live scanning** — fetch and scan a live GCP project directly (no file needed)
- **Watches** a folder and auto-rescans whenever an IAM file changes
- **AI summaries** — plain-language executive summaries via Google Gemini

---

## Requirements

- Python 3.10 or higher
- pip

---

## Installation

### ⚡ Recommended — Install via pip (easiest)

```bash
pip install cloudsentrix
```

That's it. No cloning, no virtual env setup needed.

### Alternative — Install from source

#### Windows

```powershell
git clone https://github.com/Talha-Imran-cloud/cloudsentrix.git
cd cloudsentrix
python -m venv venv
venv\Scripts\activate
pip install -e .
```

#### Linux / macOS (Kali, Ubuntu, Debian)

```bash
git clone https://github.com/Talha-Imran-cloud/cloudsentrix.git
cd cloudsentrix
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

### Verify installation

```bash
cloudsentrix --version
```

---

## Getting Your GCP IAM Policy File

```bash
gcloud projects get-iam-policy YOUR_PROJECT_ID --format=json > my_project_iam.json
```

Two sample files are included for testing:
- `sample_data/sample_gcp_iam.json` — basic 5-principal example
- `sample_data/demo_enterprise_iam.json` — realistic enterprise scenario

---

## Commands

### `scan` — Full pipeline scan
```bash
cloudsentrix scan --file sample_data/sample_gcp_iam.json
cloudsentrix scan --file my_project.json --severity high
cloudsentrix scan --file my_project.json --top 10
```

### `live-scan` — Scan a live GCP project directly ⚡ NEW
```bash
# Requires: gcloud CLI authenticated
gcloud auth application-default login

# Fetch and scan live IAM policy
cloudsentrix live-scan --project my-gcp-project-id

# Scan and save the fetched policy
cloudsentrix live-scan --project my-gcp-project-id --save fetched_policy.json

# Filter by severity
cloudsentrix live-scan --project my-gcp-project-id --severity critical
```

### `blast-radius` — Blast radius for one principal
```bash
cloudsentrix blast-radius --file my_project.json --principal admin@company.com
```

### `principal-path` — Escalation path between two principals
```bash
cloudsentrix principal-path --file my_project.json \
  --source intern@company.com \
  --target app-backend@my-project.iam.gserviceaccount.com
```

### `mitre-map` — Map findings to MITRE ATT&CK Cloud Matrix
```bash
cloudsentrix mitre-map --file my_project.json
```

### `remediate` — Generate exact gcloud fix commands
```bash
cloudsentrix remediate --file my_project.json
cloudsentrix remediate --file my_project.json --project my-real-project-id
cloudsentrix remediate --file my_project.json --severity critical
```

### `score` — Security score only (for CI/CD badges)
```bash
cloudsentrix score --file my_project.json
cloudsentrix score --file my_project.json --json
cloudsentrix score --file my_project.json --min-score 70
```

### `validate` — Check file format before scanning
```bash
cloudsentrix validate --file my_project.json
```

### `compare` — Compare two IAM exports (detect new risks)
```bash
cloudsentrix compare --old january.json --new february.json
```

### `export` — Export results to JSON, CSV, HTML, or SARIF
```bash
# JSON export
cloudsentrix export --file my_project.json --output report.json

# CSV export
cloudsentrix export --file my_project.json --output report.csv

# Interactive HTML Dashboard (open in browser)
cloudsentrix export --file my_project.json --output dashboard.html

# SARIF export (GitHub Code Scanning compatible) ⚡ NEW
cloudsentrix export --file my_project.json --output results.sarif
```

**Opening the HTML Dashboard:**

Windows:
```powershell
start dashboard.html
```

Linux / macOS:
```bash
xdg-open dashboard.html
```

The HTML dashboard includes:
- Security score card
- Finding counts by severity
- **Interactive attack graph** (drag nodes, scroll to zoom, hover for details)
- Full findings table with MITRE mapping
- Blast radius table

### `report` — Generate a client-ready PDF report
```bash
# Without AI summary
cloudsentrix report --file my_project.json --output my_report.pdf --no-ai

# With Gemini AI summary (set API key first — see below)
cloudsentrix report --file my_project.json --output my_report.pdf
```

### `watch` — Auto-rescan when file changes
```bash
# Watch a single file
cloudsentrix watch --path my_project.json

# Watch a folder (rescans any .json file that changes)
cloudsentrix watch --path /path/to/iam/exports/

# Custom poll interval (seconds)
cloudsentrix watch --path my_project.json --interval 5
```

Press `Ctrl+C` to stop watching.

### `rules` — List all detection rules
```bash
cloudsentrix rules
```

### `list-principals` — List all principals and their roles
```bash
cloudsentrix list-principals --file my_project.json
```

---

## SARIF Export — GitHub Code Scanning ⚡ NEW

SARIF (Static Analysis Results Interchange Format) output is compatible with:
- **GitHub Code Scanning** — upload directly to your repo's Security tab
- **VS Code SARIF Viewer** extension
- **Azure DevOps** security dashboards
- Any SARIF 2.1.0-compatible tool

```bash
cloudsentrix export --file my_project.json --output results.sarif
```

Upload to GitHub:
```bash
gh api repos/OWNER/REPO/code-scanning/sarifs \
  -F sarif=@results.sarif \
  -F ref=refs/heads/main \
  -F commit_sha=$(git rev-parse HEAD)
```

---

## Gemini AI Summary (Optional)

The `report` command can generate a plain-language AI summary using Google Gemini.

**Step 1 — Get a free API key** from [Google AI Studio](https://aistudio.google.com/app/apikey)

**Step 2 — Set the environment variable:**

Windows:
```powershell
$env:GEMINI_API_KEY = "your_api_key_here"
```

Linux / macOS:
```bash
export GEMINI_API_KEY="your_api_key_here"
```

**Step 3 — Run:**
```bash
cloudsentrix report --file my_project.json --output report.pdf
```

If no API key is set, a built-in template summary is used automatically.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success, no CRITICAL findings |
| `1` | CRITICAL findings detected (use this to fail CI pipelines) |
| `2` | Command could not complete (bad file, wrong format, etc.) |

---

## Detection Rules

| Rule | Title | Severity | MITRE |
|------|-------|----------|-------|
| GCP-001 | Publicly Accessible Role Binding | CRITICAL | T1078.004 |
| GCP-002 | Service Account Token Creator | CRITICAL | T1098.001 |
| GCP-003 | Service Account Key Admin | CRITICAL | T1098.001 |
| GCP-004 | IAM Policy Administrator | CRITICAL | T1098.003 |
| GCP-005 | Service Account Impersonation via Resource Attach | HIGH | T1548.005 |

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

Expected output: `144 passed`

---

## Project Structure

```
cloudsentrix/
├── src/
│   ├── cli.py              # CLI entry point (15 commands)
│   ├── parser.py           # GCP IAM JSON parser
│   ├── graph.py            # IAM permission graph engine
│   ├── detection.py        # Privilege-escalation detection rules
│   ├── risk_score.py       # 0-100 security scoring engine
│   ├── blast_radius.py     # Attack-path blast radius calculator
│   ├── watch_handler.py    # File system watcher
│   ├── live_scanner.py     # Live GCP project scanner
│   ├── pdf_report.py       # PDF report generator
│   └── ai_summary.py       # Gemini AI summary integration
├── tests/                  # 144 pytest tests
├── sample_data/
│   ├── sample_gcp_iam.json         # Basic test file
│   └── demo_enterprise_iam.json    # Realistic enterprise demo
├── .github/workflows/ci.yml        # GitHub Actions CI
├── .github/workflows/publish.yml   # PyPI auto-publish
├── pyproject.toml                  # Packaging configuration
└── README.md
```

---

## Roadmap 🗺️

### Coming Soon

| Feature | Description | Status |
|---------|-------------|--------|
| **AWS Support** | Scan AWS IAM policies — detect privilege escalation via `iam:PassRole`, `sts:AssumeRole`, admin policies | 🔄 Planned |
| **Azure Support** | Scan Azure RBAC — detect Owner/Contributor abuse, service principal risks | 🔄 Planned |
| **Multi-Cloud Dashboard** | Single HTML dashboard comparing GCP, AWS, Azure risk side by side | 🔄 Planned |
| **Slack / Teams Alerts** | Send findings to Slack or Microsoft Teams webhook automatically | 🔄 Planned |
| **PDF Multi-Project** | One PDF report covering multiple GCP projects at once | 🔄 Planned |

### AWS Support (Preview)

When AWS support ships, usage will look like:
```bash
# Export AWS IAM data
aws iam get-account-authorization-details --output json > aws_iam.json

# Scan AWS
cloudsentrix scan --file aws_iam.json --cloud aws
```

### Azure Support (Preview)

```bash
# Export Azure RBAC
az role assignment list --all --output json > azure_rbac.json

# Scan Azure
cloudsentrix scan --file azure_rbac.json --cloud azure
```

---

## License

MIT License — free to use, modify, and distribute.

---

## Author

**Talha Imran** — SOC Analyst | Cloud Security | Pentesting

[![GitHub](https://img.shields.io/badge/GitHub-Talha--Imran--cloud-black)](https://github.com/Talha-Imran-cloud)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://linkedin.com/in/talha-imran)
[![PyPI](https://img.shields.io/pypi/v/cloudsentrix?label=PyPI)](https://pypi.org/project/cloudsentrix/)
