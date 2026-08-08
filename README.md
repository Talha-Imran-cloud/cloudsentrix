# CloudSentrix 🔐

**Multi-Cloud IAM Privilege-Escalation Attack-Path Analyzer**

CloudSentrix is a free, open-source command-line tool that scans **GCP and AWS** IAM policy exports for privilege-escalation risks, generates interactive attack-path graphs, scores your security posture, and produces client-ready PDF reports — all without any paid APIs.

[![CI](https://github.com/Talha-Imran-cloud/cloudsentrix/actions/workflows/ci.yml/badge.svg)](https://github.com/Talha-Imran-cloud/cloudsentrix/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/cloudsentrix)](https://pypi.org/project/cloudsentrix/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-144%20passed-brightgreen)](tests/)

---

## What It Does

### GCP Support
- **Detects** 5 GCP IAM privilege-escalation patterns (mapped to MITRE ATT&CK Cloud Matrix)
- **Calculates blast radius** — if one account is compromised, how much can an attacker reach?
- **Generates remediation** — exact `gcloud` CLI commands to fix each finding
- **Live scanning** — fetch and scan a live GCP project directly (no file needed)

### AWS Support ⚡ NEW
- **Detects** 7 AWS IAM privilege-escalation patterns including `iam:PassRole`, `sts:AssumeRole`, backdoor user creation
- **Live scanning** — fetch and scan a live AWS account directly via boto3
- **LocalStack support** — test without a real AWS account (free, runs locally)

### Both Clouds
- **Scores** your security posture from 0–100
- **Exports** results as JSON, CSV, SARIF, Interactive HTML Dashboard, or client-ready PDF
- **Watches** a folder and auto-rescans whenever an IAM file changes
- **AI summaries** — plain-language executive summaries via Google Gemini

---

## Requirements

- Python 3.10 or higher
- pip
- For AWS live scan: `pip install boto3`

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

## Getting Your IAM Policy File

### GCP
```bash
gcloud projects get-iam-policy YOUR_PROJECT_ID --format=json > my_project_iam.json
```

### AWS ⚡ NEW
```bash
aws iam get-account-authorization-details --output json > aws_iam.json
```

Sample files included for testing:
- `sample_data/sample_gcp_iam.json` — GCP basic example
- `sample_data/demo_enterprise_iam.json` — GCP enterprise scenario
- `sample_data/sample_aws_iam.json` — AWS example with 7 escalation risks ⚡ NEW

---

## Commands

### `scan` — Full pipeline scan

```bash
# GCP (default)
cloudsentrix scan --file sample_data/sample_gcp_iam.json
cloudsentrix scan --file my_project.json --severity high
cloudsentrix scan --file my_project.json --top 10

# AWS ⚡ NEW
cloudsentrix scan --file aws_iam.json --cloud aws
cloudsentrix scan --file aws_iam.json --cloud aws --severity critical
```

### `live-scan` — Scan a live cloud account directly

#### GCP
```bash
# Requires: gcloud CLI authenticated
gcloud auth application-default login

cloudsentrix live-scan --project my-gcp-project-id
cloudsentrix live-scan --project my-gcp-project-id --save fetched_policy.json
cloudsentrix live-scan --project my-gcp-project-id --severity critical
```

#### AWS ⚡ NEW
```bash
# Requires: AWS credentials configured (aws configure)
pip install boto3

# Scan default AWS profile
cloudsentrix live-scan --cloud aws

# Scan specific profile and region
cloudsentrix live-scan --cloud aws --profile my-profile --region us-west-2

# Save fetched policy for offline analysis
cloudsentrix live-scan --cloud aws --save aws_policy.json

# Test without a real AWS account (LocalStack)
cloudsentrix live-scan --cloud aws --endpoint http://localhost:4566
```

### `blast-radius` — Blast radius for one principal (GCP)
```bash
cloudsentrix blast-radius --file my_project.json --principal admin@company.com
```

### `principal-path` — Escalation path between two principals (GCP)
```bash
cloudsentrix principal-path --file my_project.json \
  --source intern@company.com \
  --target app-backend@my-project.iam.gserviceaccount.com
```

### `mitre-map` — Map findings to MITRE ATT&CK Cloud Matrix
```bash
cloudsentrix mitre-map --file my_project.json
```

### `remediate` — Generate exact fix commands (GCP)
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
# GCP
cloudsentrix export --file my_project.json --output report.json
cloudsentrix export --file my_project.json --output dashboard.html
cloudsentrix export --file my_project.json --output results.sarif

# AWS ⚡ NEW
cloudsentrix export --file aws_iam.json --cloud aws --output aws_report.json
cloudsentrix export --file aws_iam.json --cloud aws --output aws_dashboard.html
cloudsentrix export --file aws_iam.json --cloud aws --output aws_results.sarif
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

### `report` — Generate a client-ready PDF report
```bash
# Without AI summary
cloudsentrix report --file my_project.json --output my_report.pdf --no-ai

# With Gemini AI summary
cloudsentrix report --file my_project.json --output my_report.pdf
```

### `watch` — Auto-rescan when file changes
```bash
cloudsentrix watch --path my_project.json
cloudsentrix watch --path /path/to/iam/exports/
cloudsentrix watch --path my_project.json --interval 5
```

Press `Ctrl+C` to stop watching.

### `rules` — List all detection rules
```bash
cloudsentrix rules
```

### `list-principals` — List all principals and their roles

```bash
# GCP
cloudsentrix list-principals --file my_project.json

# AWS ⚡ NEW
cloudsentrix list-principals --file aws_iam.json --cloud aws
```

---

## AWS Live Scan — Testing Without a Real Account (LocalStack)

LocalStack simulates AWS locally — free, no account needed.

```bash
# Step 1 — Install LocalStack
pip install localstack awscli-local

# Step 2 — Start LocalStack (keep this terminal open)
localstack start

# Step 3 — Create test IAM resources
awslocal iam create-user --user-name test-admin
awslocal iam attach-user-policy \
  --user-name test-admin \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Step 4 — Scan with CloudSentrix
cloudsentrix live-scan --cloud aws --endpoint http://localhost:4566
```

---

## SARIF Export — GitHub Code Scanning

SARIF output is compatible with GitHub Code Scanning, VS Code SARIF Viewer, and Azure DevOps.

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

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success, no CRITICAL findings |
| `1` | CRITICAL findings detected (use this to fail CI pipelines) |
| `2` | Command could not complete (bad file, wrong format, etc.) |

---

## Detection Rules

### GCP Rules

| Rule | Title | Severity | MITRE |
|------|-------|----------|-------|
| GCP-001 | Publicly Accessible Role Binding | CRITICAL | T1078.004 |
| GCP-002 | Service Account Token Creator | CRITICAL | T1098.001 |
| GCP-003 | Service Account Key Admin | CRITICAL | T1098.001 |
| GCP-004 | IAM Policy Administrator | CRITICAL | T1098.003 |
| GCP-005 | Service Account Impersonation via Resource Attach | HIGH | T1548.005 |

### AWS Rules ⚡ NEW

| Rule | Title | Severity | MITRE |
|------|-------|----------|-------|
| AWS-001 | Administrator Access — Full AWS Control | CRITICAL | T1078.004 |
| AWS-002 | IAM PassRole — Privilege Escalation via Service | CRITICAL | T1098.003 |
| AWS-003 | IAM Policy Manipulation — Self-Escalation Path | CRITICAL | T1098.003 |
| AWS-004 | Publicly Assumable Role — Trust Policy Allows Anyone | CRITICAL | T1078.004 |
| AWS-005 | Access Key Creation — Long-Lived Credential Backdoor | CRITICAL | T1098.001 |
| AWS-006 | Backdoor IAM User Creation | CRITICAL | T1136.003 |
| AWS-007 | IAMFullAccess — Complete IAM Control | CRITICAL | T1098.003 |

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
│   ├── cli.py                  # CLI entry point (15 commands)
│   ├── parser.py               # GCP IAM JSON parser
│   ├── graph.py                # GCP IAM permission graph engine
│   ├── detection.py            # GCP privilege-escalation detection rules
│   ├── risk_score.py           # 0-100 security scoring engine (GCP + AWS)
│   ├── blast_radius.py         # GCP attack-path blast radius calculator
│   ├── watch_handler.py        # File system watcher
│   ├── live_scanner.py         # Live GCP project scanner
│   ├── pdf_report.py           # PDF report generator
│   ├── ai_summary.py           # Gemini AI summary integration
│   ├── aws_parser.py           # AWS IAM JSON parser ⚡ NEW
│   ├── aws_graph.py            # AWS IAM permission graph engine ⚡ NEW
│   ├── aws_detection.py        # AWS privilege-escalation detection (7 rules) ⚡ NEW
│   └── aws_live_scanner.py     # Live AWS scanner via boto3 ⚡ NEW
├── tests/                      # 144 pytest tests
├── sample_data/
│   ├── sample_gcp_iam.json         # GCP basic test file
│   ├── demo_enterprise_iam.json    # GCP enterprise demo
│   └── sample_aws_iam.json         # AWS test file ⚡ NEW
├── .github/workflows/ci.yml        # GitHub Actions CI
├── .github/workflows/publish.yml   # PyPI auto-publish
├── pyproject.toml                  # Packaging configuration
└── README.md
```

---

## Roadmap 🗺️

| Feature | Description | Status |
|---------|-------------|--------|
| **GCP Support** | Full GCP IAM scanning — 5 escalation rules, blast radius, remediation | ✅ Shipped |
| **AWS Support** | AWS IAM scanning — 7 escalation rules, PassRole, AssumeRole, live scan | ✅ Shipped |
| **Azure Support** | Scan Azure RBAC — detect Owner/Contributor abuse, service principal risks | 🔄 Planned |
| **Multi-Cloud Dashboard** | Single HTML dashboard comparing GCP, AWS, Azure risk side by side | 🔄 Planned |
| **Slack / Teams Alerts** | Send findings to Slack or Microsoft Teams webhook automatically | 🔄 Planned |
| **PDF Multi-Project** | One PDF report covering multiple projects at once | 🔄 Planned |

---

## License

MIT License — free to use, modify, and distribute.

---

## Author

**Talha Imran** — SOC Analyst | Cloud Security | Pentesting

[![GitHub](https://img.shields.io/badge/GitHub-Talha--Imran--cloud-black)](https://github.com/Talha-Imran-cloud)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://linkedin.com/in/talha-imran)
[![PyPI](https://img.shields.io/pypi/v/cloudsentrix?label=PyPI)](https://pypi.org/project/cloudsentrix/)
