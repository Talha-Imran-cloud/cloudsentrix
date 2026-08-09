# CloudSentrix 🔐

**Multi-Cloud IAM Privilege-Escalation Attack-Path Analyzer**

CloudSentrix is a free, open-source command-line tool that scans **GCP, AWS, and Azure** IAM/RBAC policy exports for privilege-escalation risks, generates interactive attack-path graphs, scores your security posture, and produces client-ready PDF reports — all without any paid APIs.

[![CI](https://github.com/Talha-Imran-cloud/cloudsentrix/actions/workflows/ci.yml/badge.svg)](https://github.com/Talha-Imran-cloud/cloudsentrix/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/cloudsentrix)](https://pypi.org/project/cloudsentrix/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-144%20passed-brightgreen)](tests/)

---

## What It Does

### GCP Support ✅
- Detects 5 GCP IAM privilege-escalation patterns (MITRE ATT&CK mapped)
- Calculates blast radius — if one account is compromised, how much can an attacker reach?
- Generates remediation — exact `gcloud` CLI commands to fix each finding
- Live scanning — fetch and scan a live GCP project directly

### AWS Support ✅
- Detects 7 AWS IAM privilege-escalation patterns including `iam:PassRole`, `sts:AssumeRole`, backdoor user creation
- Live scanning — fetch and scan a live AWS account directly via boto3
- LocalStack support — test without a real AWS account (free, runs locally)

### Azure Support ✅
- Detects 5 Azure RBAC privilege-escalation patterns including Owner abuse, guest user risks, dangerous custom roles
- Blast radius calculation — per-principal scope-aware risk scoring
- Live scanning — fetch and scan a live Azure subscription via `az` CLI

### Multi-Cloud Dashboard ✅
- Single animated HTML dashboard comparing GCP, AWS, and Azure side by side

### Multi-Cloud PDF Report ✅
- One professional PDF covering GCP, AWS, and Azure findings in a single document
- Cover page, executive summary table, per-cloud findings, blast radius, recommendations
- Interactive bar charts, score counters, severity breakdown, all findings in one view
- Scroll animations, floating particles, hover effects — professional SOC-level report

### Slack / Teams Alerts ✅
- Automatically send findings to Slack or Microsoft Teams after every scan
- Rich formatted messages with score, severity breakdown, and top findings
- Supports webhook URL via env var or `--webhook` flag

### All Clouds
- Scores security posture from 0–100
- Exports results as JSON, CSV, SARIF, Interactive HTML Dashboard, or PDF
- Watches a folder and auto-rescans whenever an IAM file changes
- AI summaries — plain-language executive summaries via Google Gemini

---

## Requirements

- Python 3.10 or higher
- pip
- For AWS live scan: `pip install boto3`
- For Azure live scan: Azure CLI (`az`) installed and authenticated

---

## Installation

### Recommended — Install via pip

```bash
pip install cloudsentrix
```

**Kali Linux / Debian:**
```bash
pip install cloudsentrix --break-system-packages
# OR use pipx
pipx install cloudsentrix
# OR use virtual environment
python3 -m venv ~/cloudsentrix-env
source ~/cloudsentrix-env/bin/activate
pip install cloudsentrix
```

### Install from source

**Windows:**
```powershell
git clone https://github.com/Talha-Imran-cloud/cloudsentrix.git
cd cloudsentrix
python -m venv venv
venv\Scripts\activate
pip install -e .
```

**Linux / macOS / Kali:**
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

### AWS
```bash
aws iam get-account-authorization-details --output json > aws_iam.json
```

### Azure
```bash
az role assignment list --all --output json > azure_rbac.json
```

Sample files included for testing:
- `sample_data/sample_gcp_iam.json` — GCP basic example
- `sample_data/demo_enterprise_iam.json` — GCP enterprise scenario
- `sample_data/sample_aws_iam.json` — AWS example with 7 escalation risks
- `sample_data/sample_azure_rbac.json` — Azure RBAC example with 5 escalation risks

---

## Commands

### `scan` — Full pipeline scan

```bash
# GCP (default)
cloudsentrix scan --file sample_data/sample_gcp_iam.json
cloudsentrix scan --file my_project.json --severity high

# AWS
cloudsentrix scan --file sample_data/sample_aws_iam.json --cloud aws
cloudsentrix scan --file aws_iam.json --cloud aws --severity critical

# Azure
cloudsentrix scan --file sample_data/sample_azure_rbac.json --cloud azure
cloudsentrix scan --file azure_rbac.json --cloud azure --severity critical

# With Slack / Teams alert
cloudsentrix scan --file my_project.json --notify slack
cloudsentrix scan --file aws_iam.json --cloud aws --notify teams
cloudsentrix scan --file my_project.json --notify slack --webhook https://hooks.slack.com/...
```

### `dashboard` — Multi-Cloud HTML Dashboard ⚡ NEW

```bash
# All three clouds
cloudsentrix dashboard \
  --gcp sample_data/sample_gcp_iam.json \
  --aws sample_data/sample_aws_iam.json \
  --azure sample_data/sample_azure_rbac.json \
  --output multi_cloud_dashboard.html

# Two clouds only
cloudsentrix dashboard \
  --gcp my_gcp.json \
  --aws my_aws.json \
  --output dashboard.html

# Open the dashboard
# Windows:
start multi_cloud_dashboard.html
# Linux / macOS:
xdg-open multi_cloud_dashboard.html
```

The dashboard includes:
- Animated security score cards per cloud
- Bar charts comparing scores and severity counts
- Severity breakdown table (Critical / High / Medium / Low per cloud)
- All findings from all clouds in one filterable table
- Scroll animations, floating particles, counter animations

### `report-multi` — Multi-Cloud PDF Report ⚡ NEW

```bash
# All three clouds in one PDF
cloudsentrix report-multi \
  --gcp sample_data/sample_gcp_iam.json \
  --aws sample_data/sample_aws_iam.json \
  --azure sample_data/sample_azure_rbac.json \
  --output multi_cloud_report.pdf

# Two clouds only
cloudsentrix report-multi \
  --gcp my_gcp.json \
  --aws my_aws.json \
  --output report.pdf
```

The PDF includes:
- Cover page with scan metadata
- Executive summary — all clouds score table side by side
- Per-cloud section — findings table + blast radius top 5
- Footer with MITRE ATT&CK note and timestamp

### `live-scan` — Scan a live cloud account directly

**GCP:**
```bash
gcloud auth application-default login
cloudsentrix live-scan --project my-gcp-project-id
cloudsentrix live-scan --project my-gcp-project-id --save fetched_policy.json
```

**AWS:**
```bash
pip install boto3
cloudsentrix live-scan --cloud aws
cloudsentrix live-scan --cloud aws --profile my-profile --region us-west-2
cloudsentrix live-scan --cloud aws --save aws_policy.json
# LocalStack (no real AWS account needed)
cloudsentrix live-scan --cloud aws --endpoint http://localhost:4566
```

**Azure:**
```bash
az login
cloudsentrix live-scan --cloud azure
cloudsentrix live-scan --cloud azure --subscription my-subscription-id
cloudsentrix live-scan --cloud azure --save azure_policy.json
```

### `export` — Export to JSON, CSV, HTML, or SARIF

```bash
# GCP
cloudsentrix export --file my_project.json --output dashboard.html
cloudsentrix export --file my_project.json --output report.json
cloudsentrix export --file my_project.json --output report.csv
cloudsentrix export --file my_project.json --output results.sarif

# AWS
cloudsentrix export --file aws_iam.json --cloud aws --output aws_dashboard.html
cloudsentrix export --file aws_iam.json --cloud aws --output aws_report.json

# Azure
cloudsentrix export --file azure_rbac.json --cloud azure --output azure_dashboard.html
cloudsentrix export --file azure_rbac.json --cloud azure --output azure_results.sarif
```

### `report` — Generate a client-ready PDF report

```bash
# GCP
cloudsentrix report --file my_project.json --output report.pdf --no-ai

# AWS
cloudsentrix report --file aws_iam.json --cloud aws --output aws_report.pdf --no-ai

# Azure
cloudsentrix report --file azure_rbac.json --cloud azure --output azure_report.pdf --no-ai

# With Gemini AI summary
cloudsentrix report --file my_project.json --output report.pdf
```

### `score` — Security score only

```bash
cloudsentrix score --file my_project.json
cloudsentrix score --file aws_iam.json --cloud aws
cloudsentrix score --file azure_rbac.json --cloud azure --json
```

### `validate` — Check file format

```bash
cloudsentrix validate --file my_project.json
cloudsentrix validate --file aws_iam.json --cloud aws
cloudsentrix validate --file azure_rbac.json --cloud azure
```

### `list-principals` — List all principals

```bash
cloudsentrix list-principals --file my_project.json
cloudsentrix list-principals --file aws_iam.json --cloud aws
cloudsentrix list-principals --file azure_rbac.json --cloud azure
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

### `mitre-map` — Map findings to MITRE ATT&CK

```bash
cloudsentrix mitre-map --file my_project.json
```

### `remediate` — Generate exact fix commands (GCP)

```bash
cloudsentrix remediate --file my_project.json
cloudsentrix remediate --file my_project.json --severity critical
```

### `compare` — Compare two IAM exports

```bash
cloudsentrix compare --old january.json --new february.json
```

### `watch` — Auto-rescan when file changes

```bash
cloudsentrix watch --path my_project.json
cloudsentrix watch --path azure_rbac.json --cloud azure
cloudsentrix watch --path /path/to/iam/ --interval 5
```

### `rules` — List all detection rules (GCP + AWS + Azure)

```bash
cloudsentrix rules
```

---

## Slack / Teams Alerts Setup ⚡ NEW

### Slack

**Step 1 — Create webhook:**
1. Go to **https://api.slack.com/apps**
2. Create New App → From Scratch
3. Incoming Webhooks → Turn On
4. Add New Webhook to Workspace → Select channel
5. Copy the webhook URL

**Step 2 — Set env var:**

Windows:
```powershell
$env:CLOUDSENTRIX_SLACK_WEBHOOK = "https://hooks.slack.com/services/YOUR/WEBHOOK"
```

Linux / macOS:
```bash
export CLOUDSENTRIX_SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK"
```

**Step 3 — Scan with alert:**
```bash
cloudsentrix scan --file my_project.json --notify slack
cloudsentrix scan --file aws_iam.json --cloud aws --notify slack
```

### Microsoft Teams

**Step 1 — Create webhook:**
1. In Teams → open a channel → `...` → Connectors
2. Add **Incoming Webhook** → Configure → Name it → Copy URL

**Step 2 — Set env var:**

Windows:
```powershell
$env:CLOUDSENTRIX_TEAMS_WEBHOOK = "https://your-org.webhook.office.com/..."
```

**Step 3 — Scan with alert:**
```bash
cloudsentrix scan --file my_project.json --notify teams
cloudsentrix scan --file azure_rbac.json --cloud azure --notify teams
```

### Direct webhook URL (no env var needed)
```bash
cloudsentrix scan --file my_project.json \
  --notify slack \
  --webhook https://hooks.slack.com/services/YOUR/WEBHOOK
```

---

## AWS Live Scan — Testing Without a Real Account (LocalStack)

```bash
pip install localstack awscli-local
localstack start

awslocal iam create-user --user-name test-admin
awslocal iam attach-user-policy \
  --user-name test-admin \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

cloudsentrix live-scan --cloud aws --endpoint http://localhost:4566
```

---

## Gemini AI Summary (Optional)

```bash
# Get free API key from https://aistudio.google.com/app/apikey

# Windows
$env:GEMINI_API_KEY = "your_api_key_here"

# Linux / macOS
export GEMINI_API_KEY="your_api_key_here"

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

### AWS Rules

| Rule | Title | Severity | MITRE |
|------|-------|----------|-------|
| AWS-001 | Administrator Access — Full AWS Control | CRITICAL | T1078.004 |
| AWS-002 | IAM PassRole — Privilege Escalation via Service | CRITICAL | T1098.003 |
| AWS-003 | IAM Policy Manipulation — Self-Escalation Path | CRITICAL | T1098.003 |
| AWS-004 | Publicly Assumable Role — Trust Policy Allows Anyone | CRITICAL | T1078.004 |
| AWS-005 | Access Key Creation — Long-Lived Credential Backdoor | CRITICAL | T1098.001 |
| AWS-006 | Backdoor IAM User Creation | CRITICAL | T1136.003 |
| AWS-007 | IAMFullAccess — Complete IAM Control | CRITICAL | T1098.003 |

### Azure Rules

| Rule | Title | Severity | MITRE |
|------|-------|----------|-------|
| AZ-001 | Owner / Contributor at Broad Scope | CRITICAL | T1078.004 |
| AZ-002 | Service Principal with High-Privilege Role | CRITICAL | T1098.001 |
| AZ-003 | Guest User with Elevated Role | HIGH | T1078.006 |
| AZ-004 | Wildcard / Over-permissive Role Scope | HIGH | T1548.005 |
| AZ-005 | Custom Role with Dangerous Permissions | HIGH | T1098.003 |

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
│   ├── cli.py                    # CLI entry point (15 commands)
│   ├── parser.py                 # GCP IAM JSON parser
│   ├── graph.py                  # GCP IAM permission graph engine
│   ├── detection.py              # GCP privilege-escalation detection (5 rules)
│   ├── risk_score.py             # 0-100 security scoring engine
│   ├── blast_radius.py           # GCP attack-path blast radius calculator
│   ├── watch_handler.py          # File system watcher
│   ├── live_scanner.py           # Live GCP project scanner
│   ├── pdf_report.py             # PDF report generator
│   ├── ai_summary.py             # Gemini AI summary integration
│   ├── aws_parser.py             # AWS IAM JSON parser
│   ├── aws_graph.py              # AWS IAM permission graph engine
│   ├── aws_detection.py          # AWS privilege-escalation detection (7 rules)
│   ├── aws_live_scanner.py       # Live AWS scanner via boto3
│   ├── azure_parser.py           # Azure RBAC JSON parser
│   ├── azure_detection.py        # Azure privilege-escalation detection (5 rules)
│   ├── azure_risk_score.py       # Azure security scoring engine
│   ├── azure_blast_radius.py     # Azure blast radius calculator
│   ├── azure_exporter.py         # Azure JSON/CSV/SARIF/HTML exporter
│   ├── azure_live_scanner.py     # Live Azure scanner via az CLI
│   ├── multi_dashboard.py        # Multi-cloud animated HTML dashboard
│   ├── multi_pdf_report.py       # Multi-cloud PDF report generator
│   └── notifier.py               # Slack / Teams webhook notifications
├── tests/                        # 144 pytest tests
├── sample_data/
│   ├── sample_gcp_iam.json       # GCP basic test file
│   ├── demo_enterprise_iam.json  # GCP enterprise demo
│   ├── sample_aws_iam.json       # AWS test file
│   └── sample_azure_rbac.json    # Azure RBAC test file
├── .github/workflows/ci.yml      # GitHub Actions CI
├── .github/workflows/publish.yml # PyPI auto-publish
├── pyproject.toml                # Packaging configuration
└── README.md
```

---

## Roadmap 🗺️

| Feature | Description | Status |
|---------|-------------|--------|
| **GCP Support** | Full GCP IAM scanning — 5 rules, blast radius, remediation, live scan | ✅ Shipped |
| **AWS Support** | AWS IAM scanning — 7 rules, PassRole, AssumeRole, live scan, LocalStack | ✅ Shipped |
| **Azure Support** | Azure RBAC scanning — 5 rules, blast radius, live scan, HTML dashboard | ✅ Shipped |
| **Multi-Cloud Dashboard** | Animated HTML dashboard comparing GCP, AWS, Azure side by side | ✅ Shipped |
| **Slack / Teams Alerts** | Send findings to Slack or Teams webhook after every scan | ✅ Shipped |
| **PDF Multi-Project** | One PDF report covering GCP, AWS, and Azure findings in one document | ✅ Shipped |
| **Azure AD / Entra ID** | Detect risky app registrations, OAuth permissions, conditional access gaps | 🔄 Planned |
| **CI/CD Integration** | GitHub Actions, GitLab CI templates for automated scanning | 🔄 Planned |

---

## License

MIT License — free to use, modify, and distribute.

---

## Author

**Talha Imran** — SOC Analyst | Cloud Security | Pentesting

[![GitHub](https://img.shields.io/badge/GitHub-Talha--Imran--cloud-black)](https://github.com/Talha-Imran-cloud)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://linkedin.com/in/talha-imran)
[![PyPI](https://img.shields.io/pypi/v/cloudsentrix?label=PyPI)](https://pypi.org/project/cloudsentrix/)
