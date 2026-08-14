<div align="center">

<br/>

```
   _____ _                 _  _____            _      _      
  / ____| |               | |/ ____|          | |    (_)     
 | |    | | ___  _   _  __| | (___   ___ _ __ | |_ _ ___  __
 | |    | |/ _ \| | | |/ _` |\___ \ / _ \ '_ \| __| | \ \/ /
 | |____| | (_) | |_| | (_| |____) |  __/ | | | |_| |  >  < 
  \_____|_|\___/ \__,_|\__,_|_____/ \___|_| |_|\__|_|_/_/\_\
                                                    v2.0.0
```

**Multi-Cloud IAM Attack-Path Analyzer**

Open-source CLI that scans GCP, AWS, Azure, Kubernetes, and Terraform for privilege-escalation risks.
40 detection rules · Blast radius · MITRE ATT&CK · Cross-cloud chains · CI/CD ready.
**The free alternative to Wiz and Orca.**

[![Website](https://img.shields.io/badge/Website-cloudsentrix.netlify.app-black?style=for-the-badge&logo=netlify)](https://cloudsentrix.netlify.app/)
[![CI](https://img.shields.io/github/actions/workflow/status/Talha-Imran-cloud/cloudsentrix/ci.yml?style=for-the-badge&label=CI&logo=github)](https://github.com/Talha-Imran-cloud/cloudsentrix/actions)
[![PyPI](https://img.shields.io/pypi/v/cloudsentrix?style=for-the-badge&logo=pypi&logoColor=white)](https://pypi.org/project/cloudsentrix/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-black?style=for-the-badge&logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-black?style=for-the-badge)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-144%20passed-black?style=for-the-badge)](tests/)

[**🌐 Website**](https://cloudsentrix.netlify.app/) · [**📦 PyPI**](https://pypi.org/project/cloudsentrix/) · [**🐛 Issues**](https://github.com/Talha-Imran-cloud/cloudsentrix/issues)

</div>

---

## What It Does

| Target | Rules | Live Scan | Blast Radius | Dashboard | PDF |
|--------|-------|-----------|--------------|-----------|-----|
| ☁️ GCP IAM | 5 | ✅ gcloud | ✅ | ✅ | ✅ |
| 🟡 AWS IAM | 7 | ✅ boto3 + LocalStack | ✅ | ✅ | ✅ |
| 🔷 Azure RBAC | 5 | ✅ az CLI | ✅ | ✅ | ✅ |
| 🔷 Azure AD / Entra ID | 6 | ✅ az CLI | — | ✅ | ✅ |
| 🏗️ Terraform IaC + State | 11 | — | — | — | — |
| ☸️ Kubernetes RBAC | 6 | — | — | — | — |
| 🌐 Cross-Cloud Chains | industry-first | — | — | — | ✅ JSON |
| **Total** | **40 rules** | | | | |

---

## Installation

### Linux / Kali / macOS
```bash
pip install cloudsentrix
```

If you get externally-managed-environment error on Kali/Debian:
```bash
pip install cloudsentrix --break-system-packages
```

Or use virtual environment (recommended):
```bash
python3 -m venv venv
source venv/bin/activate
pip install cloudsentrix
cloudsentrix --version
```

Or use pipx:
```bash
pipx install cloudsentrix
```

### Windows (PowerShell)
```powershell
pip install cloudsentrix
cloudsentrix --version
```

Or virtual environment on Windows:
```powershell
python -m venv venv
venv\Scripts\activate
pip install cloudsentrix
cloudsentrix --version
```

### From source
```bash
git clone https://github.com/Talha-Imran-cloud/cloudsentrix.git
cd cloudsentrix
pip install -e .
cloudsentrix --version
```

---

## Getting Your IAM Policy File

### Linux / macOS
```bash
# GCP
gcloud projects get-iam-policy YOUR_PROJECT_ID --format=json > gcp_iam.json

# AWS
aws iam get-account-authorization-details --output json > aws_iam.json

# Azure RBAC
az role assignment list --all --output json > azure_rbac.json

# Azure AD
az ad app list --all --output json > azure_ad.json

# Kubernetes
kubectl get clusterroles,clusterrolebindings,roles,rolebindings -o json > k8s_rbac.json
```

### Windows (PowerShell)
```powershell
# GCP
gcloud projects get-iam-policy YOUR_PROJECT_ID --format=json > gcp_iam.json

# AWS
aws iam get-account-authorization-details --output json > aws_iam.json

# Azure RBAC
az role assignment list --all --output json > azure_rbac.json
```

---

## Commands

> **Important:** On Windows PowerShell, use single-line commands. Multi-line `\` does not work. All examples below work on both Linux and Windows.

### `scan` — Full pipeline scan

**Linux / macOS:**
```bash
cloudsentrix scan --file gcp_iam.json
cloudsentrix scan --file aws_iam.json --cloud aws
cloudsentrix scan --file azure_rbac.json --cloud azure
cloudsentrix scan --file azure_ad.json --cloud azure-ad
cloudsentrix scan --file gcp_iam.json --severity critical
cloudsentrix scan --file aws_iam.json --cloud aws --notify slack
```

**Windows:**
```powershell
cloudsentrix scan --file gcp_iam.json
cloudsentrix scan --file aws_iam.json --cloud aws
cloudsentrix scan --file azure_rbac.json --cloud azure
cloudsentrix scan --file gcp_iam.json --severity critical
```

---

### `cross-cloud` — Cross-Cloud Attack Chain Detection

```bash
cloudsentrix cross-cloud --aws aws_iam.json --azure azure_rbac.json
cloudsentrix cross-cloud --gcp gcp_iam.json --aws aws_iam.json --azure azure_rbac.json
cloudsentrix cross-cloud --aws aws_iam.json --azure azure_rbac.json --output chains.json
```

---

### `terraform` — Terraform IaC + State Scanning

```bash
# Scan .tf files
cloudsentrix terraform --path main.tf
cloudsentrix terraform --path /path/to/terraform/

# Scan .tfstate for leaked secrets
cloudsentrix terraform --path terraform.tfstate
cloudsentrix terraform --path terraform.tfstate --output secrets.json
```

---

### `k8s` — Kubernetes RBAC Scanning

```bash
cloudsentrix k8s --path k8s_rbac.json
cloudsentrix k8s --path /path/to/manifests/
cloudsentrix k8s --path k8s_rbac.json --output findings.json
```

---

### `dashboard` — Multi-Cloud HTML Dashboard

**Linux / macOS:**
```bash
cloudsentrix dashboard --gcp gcp_iam.json --aws aws_iam.json --azure azure_rbac.json --output dashboard.html
cloudsentrix dashboard --gcp gcp_iam.json --aws aws_iam.json --output dashboard.html

# Open
xdg-open dashboard.html
```

**Windows:**
```powershell
cloudsentrix dashboard --gcp gcp_iam.json --aws aws_iam.json --azure azure_rbac.json --output dashboard.html

# Open
start dashboard.html
```

---

### `report-multi` — Multi-Cloud PDF Report

```bash
cloudsentrix report-multi --gcp gcp_iam.json --aws aws_iam.json --azure azure_rbac.json --output report.pdf
cloudsentrix report-multi --gcp gcp_iam.json --aws aws_iam.json --output report.pdf
```

---

### `report` — Single-Cloud PDF

```bash
cloudsentrix report --file gcp_iam.json --output report.pdf --no-ai
cloudsentrix report --file aws_iam.json --cloud aws --output aws_report.pdf --no-ai
cloudsentrix report --file azure_rbac.json --cloud azure --output azure_report.pdf --no-ai
```

---

### `live-scan` — Scan Live Cloud Account

```bash
# GCP (requires gcloud CLI)
cloudsentrix live-scan --project my-gcp-project-id
cloudsentrix live-scan --project my-gcp-project-id --save policy.json

# AWS (requires: pip install boto3)
cloudsentrix live-scan --cloud aws
cloudsentrix live-scan --cloud aws --profile my-profile --region us-east-1
cloudsentrix live-scan --cloud aws --save aws_policy.json

# AWS LocalStack (no real account needed)
cloudsentrix live-scan --cloud aws --endpoint http://localhost:4566

# Azure (requires az login)
cloudsentrix live-scan --cloud azure
cloudsentrix live-scan --cloud azure --subscription my-subscription-id
```

---

### `export` — Export Results

```bash
# HTML dashboard
cloudsentrix export --file gcp_iam.json --output dashboard.html
cloudsentrix export --file aws_iam.json --cloud aws --output aws_dashboard.html
cloudsentrix export --file azure_rbac.json --cloud azure --output azure_dashboard.html

# JSON
cloudsentrix export --file gcp_iam.json --output report.json
cloudsentrix export --file aws_iam.json --cloud aws --output aws_report.json

# CSV
cloudsentrix export --file gcp_iam.json --output report.csv

# SARIF (GitHub Code Scanning)
cloudsentrix export --file gcp_iam.json --output results.sarif
cloudsentrix export --file aws_iam.json --cloud aws --output aws_results.sarif
```

---

### `score` — Security Score

```bash
cloudsentrix score --file gcp_iam.json
cloudsentrix score --file aws_iam.json --cloud aws
cloudsentrix score --file azure_rbac.json --cloud azure --json
cloudsentrix score --file gcp_iam.json --min-score 70
```

---

### `validate` — Validate File Format

```bash
cloudsentrix validate --file gcp_iam.json
cloudsentrix validate --file aws_iam.json --cloud aws
cloudsentrix validate --file azure_rbac.json --cloud azure
cloudsentrix validate --file azure_ad.json --cloud azure-ad
```

---

### `blast-radius` — Blast Radius

```bash
cloudsentrix blast-radius --file gcp_iam.json --principal admin@company.com
```

---

### `principal-path` — Escalation Path

```bash
cloudsentrix principal-path --file gcp_iam.json --source intern@company.com --target sa@my-project.iam.gserviceaccount.com
```

---

### `mitre-map` — MITRE ATT&CK Mapping

```bash
cloudsentrix mitre-map --file gcp_iam.json
```

---

### `remediate` — Generate Fix Commands

```bash
cloudsentrix remediate --file gcp_iam.json
cloudsentrix remediate --file gcp_iam.json --severity critical
```

---

### `compare` — Compare Two Exports

```bash
cloudsentrix compare --old january.json --new february.json
```

---

### `watch` — Auto-Rescan on File Change

```bash
cloudsentrix watch --path gcp_iam.json
cloudsentrix watch --path azure_rbac.json --cloud azure --interval 5
```

---

### `list-principals` — List All Principals

```bash
cloudsentrix list-principals --file gcp_iam.json
cloudsentrix list-principals --file aws_iam.json --cloud aws
cloudsentrix list-principals --file azure_rbac.json --cloud azure
```

---

### `rules` — List All Detection Rules

```bash
cloudsentrix rules
# GCP(5) + AWS(7) + Azure RBAC(5) + Azure AD(6) + Terraform(11) + K8s(6) = 40 rules
```

---

## Slack / Teams Alerts

### Linux / macOS
```bash
export CLOUDSENTRIX_SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK"
cloudsentrix scan --file gcp_iam.json --notify slack

export CLOUDSENTRIX_TEAMS_WEBHOOK="https://your-org.webhook.office.com/..."
cloudsentrix scan --file gcp_iam.json --notify teams

# Direct URL
cloudsentrix scan --file gcp_iam.json --notify slack --webhook https://hooks.slack.com/services/YOUR/WEBHOOK
```

### Windows
```powershell
$env:CLOUDSENTRIX_SLACK_WEBHOOK = "https://hooks.slack.com/services/YOUR/WEBHOOK"
cloudsentrix scan --file gcp_iam.json --notify slack

$env:CLOUDSENTRIX_TEAMS_WEBHOOK = "https://your-org.webhook.office.com/..."
cloudsentrix scan --file gcp_iam.json --notify teams
```

---

## CI/CD Integration

### GitHub Actions
```yaml
- name: Install CloudSentrix
  run: pip install cloudsentrix

- name: Scan GCP IAM
  run: cloudsentrix scan --file gcp_iam.json --severity high

- name: Generate SARIF
  run: cloudsentrix export --file gcp_iam.json --output results.sarif

- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif

- name: Generate Dashboard
  run: cloudsentrix dashboard --gcp gcp_iam.json --aws aws_iam.json --azure azure_rbac.json --output dashboard.html

- name: Upload Dashboard
  uses: actions/upload-artifact@v4
  with:
    name: security-dashboard
    path: dashboard.html
```

### GitLab CI
```yaml
cloudsentrix-scan:
  image: python:3.11
  script:
    - pip install cloudsentrix
    - cloudsentrix scan --file gcp_iam.json --cloud gcp
  allow_failure: false
```

### Jenkins
```groovy
stage('Security Scan') {
    steps {
        sh 'pip install cloudsentrix'
        sh 'cloudsentrix scan --file gcp_iam.json --cloud gcp'
    }
}
```

---

## AWS LocalStack Testing (No Real AWS Account)

```bash
pip install localstack awscli-local
localstack start
awslocal iam create-user --user-name test-admin
awslocal iam attach-user-policy --user-name test-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
cloudsentrix live-scan --cloud aws --endpoint http://localhost:4566
```

---

## Gemini AI Summary

### Linux / macOS
```bash
export GEMINI_API_KEY="your_api_key_here"
cloudsentrix report --file gcp_iam.json --output report.pdf
```

### Windows
```powershell
$env:GEMINI_API_KEY = "your_api_key_here"
cloudsentrix report --file gcp_iam.json --output report.pdf
```

Get free API key from [Google AI Studio](https://aistudio.google.com/app/apikey)

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No CRITICAL findings |
| `1` | CRITICAL findings — fail the pipeline |
| `2` | Command error |

---

## Detection Rules

### ☁️ GCP (5 rules)
| Rule | Title | Severity | MITRE |
|------|-------|----------|-------|
| GCP-001 | Publicly Accessible Role Binding | CRITICAL | T1078.004 |
| GCP-002 | Service Account Token Creator | CRITICAL | T1098.001 |
| GCP-003 | Service Account Key Admin | CRITICAL | T1098.001 |
| GCP-004 | IAM Policy Administrator | CRITICAL | T1098.003 |
| GCP-005 | Service Account Impersonation via Resource Attach | HIGH | T1548.005 |

### 🟡 AWS (7 rules)
| Rule | Title | Severity | MITRE |
|------|-------|----------|-------|
| AWS-001 | Administrator Access — Full AWS Control | CRITICAL | T1078.004 |
| AWS-002 | IAM PassRole — Privilege Escalation via Service | CRITICAL | T1098.003 |
| AWS-003 | IAM Policy Manipulation — Self-Escalation Path | CRITICAL | T1098.003 |
| AWS-004 | Publicly Assumable Role — Trust Policy Allows Anyone | CRITICAL | T1078.004 |
| AWS-005 | Access Key Creation — Long-Lived Credential Backdoor | CRITICAL | T1098.001 |
| AWS-006 | Backdoor IAM User Creation | CRITICAL | T1136.003 |
| AWS-007 | IAMFullAccess — Complete IAM Control | CRITICAL | T1098.003 |

### 🔷 Azure RBAC (5 rules)
| Rule | Title | Severity | MITRE |
|------|-------|----------|-------|
| AZ-001 | Owner / Contributor at Broad Scope | CRITICAL | T1078.004 |
| AZ-002 | Service Principal with High-Privilege Role | CRITICAL | T1098.001 |
| AZ-003 | Guest User with Elevated Role | HIGH | T1078.006 |
| AZ-004 | Over-permissive Role Scope | HIGH | T1548.005 |
| AZ-005 | Custom Role with Dangerous Permissions | HIGH | T1098.003 |

### 🔷 Azure AD / Entra ID (6 rules)
| Rule | Title | Severity | MITRE |
|------|-------|----------|-------|
| AZAD-001 | Dangerous OAuth Permission | CRITICAL | T1528 |
| AZAD-002 | Orphaned App Registration | HIGH | T1098.001 |
| AZAD-003 | Multi-Tenant App with Broad Permissions | CRITICAL | T1199 |
| AZAD-004 | Expired App Credentials | MEDIUM | T1552.001 |
| AZAD-005 | App Credential With No Expiry | HIGH | T1528 |
| AZAD-006 | Service Principal with High-Privilege App Roles | CRITICAL | T1098.003 |

### 🏗️ Terraform IaC + State (11 rules)
| Rule | Title | Severity | MITRE |
|------|-------|----------|-------|
| TF-001 | AWS IAM Wildcard Policy (Action:* Resource:*) | CRITICAL | T1078.004 |
| TF-002 | AWS IAM Role Public Trust Policy (Principal:*) | CRITICAL | T1078.004 |
| TF-003 | AWS AdministratorAccess Policy Attached | CRITICAL | T1078.004 |
| TF-004 | GCP Public IAM Binding (allUsers) | CRITICAL | T1078.004 |
| TF-005 | GCP Owner/Editor Role Binding | HIGH | T1098.003 |
| TF-006 | Azure Owner Role Assignment | CRITICAL | T1078.004 |
| TF-007 | Hardcoded Secrets / Access Keys | CRITICAL | T1552.001 |
| TF-008 | AWS IAM Policy Uses NotAction | HIGH | T1078.004 |
| TF-009 | AWS IAM Inline Policy on User | MEDIUM | T1078.004 |
| TF-010 | Sensitive Policy Missing MFA Condition | MEDIUM | T1078.004 |
| TFS-001 | Secret Leaked in Terraform State File | CRITICAL | T1552.001 |

### ☸️ Kubernetes RBAC (6 rules)
| Rule | Title | Severity | MITRE |
|------|-------|----------|-------|
| K8S-001 | ClusterRoleBinding to cluster-admin | CRITICAL | T1078.001 |
| K8S-002 | Wildcard Permissions in Role | CRITICAL | T1078.001 |
| K8S-003 | Role Can Read Kubernetes Secrets | HIGH | T1552.007 |
| K8S-004 | Default ServiceAccount Bound to Privileged Role | HIGH | T1078.001 |
| K8S-005 | Anonymous / Unauthenticated Access Granted | CRITICAL | T1078.001 |
| K8S-006 | Role Allows Pod Exec/Attach | HIGH | T1609 |

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

---

## Project Structure

```
cloudsentrix/
├── src/
│   ├── cloudsentrix/             # Main package
│   │   ├── __init__.py
│   │   ├── _entry.py             # pip install entry point
│   │   ├── cli.py                # CLI (19 commands)
│   │   ├── parser.py             # GCP parser
│   │   ├── graph.py              # GCP graph
│   │   ├── detection.py          # GCP rules (5)
│   │   ├── risk_score.py         # Scoring engine
│   │   ├── blast_radius.py       # GCP blast radius
│   │   ├── watch_handler.py      # File watcher
│   │   ├── live_scanner.py       # Live GCP scanner
│   │   ├── pdf_report.py         # Single PDF
│   │   ├── ai_summary.py         # Gemini AI
│   │   ├── aws_parser.py         # AWS parser
│   │   ├── aws_graph.py          # AWS graph
│   │   ├── aws_detection.py      # AWS rules (7)
│   │   ├── aws_blast_radius.py   # AWS blast radius
│   │   ├── aws_live_scanner.py   # Live AWS scanner
│   │   ├── azure_parser.py       # Azure RBAC parser
│   │   ├── azure_detection.py    # Azure RBAC rules (5)
│   │   ├── azure_risk_score.py   # Azure scoring
│   │   ├── azure_blast_radius.py # Azure blast radius
│   │   ├── azure_exporter.py     # Azure exporter
│   │   ├── azure_live_scanner.py # Live Azure scanner
│   │   ├── azure_ad_parser.py    # Azure AD parser
│   │   ├── azure_ad_detection.py # Azure AD rules (6)
│   │   ├── terraform_scanner.py  # Terraform rules (11)
│   │   ├── k8s_scanner.py        # K8s RBAC rules (6)
│   │   ├── cross_cloud_detector.py # Cross-cloud chains
│   │   ├── multi_dashboard.py    # Multi-cloud dashboard
│   │   ├── multi_pdf_report.py   # Multi-cloud PDF
│   │   └── notifier.py           # Slack/Teams alerts
├── ci-templates/
│   ├── github-actions-gcp.yml
│   ├── github-actions-aws.yml
│   ├── github-actions-multi-cloud.yml
│   ├── gitlab-ci.yml
│   └── jenkins-pipeline.groovy
├── tests/
├── sample_data/
│   ├── sample_gcp_iam.json
│   ├── sample_aws_iam.json
│   ├── sample_azure_rbac.json
│   ├── sample_azure_ad.json
│   ├── sample_k8s_rbac.json
│   ├── sample_terraform.tfstate
│   └── sample_terraform/main.tf
├── .github/workflows/ci.yml
├── .github/workflows/publish.yml
├── pyproject.toml
└── README.md
```

---

## Roadmap

| Feature | Status |
|---------|--------|
| GCP IAM — 5 rules, blast radius, live scan | ✅ Shipped |
| AWS IAM — 7 rules, blast radius, live scan, LocalStack | ✅ Shipped |
| Azure RBAC — 5 rules, blast radius, live scan | ✅ Shipped |
| Azure AD / Entra ID — 6 rules | ✅ Shipped |
| Terraform IaC + State Scanner — 11 rules | ✅ Shipped |
| Kubernetes RBAC Scanner — 6 rules | ✅ Shipped |
| Cross-Cloud Attack Chain Detection | ✅ Shipped |
| Multi-Cloud Dashboard + PDF | ✅ Shipped |
| Slack / Teams Alerts | ✅ Shipped |
| CI/CD Templates | ✅ Shipped |
| Gemini AI Summaries | ✅ Shipped |
| Local Web Dashboard (Flask) | 🔄 Planned |

---

## License

MIT — free to use, modify, and distribute.

---

<div align="center">

**Talha Imran** — SOC Analyst | Cloud Security | Pentesting

[![Website](https://img.shields.io/badge/🌐_Website-cloudsentrix.netlify.app-black?style=for-the-badge)](https://cloudsentrix.netlify.app/)
[![GitHub](https://img.shields.io/badge/GitHub-Talha--Imran--cloud-black?style=for-the-badge&logo=github)](https://github.com/Talha-Imran-cloud)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Talha_Imran-black?style=for-the-badge&logo=linkedin)](https://www.linkedin.com/in/talha-imran-583a44420)
[![PyPI](https://img.shields.io/badge/PyPI-cloudsentrix-black?style=for-the-badge&logo=pypi)](https://pypi.org/project/cloudsentrix/)

</div>
