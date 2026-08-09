# CloudSentrix 🔐

**Multi-Cloud IAM Privilege-Escalation Attack-Path Analyzer**

CloudSentrix is a free, open-source CLI tool that scans **GCP, AWS, Azure, and Azure AD** IAM/RBAC policies for privilege-escalation risks — with interactive dashboards, PDF reports, Slack/Teams alerts, and CI/CD integration.

[![CI](https://github.com/Talha-Imran-cloud/cloudsentrix/actions/workflows/ci.yml/badge.svg)](https://github.com/Talha-Imran-cloud/cloudsentrix/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/cloudsentrix)](https://pypi.org/project/cloudsentrix/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-144%20passed-brightgreen)](tests/)

---

## What It Does

| Cloud | Rules | Live Scan | Dashboard | PDF |
|-------|-------|-----------|-----------|-----|
| ☁️ GCP | 5 rules | ✅ via gcloud | ✅ | ✅ |
| 🟡 AWS | 7 rules | ✅ via boto3 + LocalStack | ✅ | ✅ |
| 🔷 Azure RBAC | 5 rules | ✅ via az CLI | ✅ | ✅ |
| 🔷 Azure AD / Entra ID | 6 rules | ✅ via az CLI | ✅ | ✅ |
| 🌐 Multi-Cloud | 23 rules total | — | ✅ Animated | ✅ Combined |

**Every cloud → same commands, same output formats.**

---

## Key Features

- **23 detection rules** across GCP, AWS, Azure RBAC, Azure AD — all MITRE ATT&CK mapped
- **Blast radius** — if one account is compromised, how much can an attacker reach?
- **Remediation** — exact `gcloud` / `aws` / `az` CLI fix commands
- **Multi-cloud HTML dashboard** — animated, all clouds side by side in one file
- **Multi-cloud PDF report** — cover page, executive summary, per-cloud findings
- **Slack / Teams alerts** — send findings to your team after every scan
- **CI/CD templates** — GitHub Actions, GitLab CI, Jenkins — ready to use
- **SARIF export** — upload directly to GitHub Security tab
- **Watch mode** — auto-rescan on file change
- **Gemini AI summaries** — plain-language executive reports

---

## Installation

```bash
pip install cloudsentrix
```

**Kali Linux / Debian:**
```bash
pip install cloudsentrix --break-system-packages
# OR
pipx install cloudsentrix
```

**From source:**
```bash
git clone https://github.com/Talha-Imran-cloud/cloudsentrix.git
cd cloudsentrix && pip install -e .
```

```bash
cloudsentrix --version
```

---

## Getting Your IAM Policy File

```bash
# GCP
gcloud projects get-iam-policy YOUR_PROJECT_ID --format=json > gcp_iam.json

# AWS
aws iam get-account-authorization-details --output json > aws_iam.json

# Azure RBAC
az role assignment list --all --output json > azure_rbac.json

# Azure AD / Entra ID
az ad app list --all --output json > azure_ad.json
```

**Sample files included:**
- `sample_data/sample_gcp_iam.json`
- `sample_data/sample_aws_iam.json`
- `sample_data/sample_azure_rbac.json`
- `sample_data/sample_azure_ad.json`

---

## Commands

### `scan` — Full pipeline scan

```bash
cloudsentrix scan --file sample_data/sample_gcp_iam.json
cloudsentrix scan --file sample_data/sample_aws_iam.json --cloud aws
cloudsentrix scan --file sample_data/sample_azure_rbac.json --cloud azure
cloudsentrix scan --file sample_data/sample_azure_ad.json --cloud azure-ad
cloudsentrix scan --file my.json --cloud gcp --severity critical
cloudsentrix scan --file my.json --cloud aws --notify slack
```

### `dashboard` — Multi-Cloud HTML Dashboard

```bash
cloudsentrix dashboard \
  --gcp   sample_data/sample_gcp_iam.json \
  --aws   sample_data/sample_aws_iam.json \
  --azure sample_data/sample_azure_rbac.json \
  --output multi_cloud_dashboard.html
```

Features: animated score counters, bar charts, severity breakdown, all findings table, floating particles, scroll animations.

### `report-multi` — Multi-Cloud PDF Report

```bash
cloudsentrix report-multi \
  --gcp   sample_data/sample_gcp_iam.json \
  --aws   sample_data/sample_aws_iam.json \
  --azure sample_data/sample_azure_rbac.json \
  --output multi_cloud_report.pdf
```

PDF includes: cover page, executive summary, per-cloud findings table, blast radius, MITRE mapping.

### `report` — Single-Cloud PDF

```bash
cloudsentrix report --file my_project.json --output report.pdf --no-ai
cloudsentrix report --file aws_iam.json --cloud aws --output aws_report.pdf --no-ai
cloudsentrix report --file azure_rbac.json --cloud azure --output azure_report.pdf --no-ai
```

### `live-scan` — Scan Live Cloud Account

```bash
# GCP
gcloud auth application-default login
cloudsentrix live-scan --project my-gcp-project-id

# AWS
cloudsentrix live-scan --cloud aws
cloudsentrix live-scan --cloud aws --profile my-profile --region us-west-2
cloudsentrix live-scan --cloud aws --endpoint http://localhost:4566   # LocalStack

# Azure
az login
cloudsentrix live-scan --cloud azure --subscription my-sub-id

# Azure AD
cloudsentrix live-scan --cloud azure-ad
```

### `export` — Export Results

```bash
cloudsentrix export --file my.json --output dashboard.html         # HTML
cloudsentrix export --file my.json --output report.json            # JSON
cloudsentrix export --file my.json --output report.csv             # CSV
cloudsentrix export --file my.json --output results.sarif          # SARIF
cloudsentrix export --file aws.json --cloud aws --output aws.html
cloudsentrix export --file azure_ad.json --cloud azure-ad --output azad.html
```

### `score` — Security Score

```bash
cloudsentrix score --file my.json
cloudsentrix score --file aws.json --cloud aws --json
cloudsentrix score --file my.json --min-score 70   # Fail if score < 70
```

### `validate` — Validate File Format

```bash
cloudsentrix validate --file my.json
cloudsentrix validate --file aws.json --cloud aws
cloudsentrix validate --file azure_rbac.json --cloud azure
cloudsentrix validate --file azure_ad.json --cloud azure-ad
```

### `blast-radius` — Blast Radius (GCP)

```bash
cloudsentrix blast-radius --file my.json --principal admin@company.com
```

### `principal-path` — Escalation Path (GCP)

```bash
cloudsentrix principal-path --file my.json \
  --source intern@company.com \
  --target sa@my-project.iam.gserviceaccount.com
```

### `mitre-map` — MITRE ATT&CK Mapping

```bash
cloudsentrix mitre-map --file my.json
```

### `remediate` — Generate Fix Commands (GCP)

```bash
cloudsentrix remediate --file my.json --severity critical
```

### `compare` — Compare Two Exports

```bash
cloudsentrix compare --old january.json --new february.json
```

### `watch` — Auto-Rescan on File Change

```bash
cloudsentrix watch --path my.json
cloudsentrix watch --path azure_rbac.json --cloud azure --interval 5
```

### `list-principals` — List All Principals

```bash
cloudsentrix list-principals --file my.json
cloudsentrix list-principals --file aws.json --cloud aws
cloudsentrix list-principals --file azure_ad.json --cloud azure-ad
```

### `rules` — List All Detection Rules

```bash
cloudsentrix rules
# Shows GCP (5) + AWS (7) + Azure RBAC (5) + Azure AD (6) = 23 rules
```

---

## Slack / Teams Alerts

```bash
# Slack setup
export CLOUDSENTRIX_SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK"
cloudsentrix scan --file my.json --notify slack
cloudsentrix scan --file aws.json --cloud aws --notify slack --webhook https://...

# Teams setup
export CLOUDSENTRIX_TEAMS_WEBHOOK="https://your-org.webhook.office.com/..."
cloudsentrix scan --file my.json --notify teams
```

**Slack webhook setup:**
1. Go to **https://api.slack.com/apps** → Create App → Incoming Webhooks
2. Add webhook → select channel → copy URL
3. Set env var → scan with `--notify slack`

---

## CI/CD Integration

Ready-made templates in the `ci-templates/` folder:

### GitHub Actions (GCP)

```yaml
# .github/workflows/cloudsentrix-gcp.yml
- name: Install CloudSentrix
  run: pip install cloudsentrix

- name: Scan GCP IAM
  run: cloudsentrix scan --file gcp_iam.json --severity high
  # Exit code 1 on CRITICAL findings → pipeline fails automatically
```

### GitHub Actions (Multi-Cloud)

```yaml
- name: Multi-Cloud Scan
  run: |
    cloudsentrix scan --file gcp.json --cloud gcp
    cloudsentrix scan --file aws.json --cloud aws
    cloudsentrix scan --file azure.json --cloud azure

- name: Generate Dashboard
  run: |
    cloudsentrix dashboard \
      --gcp gcp.json --aws aws.json --azure azure.json \
      --output dashboard.html

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

**Full templates:** `ci-templates/` folder in the repo.

---

## AWS LocalStack Testing (No Real AWS Account)

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

## Exit Codes (Use in CI/CD)

| Code | Meaning |
|------|---------|
| `0` | No CRITICAL findings |
| `1` | CRITICAL findings — fail the pipeline |
| `2` | Command error (bad file, wrong format) |

---

## Detection Rules

### GCP (5 rules)

| Rule | Title | Severity | MITRE |
|------|-------|----------|-------|
| GCP-001 | Publicly Accessible Role Binding | CRITICAL | T1078.004 |
| GCP-002 | Service Account Token Creator | CRITICAL | T1098.001 |
| GCP-003 | Service Account Key Admin | CRITICAL | T1098.001 |
| GCP-004 | IAM Policy Administrator | CRITICAL | T1098.003 |
| GCP-005 | Service Account Impersonation | HIGH | T1548.005 |

### AWS (7 rules)

| Rule | Title | Severity | MITRE |
|------|-------|----------|-------|
| AWS-001 | Administrator Access | CRITICAL | T1078.004 |
| AWS-002 | IAM PassRole Escalation | CRITICAL | T1098.003 |
| AWS-003 | IAM Policy Manipulation | CRITICAL | T1098.003 |
| AWS-004 | Publicly Assumable Role | CRITICAL | T1078.004 |
| AWS-005 | Access Key Creation Backdoor | CRITICAL | T1098.001 |
| AWS-006 | Backdoor IAM User Creation | CRITICAL | T1136.003 |
| AWS-007 | IAMFullAccess | CRITICAL | T1098.003 |

### Azure RBAC (5 rules)

| Rule | Title | Severity | MITRE |
|------|-------|----------|-------|
| AZ-001 | Owner / Contributor at Broad Scope | CRITICAL | T1078.004 |
| AZ-002 | Service Principal High-Privilege Role | CRITICAL | T1098.001 |
| AZ-003 | Guest User with Elevated Role | HIGH | T1078.006 |
| AZ-004 | Over-permissive Role Scope | HIGH | T1548.005 |
| AZ-005 | Custom Role Dangerous Permissions | HIGH | T1098.003 |

### Azure AD / Entra ID (6 rules)

| Rule | Title | Severity | MITRE |
|------|-------|----------|-------|
| AZAD-001 | Dangerous OAuth Permission | CRITICAL | T1528 |
| AZAD-002 | Orphaned App Registration | HIGH | T1098.001 |
| AZAD-003 | Multi-Tenant App with Broad Permissions | CRITICAL | T1199 |
| AZAD-004 | Expired App Credentials | MEDIUM | T1552.001 |
| AZAD-005 | App Credential With No Expiry | HIGH | T1528 |
| AZAD-006 | Service Principal High-Privilege App Roles | CRITICAL | T1098.003 |

---

## Project Structure

```
cloudsentrix/
├── src/
│   ├── cli.py                    # CLI entry point (15 commands)
│   ├── parser.py                 # GCP IAM parser
│   ├── graph.py                  # GCP graph engine
│   ├── detection.py              # GCP detection (5 rules)
│   ├── risk_score.py             # 0-100 scoring engine
│   ├── blast_radius.py           # GCP blast radius calculator
│   ├── watch_handler.py          # File system watcher
│   ├── live_scanner.py           # Live GCP scanner
│   ├── pdf_report.py             # Single-cloud PDF generator
│   ├── ai_summary.py             # Gemini AI integration
│   ├── aws_parser.py             # AWS IAM parser
│   ├── aws_graph.py              # AWS graph engine
│   ├── aws_detection.py          # AWS detection (7 rules)
│   ├── aws_live_scanner.py       # Live AWS scanner via boto3
│   ├── azure_parser.py           # Azure RBAC parser
│   ├── azure_detection.py        # Azure RBAC detection (5 rules)
│   ├── azure_risk_score.py       # Azure scoring engine
│   ├── azure_blast_radius.py     # Azure blast radius
│   ├── azure_exporter.py         # Azure JSON/CSV/SARIF/HTML
│   ├── azure_live_scanner.py     # Live Azure scanner via az CLI
│   ├── azure_ad_parser.py        # Azure AD / Entra ID parser
│   ├── azure_ad_detection.py     # Azure AD detection (6 rules)
│   ├── multi_dashboard.py        # Multi-cloud animated HTML dashboard
│   ├── multi_pdf_report.py       # Multi-cloud PDF report
│   └── notifier.py               # Slack / Teams webhook alerts
├── ci-templates/
│   ├── github-actions-gcp.yml    # GitHub Actions — GCP template
│   ├── github-actions-aws.yml    # GitHub Actions — AWS template
│   ├── github-actions-multi-cloud.yml  # GitHub Actions — all clouds
│   ├── gitlab-ci.yml             # GitLab CI template
│   └── jenkins-pipeline.groovy   # Jenkins pipeline template
├── tests/                        # 144 pytest tests
├── sample_data/
│   ├── sample_gcp_iam.json
│   ├── demo_enterprise_iam.json
│   ├── sample_aws_iam.json
│   ├── sample_azure_rbac.json
│   └── sample_azure_ad.json
├── .github/workflows/ci.yml
├── .github/workflows/publish.yml
├── pyproject.toml
└── README.md
```

---

## Roadmap

| Feature | Status |
|---------|--------|
| GCP IAM scanning — 5 rules, blast radius, live scan | ✅ Shipped |
| AWS IAM scanning — 7 rules, PassRole, live scan, LocalStack | ✅ Shipped |
| Azure RBAC scanning — 5 rules, blast radius, live scan | ✅ Shipped |
| Azure AD / Entra ID — 6 rules, OAuth risks, orphaned apps | ✅ Shipped |
| Multi-Cloud Animated HTML Dashboard | ✅ Shipped |
| Multi-Cloud PDF Report | ✅ Shipped |
| Slack / Teams Webhook Alerts | ✅ Shipped |
| CI/CD Templates — GitHub Actions, GitLab, Jenkins | ✅ Shipped |
| Gemini AI Executive Summaries | ✅ Shipped |

---

## License

MIT — free to use, modify, and distribute.

## Author

**Talha Imran** — SOC Analyst | Cloud Security | Pentesting

[![GitHub](https://img.shields.io/badge/GitHub-Talha--Imran--cloud-black)](https://github.com/Talha-Imran-cloud)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://linkedin.com/in/talha-imran)
[![PyPI](https://img.shields.io/pypi/v/cloudsentrix?label=PyPI)](https://pypi.org/project/cloudsentrix/)
