# CloudSentrix 🔐

**GCP IAM Privilege-Escalation Attack-Path Analyzer**

CloudSentrix is a free, open-source command-line tool that scans Google Cloud Platform IAM policy exports for privilege-escalation risks, generates attack-path graphs, scores your security posture, and produces client-ready PDF reports — all without any paid APIs.

[![CI](https://github.com/Talha-Imran-cloud/cloudsentrix/actions/workflows/ci.yml/badge.svg)](https://github.com/Talha-Imran-cloud/cloudsentrix/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## What It Does

- **Detects** 5 GCP IAM privilege-escalation patterns (mapped to MITRE ATT&CK Cloud Matrix)
- **Scores** your project's security posture from 0–100
- **Calculates blast radius** — if one account is compromised, how much can an attacker reach?
- **Generates remediation** — exact `gcloud` CLI commands to fix each finding
- **Exports** results as JSON, CSV, HTML, or a client-ready PDF report
- **Watches** a folder and auto-rescans whenever an IAM file changes

---

## Requirements

- Python 3.10 or higher
- pip

---

## Installation

### Windows

```powershell
git clone https://github.com/Talha-Imran-cloud/cloudsentrix.git
cd cloudsentrix
python -m venv venv
venv\Scripts\activate
pip install -e .
```

### Linux / macOS

```bash
git clone https://github.com/Talha-Imran-cloud/cloudsentrix.git
cd cloudsentrix
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

---

## Getting Your GCP IAM Policy File

```bash
gcloud projects get-iam-policy YOUR_PROJECT_ID --format=json > my_project_iam.json
```

A sample file is included at `sample_data/sample_gcp_iam.json` for testing.

---

## Commands

### `scan` — Full pipeline scan
```bash
cloudsentrix scan --file sample_data/sample_gcp_iam.json
cloudsentrix scan --file my_project.json --severity high
cloudsentrix scan --file my_project.json --top 10
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

### `export` — Export results to JSON, CSV, or HTML
```bash
cloudsentrix export --file my_project.json --output report.json
cloudsentrix export --file my_project.json --output report.csv
cloudsentrix export --file my_project.json --output report.html
```

### `report` — Generate a client-ready PDF report
```bash
# Without AI summary
cloudsentrix report --file my_project.json --output my_report.pdf --no-ai

# With Gemini AI summary (set API key first)
cloudsentrix report --file my_project.json --output my_report.pdf
```

### `watch` — Auto-rescan when file changes
```bash
# Watch a single file
cloudsentrix watch --path my_project.json

# Watch a folder
cloudsentrix watch --path /path/to/iam/exports/

# Custom poll interval (seconds)
cloudsentrix watch --path my_project.json --interval 5
```

### `rules` — List all detection rules
```bash
cloudsentrix rules
```

### `list-principals` — List all principals and their roles
```bash
cloudsentrix list-principals --file my_project.json
```

---

## Gemini AI Summary (Optional)

The `report` command can generate a plain-language AI summary using Google Gemini. To enable it:

**Get a free API key** from [Google AI Studio](https://aistudio.google.com/app/apikey)

**Set the environment variable:**

Windows:
```powershell
$env:GEMINI_API_KEY = "your_api_key_here"
```

Linux / macOS:
```bash
export GEMINI_API_KEY="your_api_key_here"
```

**Then run:**
```bash
cloudsentrix report --file my_project.json --output report.pdf
```

If no API key is set, a built-in template summary is used automatically — the command never fails because of a missing key.

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

---

## Project Structure

```
cloudsentrix/
├── src/
│   ├── cli.py              # CLI entry point (13 commands)
│   ├── parser.py           # GCP IAM JSON parser
│   ├── graph.py            # IAM permission graph engine
│   ├── detection.py        # Privilege-escalation detection rules
│   ├── risk_score.py       # 0-100 security scoring engine
│   ├── blast_radius.py     # Attack-path blast radius calculator
│   ├── watch_handler.py    # File system watcher
│   ├── pdf_report.py       # PDF report generator
│   └── ai_summary.py       # Gemini AI summary integration
├── tests/                  # 144 pytest tests
├── sample_data/            # Sample GCP IAM policy for testing
├── pyproject.toml          # Packaging configuration
└── README.md
```

---

## License

MIT License — free to use, modify, and distribute.

---

## Author

**Talha Imran** — SOC Analyst | Cloud Security | Pentesting

[![GitHub](https://img.shields.io/badge/GitHub-Talha--Imran--cloud-black)](https://github.com/Talha-Imran-cloud)
