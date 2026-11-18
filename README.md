# ARTEX V 2.0 - Automated Reconnaissance & Threat Exposure Analyzer

![Security](https://img.shields.io/badge/Security-Pentesting-blue)
![Python](https://img.shields.io/badge/Python-3.8%2B-green)
![Flask](https://img.shields.io/badge/Flask-2.3.2-lightgrey)

ARTEX is an advanced web application security analysis platform that automates reconnaissance, vulnerability scanning, vulnerability scanning, threat assessment and AI-powered security recommendations  for modern web applications and infrastructure.

<img width="545" height="402" alt="ChatGPT Image Jul 17, 2025, 10_28_41 AM" src="https://github.com/user-attachments/assets/3357002f-5aa7-41c6-bc7d-090c463a836f" />


## Key Features

- **Comprehensive Scanning**:
  - Subdomain enumeration
  - Port scanning with risk assessment
  - Comprehensive DNS scanning
  - Advanced SSL/TLS scanning & vulns discovering by versions
  - Technology stack fingerprinting
  - Authentication surface detection

- **Intelligent Analysis**:
  - AI-powered security recommendations (Groq/Llama3 integration)
  - Dual-perspective reports (Owner vs Hunter views)
  - Automated risk scoring

- **Enterprise Ready**:
  - Parallel scanning engine
  - PDF/JSON report generation
  - REST API for integration

## Installation

### Prerequisites
- Python 3.8+
- Nmap (system installation)
- Redis (for job queueing - optional)

```bash
# Ubuntu/Debian
sudo apt-get install nmap wkhtmltopdf

# macOS
brew install nmap wkhtmltopdf
```

Setup
```bash

git clone https://github.com/yourrepo/artex.git
cd artex

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate  # Windows

pip install -r requirements.txt

```
Configuration

U need to add your GROQ api key in the AI_analyst.py script (U can do this here : https://console.groq.com/keys ) , here :

```bash

# AI_analyst.py
import requests
import json
from typing import Dict, List, Optional
import logging
from datetime import datetime
import time

class AIAnalyst:
    def __init__(self, groq_api_key: str = None):
        """
        Initialize the AI analyst with Groq API integration
        
        Args:
            groq_api_key: Optional Groq API key (if not provided, will use rule-based analysis only)
        """
        self.groq_api_key = "Add here your GROQ_API_KEY"
        self.logger = logging.getLogger(__name__)
        
        # Set up logging
        logging.basicConfig(level=logging.INFO)
        ......
        
```

Usage
Web Interface
```bash

python app.py

Access the interface at: http://localhost:5000
API Endpoints

    POST /start_scan - Initiate new scan

    GET /scan_status/<scan_id> - Check scan progress

    GET /results/<scan_id> - View results

    GET /export/<scan_id> - Export reports (PDF/JSON)
```

Scan Types
Scan Type	Description	Intensity Levels
Full Audit	Complete security assessment	Light/Normal/Aggressive
Web Focus	Application-layer only	Normal
Infrastructure	Network and server assessment	Aggressive
Quick Scan	Surface-level vulnerabilities	Light
Sample Report Output

Security Notice

This tool is for authorized security assessments only. Unauthorized use against systems you don't own or have permission to test is illegal.

## Scope gate (artex_gate) + Hermes integration

ARTEX refuses to start without a scope file. Everything it sends goes through `artex_gate`:

| Path | What the gate does |
|------|--------------------|
| `requests` (every redirect hop) | scope check on URL, researcher `User-Agent` + custom headers, RPS limit |
| raw sockets / TLS probes / port fallback / AXFR / UDP DNS | hostname + IP check (IPs must be in scope or resolved from an in-scope name) |
| `nmap` | only in-scope hosts, adds `--max-rate` and `http.useragent` |
| everything | JSONL audit log of every allow/block (`logs/gate-audit.jsonl`) |

```bash
cp scopes/example.yaml scopes/acme.yaml      # fill in from the program policy
ln -sfn acme.yaml scopes/active.yaml
.venv/bin/python -m artex_gate check --scope scopes/active.yaml https://api.acme.com
.venv/bin/python -m artex_gate scan  --scope scopes/active.yaml acme.com --intensity light
.venv/bin/python -m artex_gate fetch --scope scopes/active.yaml https://acme.com/robots.txt
.venv/bin/python -m artex_gate serve --scope scopes/active.yaml   # web UI, 127.0.0.1 only
```

Hermes: `hermes/install.sh --approve` installs the `artex-recon` skill and a fail-closed
`pre_tool_call` hook that blocks direct traffic to in/out-of-scope targets (curl, browser,
web_extract, python), direct attack tools, and any agent edit of `scopes/`, `artex_gate/`
or `hermes/`. Tests: `.venv/bin/python -m pytest tests/`.
