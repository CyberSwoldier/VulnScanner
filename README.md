# LACUNA

> The gap in your defences. Found before they find it.

LACUNA is an AI-assisted vulnerability assessment platform built with Streamlit and the Anthropic Claude API. It combines network scanning, CVE intelligence, cloud misconfiguration auditing, attack path modeling, and AI-powered risk scoring into a single dark-terminal dashboard.

---

## Features

**Network and Port Scanning**
Drives nmap for host discovery, OS detection, and service fingerprinting across any IP, CIDR range, or hostname. Falls back to a realistic simulation mode automatically when nmap is not available, so the tool is always runnable.

**CVE Intelligence**
Correlates discovered open ports against an embedded database of 40+ known CVEs across 21 service types. Enriches findings in real time via the NVD 2.0 API — pulling live CVSS scores, descriptions, and reference links with no API key required.

**Cloud Configuration Audit**
Runs 14 AWS misconfiguration checks covering public S3 buckets, IAM wildcard policies, open security groups, missing MFA enforcement, disabled CloudTrail, unencrypted storage, public RDS snapshots, disabled GuardDuty, IMDSv1 exposure, and more. Each finding includes a specific remediation step.

**Attack Path Modeling**
Chains vulnerabilities into end-to-end attack paths from public internet to crown jewel assets. Paths are ranked by exploitability likelihood derived from CVSS scores, with lateral movement and privilege escalation steps modeled where multiple high-severity findings exist on the same host.

**AI Risk Analysis**
Sends a structured scan summary to Claude and receives back an executive-level report containing an overall risk score, top three critical risks with business impact, the most likely attack scenario with specific CVE references, and a time-boxed remediation roadmap (24 hours, 30 days, 90 days).

**Audit Trail**
Every scan action is logged with millisecond-precision timestamps, suitable for compliance documentation and incident response timelines.

---

## Requirements

### Python packages

```
pip install -r requirements.txt
```

| Package | Purpose | Required |
|---|---|---|
| `streamlit` | Web dashboard framework | Yes |
| `python-nmap` | Python wrapper for the nmap binary | No — simulation mode fallback |
| `requests` | NVD 2.0 API calls for CVE enrichment | No — falls back to embedded data |
| `anthropic` | Claude API for AI risk analysis | No — AI tab disabled without key |
| `plotly` | Interactive charts and graphs | No — text fallback |
| `networkx` | Reserved for future graph export | No |

### System dependency

nmap must be installed as a system binary. `python-nmap` is a wrapper — it cannot function without the underlying binary.

| OS | Command |
|---|---|
| Debian / Ubuntu | `sudo apt install nmap` |
| macOS | `brew install nmap` |
| Windows | [nmap.org/download](https://nmap.org/download.html#windows) |

If nmap is not found at runtime, LACUNA switches to simulation mode silently.

### Anthropic API key

Required only for the AI Analysis tab. The key is never stored — it is read from the sidebar input or from the environment variable.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## Deploying on Streamlit Cloud

LACUNA is ready for one-click deployment on [Streamlit Community Cloud](https://streamlit.io/cloud).

The repository includes both files Streamlit Cloud needs:

- `requirements.txt` — Python packages installed via pip
- `packages.txt` — installs the `nmap` system binary via apt so real scans work in the cloud environment

Steps:

1. Fork or push this repository to your GitHub account.
2. Go to [share.streamlit.io](https://share.streamlit.io) and connect your repo.
3. Set the main file to `lacuna.py`.
4. Add `ANTHROPIC_API_KEY` as a secret in the Streamlit Cloud dashboard if you want AI analysis enabled by default.
5. Deploy.

---

## Local installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/lacuna.git
cd lacuna

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt

# Install nmap binary (Linux)
sudo apt install nmap

# Run
streamlit run lacuna.py
```

The dashboard opens at `http://localhost:8501`.

---

## Usage

1. Enter a target in the sidebar — an IP address (`10.0.0.1`), CIDR range (`192.168.1.0/24`), or hostname (`example.com`).
2. Set a port range — comma-separated (`22,80,443`) or a range (`1-1024`).
3. Choose a scan profile.

| Profile | Behaviour |
|---|---|
| Quick | Fast service detection, low network impact |
| Standard | Full version scan with service fingerprinting |
| Aggressive | OS detection, scripts, maximum version intensity |

4. Enable or disable the Cloud Config Audit and AI Analysis modules.
5. Paste your Anthropic API key if AI Analysis is enabled.
6. Click **LAUNCH SCAN**.

Results appear across six tabs: Hosts / Ports, Vulnerabilities, Cloud Config, Attack Paths, AI Analysis, and Scan Log.

---

## Data sources

| Module | Source | Network traffic |
|---|---|---|
| Port scan (nmap mode) | Live nmap probe | Active — sends packets to target |
| Port scan (simulation mode) | Internal dataset | None |
| CVE correlation | Embedded database | None |
| NVD enrichment | NVD 2.0 REST API | HTTPS to nvd.nist.gov |
| Cloud config audit | Simulated | None |
| AI analysis | Anthropic API | HTTPS to api.anthropic.com |

---

## Legal and ethical use

LACUNA is designed for use against systems you own or have explicit written permission to test. Running network scans against systems without authorisation is illegal in most jurisdictions regardless of intent.

The cloud configuration audit is simulated and does not connect to any cloud provider API. NVD enrichment queries only the public NVD 2.0 API for CVE metadata.

The authors accept no liability for misuse of this tool.

---

## Project structure

```
lacuna/
├── lacuna.py           # Main application — single-file Streamlit app
├── requirements.txt    # Python packages for Streamlit Cloud
├── packages.txt        # System packages for Streamlit Cloud (nmap binary)
└── README.md           # This file
```

---

## Roadmap

- Shodan API integration for passive external recon
- Export scan results to PDF report
- MITRE ATT&CK TTP tagging per CVE finding
- Multi-host CIDR scan with aggregate risk dashboard
- Persistent scan history with SQLite backend
- Docker image for zero-install deployment

---

## Dependencies and licences

| Package | Licence |
|---|---|
| Streamlit | Apache 2.0 |
| python-nmap | GPL-3.0 |
| requests | Apache 2.0 |
| anthropic | MIT |
| plotly | MIT |
| networkx | BSD-3-Clause |
| nmap (binary) | GPL-2.0 |

---

## Contributing

Pull requests are welcome. For significant changes, open an issue first to discuss the proposed direction. Please ensure any new scan modules degrade gracefully when their dependencies are absent, consistent with the rest of the codebase.

---

## Author

Built by Ricardo — security awareness engineer, threat intelligence practitioner, and builder of things that find things other things missed.
