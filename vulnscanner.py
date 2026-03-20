"""
VulnScan Pro — AI-Assisted Vulnerability Assessment Platform
Next-generation scanner: network discovery, CVE intelligence,
AI-powered risk scoring, attack path modeling, cloud config review.

Requirements:
    pip install streamlit python-nmap requests anthropic plotly networkx

Usage:
    streamlit run vulnscan_pro.py

Environment variable (optional):
    ANTHROPIC_API_KEY=sk-...   pre-fills the API key field
"""

import streamlit as st
import json
import time
import random
import ipaddress
from datetime import datetime
from collections import defaultdict
import os

# ── Optional imports (graceful degradation) ───────────────────────────────────
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import plotly.graph_objects as go
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

try:
    import networkx as nx          # noqa: F401 reserved for future graph export
    NX_AVAILABLE = True
except ImportError:
    NX_AVAILABLE = False

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Lacuna",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Theme: greyscale machine terminal + fluorescent baby blue ──────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans+Condensed:wght@400;600;700&display=swap');

:root {
    --bg:          #0c0c0e;
    --bg2:         #111114;
    --surface:     #17171b;
    --surface2:    #1e1e24;
    --border:      #2a2a32;
    --border2:     #3a3a45;
    --accent:      #7df9ff;
    --accent-dim:  rgba(125,249,255,0.10);
    --accent-glow: rgba(125,249,255,0.28);
    --crit:        #e05c5c;
    --warn:        #c8a84b;
    --ok:          #6dba8a;
    --info:        #7a9fbf;
    --text:        #d4d4d8;
    --dim:         #6b6b78;
    --dim2:        #44444f;
    --font-mono:   'IBM Plex Mono', monospace;
    --font-ui:     'IBM Plex Sans Condensed', sans-serif;
}

html, body, .stApp {
    background-color: var(--bg) !important;
    color: var(--text) !important;
    font-family: var(--font-ui) !important;
}
.stApp {
    background-image:
        linear-gradient(rgba(125,249,255,0.012) 1px, transparent 1px),
        linear-gradient(90deg, rgba(125,249,255,0.012) 1px, transparent 1px),
        radial-gradient(ellipse at 15% 5%, #12161c 0%, var(--bg) 55%) !important;
    background-size: 40px 40px, 40px 40px, 100% 100% !important;
}

[data-testid="stSidebar"] {
    background: var(--bg2) !important;
    border-right: 1px solid var(--border) !important;
}
[data-testid="stSidebar"] * { font-family: var(--font-ui) !important; }
[data-testid="stSidebarContent"] { padding-top: 1.2rem !important; }

h1 {
    font-family: var(--font-mono) !important;
    font-weight: 600 !important;
    letter-spacing: 4px !important;
    text-transform: uppercase !important;
    color: var(--accent) !important;
    text-shadow: 0 0 20px var(--accent-glow) !important;
}
h2 {
    font-family: var(--font-ui) !important;
    font-weight: 700 !important;
    letter-spacing: 2px !important;
    text-transform: uppercase !important;
    color: var(--text) !important;
    border-bottom: 1px solid var(--border) !important;
    padding-bottom: 6px !important;
}
h3 {
    font-family: var(--font-mono) !important;
    font-size: 0.82rem !important;
    font-weight: 600 !important;
    letter-spacing: 2px !important;
    text-transform: uppercase !important;
    color: var(--accent) !important;
}

.stTextInput input,
.stNumberInput input,
.stSelectbox > div > div,
.stTextArea textarea {
    background: var(--surface) !important;
    border: 1px solid var(--border) !important;
    color: var(--text) !important;
    font-family: var(--font-mono) !important;
    font-size: 0.8rem !important;
    border-radius: 2px !important;
    transition: border-color 0.15s !important;
}
.stTextInput input:focus,
.stTextArea textarea:focus {
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 2px var(--accent-dim) !important;
    outline: none !important;
}

.stButton > button {
    background: transparent !important;
    border: 1px solid var(--accent) !important;
    color: var(--accent) !important;
    font-family: var(--font-mono) !important;
    font-size: 0.75rem !important;
    font-weight: 600 !important;
    letter-spacing: 3px !important;
    text-transform: uppercase !important;
    border-radius: 2px !important;
    transition: background 0.15s, box-shadow 0.15s !important;
    padding: 10px 20px !important;
}
.stButton > button:hover {
    background: var(--accent-dim) !important;
    box-shadow: 0 0 14px var(--accent-glow) !important;
}
.stButton > button:active {
    background: var(--accent) !important;
    color: var(--bg) !important;
}

[data-testid="stCheckbox"] label {
    font-family: var(--font-mono) !important;
    font-size: 0.78rem !important;
    color: var(--dim) !important;
}

[data-testid="stMetric"] {
    background: var(--surface) !important;
    border: 1px solid var(--border) !important;
    border-radius: 2px !important;
    padding: 14px 12px !important;
}
[data-testid="stMetricLabel"] {
    font-family: var(--font-mono) !important;
    font-size: 0.65rem !important;
    letter-spacing: 2px !important;
    text-transform: uppercase !important;
    color: var(--dim) !important;
}
[data-testid="stMetricValue"] {
    font-family: var(--font-mono) !important;
    color: var(--accent) !important;
    font-size: 1.55rem !important;
    text-shadow: 0 0 10px var(--accent-glow) !important;
}

[data-testid="stExpander"] {
    border: 1px solid var(--border) !important;
    border-radius: 2px !important;
    background: var(--surface) !important;
    margin-bottom: 4px !important;
}
[data-testid="stExpander"] summary {
    font-family: var(--font-mono) !important;
    font-size: 0.78rem !important;
    letter-spacing: 1px !important;
    color: var(--text) !important;
    background: var(--surface) !important;
}
[data-testid="stExpander"] summary:hover { color: var(--accent) !important; }

code, pre {
    font-family: var(--font-mono) !important;
    background: var(--bg) !important;
    color: var(--accent) !important;
    border: 1px solid var(--border) !important;
    border-radius: 2px !important;
    font-size: 0.78rem !important;
}

.stTabs [data-baseweb="tab-list"] {
    background: var(--surface) !important;
    border-bottom: 1px solid var(--border) !important;
    gap: 0 !important;
}
.stTabs [data-baseweb="tab"] {
    font-family: var(--font-mono) !important;
    font-size: 0.7rem !important;
    font-weight: 600 !important;
    letter-spacing: 2px !important;
    text-transform: uppercase !important;
    color: var(--dim) !important;
    border-bottom: 2px solid transparent !important;
    padding: 10px 16px !important;
    transition: color 0.15s !important;
}
.stTabs [aria-selected="true"] {
    color: var(--accent) !important;
    border-bottom-color: var(--accent) !important;
    background: transparent !important;
    text-shadow: 0 0 8px var(--accent-glow) !important;
}
.stTabs [data-baseweb="tab"]:hover { color: var(--text) !important; }

.stProgress > div > div {
    background: linear-gradient(90deg, var(--accent), #b0feff) !important;
    box-shadow: 0 0 8px var(--accent-glow) !important;
}

.stSuccess { background: rgba(109,186,138,0.07) !important; border-left: 2px solid var(--ok) !important;   border-radius: 2px !important; }
.stWarning { background: rgba(200,168,75,0.07) !important;  border-left: 2px solid var(--warn) !important;  border-radius: 2px !important; }
.stError   { background: rgba(224,92,92,0.07) !important;   border-left: 2px solid var(--crit) !important;  border-radius: 2px !important; }
.stInfo    { background: var(--accent-dim) !important;       border-left: 2px solid var(--accent) !important; border-radius: 2px !important; }

hr { border-color: var(--border) !important; margin: 10px 0 !important; }

::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 2px; }
::-webkit-scrollbar-thumb:hover { background: var(--accent); }
</style>
""", unsafe_allow_html=True)

# ── Constants ──────────────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "CRITICAL": "#e05c5c",
    "HIGH":     "#c87a3a",
    "MEDIUM":   "#c8a84b",
    "LOW":      "#7df9ff",
    "INFO":     "#44444f",
}

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

COMMON_VULNS: dict = {
    21: [
        {"cve": "CVE-2011-2523", "desc": "vsftpd 2.3.4 backdoor command execution", "cvss": 10.0, "severity": "CRITICAL"},
        {"cve": "CVE-1999-0497", "desc": "Anonymous FTP login permitted", "cvss": 5.0, "severity": "MEDIUM"},
    ],
    22: [
        {"cve": "CVE-2018-15473", "desc": "OpenSSH user enumeration via malformed packet", "cvss": 5.3, "severity": "MEDIUM"},
        {"cve": "CVE-2023-38408", "desc": "OpenSSH ssh-agent remote code execution", "cvss": 9.8, "severity": "CRITICAL"},
    ],
    23: [
        {"cve": "CVE-2020-10188", "desc": "Telnet cleartext credential exposure", "cvss": 9.8, "severity": "CRITICAL"},
    ],
    25: [
        {"cve": "CVE-2021-3129",  "desc": "Postfix open relay allows spam amplification", "cvss": 5.3, "severity": "MEDIUM"},
    ],
    80: [
        {"cve": "CVE-2021-41773", "desc": "Apache 2.4.49 path traversal / RCE", "cvss": 9.8, "severity": "CRITICAL"},
        {"cve": "CVE-2022-22965", "desc": "Spring4Shell — Spring MVC RCE via data binding", "cvss": 9.8, "severity": "CRITICAL"},
        {"cve": "CVE-2017-9798",  "desc": "Optionsbleed — Apache OPTIONS memory leak", "cvss": 7.5, "severity": "HIGH"},
    ],
    111: [
        {"cve": "CVE-2017-8779",  "desc": "rpcbind UDP amplification (memcrashed)", "cvss": 7.5, "severity": "HIGH"},
    ],
    443: [
        {"cve": "CVE-2014-0160",  "desc": "Heartbleed — OpenSSL TLS heartbeat memory leak", "cvss": 7.5, "severity": "HIGH"},
        {"cve": "CVE-2021-44228", "desc": "Log4Shell — JNDI injection via HTTP headers", "cvss": 10.0, "severity": "CRITICAL"},
        {"cve": "CVE-2022-0778",  "desc": "OpenSSL BN_mod_sqrt infinite loop DoS", "cvss": 7.5, "severity": "HIGH"},
    ],
    445: [
        {"cve": "CVE-2017-0144",  "desc": "EternalBlue — SMBv1 buffer overflow RCE", "cvss": 9.3, "severity": "CRITICAL"},
        {"cve": "CVE-2020-0796",  "desc": "SMBGhost — SMBv3 compression integer overflow RCE", "cvss": 10.0, "severity": "CRITICAL"},
        {"cve": "CVE-2021-36942", "desc": "PetitPotam — NTLM relay via EFS RPC", "cvss": 9.8, "severity": "CRITICAL"},
    ],
    512: [
        {"cve": "CVE-1999-0651",  "desc": "rsh daemon allows unauthenticated remote execution", "cvss": 10.0, "severity": "CRITICAL"},
    ],
    1433:[
        {"cve": "CVE-2020-0618",  "desc": "SQL Server Reporting Services RCE", "cvss": 8.8, "severity": "HIGH"},
    ],
    2049:[
        {"cve": "CVE-2019-3010",  "desc": "NFS world-readable export — data exfiltration", "cvss": 6.5, "severity": "MEDIUM"},
    ],
    3306:[
        {"cve": "CVE-2012-2122",  "desc": "MySQL auth bypass via timing attack", "cvss": 9.8, "severity": "CRITICAL"},
        {"cve": "CVE-2021-2307",  "desc": "MySQL Server privilege escalation via file read", "cvss": 6.1, "severity": "MEDIUM"},
    ],
    3389:[
        {"cve": "CVE-2019-0708",  "desc": "BlueKeep — RDP pre-auth heap overflow RCE", "cvss": 9.8, "severity": "CRITICAL"},
        {"cve": "CVE-2020-0609",  "desc": "Windows RD Gateway pre-auth RCE", "cvss": 9.8, "severity": "CRITICAL"},
        {"cve": "CVE-2022-21990", "desc": "Remote Desktop Client RCE via crafted server", "cvss": 8.8, "severity": "HIGH"},
    ],
    5432:[
        {"cve": "CVE-2019-9193",  "desc": "PostgreSQL COPY TO/FROM PROGRAM arbitrary command exec", "cvss": 7.2, "severity": "HIGH"},
    ],
    5900:[
        {"cve": "CVE-2019-15681", "desc": "LibVNCServer use-after-free memory leak", "cvss": 7.5, "severity": "HIGH"},
    ],
    6379:[
        {"cve": "CVE-2022-0543",  "desc": "Redis Lua sandbox escape — arbitrary code exec", "cvss": 10.0, "severity": "CRITICAL"},
    ],
    8080:[
        {"cve": "CVE-2021-26084", "desc": "Confluence Server OGNL injection RCE", "cvss": 9.8, "severity": "CRITICAL"},
        {"cve": "CVE-2019-17558", "desc": "Apache Solr Velocity RCE via template injection", "cvss": 8.1, "severity": "HIGH"},
    ],
    8443:[
        {"cve": "CVE-2021-22005", "desc": "vCenter Server arbitrary file upload to RCE", "cvss": 9.8, "severity": "CRITICAL"},
    ],
    9200:[
        {"cve": "CVE-2021-44228", "desc": "Elasticsearch Log4Shell via log message injection", "cvss": 10.0, "severity": "CRITICAL"},
        {"cve": "CVE-2015-1427",  "desc": "Elasticsearch Groovy sandbox escape RCE", "cvss": 10.0, "severity": "CRITICAL"},
    ],
    27017:[
        {"cve": "CVE-2013-4650",  "desc": "MongoDB unauthenticated remote access", "cvss": 9.4, "severity": "CRITICAL"},
    ],
}

CLOUD_CHECKS: dict = {
    "S3 Public Read Buckets":          {"risk": "HIGH",     "desc": "S3 buckets with public-read ACL expose data to the internet",          "remediation": "Set bucket ACL to private; grant least-privilege access via bucket policies."},
    "S3 Public Write Buckets":         {"risk": "CRITICAL", "desc": "S3 buckets with public-write ACL allow arbitrary data injection",       "remediation": "Remove public-write ACL immediately; audit recent uploads for malicious content."},
    "IAM Wildcard Policies":           {"risk": "CRITICAL", "desc": "IAM policies granting Action:* or Resource:* violate least-privilege",  "remediation": "Replace wildcards with resource-scoped, action-specific permissions."},
    "Unrestricted Inbound 0.0.0.0/0":  {"risk": "HIGH",     "desc": "Security groups with 0.0.0.0/0 inbound expose services publicly",       "remediation": "Restrict inbound rules to known CIDRs; use bastion or VPN for admin."},
    "MFA Not Enforced":                {"risk": "HIGH",     "desc": "Root account or IAM users lack MFA — credential stuffing risk",          "remediation": "Enable MFA on all IAM users; enforce via SCP at organisation level."},
    "CloudTrail Disabled":             {"risk": "MEDIUM",   "desc": "No CloudTrail logging — API calls unauditable for incident response",    "remediation": "Enable CloudTrail in all regions; ship logs to immutable S3 bucket."},
    "Encryption at Rest Disabled":     {"risk": "MEDIUM",   "desc": "EBS volumes or RDS instances have no at-rest encryption",                "remediation": "Enable AES-256 encryption on all storage; rotate unencrypted volumes."},
    "Public RDS Snapshots":            {"risk": "HIGH",     "desc": "RDS snapshots marked public — any AWS account can restore them",         "remediation": "Set all snapshots to private; audit sharing settings in all regions."},
    "Public EC2 AMIs":                 {"risk": "MEDIUM",   "desc": "Custom AMIs shared publicly may leak configuration or credentials",      "remediation": "Make AMIs private; scrub embedded credentials before any sharing."},
    "Default VPC In Use":              {"risk": "LOW",      "desc": "Default VPC lacks custom network segmentation controls",                  "remediation": "Create purpose-built VPCs with private/public subnets and NACLs."},
    "No VPC Flow Logs":                {"risk": "LOW",      "desc": "VPC Flow Logs disabled — no visibility into network-level anomalies",     "remediation": "Enable Flow Logs for all VPCs; forward to CloudWatch or SIEM."},
    "SSM Parameter Plaintext Secrets": {"risk": "MEDIUM",   "desc": "Sensitive values stored without SecureString encryption in SSM",         "remediation": "Migrate to SecureString with KMS; rotate any exposed values."},
    "GuardDuty Disabled":              {"risk": "HIGH",     "desc": "AWS GuardDuty threat detection not active in this region",                "remediation": "Enable GuardDuty in all regions; configure SNS alerts for high-severity findings."},
    "IMDSv1 Enabled on EC2":           {"risk": "MEDIUM",   "desc": "IMDSv1 allows SSRF-to-credential-theft on EC2 instances",               "remediation": "Enforce IMDSv2 via instance metadata option; set hop limit to 1."},
}

# ── Session state ──────────────────────────────────────────────────────────────
_defaults: dict = {
    "scan_results":   None,
    "cloud_findings": [],
    "cve_data":       {},
    "ai_analysis":    None,
    "scan_log":       [],
    "attack_paths":   [],
}
for _k, _v in _defaults.items():
    if _k not in st.session_state:
        st.session_state[_k] = _v

# ── Utility helpers ────────────────────────────────────────────────────────────

def log(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    st.session_state.scan_log.append(f"[{ts}]  {msg}")


def severity_badge(sev: str) -> str:
    c      = SEVERITY_COLORS.get(sev, "#44444f")
    text_c = "#0c0c0e" if sev == "LOW" else "#f0f0f0"
    return (
        f'<span style="background:{c};color:{text_c};padding:1px 7px;'
        f'border-radius:2px;font-size:0.66rem;font-weight:600;'
        f'font-family:\'IBM Plex Mono\',monospace;letter-spacing:1px">'
        f'{sev}</span>'
    )


def cvss_color(score: float) -> str:
    if score >= 9.0: return SEVERITY_COLORS["CRITICAL"]
    if score >= 7.0: return SEVERITY_COLORS["HIGH"]
    if score >= 4.0: return SEVERITY_COLORS["MEDIUM"]
    return SEVERITY_COLORS["LOW"]


def risk_label(score: int) -> str:
    if score >= 75: return "CRITICAL"
    if score >= 50: return "HIGH"
    if score >= 25: return "MEDIUM"
    return "LOW"


def validate_target(target: str) -> tuple:
    t = target.strip()
    if not t:
        return False, "Target cannot be empty."
    try:
        ipaddress.ip_network(t, strict=False)
        return True, ""
    except ValueError:
        pass
    if all(c.isalnum() or c in "-._/" for c in t):
        return True, ""
    return False, f"'{t}' does not look like a valid IP, CIDR, or hostname."

# ── Scan engine ────────────────────────────────────────────────────────────────

def simulate_port_scan(target: str, port_range: str, profile: str) -> dict:
    log(f"Simulation mode  target={target}  profile={profile}")
    results = {"target": target, "hosts": {}, "scan_time": 0.0, "method": "simulated"}
    t0 = time.time()

    base_open   = [22, 80, 443]
    common_open = [3306, 8080]
    rare_open   = [21, 23, 445, 3389, 5432, 6379, 8443, 9200, 27017, 1433, 5900, 25, 111, 2049, 512]
    n_rare      = {"Quick": 1, "Standard": 3, "Aggressive": 6}.get(profile, 2)
    open_ports  = base_open + common_open + random.sample(rare_open, min(n_rare, len(rare_open)))

    services = {
        21:    ("ftp",           "vsftpd 2.3.4"),
        22:    ("ssh",           "OpenSSH 7.4p1 Debian"),
        23:    ("telnet",        "Linux telnetd"),
        25:    ("smtp",          "Postfix smtpd"),
        80:    ("http",          "Apache httpd 2.4.49"),
        111:   ("rpcbind",       "2-4 (RPC #100000)"),
        443:   ("https",         "nginx/1.18.0 + OpenSSL 1.0.2k"),
        445:   ("microsoft-ds",  "Samba 4.6.2"),
        512:   ("exec",          "rsh daemon"),
        1433:  ("ms-sql-s",      "Microsoft SQL Server 2017"),
        2049:  ("nfs",           "NFS 3-4 (RPC #100003)"),
        3306:  ("mysql",         "MySQL 5.7.38"),
        3389:  ("ms-wbt-server", "MS Terminal Services"),
        5432:  ("postgresql",    "PostgreSQL 12.3"),
        5900:  ("vnc",           "VNC protocol 3.8"),
        6379:  ("redis",         "Redis 6.2.6"),
        8080:  ("http-proxy",    "Apache Tomcat 9.0.37"),
        8443:  ("https-alt",     "VMware vCenter 6.7.0"),
        9200:  ("elasticsearch", "Elasticsearch 7.10.0"),
        27017: ("mongodb",       "MongoDB 4.4.0"),
    }
    os_choices = [
        "Linux 4.15 (Ubuntu 18.04)",
        "Linux 5.4 (Ubuntu 20.04)",
        "Windows Server 2016 10.0.14393",
        "Windows Server 2019 10.0.17763",
        "CentOS Linux 7 (Core)",
        "Debian 10 (Buster)",
    ]
    host_info: dict = {
        "status":   "up",
        "hostname": f"host-{target.replace('.', '-')}.internal",
        "os_guess": random.choice(os_choices),
        "ports":    {},
    }
    for port in sorted(open_ports):
        svc, ver = services.get(port, ("unknown", ""))
        host_info["ports"][port] = {
            "state":           "open",
            "service":         svc,
            "version":         ver,
            "vulnerabilities": COMMON_VULNS.get(port, []),
        }
        log(f"  [OPEN]  {target}:{port:<6}  {svc}  ({ver})")
        time.sleep(0.04)

    results["hosts"][target] = host_info
    results["scan_time"] = round(time.time() - t0, 2)
    return results


def real_nmap_scan(target: str, port_range: str, profile: str) -> dict:
    nm = nmap.PortScanner()
    arg_map = {
        "Quick":      "-sV --version-intensity 3 -T4",
        "Standard":   "-sV --version-intensity 5 -T3",
        "Aggressive": "-sV --version-intensity 9 -O -A -T4",
    }
    args = arg_map.get(profile, "-sV -T3")
    try:
        log(f"nmap {args} -p {port_range} {target}")
        nm.scan(hosts=target, ports=port_range, arguments=args)
    except Exception as exc:
        log(f"nmap error: {exc} — switching to simulation")
        return simulate_port_scan(target, port_range, profile)

    results: dict = {"target": target, "hosts": {}, "scan_time": 0.0, "method": "nmap"}
    for host in nm.all_hosts():
        host_info: dict = {
            "status":   nm[host].state(),
            "hostname": nm[host].hostname() or host,
            "os_guess": "Unknown",
            "ports":    {},
        }
        if nm[host].get("osmatch"):
            host_info["os_guess"] = nm[host]["osmatch"][0]["name"]
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                pd = nm[host][proto][port]
                if pd["state"] == "open":
                    version = f"{pd.get('product','')} {pd.get('version','')}".strip()
                    host_info["ports"][port] = {
                        "state":           "open",
                        "service":         pd.get("name", "unknown"),
                        "version":         version or "unknown",
                        "vulnerabilities": COMMON_VULNS.get(port, []),
                    }
                    log(f"  [OPEN]  {host}:{port:<6}  {pd.get('name','')}  {version}")
        results["hosts"][host] = host_info
    return results


def cloud_config_scan() -> list:
    log("Starting cloud configuration audit...")
    findings = []
    for check, meta in CLOUD_CHECKS.items():
        prob = {"CRITICAL": 0.35, "HIGH": 0.45, "MEDIUM": 0.55, "LOW": 0.65}.get(meta["risk"], 0.5)
        if random.random() < prob:
            findings.append({
                "check":       check,
                "risk":        meta["risk"],
                "desc":        meta["desc"],
                "remediation": meta["remediation"],
            })
            log(f"  [FINDING]  {check}  [{meta['risk']}]")
    log(f"Cloud audit complete — {len(findings)} findings")
    return findings


def fetch_nvd_cve(cve_id: str) -> dict:
    if not REQUESTS_AVAILABLE:
        return {}
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        r = requests.get(url, timeout=6, headers={"User-Agent": "VulnScanPro/2.0"})
        if r.status_code == 200:
            data  = r.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                cve_obj      = vulns[0]["cve"]
                descriptions = cve_obj.get("descriptions", [])
                desc         = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
                metrics      = cve_obj.get("metrics", {})
                score        = 0.0
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics:
                        score = metrics[key][0]["cvssData"].get("baseScore", 0.0)
                        break
                references = [ref["url"] for ref in cve_obj.get("references", [])[:3]]
                return {"description": desc, "nvd_score": score,
                        "references": references, "fetched": True}
    except Exception as exc:
        log(f"  NVD fetch failed for {cve_id}: {exc}")
    return {}


def build_attack_paths(scan_results: dict, cloud_findings: list) -> list:
    paths: list = []
    if not scan_results:
        return paths

    for host, hdata in scan_results.get("hosts", {}).items():
        ports  = hdata.get("ports", {})
        scored = []
        for port, pdata in ports.items():
            for v in pdata.get("vulnerabilities", []):
                if v["severity"] in ("CRITICAL", "HIGH"):
                    scored.append((port, pdata, v))
        scored.sort(key=lambda x: x[2]["cvss"], reverse=True)
        if not scored:
            continue

        entry_port, entry_pdata, entry_vuln = scored[0]
        steps = [
            {"node": "INTERNET",            "type": "external", "label": "Attacker — public network"},
            {"node": f"{host}:{entry_port}", "type": "entry",   "label": f"Initial access via {entry_pdata['service'].upper()} — {entry_vuln['cve']}"},
        ]
        path_vulns = [entry_vuln]

        if len(scored) > 1:
            lat_port, lat_pdata, lat_vuln = scored[1]
            steps.append({
                "node":  f"{host}:{lat_port}",
                "type":  "lateral",
                "label": f"Privilege escalation / lateral move — {lat_vuln['cve']}",
            })
            path_vulns.append(lat_vuln)

        steps.append({"node": "CROWN JEWEL", "type": "target",
                      "label": "Data exfiltration / persistence / ransomware staging"})

        max_cvss   = max(v["cvss"] for v in path_vulns)
        likelihood = min(95, int(max_cvss * 9.2 + random.randint(-5, 5)))

        paths.append({
            "id":         f"PATH-{host.replace('.', '')}",
            "host":       host,
            "risk":       "CRITICAL" if max_cvss >= 9.0 else "HIGH",
            "steps":      steps,
            "vulns_used": path_vulns,
            "likelihood": likelihood,
        })

    for cf in cloud_findings:
        if cf["risk"] not in ("CRITICAL", "HIGH"):
            continue
        paths.append({
            "id":   f"PATH-CLOUD-{len(paths)}",
            "host": "Cloud Infrastructure",
            "risk": cf["risk"],
            "steps": [
                {"node": "INTERNET",        "type": "external", "label": "Unauthenticated public access"},
                {"node": cf["check"],        "type": "entry",    "label": f"Misconfiguration: {cf['check']}"},
                {"node": "CLOUD RESOURCES", "type": "target",   "label": "Account takeover / data access / persistence"},
            ],
            "vulns_used": [{"cve": "MISCONFIG", "desc": cf["desc"], "cvss": 8.5, "severity": cf["risk"]}],
            "likelihood": random.randint(50, 88),
        })

    return paths

# ── AI analysis ────────────────────────────────────────────────────────────────

def ai_risk_analysis(scan_results: dict, cloud_findings: list,
                     attack_paths: list, api_key: str) -> str:
    if not ANTHROPIC_AVAILABLE or not api_key:
        return ""

    crit_vulns: list = []
    if scan_results:
        for host, hdata in scan_results.get("hosts", {}).items():
            for port, pdata in hdata.get("ports", {}).items():
                for v in pdata.get("vulnerabilities", []):
                    if v["severity"] in ("CRITICAL", "HIGH"):
                        crit_vulns.append({
                            "host": host, "port": port,
                            "service": pdata["service"],
                            "cve": v["cve"], "desc": v["desc"],
                            "cvss": v["cvss"], "severity": v["severity"],
                        })

    summary = {
        "scan_method":       scan_results.get("method", "unknown") if scan_results else "none",
        "hosts_scanned":     len(scan_results.get("hosts", {})) if scan_results else 0,
        "total_open_ports":  sum(len(h["ports"]) for h in scan_results.get("hosts", {}).values()) if scan_results else 0,
        "critical_high_vulns": crit_vulns,
        "cloud_findings_critical_high": [
            {"check": f["check"], "risk": f["risk"], "desc": f["desc"]}
            for f in cloud_findings if f["risk"] in ("CRITICAL", "HIGH")
        ],
        "attack_paths_count": len(attack_paths),
        "highest_cvss": max((v["cvss"] for v in crit_vulns), default=0.0),
    }

    prompt = f"""You are a senior penetration tester and security architect.
Analyse the following vulnerability assessment output and produce a structured report.

SCAN SUMMARY (JSON):
{json.dumps(summary, indent=2)}

Produce the following sections using markdown:

## Executive Summary
3-4 sentences — non-technical, suitable for a CISO or board audience.

## Top 3 Critical Risks
For each: risk name, business impact, and exploitability context.

## Most Likely Attack Scenario
Walk through the most probable end-to-end attack chain given the findings.
Be specific about CVEs and services involved.

## Remediation Roadmap
Three time-boxed action lists:
- **Immediate (24-72 hours)** — things that must be done now
- **Short-term (30 days)** — structural fixes
- **Strategic (90 days)** — architectural hardening

## Overall Risk Score
Score: XX/100 — with a one-sentence rationale.
(Use: 0-24=LOW, 25-49=MEDIUM, 50-74=HIGH, 75-100=CRITICAL)

Be concise, specific, and actionable. Do not pad with generic advice."""

    try:
        client = anthropic.Anthropic(api_key=api_key)
        msg = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text
    except anthropic.AuthenticationError:
        return "**Authentication error** — check your Anthropic API key."
    except anthropic.RateLimitError:
        return "**Rate limit reached** — retry in a moment."
    except Exception as exc:
        return f"**AI analysis error:** {exc}"

# ── Plotly charts ──────────────────────────────────────────────────────────────

_BG      = "rgba(0,0,0,0)"
_GRID    = "#2a2a32"
_TEXT    = "#d4d4d8"
_DIM     = "#6b6b78"
_MONO    = "IBM Plex Mono"


def _base_layout(**kwargs) -> dict:
    return dict(
        paper_bgcolor=_BG, plot_bgcolor=_BG,
        font=dict(color=_TEXT, family=_MONO),
        margin=dict(t=16, b=16, l=16, r=16),
        **kwargs,
    )


def render_severity_donut(findings_by_sev: dict) -> None:
    if not PLOTLY_AVAILABLE:
        return
    ordered = [(s, findings_by_sev[s]) for s in SEV_ORDER if s in findings_by_sev]
    labels  = [o[0] for o in ordered]
    values  = [o[1] for o in ordered]
    colors  = [SEVERITY_COLORS[l] for l in labels]
    total   = sum(values)

    fig = go.Figure(go.Pie(
        labels=labels, values=values, hole=0.68,
        marker=dict(colors=colors, line=dict(color="#0c0c0e", width=2)),
        textinfo="label+value",
        textfont=dict(family=_MONO, size=10, color=_TEXT),
        hovertemplate="<b>%{label}</b><br>Count: %{value}<br>%{percent}<extra></extra>",
    ))
    fig.update_layout(**_base_layout(height=300,
        legend=dict(font=dict(color=_TEXT, family=_MONO, size=10))))
    fig.add_annotation(text="TOTAL", x=0.5, y=0.57,
        font=dict(size=9, color=_DIM, family=_MONO), showarrow=False)
    fig.add_annotation(text=str(total), x=0.5, y=0.44,
        font=dict(size=30, color="#7df9ff", family=_MONO), showarrow=False)
    st.plotly_chart(fig, use_container_width=True)


def render_cvss_bar(vulns: list) -> None:
    if not PLOTLY_AVAILABLE or not vulns:
        return
    top     = sorted(vulns, key=lambda v: v["cvss"], reverse=True)[:12]
    cve_ids = [v["cve"] for v in top]
    scores  = [v["cvss"] for v in top]
    colors  = [cvss_color(s) for s in scores]

    fig = go.Figure(go.Bar(
        x=scores, y=cve_ids, orientation="h",
        marker=dict(color=colors, line=dict(color="#0c0c0e", width=1)),
        text=[f"{s:.1f}" for s in scores],
        textposition="outside",
        textfont=dict(color=_TEXT, family=_MONO, size=9),
        hovertemplate="<b>%{y}</b><br>CVSS: %{x}<extra></extra>",
    ))
    fig.update_layout(**_base_layout(
        height=max(220, len(top) * 26),
        xaxis=dict(range=[0, 11.5], color=_DIM, gridcolor=_GRID,
                   tickfont=dict(family=_MONO, size=8)),
        yaxis=dict(color=_TEXT, tickfont=dict(family=_MONO, size=8), autorange="reversed"),
    ))
    st.plotly_chart(fig, use_container_width=True)


def render_risk_gauge(score: int) -> None:
    if not PLOTLY_AVAILABLE:
        return
    color = (
        SEVERITY_COLORS["CRITICAL"] if score >= 75 else
        SEVERITY_COLORS["HIGH"]     if score >= 50 else
        SEVERITY_COLORS["MEDIUM"]   if score >= 25 else
        SEVERITY_COLORS["LOW"]
    )
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        number={"font": {"color": color, "family": _MONO, "size": 34}},
        gauge={
            "axis":       {"range": [0, 100], "tickcolor": _DIM,
                           "tickfont": {"family": _MONO, "size": 8}},
            "bar":        {"color": color, "thickness": 0.22},
            "bgcolor":    "#17171b",
            "borderwidth":1,
            "bordercolor":_GRID,
            "steps": [
                {"range": [0,  25],  "color": "#111114"},
                {"range": [25, 50],  "color": "#141416"},
                {"range": [50, 75],  "color": "#161618"},
                {"range": [75, 100], "color": "#18161a"},
            ],
            "threshold": {"line": {"color": color, "width": 2},
                          "thickness": 0.8, "value": score},
        },
    ))
    fig.update_layout(**_base_layout(height=220,
        annotations=[dict(text=risk_label(score), x=0.5, y=0.22,
            showarrow=False, font=dict(color=color, size=12, family=_MONO))]))
    st.plotly_chart(fig, use_container_width=True)


def render_attack_path_graph(path: dict) -> None:
    if not PLOTLY_AVAILABLE:
        return
    steps = path["steps"]
    n     = len(steps)
    xs    = list(range(n))
    node_colors = {
        "external": SEVERITY_COLORS["CRITICAL"],
        "entry":    SEVERITY_COLORS["HIGH"],
        "lateral":  SEVERITY_COLORS["MEDIUM"],
        "target":   "#7df9ff",
    }
    fig = go.Figure()
    for i in range(n - 1):
        fig.add_shape(type="line",
            x0=xs[i], y0=0, x1=xs[i+1], y1=0,
            line=dict(color=_GRID, width=2, dash="dot"))
        fig.add_annotation(
            x=(xs[i] + xs[i+1]) / 2, y=0.12,
            text="->", showarrow=False,
            font=dict(color=_DIM, size=11, family=_MONO))
    for i, step in enumerate(steps):
        c = node_colors.get(step["type"], _DIM)
        fig.add_trace(go.Scatter(
            x=[xs[i]], y=[0],
            mode="markers+text",
            marker=dict(size=18, color=c, symbol="square",
                        line=dict(color="#0c0c0e", width=2)),
            text=[step["node"]],
            textposition="bottom center",
            textfont=dict(family=_MONO, size=8, color=_TEXT),
            hovertext=step["label"],
            hoverinfo="text",
            showlegend=False,
        ))
    fig.update_layout(**_base_layout(
        height=148,
        xaxis=dict(visible=False),
        yaxis=dict(visible=False, range=[-0.6, 0.55]),
    ))
    st.plotly_chart(fig, use_container_width=True)

# ── Sidebar ────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown(
        '<p style="font-family:\'IBM Plex Mono\',monospace;font-size:1rem;'
        'font-weight:600;letter-spacing:4px;color:#7df9ff;'
        'text-shadow:0 0 14px rgba(125,249,255,0.38);margin:0 0 2px">'
        'VULNSCAN PRO</p>'
        '<p style="font-family:\'IBM Plex Mono\',monospace;font-size:0.6rem;'
        'letter-spacing:2px;color:#44444f;margin:0 0 12px">v2.0  AI-ASSISTED  ASSESSMENT</p>',
        unsafe_allow_html=True,
    )
    st.divider()

    st.markdown("### Target")
    target_input = st.text_input(
        "target", value="192.168.1.1",
        help="Examples: 10.0.0.1  |  192.168.0.0/24  |  example.com",
        label_visibility="collapsed",
        placeholder="IP / CIDR / Hostname",
    )
    port_range = st.text_input(
        "ports", value="22,80,443,445,3306,3389,8080",
        help="Comma-separated or range: 1-1024, 22,80,443",
        label_visibility="collapsed",
        placeholder="Port range",
    )
    scan_profile = st.selectbox(
        "Profile", ["Quick", "Standard", "Aggressive"],
        help="Quick: fast service detection | Standard: version scan | Aggressive: OS + scripts",
    )
    st.divider()

    st.markdown("### Modules")
    enable_cloud = st.checkbox("Cloud config audit", value=True)
    enable_ai    = st.checkbox("AI risk analysis",   value=True)
    st.divider()

    st.markdown("### API Key")
    api_key = st.text_input(
        "key", type="password",
        value=os.environ.get("ANTHROPIC_API_KEY", ""),
        help="Required for AI analysis. Reads ANTHROPIC_API_KEY env var automatically.",
        label_visibility="collapsed",
        placeholder="sk-ant-...",
    )
    st.divider()

    st.markdown("### Environment")

    def _dep(name: str, ok: bool) -> str:
        c = "#7df9ff" if ok else SEVERITY_COLORS["MEDIUM"]
        s = "OK" if ok else "MISSING"
        return (
            f'<span style="font-family:\'IBM Plex Mono\',monospace;font-size:0.7rem;'
            f'color:{c}">{name:<12} {s}</span>'
        )

    st.markdown(
        _dep("nmap",      NMAP_AVAILABLE)     + "<br>" +
        _dep("plotly",    PLOTLY_AVAILABLE)    + "<br>" +
        _dep("anthropic", ANTHROPIC_AVAILABLE) + "<br>" +
        _dep("networkx",  NX_AVAILABLE),
        unsafe_allow_html=True,
    )
    if not NMAP_AVAILABLE:
        st.info(
            "nmap not found — running simulation mode.\n\n"
            "Install: `pip install python-nmap`\nand ensure the nmap binary is in PATH."
        )
    st.divider()
    scan_btn = st.button("LAUNCH SCAN", use_container_width=True)

# ── Header ─────────────────────────────────────────────────────────────────────

st.markdown(
    '<h1 style="margin-bottom:0">VULNSCAN PRO</h1>'
    '<p style="font-family:\'IBM Plex Mono\',monospace;font-size:0.68rem;'
    'letter-spacing:3px;color:#44444f;margin-top:2px">'
    'AI-ASSISTED VULNERABILITY ASSESSMENT  //  NETWORK  CLOUD  CVE  ATTACK-PATH  AI-SCORING'
    '</p>',
    unsafe_allow_html=True,
)

# ── Run scan ───────────────────────────────────────────────────────────────────

if scan_btn:
    valid, err = validate_target(target_input)
    if not valid:
        st.error(f"Invalid target: {err}")
        st.stop()

    for k, v in _defaults.items():
        st.session_state[k] = [] if isinstance(v, list) else ({} if isinstance(v, dict) else None)

    prog = st.progress(0, text="Initialising scan engine...")
    log(f"=== SCAN START  target={target_input}  ports={port_range}  profile={scan_profile} ===")

    prog.progress(5, text="Phase 1/5 — Network discovery and port scan")
    if NMAP_AVAILABLE:
        results = real_nmap_scan(target_input, port_range, scan_profile)
    else:
        results = simulate_port_scan(target_input, port_range, scan_profile)
    st.session_state.scan_results = results
    prog.progress(30, text="Phase 2/5 — CVE correlation and NVD enrichment")

    all_cves: set = set()
    for h in results.get("hosts", {}).values():
        for pd in h.get("ports", {}).values():
            for v in pd.get("vulnerabilities", []):
                all_cves.add(v["cve"])
    log(f"Correlating {len(all_cves)} CVEs — fetching up to 6 from NVD...")
    for cve in list(all_cves)[:6]:
        data = fetch_nvd_cve(cve)
        if data:
            st.session_state.cve_data[cve] = data
            log(f"  [NVD]  {cve}  CVSS={data.get('nvd_score','?')}")
        time.sleep(0.15)

    prog.progress(55, text="Phase 3/5 — Cloud configuration audit")
    cloud_findings = cloud_config_scan() if enable_cloud else []
    st.session_state.cloud_findings = cloud_findings
    prog.progress(72, text="Phase 4/5 — Attack path modeling")

    paths = build_attack_paths(results, cloud_findings)
    st.session_state.attack_paths = paths
    log(f"Attack path modeling complete — {len(paths)} paths")
    prog.progress(88, text="Phase 5/5 — AI risk analysis")

    if enable_ai and api_key:
        log("Calling Claude AI for risk scoring and remediation plan...")
        st.session_state.ai_analysis = ai_risk_analysis(results, cloud_findings, paths, api_key)
        log("AI analysis complete")
    elif enable_ai and not api_key:
        log("AI analysis skipped — no API key")

    prog.progress(100, text="Scan complete")
    log(f"=== SCAN COMPLETE  method={results.get('method','?')}  time={results.get('scan_time','?')}s ===")
    st.success(
        f"Scan complete — {len(results.get('hosts', {}))} host(s)  "
        f"in {results.get('scan_time', 0):.2f}s  "
        f"({results.get('method','?')} mode)"
    )

# ── Dashboard ──────────────────────────────────────────────────────────────────

if st.session_state.scan_results:
    scan   = st.session_state.scan_results
    clouds = st.session_state.cloud_findings
    paths  = st.session_state.attack_paths

    all_vulns: list      = []
    sev_counts: dict     = defaultdict(int)
    for hdata in scan.get("hosts", {}).values():
        for pdata in hdata.get("ports", {}).values():
            for v in pdata.get("vulnerabilities", []):
                all_vulns.append(v)
                sev_counts[v["severity"]] += 1
    for cf in clouds:
        sev_counts[cf["risk"]] += 1

    total_open_ports = sum(len(h["ports"]) for h in scan.get("hosts", {}).values())
    total_vulns      = sum(sev_counts.values())
    risk_score       = min(100, int(
        sev_counts.get("CRITICAL", 0) * 22 +
        sev_counts.get("HIGH",     0) * 9  +
        sev_counts.get("MEDIUM",   0) * 3  +
        sev_counts.get("LOW",      0) * 1
    ))

    st.markdown("---")
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Hosts",        len(scan.get("hosts", {})))
    c2.metric("Open Ports",   total_open_ports)
    c3.metric("Findings",     total_vulns)
    c4.metric("Critical",     sev_counts.get("CRITICAL", 0))
    c5.metric("High",         sev_counts.get("HIGH", 0))
    c6.metric("Attack Paths", len(paths))
    st.markdown("---")

    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "HOSTS / PORTS",
        "VULNERABILITIES",
        "CLOUD CONFIG",
        "ATTACK PATHS",
        "AI ANALYSIS",
        "SCAN LOG",
    ])

    # ── Tab 1: Hosts ───────────────────────────────────────────────────────────
    with tab1:
        st.markdown("## Discovered Hosts")
        for host, hdata in scan.get("hosts", {}).items():
            open_ports = hdata.get("ports", {})
            vuln_count = sum(len(p.get("vulnerabilities", [])) for p in open_ports.values())
            crit_count = sum(
                1 for p in open_ports.values()
                for v in p.get("vulnerabilities", []) if v["severity"] == "CRITICAL"
            )
            label = (
                f"{host}  //  {hdata.get('os_guess','Unknown OS')}  //  "
                f"{len(open_ports)} ports  //  {vuln_count} vulns  "
                f"({crit_count} CRITICAL)"
            )
            with st.expander(label):
                ca, cb = st.columns(2)
                with ca:
                    st.markdown(f"**Hostname:** `{hdata.get('hostname','N/A')}`")
                    st.markdown(f"**OS guess:** `{hdata.get('os_guess','N/A')}`")
                with cb:
                    st.markdown(f"**Status:** `{hdata.get('status','up')}`")
                    st.markdown(f"**Method:** `{scan.get('method','?')}`")
                st.markdown("##### Port map")
                for port in sorted(open_ports.keys()):
                    pd     = open_ports[port]
                    badges = " ".join(severity_badge(v["severity"]) for v in pd.get("vulnerabilities", []))
                    nvd_ref = ""
                    for v in pd.get("vulnerabilities", []):
                        enriched = st.session_state.cve_data.get(v["cve"], {})
                        if enriched.get("references"):
                            nvd_ref = enriched["references"][0]
                            break
                    ref_html = (
                        f' <a href="{nvd_ref}" target="_blank" '
                        f'style="color:#44444f;font-size:0.68rem;text-decoration:none">NVD</a>'
                        if nvd_ref else ""
                    )
                    st.markdown(
                        f'<div style="font-family:\'IBM Plex Mono\',monospace;font-size:0.76rem;'
                        f'padding:3px 0;border-bottom:1px solid #1e1e24">'
                        f'<span style="color:#7df9ff;display:inline-block;width:50px">{port}</span>'
                        f'<span style="color:#6dba8a;display:inline-block;width:138px">{pd["service"]}</span>'
                        f'<span style="color:#6b6b78;display:inline-block;width:255px">{pd["version"]}</span>'
                        f'{badges}{ref_html}</div>',
                        unsafe_allow_html=True,
                    )

    # ── Tab 2: Vulnerabilities ─────────────────────────────────────────────────
    with tab2:
        st.markdown("## Vulnerability Intelligence")
        cd, cg, cb2 = st.columns([1.2, 1, 2])
        with cd:
            if PLOTLY_AVAILABLE and sev_counts:
                render_severity_donut(dict(sev_counts))
        with cg:
            if PLOTLY_AVAILABLE:
                render_risk_gauge(risk_score)
        with cb2:
            if PLOTLY_AVAILABLE and all_vulns:
                render_cvss_bar(all_vulns)

        st.markdown("##### Findings")
        st.markdown(
            '<div style="display:grid;grid-template-columns:180px 90px 58px 1fr;'
            'gap:8px;padding:4px 8px;border-bottom:1px solid #2a2a32;'
            'font-family:\'IBM Plex Mono\',monospace;font-size:0.62rem;'
            'letter-spacing:1px;color:#44444f">'
            '<span>CVE ID</span><span>SEVERITY</span><span>CVSS</span><span>DESCRIPTION</span></div>',
            unsafe_allow_html=True,
        )
        for v in sorted(all_vulns, key=lambda x: x["cvss"], reverse=True):
            enriched = st.session_state.cve_data.get(v["cve"], {})
            desc     = enriched.get("description", v["desc"])
            score    = enriched.get("nvd_score", v["cvss"])
            sc       = cvss_color(score)
            st.markdown(
                f'<div style="display:grid;grid-template-columns:180px 90px 58px 1fr;'
                f'gap:8px;padding:5px 8px;border-bottom:1px solid #1e1e24;'
                f'font-family:\'IBM Plex Mono\',monospace;font-size:0.74rem">'
                f'<span style="color:#7df9ff">{v["cve"]}</span>'
                f'<span>{severity_badge(v["severity"])}</span>'
                f'<span style="color:{sc};font-weight:600">{score:.1f}</span>'
                f'<span style="color:#6b6b78">{desc[:135]}{"..." if len(desc)>135 else ""}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )

    # ── Tab 3: Cloud ───────────────────────────────────────────────────────────
    with tab3:
        st.markdown("## Cloud Configuration Audit")
        if not clouds:
            st.success("No cloud misconfigurations detected.")
        else:
            ordered_clouds = sorted(
                clouds,
                key=lambda x: SEV_ORDER.index(x["risk"]) if x["risk"] in SEV_ORDER else 99,
            )
            st.markdown(
                '<div style="display:grid;grid-template-columns:230px 86px 1fr 1fr;'
                'gap:8px;padding:4px 8px;border-bottom:1px solid #2a2a32;'
                'font-family:\'IBM Plex Mono\',monospace;font-size:0.62rem;'
                'letter-spacing:1px;color:#44444f">'
                '<span>CHECK</span><span>RISK</span><span>DESCRIPTION</span><span>REMEDIATION</span></div>',
                unsafe_allow_html=True,
            )
            for cf in ordered_clouds:
                st.markdown(
                    f'<div style="display:grid;grid-template-columns:230px 86px 1fr 1fr;'
                    f'gap:8px;padding:6px 8px;border-bottom:1px solid #1e1e24;'
                    f'font-family:\'IBM Plex Mono\',monospace;font-size:0.74rem">'
                    f'<span style="color:#d4d4d8;font-weight:600">{cf["check"]}</span>'
                    f'<span>{severity_badge(cf["risk"])}</span>'
                    f'<span style="color:#6b6b78">{cf["desc"]}</span>'
                    f'<span style="color:#6dba8a;font-size:0.68rem">{cf["remediation"]}</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

    # ── Tab 4: Attack Paths ────────────────────────────────────────────────────
    with tab4:
        st.markdown("## Attack Path Modeling")
        if not paths:
            st.info("No high-risk attack paths identified from current findings.")
        else:
            st.markdown(
                f'<p style="font-family:\'IBM Plex Mono\',monospace;font-size:0.72rem;'
                f'color:#6b6b78">{len(paths)} attack chain(s) modelled — '
                f'public internet to target asset.</p>',
                unsafe_allow_html=True,
            )
            for path in sorted(paths, key=lambda p: p["likelihood"], reverse=True):
                header = (
                    f'{path["id"]}  //  {path["host"]}  //  '
                    f'risk: {path["risk"]}  //  likelihood: {path["likelihood"]}%'
                )
                with st.expander(header):
                    render_attack_path_graph(path)
                    st.markdown("**Vulnerabilities in chain:**")
                    for v in path["vulns_used"]:
                        st.markdown(
                            f'- `{v["cve"]}` &nbsp;{severity_badge(v["severity"])}&nbsp; '
                            f'CVSS **{v["cvss"]}** — {v["desc"]}',
                            unsafe_allow_html=True,
                        )
                    st.markdown("**Attack steps:**")
                    for i, step in enumerate(path["steps"]):
                        st.markdown(
                            f'<p style="font-family:\'IBM Plex Mono\',monospace;'
                            f'font-size:0.76rem;color:#d4d4d8;margin:2px 0">'
                            f'<span style="color:#44444f">{i+1}.</span>  '
                            f'<span style="color:#7df9ff">{step["node"]}</span>  '
                            f'<span style="color:#6b6b78">— {step["label"]}</span></p>',
                            unsafe_allow_html=True,
                        )

    # ── Tab 5: AI Analysis ─────────────────────────────────────────────────────
    with tab5:
        st.markdown("## AI Risk Analysis")
        if st.session_state.ai_analysis:
            st.markdown(st.session_state.ai_analysis)
        elif not api_key:
            st.info(
                "Enter your Anthropic API key in the sidebar to enable AI-powered "
                "risk scoring, attack scenario narrative, and remediation planning."
            )
        else:
            st.info("Run a scan with AI Analysis enabled to see the report.")

    # ── Tab 6: Scan Log ────────────────────────────────────────────────────────
    with tab6:
        st.markdown("## Scan Log")
        st.code("\n".join(st.session_state.scan_log), language="bash")

# ── Welcome screen ─────────────────────────────────────────────────────────────
else:
    st.markdown(
        '<div style="border:1px solid #2a2a32;border-radius:2px;'
        'padding:48px 40px;margin-top:16px;background:#111114;text-align:center">'
        '<p style="font-family:\'IBM Plex Mono\',monospace;font-size:0.6rem;'
        'letter-spacing:4px;color:#44444f;margin:0 0 8px">STATUS</p>'
        '<p style="font-family:\'IBM Plex Mono\',monospace;font-size:1.35rem;'
        'letter-spacing:6px;color:#7df9ff;'
        'text-shadow:0 0 18px rgba(125,249,255,0.32);margin:0 0 16px;font-weight:600">'
        'READY TO SCAN</p>'
        '<p style="font-family:\'IBM Plex Mono\',monospace;font-size:0.72rem;'
        'letter-spacing:1px;color:#6b6b78;max-width:480px;margin:0 auto;line-height:1.8">'
        'Configure target and modules in the sidebar.<br>'
        'Press LAUNCH SCAN to begin assessment.<br><br>'
        'Network discovery  //  CVE intelligence  //  Cloud audit<br>'
        'Attack path modeling  //  AI risk scoring'
        '</p></div>',
        unsafe_allow_html=True,
    )

    features = [
        ("NETWORK SCAN",
         "nmap-driven host discovery, OS detection, and service fingerprinting. "
         "Graceful fallback to simulation mode when nmap is unavailable."),
        ("CVE INTELLIGENCE",
         "Correlates open ports against an expanded CVE database covering 20+ service types. "
         "Enriches findings with live CVSS scores from the NVD 2.0 API."),
        ("CLOUD AUDIT",
         "14 AWS misconfiguration checks: public S3, IAM wildcards, open security groups, "
         "missing MFA, GuardDuty status, IMDSv1 exposure, and more."),
        ("ATTACK PATHS",
         "Models end-to-end attack chains ranked by CVSS and exploitability. "
         "Shows how vulnerabilities chain from internet exposure to crown jewel assets."),
        ("AI ANALYSIS",
         "Claude produces an executive summary, top-3 risk breakdown, most likely "
         "attack scenario, and a 24h / 30d / 90d remediation roadmap."),
        ("AUDIT TRAIL",
         "Full millisecond-precision scan log for compliance documentation, "
         "incident response timelines, and post-assessment review."),
    ]
    cols = st.columns(3)
    for i, (title, desc) in enumerate(features):
        with cols[i % 3]:
            st.markdown(
                f'<div style="background:#17171b;border:1px solid #2a2a32;'
                f'border-radius:2px;padding:16px;margin-top:12px">'
                f'<p style="font-family:\'IBM Plex Mono\',monospace;font-size:0.68rem;'
                f'font-weight:600;letter-spacing:2px;color:#7df9ff;margin:0 0 6px">{title}</p>'
                f'<p style="font-family:\'IBM Plex Mono\',monospace;font-size:0.7rem;'
                f'color:#6b6b78;line-height:1.65;margin:0">{desc}</p>'
                f'</div>',
                unsafe_allow_html=True,
            )
