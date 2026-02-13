A professional-grade, interactive security assessment tool for comprehensive vulnerability scanning of local systems and network infrastructure. Written in pure Python with zero external dependencies.

# Features

### Core Capabilities

| Feature | Description |
|---------|-------------|
|  **Interactive Menu** | Choose from 4 scan modes with a beautiful TUI - no complex commands to remember |
|  **Multi-threaded** | Scan hundreds of hosts simultaneously with configurable thread pools (default: 50 threads) |
|  **Risk Scoring** | Get an instant 0-100 security score - know your security posture at a glance |
|  **Zero Dependencies** | Pure Python stdlib - no `pip install`, no virtual environments, just run it |
|  **Cross-Platform** | One script works everywhere: Linux, Windows, macOS - write once, scan anywhere |
|  **Actionable Reports** | Every vulnerability includes detailed remediation steps - not just detection |
|  **Real-time Output** | Color-coded severity levels with live progress - watch your scan unfold |

### Local System Security Checks (25+ Tests)

| Category | Checks |
|----------|--------|
| **System Updates** | OS version, available patches, outdated packages |
| **Network Security** | Open ports, firewall status, weak protocols (Telnet, FTP) |
| **Access Control** | User accounts with UID 0, excessive login users, password policies |
| **Services** | Running risky services (Telnet, RSH, FTP), SSH configuration |
| **Data Protection** | Disk encryption (LUKS/BitLocker), file permissions on critical files |
| **Software** | Antivirus presence, vulnerable software, system hardening (SELinux/AppArmor) |
| **Network Shares** | Samba, NFS, Windows shares exposure |

### Network Discovery & Scanning

- **Automatic Subnet Detection** - Identifies your network range (e.g., 192.168.1.0/24)
- **Host Discovery** - Multi-threaded ping sweep to find active devices
- **Port Scanning** - Scans 22+ common ports on each discovered host
- **Service Identification** - Detects running services and versions
- **Banner Grabbing** - Retrieves service banners for version analysis
- **Database Exposure** - Checks for exposed MySQL, PostgreSQL, MongoDB, Redis
- **Vulnerability Mapping** - Cross-references findings with known CVEs

## Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/vulnscanner.git
cd vulnscanner

# Run with elevated privileges (recommended)
sudo python3 vulnscanner.py

# Or without sudo (limited checks)
python3 vulnscanner.py
```

That's it! No dependencies to install. The interactive menu will guide you through the rest.

## Scan Modes

### Mode 1: Local System Only 

**Best for:** Workstation security audits, compliance checks

```
✓ Fast execution (30-60 seconds)
✓ No network traffic generated
✓ Comprehensive local security assessment
✓ Perfect for individual machine hardening
```

**Checks performed:**
- OS version & patches
- Open ports & services
- Firewall configuration
- User accounts & passwords
- SSH settings
- File permissions
- Antivirus status
- Disk encryption

---

### Mode 2: Network Only 

**Best for:** Network infrastructure assessment, discovering rogue devices

```
✓ Discovers all active hosts
✓ Port scans each device
✓ Identifies vulnerable services
✓ Maps network topology
✓ Does NOT scan local system
```

**Checks performed:**
- Host discovery (ping sweep)
- Port scanning (22+ ports per host)
- Service identification
- Version detection
- Exposed database checks
- Insecure protocol detection

---

### Mode 3: Full Scan (Recommended) 

**Best for:** Complete security audit, quarterly assessments

```
✓ Most comprehensive option
✓ Combines Mode 1 + Mode 2
✓ Complete security posture assessment
✓ Takes longer but most thorough
```

**Checks performed:**
- Everything from Mode 1
- Everything from Mode 2
- Network-wide risk assessment
- Cross-host vulnerability correlation

**Typical duration:** 5-15 minutes depending on network size

---

### Mode 4: Quick Scan 

**Best for:** Regular monitoring, quick security overview

```
✓ Essential checks only
✓ Fast execution
✓ Good for weekly/daily monitoring
✓ Lightweight resource usage
```

**Checks performed:**
- Critical vulnerabilities only
- Open dangerous ports (Telnet, FTP)
- Basic firewall check
- Critical file permissions

---

## What Gets Scanned

### Local System Vulnerabilities

<details>
<summary><b>🔴 CRITICAL Severity Issues</b></summary>

- Non-root users with UID 0 (root privileges)
- SSH Protocol 1 enabled
- SSH permits empty passwords
- `/etc/shadow` world-readable
- Telnet service running locally

</details>

<details>
<summary><b>🟠 HIGH Severity Issues</b></summary>

- Firewall disabled (UFW, iptables, Windows Firewall)
- SSH root login enabled
- RDP exposed to network (port 3389)
- VNC server accessible (port 5900)
- Weak minimum password length (<8 chars)
- Insecure services running (FTP, RSH, Rlogin)
- Windows Defender disabled

</details>

<details>
<summary><b>🟡 MEDIUM Severity Issues</b></summary>

- 10+ package updates available
- Weak password expiration policy (>90 days)
- SSH password authentication enabled
- SMB exposed (EternalBlue risk)
- Database exposed to network
- No disk encryption
- Multiple network shares configured
- Vulnerable software installed

</details>

<details>
<summary><b>🔵 LOW Severity Issues</b></summary>

- No antivirus/security tools installed
- Excessive user accounts (>15)
- Samba/NFS configured
- Information disclosure (server versions)

</details>

### Network Vulnerabilities Detected

| Service/Port | Severity | Risk Description |
|--------------|----------|------------------|
| **Telnet (23)** | CRITICAL | Cleartext credential transmission |
| **FTP (21)** | HIGH | Unencrypted file transfer |
| **RDP (3389)** | HIGH | Remote Desktop brute-force target |
| **VNC (5900)** | HIGH | Often weak/no authentication |
| **SMB (445)** | MEDIUM | EternalBlue vulnerability risk |
| **MySQL (3306)** | HIGH | Database exposed to network |
| **MongoDB (27017)** | HIGH | NoSQL database often lacks auth |
| **Redis (6379)** | HIGH | In-memory DB with weak defaults |
| **PostgreSQL (5432)** | HIGH | Database network exposure |

---
