KEY FEATURES
Interactive Menu System

4 Scan Modes: Local Only, Network Only, Full Scan, Quick Scan
User-friendly menu with color-coded options
Configurable verbose output and threading

Local System Scanning (Your Computer)
✅ OS version & security patches
✅ Open ports & risky services detection
✅ Firewall status (UFW, iptables, Windows Firewall)
✅ User account security (UID 0 checks, excessive accounts)
✅ Password policies (aging, length requirements)
✅ Running services (Telnet, FTP, RSH detection)
✅ File permissions on critical files (/etc/shadow, sshd_config)
✅ SSH configuration (root login, password auth, Protocol 1)
✅ Antivirus/security software presence
✅ Disk encryption (LUKS, BitLocker)
✅ Network shares (Samba, NFS, Windows shares)
✅ Vulnerable software detection
✅ Weak protocols (Telnet, FTP, TFTP)
✅ System hardening (SELinux, AppArmor)
Network Scanning
✅ Automatic network discovery (detects your subnet)
✅ Multi-threaded host discovery (fast!)
✅ Port scanning on discovered hosts
✅ Service identification & banner grabbing
✅ Remote vulnerability detection
✅ Database exposure checks (MySQL, MongoDB, Redis, PostgreSQL)
✅ Outdated software detection (old SSH versions)
Advanced Features
✅ Risk scoring (0-100 scale)
✅ Severity-based vulnerability classification (CRITICAL → INFO)
✅ CVE tracking where applicable
✅ Detailed remediation recommendations
✅ Grouped reporting by severity
✅ JSON export for automation
✅ Progress indicators
✅ Graceful interruption handling (Ctrl+C safe)
HOW TO RUN
Basic Usage
bash# Simply run the script
python3 vuln_scanner.py

# Or with elevated privileges (recommended)
sudo python3 vuln_scanner.py
```

### **What You'll See**
1. **Warning** if not running as root/admin
2. **Interactive menu** with 4 scan options
3. **Configuration prompts** (verbose mode, thread count)
4. **Real-time progress** with color-coded findings
5. **Comprehensive report** at the end

### **Scan Modes Explained**

**Mode 1 - Local System Only** 
- Fastest option
- No network traffic
- Scans only your computer
- Perfect for workstation audits

**Mode 2 - Network Only** 
- Discovers network devices
- Scans other computers
- Skips local checks
- Good for network infrastructure assessment

**Mode 3 - Full Scan** 
- Most comprehensive
- Local + Network
- Takes longer but thorough
- Recommended for complete security audit

**Mode 4 - Quick Scan** ⚡
- Fast overview
- Essential checks only
- Good for regular monitoring

## **WHAT YOU GET**

### **Real-Time Console Output**
```
[14:30:01] [INFO] Starting local system vulnerability scan...
[14:30:02] [WARNING] [HIGH] SSH (22) is open on local
[14:30:15] [SUCCESS] Firewall is active
[14:30:45] [CRITICAL] [CRITICAL] Telnet exposed on 192.168.1.105
Summary Report

Total vulnerabilities found
Breakdown by severity (Critical/High/Medium/Low/Info)
Risk Score (0-100) with color coding
System information
Network hosts discovered
Scan statistics

Detailed Findings
Each vulnerability includes:

Title - Clear description
Host - Affected system (local or IP)
Category - Type of issue
Severity - CRITICAL, HIGH, MEDIUM, LOW, INFO
Description - What's wrong
Recommendation - How to fix it
CVE - Related CVE if applicable

JSON Report
Automatically saved as vulnerability_report.json:
json{
  "scan_time": "2025-02-13T14:30:00",
  "scan_mode": "Full Scan",
  "summary": {
    "critical": 1,
    "high": 3,
    "medium": 5,
    "risk_score": 67
  },
  "vulnerabilities": [...],
  "network_hosts": [...]
}
Code Quality Improvements
As a senior Python programmer, I've implemented:
✅ Type hints throughout for better IDE support
✅ Comprehensive error handling with try-except blocks
✅ Thread safety with locks for concurrent operations
✅ Clean separation of concerns (classes, methods)
✅ Detailed docstrings for all functions
✅ Proper resource management (context managers)
✅ Timeout handling to prevent hangs
✅ Progress indicators for long operations
✅ Graceful degradation when privileges are insufficient
✅ Cross-platform compatibility (Linux, Windows, macOS)
✅ No external dependencies - pure Python standard library
✅ Professional logging with color-coded severity
✅ Modular architecture for easy extension
Security & Legal

Displays legal warning before scanning
Checks for elevated privileges
Safe interrupt handling (Ctrl+C)
No destructive operations
Read-only assessment

Use responsibly and only on systems you own or have permission to scan!
