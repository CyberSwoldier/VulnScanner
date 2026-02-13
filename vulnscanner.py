#!/usr/bin/env python3
"""
Advanced Network and Station Vulnerability Scanner
A professional-grade security assessment tool for local systems and networks

Author: Security Assessment Team
Version: 2.0
License: MIT

This tool performs comprehensive security scans on:
- Local system (workstation/server)
- Network infrastructure
- Remote hosts on the same network
"""

import socket
import subprocess
import platform
import os
import sys
import json
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple, Any
import ipaddress
import threading
import time

# ==================== CONSTANTS ====================

class Colors:
    """ANSI color codes for enhanced terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class ScanMode:
    """Enumeration for scan modes"""
    LOCAL_ONLY = "1"
    NETWORK_ONLY = "2"
    FULL_SCAN = "3"
    QUICK_SCAN = "4"


# Common ports to scan
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
    443: 'HTTPS', 445: 'SMB', 1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP',
    5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt', 27017: 'MongoDB', 5000: 'Flask/Docker'
}

# Risky services that should trigger alerts
RISKY_SERVICES = {
    23: ('Telnet', 'CRITICAL', 'Transmits credentials in cleartext'),
    21: ('FTP', 'HIGH', 'Unencrypted file transfer protocol'),
    69: ('TFTP', 'HIGH', 'Trivial FTP with no authentication'),
    135: ('RPC', 'HIGH', 'Windows RPC can be exploited'),
    3389: ('RDP', 'HIGH', 'Remote Desktop exposed to brute force'),
    5900: ('VNC', 'HIGH', 'Often has weak or no authentication'),
}

# ==================== UTILITY FUNCTIONS ====================

def clear_screen():
    """Clear terminal screen based on OS"""
    os.system('cls' if platform.system() == 'Windows' else 'clear')


def print_separator(char='=', length=70):
    """Print a separator line"""
    print(f"{Colors.CYAN}{char * length}{Colors.ENDC}")


def get_timestamp() -> str:
    """Get formatted timestamp"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def is_root() -> bool:
    """Check if running with elevated privileges"""
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False


# ==================== MAIN SCANNER CLASS ====================

class VulnerabilityScanner:
    """
    Main vulnerability scanner class
    Performs comprehensive security assessments on local and network systems
    """
    
    def __init__(self, scan_mode: str, verbose: bool = False, threads: int = 50):
        """
        Initialize the vulnerability scanner
        
        Args:
            scan_mode: Type of scan to perform
            verbose: Enable verbose output
            threads: Number of concurrent threads for network scanning
        """
        self.scan_mode = scan_mode
        self.verbose = verbose
        self.threads = threads
        self.system = platform.system()
        self.lock = threading.Lock()
        
        # Results storage
        self.results = {
            'scan_time': datetime.now().isoformat(),
            'scan_mode': self._get_scan_mode_name(),
            'scanner_version': '2.0',
            'local_system': {},
            'network_hosts': [],
            'vulnerabilities': [],
            'summary': {}
        }
        
        # Statistics
        self.stats = {
            'ports_scanned': 0,
            'hosts_scanned': 0,
            'vulnerabilities_found': 0
        }
    
    def _get_scan_mode_name(self) -> str:
        """Get human-readable scan mode name"""
        modes = {
            ScanMode.LOCAL_ONLY: "Local System Only",
            ScanMode.NETWORK_ONLY: "Network Only",
            ScanMode.FULL_SCAN: "Full Scan (Local + Network)",
            ScanMode.QUICK_SCAN: "Quick Scan"
        }
        return modes.get(self.scan_mode, "Unknown")
    
    def log(self, message: str, level: str = "INFO"):
        """
        Log messages with color coding and timestamps
        
        Args:
            message: Message to log
            level: Log level (INFO, SUCCESS, WARNING, ERROR, CRITICAL)
        """
        colors = {
            "INFO": Colors.BLUE,
            "SUCCESS": Colors.GREEN,
            "WARNING": Colors.YELLOW,
            "ERROR": Colors.RED,
            "CRITICAL": Colors.RED + Colors.BOLD
        }
        
        if level in ["WARNING", "ERROR", "CRITICAL"] or self.verbose:
            timestamp = datetime.now().strftime("%H:%M:%S")
            color = colors.get(level, '')
            print(f"{color}[{timestamp}] [{level}]{Colors.ENDC} {message}")
    
    def add_vulnerability(
        self,
        category: str,
        severity: str,
        title: str,
        description: str,
        host: str = "local",
        recommendation: str = "",
        cve: str = ""
    ):
        """
        Add a vulnerability finding to results
        
        Args:
            category: Vulnerability category
            severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
            title: Short title
            description: Detailed description
            host: Affected host (default: "local")
            recommendation: Remediation recommendation
            cve: Related CVE identifier if applicable
        """
        vuln = {
            'host': host,
            'category': category,
            'severity': severity,
            'title': title,
            'description': description,
            'recommendation': recommendation,
            'cve': cve,
            'timestamp': datetime.now().isoformat()
        }
        
        with self.lock:
            self.results['vulnerabilities'].append(vuln)
            self.stats['vulnerabilities_found'] += 1
        
        # Color-coded severity display
        severity_colors = {
            'CRITICAL': Colors.RED + Colors.BOLD,
            'HIGH': Colors.RED,
            'MEDIUM': Colors.YELLOW,
            'LOW': Colors.CYAN,
            'INFO': Colors.BLUE
        }
        
        color = severity_colors.get(severity, '')
        log_level = "CRITICAL" if severity == "CRITICAL" else "WARNING"
        self.log(f"{color}[{severity}] {title}{Colors.ENDC} ({host})", log_level)
    
    # ==================== LOCAL SYSTEM CHECKS ====================
    
    def check_local_system(self):
        """Perform comprehensive local system security assessment"""
        self.log("Initiating local system vulnerability scan...", "INFO")
        
        hostname = socket.gethostname()
        try:
            local_ip = socket.gethostbyname(hostname)
        except:
            local_ip = "Unknown"
        
        self.results['local_system'] = {
            'hostname': hostname,
            'local_ip': local_ip,
            'platform': platform.platform(),
            'system': self.system,
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
        }
        
        # Execute all security checks
        security_checks = [
            ('OS Version', self.check_os_version),
            ('Open Ports', self.check_open_ports),
            ('Firewall Status', self.check_firewall_status),
            ('User Accounts', self.check_user_accounts),
            ('Password Policy', self.check_password_policy),
            ('Running Services', self.check_running_services),
            ('File Permissions', self.check_file_permissions),
            ('SSH Configuration', self.check_ssh_config),
            ('Security Software', self.check_antivirus),
            ('Disk Encryption', self.check_disk_encryption),
            ('Network Shares', self.check_network_shares),
            ('Installed Software', self.check_installed_software),
            ('Weak Protocols', self.check_weak_protocols),
            ('System Hardening', self.check_system_hardening),
        ]
        
        for check_name, check_func in security_checks:
            try:
                if self.verbose:
                    self.log(f"Running check: {check_name}", "INFO")
                check_func()
            except Exception as e:
                self.log(f"Error in {check_name}: {str(e)}", "ERROR")
        
        self.log("Local system scan completed", "SUCCESS")
    
    def check_os_version(self):
        """Check operating system version and update status"""
        try:
            if self.system == "Linux":
                kernel = platform.release()
                self.results['local_system']['kernel'] = kernel
                
                # Check for available updates (apt-based systems)
                if os.path.exists('/usr/bin/apt'):
                    try:
                        result = subprocess.run(
                            ['apt', 'list', '--upgradable'],
                            capture_output=True,
                            text=True,
                            timeout=15
                        )
                        updates = [
                            line for line in result.stdout.split('\n')
                            if '/' in line and 'upgradable' in line.lower()
                        ]
                        
                        if len(updates) > 10:
                            self.add_vulnerability(
                                'System Updates',
                                'MEDIUM',
                                f'{len(updates)} package updates available',
                                f'System has {len(updates)} outdated packages that may contain security vulnerabilities',
                                recommendation='Update system: sudo apt update && sudo apt upgrade'
                            )
                        elif len(updates) > 0:
                            self.log(f"{len(updates)} updates available", "INFO")
                            
                    except subprocess.TimeoutExpired:
                        self.log("Package update check timed out", "WARNING")
                    except Exception as e:
                        if self.verbose:
                            self.log(f"Could not check updates: {e}", "ERROR")
                
                # Check for RedHat/CentOS
                elif os.path.exists('/usr/bin/yum'):
                    try:
                        result = subprocess.run(
                            ['yum', 'check-update'],
                            capture_output=True,
                            text=True,
                            timeout=15
                        )
                        if result.returncode == 100:  # Updates available
                            self.add_vulnerability(
                                'System Updates',
                                'MEDIUM',
                                'Package updates available',
                                'System packages need updating',
                                recommendation='Update system: sudo yum update'
                            )
                    except:
                        pass
                        
            elif self.system == "Windows":
                version = platform.version()
                self.results['local_system']['windows_version'] = version
                
            elif self.system == "Darwin":
                version = platform.mac_ver()[0]
                self.results['local_system']['macos_version'] = version
                
        except Exception as e:
            self.log(f"Error checking OS version: {e}", "ERROR")
    
    def check_open_ports(self):
        """Scan for open ports on localhost"""
        self.log("Scanning local ports...", "INFO")
        open_ports = []
        
        for port, service in COMMON_PORTS.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.3)
                    result = sock.connect_ex(('127.0.0.1', port))
                    
                    if result == 0:
                        open_ports.append({'port': port, 'service': service})
                        self.stats['ports_scanned'] += 1
                        
                        # Check if it's a risky service
                        if port in RISKY_SERVICES:
                            service_name, severity, risk_desc = RISKY_SERVICES[port]
                            self.add_vulnerability(
                                'Open Ports',
                                severity,
                                f'{service_name} (port {port}) is open',
                                f'{risk_desc}. Port {port} is accessible on localhost.',
                                recommendation=f'Disable {service_name} if not required, or restrict access'
                            )
                        elif port in [3306, 5432, 27017, 6379]:  # Database ports
                            self.add_vulnerability(
                                'Open Ports',
                                'MEDIUM',
                                f'{service} (port {port}) is open',
                                f'Database service exposed on localhost. Should only accept connections from trusted sources.',
                                recommendation=f'Configure {service} to bind only to localhost or use authentication'
                            )
                            
            except Exception as e:
                if self.verbose:
                    self.log(f"Error checking port {port}: {e}", "ERROR")
        
        self.results['local_system']['open_ports'] = open_ports
        self.log(f"Found {len(open_ports)} open ports", "SUCCESS")
    
    def check_firewall_status(self):
        """Check system firewall configuration"""
        try:
            if self.system == "Linux":
                # Check UFW (Ubuntu/Debian)
                try:
                    result = subprocess.run(
                        ['sudo', '-n', 'ufw', 'status'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    if 'inactive' in result.stdout.lower():
                        self.add_vulnerability(
                            'Firewall',
                            'HIGH',
                            'UFW firewall is disabled',
                            'System firewall is not active, exposing all services to network',
                            recommendation='Enable firewall: sudo ufw enable'
                        )
                    elif result.returncode == 0:
                        self.log("UFW firewall is active", "SUCCESS")
                        
                except subprocess.CalledProcessError:
                    # Try iptables
                    try:
                        result = subprocess.run(
                            ['sudo', '-n', 'iptables', '-L', '-n'],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        
                        if 'Chain INPUT (policy ACCEPT)' in result.stdout:
                            lines = result.stdout.split('\n')
                            if len(lines) < 5:  # Very few rules
                                self.add_vulnerability(
                                    'Firewall',
                                    'MEDIUM',
                                    'Minimal firewall rules detected',
                                    'Firewall has very few rules, may be too permissive',
                                    recommendation='Review and configure iptables rules'
                                )
                    except:
                        self.log("Could not check iptables (requires sudo)", "WARNING")
                        
            elif self.system == "Windows":
                try:
                    result = subprocess.run(
                        ['netsh', 'advfirewall', 'show', 'allprofiles'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    if 'State' in result.stdout and 'OFF' in result.stdout:
                        self.add_vulnerability(
                            'Firewall',
                            'HIGH',
                            'Windows Firewall is disabled',
                            'One or more firewall profiles are turned off',
                            recommendation='Enable Windows Firewall for all profiles'
                        )
                    elif result.returncode == 0:
                        self.log("Windows Firewall is active", "SUCCESS")
                        
                except Exception as e:
                    if self.verbose:
                        self.log(f"Could not check Windows firewall: {e}", "ERROR")
                        
        except Exception as e:
            self.log(f"Error checking firewall: {e}", "ERROR")
    
    def check_user_accounts(self):
        """Analyze user accounts for security issues"""
        try:
            if self.system == "Linux":
                if not os.path.exists('/etc/passwd'):
                    return
                
                with open('/etc/passwd', 'r') as f:
                    users = []
                    for line in f:
                        parts = line.strip().split(':')
                        if len(parts) >= 7:
                            username, _, uid, _, _, _, shell = parts[:7]
                            
                            # Critical: Non-root user with UID 0
                            if uid == '0' and username != 'root':
                                self.add_vulnerability(
                                    'User Accounts',
                                    'CRITICAL',
                                    f'User "{username}" has root privileges',
                                    f'Non-root user {username} has UID 0, granting full root access',
                                    recommendation=f'Remove user {username} or change UID immediately'
                                )
                            
                            # Track users with login shells
                            if shell not in ['/usr/sbin/nologin', '/bin/false', '/sbin/nologin', '/bin/sync']:
                                users.append(username)
                    
                    self.results['local_system']['login_users'] = users
                    
                    if len(users) > 15:
                        self.add_vulnerability(
                            'User Accounts',
                            'LOW',
                            f'{len(users)} users have shell access',
                            'Large number of users with login shells increases attack surface',
                            recommendation='Review users and disable accounts that don\'t need shell access'
                        )
                        
            elif self.system == "Windows":
                try:
                    result = subprocess.run(
                        ['net', 'user'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    users = re.findall(r'\b[A-Za-z0-9_-]+\b', result.stdout)
                    self.results['local_system']['users'] = users
                    
                    # Check for Guest account
                    if 'Guest' in users or 'guest' in users:
                        self.add_vulnerability(
                            'User Accounts',
                            'MEDIUM',
                            'Guest account detected',
                            'Guest account may be enabled on the system',
                            recommendation='Disable Guest account if not needed'
                        )
                except:
                    pass
                    
        except Exception as e:
            if self.verbose:
                self.log(f"Error checking user accounts: {e}", "ERROR")
    
    def check_password_policy(self):
        """Check password policy configuration"""
        try:
            if self.system == "Linux":
                if os.path.exists('/etc/login.defs'):
                    with open('/etc/login.defs', 'r') as f:
                        content = f.read()
                        
                        # Check password aging
                        max_days_match = re.search(r'^\s*PASS_MAX_DAYS\s+(\d+)', content, re.MULTILINE)
                        min_days_match = re.search(r'^\s*PASS_MIN_DAYS\s+(\d+)', content, re.MULTILINE)
                        min_len_match = re.search(r'^\s*PASS_MIN_LEN\s+(\d+)', content, re.MULTILINE)
                        
                        if max_days_match:
                            max_days = int(max_days_match.group(1))
                            if max_days > 90 or max_days == 99999:
                                self.add_vulnerability(
                                    'Password Policy',
                                    'MEDIUM',
                                    'Weak password expiration policy',
                                    f'Password maximum age is {max_days} days (recommended: 90 or less)',
                                    recommendation='Set PASS_MAX_DAYS to 90 in /etc/login.defs'
                                )
                        
                        if min_len_match:
                            min_len = int(min_len_match.group(1))
                            if min_len < 8:
                                self.add_vulnerability(
                                    'Password Policy',
                                    'HIGH',
                                    'Weak minimum password length',
                                    f'Minimum password length is only {min_len} characters (recommended: 12+)',
                                    recommendation='Set PASS_MIN_LEN to at least 12 in /etc/login.defs'
                                )
                                
        except Exception as e:
            if self.verbose:
                self.log(f"Error checking password policy: {e}", "ERROR")
    
    def check_running_services(self):
        """Check for risky or unnecessary services"""
        try:
            risky_service_names = [
                'telnet', 'ftp', 'rsh', 'rlogin', 'vsftpd', 'rsh-server'
            ]
            
            if self.system == "Linux":
                try:
                    result = subprocess.run(
                        ['systemctl', 'list-units', '--type=service', '--state=running'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    services_output = result.stdout.lower()
                    
                    for service in risky_service_names:
                        if service in services_output:
                            severity = 'HIGH' if service in ['telnet', 'rsh', 'rlogin'] else 'MEDIUM'
                            self.add_vulnerability(
                                'Running Services',
                                severity,
                                f'{service.upper()} service is running',
                                f'Insecure service {service} is active and should be disabled',
                                recommendation=f'Stop and disable service: sudo systemctl stop {service} && sudo systemctl disable {service}'
                            )
                            
                except subprocess.CalledProcessError:
                    pass
                except subprocess.TimeoutExpired:
                    self.log("Service check timed out", "WARNING")
                    
        except Exception as e:
            if self.verbose:
                self.log(f"Error checking services: {e}", "ERROR")
    
    def check_file_permissions(self):
        """Check critical file permissions"""
        try:
            if self.system == "Linux":
                critical_files = {
                    '/etc/passwd': ('644', 'MEDIUM'),
                    '/etc/shadow': ('000', 'CRITICAL'),
                    '/etc/group': ('644', 'MEDIUM'),
                    '/etc/gshadow': ('000', 'CRITICAL'),
                    '/etc/ssh/sshd_config': ('600', 'HIGH'),
                }
                
                for file_path, (expected_mode, severity) in critical_files.items():
                    if os.path.exists(file_path):
                        try:
                            stat_info = os.stat(file_path)
                            actual_mode = oct(stat_info.st_mode)[-3:]
                            
                            # Check if world-readable or world-writable
                            world_perms = int(actual_mode[-1])
                            
                            if file_path == '/etc/shadow' and world_perms != 0:
                                self.add_vulnerability(
                                    'File Permissions',
                                    'CRITICAL',
                                    f'{file_path} has insecure permissions',
                                    f'Shadow password file has mode {actual_mode} - should be 000 or 600',
                                    recommendation=f'Fix immediately: sudo chmod 000 {file_path}'
                                )
                            elif world_perms > 0 and file_path in ['/etc/shadow', '/etc/gshadow']:
                                self.add_vulnerability(
                                    'File Permissions',
                                    severity,
                                    f'{file_path} is world-accessible',
                                    f'Critical file has permissions {actual_mode} (world-accessible)',
                                    recommendation=f'Fix: sudo chmod {expected_mode} {file_path}'
                                )
                        except Exception as e:
                            if self.verbose:
                                self.log(f"Error checking {file_path}: {e}", "ERROR")
                                
        except Exception as e:
            if self.verbose:
                self.log(f"Error in file permissions check: {e}", "ERROR")
    
    def check_ssh_config(self):
        """Analyze SSH server configuration"""
        try:
            if self.system == "Linux":
                ssh_config_path = '/etc/ssh/sshd_config'
                
                if not os.path.exists(ssh_config_path):
                    return
                
                with open(ssh_config_path, 'r') as f:
                    content = f.read()
                    
                    # Check for root login
                    if re.search(r'^\s*PermitRootLogin\s+yes', content, re.MULTILINE | re.IGNORECASE):
                        self.add_vulnerability(
                            'SSH Configuration',
                            'HIGH',
                            'SSH permits root login',
                            'Direct root login via SSH is enabled, increasing brute-force attack risk',
                            recommendation='Set "PermitRootLogin no" in sshd_config and restart SSH'
                        )
                    
                    # Check password authentication
                    if re.search(r'^\s*PasswordAuthentication\s+yes', content, re.MULTILINE | re.IGNORECASE):
                        self.add_vulnerability(
                            'SSH Configuration',
                            'MEDIUM',
                            'SSH allows password authentication',
                            'Password authentication is less secure than key-based authentication',
                            recommendation='Use SSH keys and set "PasswordAuthentication no"'
                        )
                    
                    # Check for Protocol 1 (very old SSH)
                    if re.search(r'^\s*Protocol\s+1', content, re.MULTILINE):
                        self.add_vulnerability(
                            'SSH Configuration',
                            'CRITICAL',
                            'SSH Protocol 1 is enabled',
                            'SSH Protocol 1 has known security vulnerabilities and should never be used',
                            recommendation='Remove Protocol 1, use Protocol 2 only',
                            cve='CVE-2001-0572'
                        )
                    
                    # Check for empty passwords
                    if re.search(r'^\s*PermitEmptyPasswords\s+yes', content, re.MULTILINE | re.IGNORECASE):
                        self.add_vulnerability(
                            'SSH Configuration',
                            'CRITICAL',
                            'SSH permits empty passwords',
                            'SSH is configured to allow empty passwords',
                            recommendation='Set "PermitEmptyPasswords no" immediately'
                        )
                        
        except Exception as e:
            if self.verbose:
                self.log(f"Error checking SSH config: {e}", "ERROR")
    
    def check_antivirus(self):
        """Check for antivirus/security software presence"""
        try:
            if self.system == "Linux":
                av_tools = {
                    'clamav': 'ClamAV',
                    'clamscan': 'ClamAV',
                    'rkhunter': 'RKHunter',
                    'chkrootkit': 'chkrootkit',
                    'lynis': 'Lynis'
                }
                
                found_tools = []
                for tool, name in av_tools.items():
                    try:
                        result = subprocess.run(
                            ['which', tool],
                            capture_output=True,
                            text=True,
                            timeout=2
                        )
                        if result.returncode == 0:
                            found_tools.append(name)
                    except:
                        pass
                
                if found_tools:
                    self.log(f"Security tools found: {', '.join(found_tools)}", "SUCCESS")
                else:
                    self.add_vulnerability(
                        'Security Software',
                        'LOW',
                        'No security/antivirus tools detected',
                        'System lacks antivirus or anti-malware protection',
                        recommendation='Consider installing ClamAV, RKHunter, or similar tools'
                    )
                    
            elif self.system == "Windows":
                try:
                    result = subprocess.run(
                        ['powershell', '-Command', 'Get-MpComputerStatus'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    if 'AntivirusEnabled' in result.stdout:
                        if ': False' in result.stdout or ': $false' in result.stdout:
                            self.add_vulnerability(
                                'Security Software',
                                'HIGH',
                                'Windows Defender is disabled',
                                'Real-time antivirus protection is turned off',
                                recommendation='Enable Windows Defender in Windows Security settings'
                            )
                        else:
                            self.log("Windows Defender is active", "SUCCESS")
                            
                except Exception as e:
                    if self.verbose:
                        self.log(f"Could not check Windows Defender: {e}", "ERROR")
                        
        except Exception as e:
            if self.verbose:
                self.log(f"Error checking antivirus: {e}", "ERROR")
    
    def check_disk_encryption(self):
        """Check disk encryption status"""
        try:
            if self.system == "Linux":
                try:
                    result = subprocess.run(
                        ['lsblk', '-f'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    if 'crypto_LUKS' in result.stdout:
                        self.log("LUKS encryption detected", "SUCCESS")
                    else:
                        self.add_vulnerability(
                            'Disk Encryption',
                            'MEDIUM',
                            'Disk encryption not detected',
                            'System partitions do not appear to be encrypted with LUKS',
                            recommendation='Consider enabling full disk encryption for data protection'
                        )
                        
                except subprocess.CalledProcessError:
                    pass
                    
            elif self.system == "Windows":
                try:
                    result = subprocess.run(
                        ['manage-bde', '-status'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    if 'Protection Off' in result.stdout or 'Protection Status:    Off' in result.stdout:
                        self.add_vulnerability(
                            'Disk Encryption',
                            'MEDIUM',
                            'BitLocker not enabled',
                            'Disk encryption (BitLocker) is not active on system drives',
                            recommendation='Enable BitLocker encryption in Windows settings'
                        )
                    elif 'Protection On' in result.stdout:
                        self.log("BitLocker encryption is active", "SUCCESS")
                        
                except Exception as e:
                    if self.verbose:
                        self.log(f"Could not check BitLocker: {e}", "ERROR")
                        
        except Exception as e:
            if self.verbose:
                self.log(f"Error checking disk encryption: {e}", "ERROR")
    
    def check_network_shares(self):
        """Check for network file shares"""
        try:
            if self.system == "Linux":
                # Check for Samba
                if os.path.exists('/etc/samba/smb.conf'):
                    self.add_vulnerability(
                        'Network Shares',
                        'LOW',
                        'Samba file sharing is configured',
                        'SMB/Samba service is configured on this system',
                        recommendation='Ensure Samba shares are properly secured with authentication'
                    )
                
                # Check for NFS
                if os.path.exists('/etc/exports'):
                    with open('/etc/exports', 'r') as f:
                        exports = f.read().strip()
                        if exports and not exports.startswith('#'):
                            self.add_vulnerability(
                                'Network Shares',
                                'MEDIUM',
                                'NFS exports configured',
                                'NFS file shares are configured and may be accessible',
                                recommendation='Review /etc/exports and ensure proper access controls'
                            )
                            
            elif self.system == "Windows":
                try:
                    result = subprocess.run(
                        ['net', 'share'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    # Parse shares (excluding default admin shares)
                    shares = [
                        line for line in result.stdout.split('\n')
                        if line.strip() and '$' not in line
                        and 'Share name' not in line
                        and '---' not in line
                        and 'The command completed' not in line
                    ]
                    
                    if len(shares) > 0:
                        self.add_vulnerability(
                            'Network Shares',
                            'MEDIUM',
                            f'{len(shares)} network shares detected',
                            'Multiple network shares are configured and accessible',
                            recommendation='Review shares with "net share" and remove unnecessary ones'
                        )
                        
                except Exception as e:
                    if self.verbose:
                        self.log(f"Could not enumerate shares: {e}", "ERROR")
                        
        except Exception as e:
            if self.verbose:
                self.log(f"Error checking network shares: {e}", "ERROR")
    
    def check_installed_software(self):
        """Check for known vulnerable software"""
        try:
            vulnerable_software = {
                'telnet': ('Telnet client', 'MEDIUM', 'Insecure, use SSH instead'),
                'ftp': ('FTP client', 'MEDIUM', 'Use SFTP or SCP instead'),
                'rsh': ('RSH client', 'HIGH', 'Extremely insecure, remove immediately'),
                'rlogin': ('RLogin', 'HIGH', 'Extremely insecure, remove immediately'),
            }
            
            if self.system == "Linux":
                for software, (name, severity, message) in vulnerable_software.items():
                    try:
                        result = subprocess.run(
                            ['which', software],
                            capture_output=True,
                            text=True,
                            timeout=2
                        )
                        
                        if result.returncode == 0:
                            self.add_vulnerability(
                                'Installed Software',
                                severity,
                                f'{name} is installed',
                                message,
                                recommendation=f'Remove package: sudo apt remove {software} (or equivalent)'
                            )
                    except:
                        pass
                        
        except Exception as e:
            if self.verbose:
                self.log(f"Error checking software: {e}", "ERROR")
    
    def check_weak_protocols(self):
        """Check for weak/insecure network protocols"""
        weak_protocol_ports = {
            23: ('Telnet', 'CRITICAL'),
            21: ('FTP', 'HIGH'),
            69: ('TFTP', 'HIGH'),
            79: ('Finger', 'MEDIUM'),
            513: ('rlogin', 'HIGH'),
            514: ('rsh', 'HIGH'),
        }
        
        for port, (protocol, severity) in weak_protocol_ports.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.2)
                    result = sock.connect_ex(('127.0.0.1', port))
                    
                    if result == 0:
                        self.add_vulnerability(
                            'Weak Protocols',
                            severity,
                            f'{protocol} protocol active on port {port}',
                            f'{protocol} transmits data in cleartext and should not be used',
                            recommendation=f'Disable {protocol} and use secure alternatives (SSH, SFTP, etc.)'
                        )
            except:
                pass
    
    def check_system_hardening(self):
        """Check for system hardening measures"""
        try:
            if self.system == "Linux":
                # Check if SELinux is enabled
                if os.path.exists('/usr/sbin/getenforce'):
                    try:
                        result = subprocess.run(
                            ['getenforce'],
                            capture_output=True,
                            text=True,
                            timeout=2
                        )
                        
                        if 'Disabled' in result.stdout:
                            self.add_vulnerability(
                                'System Hardening',
                                'MEDIUM',
                                'SELinux is disabled',
                                'Security-Enhanced Linux is not active',
                                recommendation='Enable SELinux for enhanced security (requires reboot)'
                            )
                        elif 'Enforcing' in result.stdout:
                            self.log("SELinux is enforcing", "SUCCESS")
                    except:
                        pass
                
                # Check AppArmor
                if os.path.exists('/sys/module/apparmor'):
                    try:
                        result = subprocess.run(
                            ['aa-status'],
                            capture_output=True,
                            text=True,
                            timeout=2
                        )
                        
                        if 'apparmor module is loaded' in result.stdout.lower():
                            self.log("AppArmor is active", "SUCCESS")
                    except:
                        pass
                        
        except Exception as e:
            if self.verbose:
                self.log(f"Error checking system hardening: {e}", "ERROR")
    
    # ==================== NETWORK DISCOVERY ====================
    
    def get_local_network(self) -> Optional[str]:
        """
        Determine local network subnet
        
        Returns:
            Network address in CIDR notation (e.g., '192.168.1.0/24')
        """
        try:
            # Get local IP by connecting to external host
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            
            # Try to get network from routing table
            if self.system in ["Linux", "Darwin"]:
                try:
                    result = subprocess.run(
                        ['ip', 'route'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    # Parse routing table
                    for line in result.stdout.split('\n'):
                        if 'default' not in line and local_ip.rsplit('.', 1)[0] in line:
                            parts = line.split()
                            if parts and '/' in parts[0]:
                                return parts[0]
                                
                except subprocess.CalledProcessError:
                    pass
            
            # Fallback: assume /24 network
            network_prefix = '.'.join(local_ip.split('.')[:-1])
            return f"{network_prefix}.0/24"
            
        except Exception as e:
            self.log(f"Error detecting network: {e}", "ERROR")
            return None
    
    def ping_host(self, ip: str) -> bool:
        """
        Check if a host is alive using TCP connection attempts
        
        Args:
            ip: IP address to check
            
        Returns:
            True if host responds, False otherwise
        """
        # Try common ports that are likely to be open
        test_ports = [80, 443, 22, 445, 139]
        
        for port in test_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.3)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        return True
            except:
                continue
        
        return False
    
    def discover_hosts(self, network: str) -> List[str]:
        """
        Discover active hosts on the network
        
        Args:
            network: Network address in CIDR notation
            
        Returns:
            List of active IP addresses
        """
        self.log(f"Discovering hosts on network {network}...", "INFO")
        
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
            all_hosts = list(network_obj.hosts())
            
            self.log(f"Scanning {len(all_hosts)} potential hosts...", "INFO")
            
            active_hosts = []
            
            # Use thread pool for concurrent scanning
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_ip = {
                    executor.submit(self.ping_host, str(ip)): ip
                    for ip in all_hosts
                }
                
                completed = 0
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    completed += 1
                    
                    if completed % 50 == 0:
                        self.log(f"Progress: {completed}/{len(all_hosts)} hosts checked", "INFO")
                    
                    try:
                        if future.result():
                            active_hosts.append(str(ip))
                            if self.verbose:
                                self.log(f"Active host found: {ip}", "SUCCESS")
                    except Exception as e:
                        if self.verbose:
                            self.log(f"Error checking {ip}: {e}", "ERROR")
            
            self.log(f"Discovery complete: {len(active_hosts)} active hosts found", "SUCCESS")
            return active_hosts
            
        except Exception as e:
            self.log(f"Error during host discovery: {e}", "ERROR")
            return []
    
    # ==================== REMOTE HOST SCANNING ====================
    
    def scan_ports(self, ip: str) -> List[Dict[str, Any]]:
        """
        Scan common ports on a remote host
        
        Args:
            ip: Target IP address
            
        Returns:
            List of open ports with service information
        """
        open_ports = []
        
        for port, service in COMMON_PORTS.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.5)
                    result = sock.connect_ex((ip, port))
                    
                    if result == 0:
                        open_ports.append({
                            'port': port,
                            'service': service,
                            'state': 'open'
                        })
                        self.stats['ports_scanned'] += 1
                        
            except Exception as e:
                if self.verbose:
                    self.log(f"Error scanning {ip}:{port} - {e}", "ERROR")
        
        return open_ports
    
    def grab_banner(self, ip: str, port: int) -> Optional[str]:
        """
        Attempt to grab service banner
        
        Args:
            ip: Target IP
            port: Target port
            
        Returns:
            Banner string if successful, None otherwise
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect((ip, port))
                
                # Send appropriate probe
                if port in [80, 8080, 8443]:
                    sock.send(b'GET / HTTP/1.0\r\nHost: ' + ip.encode() + b'\r\n\r\n')
                elif port == 22:
                    pass  # SSH sends banner automatically
                else:
                    sock.send(b'\r\n')
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner if banner else None
                
        except:
            return None
    
    def scan_remote_host(self, ip: str) -> Dict[str, Any]:
        """
        Perform comprehensive vulnerability scan on remote host
        
        Args:
            ip: Target IP address
            
        Returns:
            Dictionary containing host information and findings
        """
        if self.verbose:
            self.log(f"Scanning remote host {ip}...", "INFO")
        
        host_info = {
            'ip': ip,
            'hostname': None,
            'open_ports': [],
            'os_guess': None,
            'vulnerabilities': []
        }
        
        # Reverse DNS lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            host_info['hostname'] = hostname
        except:
            pass
        
        # Port scan
        open_ports = self.scan_ports(ip)
        host_info['open_ports'] = open_ports
        
        # Analyze each open port
        for port_info in open_ports:
            port = port_info['port']
            service = port_info['service']
            
            # Check against known risky services
            if port in RISKY_SERVICES:
                service_name, severity, risk_desc = RISKY_SERVICES[port]
                self.add_vulnerability(
                    'Remote Services',
                    severity,
                    f'{service_name} exposed on {ip}',
                    f'Host {ip} has {service_name} (port {port}) accessible from network. {risk_desc}',
                    host=ip,
                    recommendation=f'Disable {service_name} or restrict access with firewall rules'
                )
            
            # Database exposure checks
            elif port in [3306, 5432, 27017, 6379, 1433]:
                self.add_vulnerability(
                    'Remote Services',
                    'HIGH',
                    f'{service} database exposed on {ip}',
                    f'Database service {service} (port {port}) is accessible from network',
                    host=ip,
                    recommendation='Restrict database access to localhost or use firewall rules'
                )
            
            # Web servers
            elif port in [80, 443, 8080, 8443]:
                banner = self.grab_banner(ip, port)
                if banner:
                    # Check for server version disclosure
                    if 'Server:' in banner:
                        self.add_vulnerability(
                            'Information Disclosure',
                            'LOW',
                            f'Web server version disclosed on {ip}',
                            f'Web server on {ip}:{port} reveals version information',
                            host=ip,
                            recommendation='Configure web server to hide version information'
                        )
            
            # SSH version check
            elif port == 22:
                banner = self.grab_banner(ip, port)
                if banner and 'ssh' in banner.lower():
                    # Check for outdated OpenSSH
                    version_match = re.search(r'openssh[_\s]+([\d.]+)', banner.lower())
                    if version_match:
                        version_str = version_match.group(1)
                        try:
                            major, minor = map(int, version_str.split('.')[:2])
                            if major < 7:
                                self.add_vulnerability(
                                    'Outdated Software',
                                    'HIGH',
                                    f'Outdated OpenSSH on {ip}',
                                    f'Host {ip} running OpenSSH {version_str} (older than 7.0)',
                                    host=ip,
                                    recommendation='Update OpenSSH to latest version'
                                )
                        except:
                            pass
        
        self.stats['hosts_scanned'] += 1
        return host_info
    
    def scan_network_hosts(self, hosts: List[str]):
        """
        Scan all discovered network hosts
        
        Args:
            hosts: List of IP addresses to scan
        """
        self.log(f"Initiating vulnerability scan on {len(hosts)} hosts...", "INFO")
        
        # Use thread pool for concurrent host scanning
        with ThreadPoolExecutor(max_workers=min(10, len(hosts))) as executor:
            future_to_host = {
                executor.submit(self.scan_remote_host, host): host
                for host in hosts
            }
            
            for future in as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    host_info = future.result()
                    self.results['network_hosts'].append(host_info)
                except Exception as e:
                    self.log(f"Error scanning {host}: {e}", "ERROR")
        
        self.log("Network host scanning completed", "SUCCESS")
    
    # ==================== REPORTING ====================
    
    def calculate_risk_score(self) -> int:
        """
        Calculate overall risk score (0-100)
        
        Returns:
            Risk score based on vulnerability severity
        """
        severity_weights = {
            'CRITICAL': 25,
            'HIGH': 15,
            'MEDIUM': 5,
            'LOW': 1,
            'INFO': 0
        }
        
        score = 0
        for vuln in self.results['vulnerabilities']:
            score += severity_weights.get(vuln['severity'], 0)
        
        # Cap at 100
        return min(score, 100)
    
    def generate_summary(self):
        """Generate vulnerability summary statistics"""
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'total': len(self.results['vulnerabilities'])
        }
        
        for vuln in self.results['vulnerabilities']:
            severity = vuln['severity'].lower()
            if severity in summary:
                summary[severity] += 1
        
        summary['risk_score'] = self.calculate_risk_score()
        summary['hosts_scanned'] = self.stats['hosts_scanned']
        summary['ports_scanned'] = self.stats['ports_scanned']
        
        self.results['summary'] = summary
    
    def print_report(self):
        """Print comprehensive vulnerability report to console"""
        print_separator('=')
        print(f"{Colors.BOLD}{Colors.CYAN}VULNERABILITY SCAN REPORT{Colors.ENDC}")
        print_separator('=')
        
        self.generate_summary()
        summary = self.results['summary']
        
        # Summary section
        print(f"\n{Colors.BOLD}SCAN SUMMARY:{Colors.ENDC}")
        print(f"  Scan Mode: {self.results['scan_mode']}")
        print(f"  Scan Time: {self.results['scan_time']}")
        print(f"  Total Vulnerabilities: {summary['total']}")
        
        if summary['critical'] > 0:
            print(f"  {Colors.RED}{Colors.BOLD}⚠ Critical: {summary['critical']}{Colors.ENDC}")
        if summary['high'] > 0:
            print(f"  {Colors.RED}● High: {summary['high']}{Colors.ENDC}")
        if summary['medium'] > 0:
            print(f"  {Colors.YELLOW}● Medium: {summary['medium']}{Colors.ENDC}")
        if summary['low'] > 0:
            print(f"  {Colors.CYAN}● Low: {summary['low']}{Colors.ENDC}")
        if summary['info'] > 0:
            print(f"  ○ Info: {summary['info']}")
        
        # Risk score
        risk_score = summary['risk_score']
        risk_color = Colors.RED if risk_score > 70 else Colors.YELLOW if risk_score > 30 else Colors.GREEN
        print(f"\n  {Colors.BOLD}Risk Score: {risk_color}{risk_score}/100{Colors.ENDC}")
        
        # Local system info
        if self.results['local_system']:
            print(f"\n{Colors.BOLD}LOCAL SYSTEM:{Colors.ENDC}")
            local = self.results['local_system']
            print(f"  Hostname: {local.get('hostname', 'N/A')}")
            print(f"  IP Address: {local.get('local_ip', 'N/A')}")
            print(f"  Platform: {local.get('platform', 'N/A')}")
            print(f"  Open Ports: {len(local.get('open_ports', []))}")
        
        # Network hosts
        if self.results['network_hosts']:
            print(f"\n{Colors.BOLD}NETWORK HOSTS DISCOVERED:{Colors.ENDC}")
            print(f"  Total Active Hosts: {len(self.results['network_hosts'])}")
            
            for host in self.results['network_hosts'][:10]:  # Show first 10
                hostname = host.get('hostname', 'Unknown')
                ports_count = len(host.get('open_ports', []))
                print(f"  • {host['ip']} ({hostname}) - {ports_count} open ports")
            
            if len(self.results['network_hosts']) > 10:
                print(f"  ... and {len(self.results['network_hosts']) - 10} more")
        
        # Detailed vulnerabilities
        if self.results['vulnerabilities']:
            print(f"\n{Colors.BOLD}DETAILED VULNERABILITY FINDINGS:{Colors.ENDC}")
            print_separator('-')
            
            # Group by severity
            by_severity = {}
            for vuln in self.results['vulnerabilities']:
                sev = vuln['severity']
                if sev not in by_severity:
                    by_severity[sev] = []
                by_severity[sev].append(vuln)
            
            # Display in severity order
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if severity in by_severity:
                    vulns = by_severity[severity]
                    
                    severity_colors = {
                        'CRITICAL': Colors.RED + Colors.BOLD,
                        'HIGH': Colors.RED,
                        'MEDIUM': Colors.YELLOW,
                        'LOW': Colors.CYAN,
                        'INFO': Colors.BLUE
                    }
                    
                    color = severity_colors[severity]
                    print(f"\n{color}[{severity}] {len(vulns)} finding(s):{Colors.ENDC}")
                    
                    for i, vuln in enumerate(vulns, 1):
                        print(f"\n  {i}. {Colors.BOLD}{vuln['title']}{Colors.ENDC}")
                        print(f"     Host: {vuln['host']}")
                        print(f"     Category: {vuln['category']}")
                        print(f"     {vuln['description']}")
                        
                        if vuln.get('recommendation'):
                            print(f"     {Colors.GREEN}→ Fix: {vuln['recommendation']}{Colors.ENDC}")
                        
                        if vuln.get('cve'):
                            print(f"     CVE: {vuln['cve']}")
        
        print_separator('=')
        print(f"{Colors.BOLD}Scan completed at {get_timestamp()}{Colors.ENDC}\n")
    
    def save_report(self, filename: str = 'vulnerability_report.json'):
        """
        Save detailed report to JSON file
        
        Args:
            filename: Output filename
        """
        try:
            output_path = os.path.join('/Users/ricardomendespinto/Desktop/vulnscanner', filename)
            
            with open(output_path, 'w') as f:
                json.dump(self.results, f, indent=2, sort_keys=True)
            
            self.log(f"Report saved to {output_path}", "SUCCESS")
            
            # Also save a copy in current directory for convenience
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2, sort_keys=True)
                
        except Exception as e:
            self.log(f"Error saving report: {e}", "ERROR")
    
    # ==================== MAIN EXECUTION ====================
    
    def run(self):
        """Execute vulnerability scan based on selected mode"""
        self.print_banner()
        
        start_time = time.time()
        
        try:
            # Local system scan
            if self.scan_mode in [ScanMode.LOCAL_ONLY, ScanMode.FULL_SCAN, ScanMode.QUICK_SCAN]:
                self.check_local_system()
            
            # Network scan
            if self.scan_mode in [ScanMode.NETWORK_ONLY, ScanMode.FULL_SCAN]:
                network = self.get_local_network()
                
                if network:
                    self.log(f"Detected network: {network}", "INFO")
                    
                    # Discover hosts
                    hosts = self.discover_hosts(network)
                    
                    if hosts:
                        # Remove localhost
                        try:
                            local_ip = socket.gethostbyname(socket.gethostname())
                            hosts = [h for h in hosts if h != local_ip]
                        except:
                            pass
                        
                        if hosts:
                            self.scan_network_hosts(hosts)
                        else:
                            self.log("No remote hosts found on network", "INFO")
                    else:
                        self.log("No active hosts discovered", "INFO")
                else:
                    self.log("Could not determine network range", "ERROR")
            
            # Quick scan mode (limited checks)
            if self.scan_mode == ScanMode.QUICK_SCAN:
                self.log("Quick scan mode: limited checks performed", "INFO")
            
            # Calculate execution time
            elapsed_time = time.time() - start_time
            self.results['scan_duration_seconds'] = round(elapsed_time, 2)
            
            # Generate and display report
            self.print_report()
            
            # Save to file
            self.save_report()
            
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Scan interrupted by user{Colors.ENDC}")
            self.print_report()
            self.save_report()
        except Exception as e:
            self.log(f"Critical error during scan: {e}", "CRITICAL")
            raise
    
    def print_banner(self):
        """Display scanner banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║     Advanced Network & Station Vulnerability Scanner v2.0     ║
║                                                                ║
║              Professional Security Assessment Tool            ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
{Colors.ENDC}
{Colors.BOLD}Scan initiated:{Colors.ENDC} {get_timestamp()}
{Colors.BOLD}Mode:{Colors.ENDC} {self._get_scan_mode_name()}

{Colors.YELLOW}{Colors.BOLD}⚠ LEGAL WARNING:{Colors.ENDC}
{Colors.YELLOW}Only scan systems and networks you own or have explicit permission to test.
Unauthorized scanning may violate laws and regulations.{Colors.ENDC}

        """
        print(banner)


# ==================== INTERACTIVE MENU ====================

def display_menu():
    """Display interactive scan mode selection menu"""
    clear_screen()
    
    print(f"""
{Colors.CYAN}{Colors.BOLD}
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║     Advanced Network & Station Vulnerability Scanner v2.0      ║
║                        CyberSwoldier                           ║
╚════════════════════════════════════════════════════════════════╝
{Colors.ENDC}

{Colors.BOLD}Select Scan Mode:{Colors.ENDC}

  {Colors.GREEN}1{Colors.ENDC} → {Colors.BOLD}Local System Only{Colors.ENDC}
       Scan only this computer for vulnerabilities
       Fast, no network traffic generated
       Recommended for: Workstation security audit

  {Colors.CYAN}2{Colors.ENDC} → {Colors.BOLD}Network Only{Colors.ENDC}
       Discover and scan other devices on the network
       Does not scan local system
       Recommended for: Network infrastructure assessment

  {Colors.YELLOW}3{Colors.ENDC} → {Colors.BOLD}Full Scan (Local + Network){Colors.ENDC}
       Comprehensive scan of local system AND network
       Most thorough option
       Recommended for: Complete security assessment

  {Colors.BLUE}4{Colors.ENDC} → {Colors.BOLD}Quick Scan{Colors.ENDC}
       Fast scan with essential checks only
       Limited depth
       Recommended for: Quick security overview

  {Colors.RED}0{Colors.ENDC} → {Colors.BOLD}Exit{Colors.ENDC}

{Colors.YELLOW}Note: Some checks require elevated privileges (sudo/admin){Colors.ENDC}
    """)


def get_user_choice() -> str:
    """
    Get and validate user's scan mode choice
    
    Returns:
        Valid scan mode choice
    """
    while True:
        try:
            choice = input(f"{Colors.BOLD}Enter your choice [0-4]: {Colors.ENDC}").strip()
            
            if choice == '0':
                print(f"\n{Colors.YELLOW}Exiting scanner. Stay secure!{Colors.ENDC}\n")
                sys.exit(0)
            
            if choice in ['1', '2', '3', '4']:
                return choice
            else:
                print(f"{Colors.RED}Invalid choice. Please enter 0-4.{Colors.ENDC}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Exiting...{Colors.ENDC}\n")
            sys.exit(0)


def get_verbose_preference() -> bool:
    """
    Ask user if they want verbose output
    
    Returns:
        True if verbose mode requested
    """
    while True:
        try:
            response = input(f"\n{Colors.BOLD}Enable verbose output? [y/N]: {Colors.ENDC}").strip().lower()
            
            if response in ['y', 'yes']:
                return True
            elif response in ['n', 'no', '']:
                return False
            else:
                print(f"{Colors.RED}Please enter 'y' or 'n'{Colors.ENDC}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Exiting...{Colors.ENDC}\n")
            sys.exit(0)


# ==================== MAIN ENTRY POINT ====================

def main():
    """Main application entry point"""
    
    # Check Python version
    if sys.version_info < (3, 6):
        print(f"{Colors.RED}Error: Python 3.6 or higher required{Colors.ENDC}")
        sys.exit(1)
    
    # Display privilege warning if not running as root/admin
    if not is_root():
        print(f"\n{Colors.YELLOW}{Colors.BOLD}⚠ WARNING:{Colors.ENDC}")
        print(f"{Colors.YELLOW}Not running with elevated privileges.")
        print("Some security checks will be limited.")
        print(f"For complete scan, run with sudo (Linux/Mac) or as Administrator (Windows){Colors.ENDC}\n")
        
        try:
            input("Press Enter to continue...")
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Exiting...{Colors.ENDC}\n")
            sys.exit(0)
    
    # Display menu and get user choice
    display_menu()
    scan_mode = get_user_choice()
    
    # Get verbose preference
    verbose = get_verbose_preference()
    
    # Get thread count for network scanning
    threads = 50
    if scan_mode in [ScanMode.NETWORK_ONLY, ScanMode.FULL_SCAN]:
        try:
            thread_input = input(f"\n{Colors.BOLD}Number of threads for network scan [50]: {Colors.ENDC}").strip()
            if thread_input:
                threads = int(thread_input)
                if threads < 1 or threads > 200:
                    print(f"{Colors.YELLOW}Using default: 50 threads{Colors.ENDC}")
                    threads = 50
        except:
            threads = 50
    
    print(f"\n{Colors.GREEN}Starting scan...{Colors.ENDC}\n")
    time.sleep(1)
    
    # Create and run scanner
    scanner = VulnerabilityScanner(
        scan_mode=scan_mode,
        verbose=verbose,
        threads=threads
    )
    
    try:
        scanner.run()
        
        # Final message
        print(f"\n{Colors.GREEN}{Colors.BOLD}✓ Scan completed successfully!{Colors.ENDC}")
        print(f"{Colors.BOLD}Report saved to: vulnerability_report.json{Colors.ENDC}\n")
        
    except Exception as e:
        print(f"\n{Colors.RED}{Colors.BOLD}✗ Scan failed with error:{Colors.ENDC}")
        print(f"{Colors.RED}{str(e)}{Colors.ENDC}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()