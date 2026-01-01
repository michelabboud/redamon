"""
RedAmon - Nmap Port, Service & Vulnerability Scanner
=====================================================
Enriches reconnaissance data with comprehensive nmap scanning:
- Port scanning (TCP/UDP)
- Service/version detection
- OS fingerprinting
- Banner grabbing
- NSE script scanning (safe + vulnerability scripts)

Vulnerability Scanning Features:
- CVE detection (ssl-*, smb-vuln-*, http-vuln-*, etc.)
- Web vulnerabilities (SQL injection, XSS, shellshock, etc.)
- SSL/TLS issues (heartbleed, poodle, weak ciphers)
- SMB vulnerabilities (EternalBlue, MS17-010, etc.)
- Authentication weaknesses (default creds, anonymous access)
- DNS zone transfers, SMTP open relays
- Full CVE extraction with CVSS scores

Scans both IPs and hostnames (subdomains) for complete coverage.
Organizes results by IP and by hostname in the JSON output.
Supports Tor/proxychains for anonymous scanning.
"""

import nmap
import json
import subprocess
import shutil
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional, Any
import sys

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from params import (
    NMAP_USE_DOCKER,
    NMAP_DOCKER_IMAGE,
    NMAP_SCAN_TYPE,
    NMAP_TOP_PORTS,
    NMAP_CUSTOM_PORTS,
    NMAP_SERVICE_DETECTION,
    NMAP_OS_DETECTION,
    NMAP_SCRIPT_SCAN,
    NMAP_TIMEOUT,
    NMAP_SCAN_UDP,
    NMAP_SCAN_HOSTNAMES,
    USE_TOR_FOR_RECON,
    NMAP_VULN_SCAN,
    NMAP_VULN_INTENSITY,
    NMAP_VULN_CATEGORIES,
    NMAP_CUSTOM_SCRIPTS,
    NMAP_BRUTE_SCAN,
    NMAP_SCRIPT_TIMEOUT,
)


# =============================================================================
# Vulnerability Script Definitions
# =============================================================================
# All scripts verified to exist in nmap 7.94+

# Light vuln scripts - safe, non-intrusive checks
VULN_SCRIPTS_LIGHT = [
    # SSL/TLS
    "ssl-cert", "ssl-enum-ciphers", "ssl-known-key", "ssl-date",
    # HTTP headers & info
    "http-headers", "http-server-header", "http-security-headers",
    "http-cookie-flags", "http-cors", "http-methods",
    # SSH
    "ssh-hostkey", "ssh2-enum-algos",
    # DNS
    "dns-nsid", "dns-recursion",
    # General
    "banner", "unusual-port",
]

# Standard vuln scripts - common CVE checks, safe active testing
VULN_SCRIPTS_STANDARD = VULN_SCRIPTS_LIGHT + [
    # SSL/TLS vulnerabilities
    "ssl-heartbleed", "ssl-poodle", "ssl-ccs-injection", "ssl-dh-params",
    "sslv2", "sslv2-drown",
    # HTTP vulnerabilities
    "http-vuln-cve2017-5638",  # Apache Struts RCE
    "http-vuln-cve2017-1001000",  # WordPress RCE
    "http-vuln-cve2017-5689",  # Intel AMT
    "http-vuln-cve2017-8917",  # Joomla SQL injection
    "http-shellshock",  # Shellshock
    "http-vuln-cve2014-3704",  # Drupalgeddon
    "http-vuln-cve2015-1635",  # MS15-034 HTTP.sys
    "http-iis-webdav-vuln",  # IIS WebDAV
    "http-vuln-misfortune-cookie",  # Allegro RomPager
    "http-sql-injection", "http-stored-xss", "http-dombased-xss",
    "http-phpself-xss", "http-xssed", "http-csrf",
    "http-fileupload-exploiter", "http-rfi-spider",
    "http-enum", "http-robots.txt", "http-git",
    "http-config-backup", "http-backup-finder",
    "http-passwd", "http-internal-ip-disclosure",
    "http-trace", "http-put", "http-webdav-scan",
    # SMB vulnerabilities
    "smb-vuln-ms17-010",  # EternalBlue
    "smb-vuln-ms08-067",  # Conficker
    "smb-vuln-cve-2017-7494",  # SambaCry
    "smb-vuln-ms10-054", "smb-vuln-ms10-061",
    "smb-vuln-conficker",
    "smb-vuln-cve2009-3103",
    "smb-double-pulsar-backdoor",
    "smb-security-mode", "smb-os-discovery",
    # FTP
    "ftp-anon", "ftp-bounce", "ftp-proftpd-backdoor", "ftp-vsftpd-backdoor",
    "ftp-vuln-cve2010-4221",
    # SSH
    "ssh-auth-methods", "sshv1",
    # DNS
    "dns-zone-transfer", "dns-cache-snoop",
    # SMTP
    "smtp-open-relay", "smtp-vuln-cve2010-4344",
    "smtp-vuln-cve2011-1720", "smtp-vuln-cve2011-1764",
    # MySQL/Databases
    "mysql-vuln-cve2012-2122", "mysql-empty-password",
    "mongodb-databases", "redis-info", "memcached-info",
    # RDP
    "rdp-vuln-ms12-020",
    # VNC
    "vnc-info", "realvnc-auth-bypass",
    # Telnet
    "telnet-encryption",
    # NFS
    "nfs-showmount", "nfs-ls",
    # SNMP
    "snmp-info", "snmp-netstat", "snmp-processes",
    # Java RMI
    "rmi-vuln-classloader",
    # RSA
    "rsa-vuln-roca",
    # Samba
    "samba-vuln-cve-2012-1182",
    # IRC backdoor
    "irc-unrealircd-backdoor",
    # General CVE checks
    "vulners",  # Check versions against vulners.com CVE database
]

# Aggressive vuln scripts - includes intrusive/dangerous checks
# Note: "exploit" and "vuln" are NSE categories, not scripts
VULN_SCRIPTS_AGGRESSIVE = VULN_SCRIPTS_STANDARD + [
    # Additional HTTP CVE checks
    "http-vuln-cve2006-3392",  # Webmin file disclosure
    "http-vuln-cve2009-3960",  # Adobe BlazeDS
    "http-vuln-cve2010-0738",  # JBoss
    "http-vuln-cve2010-2861",  # Adobe ColdFusion
    "http-vuln-cve2011-3192",  # Apache byterange DoS
    "http-vuln-cve2011-3368",  # Apache mod_proxy
    "http-vuln-cve2012-1823",  # PHP CGI
    "http-vuln-cve2013-0156",  # Ruby on Rails
    "http-vuln-cve2013-6786",  # Allegro RomPager XSS
    "http-vuln-cve2013-7091",  # Zimbra LFI
    "http-vuln-cve2014-2126",  # Cisco ASA ASDM
    "http-vuln-cve2014-2127",  # Cisco ASA ASDM
    "http-vuln-cve2014-2128",  # Cisco ASA ASDM
    "http-vuln-cve2014-2129",  # Cisco ASA ASDM
    "http-vuln-cve2014-8877",  # WordPress CM Download Manager
    "http-vuln-cve2015-1427",  # Elasticsearch RCE
    "http-vuln-wnr1000-creds",  # Netgear WNR1000
    "http-huawei-hg5xx-vuln",  # Huawei router
    "http-vmware-path-vuln",  # VMware
    "http-dlink-backdoor",  # D-Link backdoor
    # DoS check
    "http-slowloris-check",
    # Additional SMB
    "smb-vuln-ms06-025",
    "smb-vuln-ms07-029",
    "smb-vuln-regsvc-dos",
    "smb-vuln-webexec",
    "smb2-vuln-uptime",
    # AFP
    "afp-path-vuln",
]

# Brute force scripts (separate flag)
BRUTE_SCRIPTS = [
    "ssh-brute", "ftp-brute", "http-brute", "mysql-brute",
    "smb-brute", "vnc-brute", "telnet-brute", "pop3-brute",
    "imap-brute", "smtp-brute", "snmp-brute",
]

# Category-specific scripts (wildcards expanded where needed)
VULN_CATEGORIES = {
    "ssl": ["ssl-heartbleed", "ssl-poodle", "ssl-ccs-injection", "ssl-dh-params",
            "ssl-cert", "ssl-enum-ciphers", "ssl-known-key", "ssl-date",
            "sslv2", "sslv2-drown"],
    "http": ["http-vuln-cve2017-5638", "http-vuln-cve2017-1001000", "http-vuln-cve2014-3704",
             "http-sql-injection", "http-stored-xss", "http-dombased-xss", "http-csrf",
             "http-shellshock", "http-enum", "http-git", "http-robots.txt",
             "http-config-backup", "http-passwd", "http-webdav-scan", "http-iis-webdav-vuln"],
    "smb": ["smb-vuln-ms17-010", "smb-vuln-ms08-067", "smb-vuln-cve-2017-7494",
            "smb-vuln-ms10-054", "smb-vuln-ms10-061", "smb-vuln-conficker",
            "smb-security-mode", "smb-os-discovery", "smb-enum-shares",
            "smb-enum-users", "smb-double-pulsar-backdoor"],
    "ftp": ["ftp-anon", "ftp-bounce", "ftp-proftpd-backdoor", "ftp-vsftpd-backdoor",
            "ftp-vuln-cve2010-4221"],
    "ssh": ["ssh-auth-methods", "ssh-hostkey", "ssh2-enum-algos", "sshv1"],
    "dns": ["dns-zone-transfer", "dns-cache-snoop", "dns-nsid", "dns-recursion"],
    "smtp": ["smtp-open-relay", "smtp-vuln-cve2010-4344", "smtp-vuln-cve2011-1720",
             "smtp-vuln-cve2011-1764", "smtp-enum-users"],
    "auth": ["ftp-anon", "mysql-empty-password", "vnc-info", "realvnc-auth-bypass"],
    "dos": ["http-slowloris-check", "smb-vuln-regsvc-dos"],
}


# =============================================================================
# Docker Helper Functions
# =============================================================================

def is_docker_installed() -> bool:
    """Check if Docker is installed and accessible."""
    return shutil.which("docker") is not None


def is_docker_running() -> bool:
    """Check if Docker daemon is running."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def pull_nmap_docker_image() -> bool:
    """Pull the nmap Docker image if not present."""
    try:
        print(f"    [*] Pulling Docker image: {NMAP_DOCKER_IMAGE}...")
        result = subprocess.run(
            ["docker", "pull", NMAP_DOCKER_IMAGE],
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.returncode == 0
    except Exception:
        return False


def run_nmap_docker(target: str, arguments: str, output_dir: Path, 
                    use_proxy: bool = False) -> Optional[str]:
    """
    Run nmap scan using Docker container.
    
    Args:
        target: Target IP or hostname
        arguments: Nmap arguments string
        output_dir: Directory for output files
        use_proxy: Whether to use Tor proxy
        
    Returns:
        XML output string or None if failed
    """
    # Create unique output filename
    safe_target = re.sub(r'[^a-zA-Z0-9.-]', '_', target)
    xml_file = output_dir / f"nmap_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
    
    # Build Docker command
    cmd = ["docker", "run", "--rm"]
    
    # Add network host mode for Tor proxy access
    if use_proxy:
        cmd.extend(["--network", "host"])
    
    # Mount output directory
    cmd.extend(["-v", f"{output_dir}:/output"])
    
    # Add the image
    cmd.append(NMAP_DOCKER_IMAGE)
    
    # Add nmap arguments
    # Parse arguments string into list, preserving quoted strings
    args_list = arguments.split()
    cmd.extend(args_list)
    
    # Add XML output
    cmd.extend(["-oX", f"/output/{xml_file.name}"])
    
    # Add target
    cmd.append(target)
    
    # Add proxy if using Tor (proxychains not available in Docker, use --proxies)
    if use_proxy:
        cmd.extend(["--proxies", "socks4://127.0.0.1:9050"])
    
    try:
        # Calculate timeout based on settings
        timeout = NMAP_TIMEOUT + NMAP_SCRIPT_TIMEOUT + 120  # Extra buffer
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        # Read XML output
        if xml_file.exists():
            with open(xml_file, 'r') as f:
                xml_content = f.read()
            # Clean up
            xml_file.unlink()
            return xml_content
        else:
            if result.stderr:
                print(f"        [!] Nmap Docker error: {result.stderr[:200]}")
            return None
            
    except subprocess.TimeoutExpired:
        print(f"        [!] Nmap Docker timeout for {target}")
        if xml_file.exists():
            xml_file.unlink()
        return None
    except Exception as e:
        print(f"        [!] Nmap Docker error: {e}")
        if xml_file.exists():
            xml_file.unlink()
        return None


def get_nmap_version_docker() -> str:
    """Get nmap version from Docker image."""
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", NMAP_DOCKER_IMAGE, "--version"],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0 and result.stdout:
            # Parse version from "Nmap version X.XX"
            match = re.search(r'Nmap version (\d+\.\d+)', result.stdout)
            if match:
                return match.group(1)
        return "unknown"
    except Exception:
        return "unknown"


# =============================================================================
# Script Discovery Functions
# =============================================================================

def get_available_nmap_scripts() -> Set[str]:
    """
    Get set of NSE scripts available on this system.

    Returns:
        Set of available script names (without .nse extension)
    """
    scripts_dir = Path("/usr/share/nmap/scripts")
    if not scripts_dir.exists():
        # Try alternate location
        scripts_dir = Path("/usr/local/share/nmap/scripts")

    if not scripts_dir.exists():
        return set()

    available = set()
    for script_file in scripts_dir.glob("*.nse"):
        # Remove .nse extension
        available.add(script_file.stem)

    return available


def get_vuln_scripts() -> List[str]:
    """
    Build list of vulnerability scripts based on configuration.
    Filters out scripts that don't exist on this system.

    Returns:
        List of NSE script names to run
    """
    scripts = []

    # Base scripts based on intensity
    if NMAP_VULN_INTENSITY == "light":
        scripts.extend(VULN_SCRIPTS_LIGHT)
    elif NMAP_VULN_INTENSITY == "aggressive":
        scripts.extend(VULN_SCRIPTS_AGGRESSIVE)
    else:  # standard
        scripts.extend(VULN_SCRIPTS_STANDARD)

    # Add category-specific scripts if specified
    if NMAP_VULN_CATEGORIES:
        for category in NMAP_VULN_CATEGORIES:
            if category in VULN_CATEGORIES:
                scripts.extend(VULN_CATEGORIES[category])

    # Add custom scripts
    if NMAP_CUSTOM_SCRIPTS:
        scripts.extend(NMAP_CUSTOM_SCRIPTS)

    # Add brute force scripts if enabled
    if NMAP_BRUTE_SCAN:
        scripts.extend(BRUTE_SCRIPTS)

    # Remove duplicates while preserving order
    seen = set()
    unique_scripts = []
    for script in scripts:
        if script not in seen:
            seen.add(script)
            unique_scripts.append(script)

    # Filter out scripts that don't exist on this system
    # Skip filtering for wildcard patterns (e.g., "http-vuln-*")
    available_scripts = get_available_nmap_scripts()
    if available_scripts:
        filtered_scripts = []
        for script in unique_scripts:
            if "*" in script:
                # Keep wildcard patterns as-is
                filtered_scripts.append(script)
            elif script in available_scripts:
                filtered_scripts.append(script)
            # Silently skip non-existent scripts
        return filtered_scripts

    return unique_scripts


def get_proxychains_cmd() -> Optional[str]:
    """Get the proxychains command if available."""
    for cmd in ['proxychains4', 'proxychains']:
        if shutil.which(cmd):
            return cmd
    return None


def is_root() -> bool:
    """Check if the script is running with root privileges."""
    import os
    return os.geteuid() == 0


def is_tor_running() -> bool:
    """Check if Tor is running by testing SOCKS proxy."""
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(('127.0.0.1', 9050))
        sock.close()
        return result == 0
    except Exception:
        return False


def extract_targets_from_recon(recon_data: dict) -> Tuple[Set[str], Set[str], Dict[str, List[str]]]:
    """
    Extract all unique IPs, hostnames, and build IP-to-hostname mapping.
    
    Args:
        recon_data: The domain reconnaissance JSON data
        
    Returns:
        Tuple of (unique_ips, unique_hostnames, ip_to_hostnames_mapping)
    """
    ips = set()
    hostnames = set()
    ip_to_hostnames = {}  # Maps each IP to list of hostnames pointing to it
    
    dns_data = recon_data.get("dns", {})
    if not dns_data:
        return ips, hostnames, ip_to_hostnames
    
    # Extract from root domain
    domain = recon_data.get("domain", "")
    domain_dns = dns_data.get("domain", {})
    if domain_dns:
        domain_ips = domain_dns.get("ips", {})
        ipv4_list = domain_ips.get("ipv4", [])
        ipv6_list = domain_ips.get("ipv6", [])
        
        ips.update(ipv4_list)
        ips.update(ipv6_list)
        
        if domain:
            hostnames.add(domain)
            # Map IPs to this hostname
            for ip in ipv4_list + ipv6_list:
                if ip:
                    if ip not in ip_to_hostnames:
                        ip_to_hostnames[ip] = []
                    if domain not in ip_to_hostnames[ip]:
                        ip_to_hostnames[ip].append(domain)
    
    # Extract from all subdomains
    subdomains_dns = dns_data.get("subdomains", {})
    for subdomain, subdomain_data in subdomains_dns.items():
        if subdomain_data:
            # Add hostname
            if subdomain_data.get("has_records"):
                hostnames.add(subdomain)
            
            # Add IPs and build mapping
            if subdomain_data.get("ips"):
                ipv4_list = subdomain_data["ips"].get("ipv4", [])
                ipv6_list = subdomain_data["ips"].get("ipv6", [])
                
                ips.update(ipv4_list)
                ips.update(ipv6_list)
                
                for ip in ipv4_list + ipv6_list:
                    if ip:
                        if ip not in ip_to_hostnames:
                            ip_to_hostnames[ip] = []
                        if subdomain not in ip_to_hostnames[ip]:
                            ip_to_hostnames[ip].append(subdomain)
    
    # Filter out empty strings
    ips = {ip for ip in ips if ip}
    hostnames = {h for h in hostnames if h}
    
    return ips, hostnames, ip_to_hostnames


def build_nmap_arguments(for_hostname: bool = False, use_tor: bool = False, 
                         use_docker: bool = False) -> Tuple[str, List[str]]:
    """
    Build nmap command arguments based on configuration.

    Args:
        for_hostname: If True, skip OS detection (less reliable for hostnames)
        use_tor: If True, use connect scan (-sT) and disable OS detection (required for proxies)
        use_docker: If True, running via Docker (root inside container, so OS detection works)

    Returns:
        Tuple of (arguments string, list of scripts being used)
    """
    args = []
    scripts_used = []

    # When using Tor/proxy, force connect scan (SYN scans don't work through proxies)
    if use_tor:
        args.append("-sT")  # Connect scan (works through proxies)

    # Scan type
    if NMAP_SCAN_TYPE == "fast":
        args.append("-T4")  # Aggressive timing
    elif NMAP_SCAN_TYPE == "thorough":
        args.append("-T3")  # Normal timing
        # -A includes OS detection which doesn't work through proxies
        if not for_hostname and not use_tor:
            args.append("-A")   # OS detection, version detection, script scanning, traceroute
    elif NMAP_SCAN_TYPE == "stealth":
        if use_tor:
            args.append("-T3")  # Can't use stealth through proxy
        else:
            args.append("-T2")  # Polite timing
            args.append("-sS")  # SYN scan (stealth)
    else:  # default
        args.append("-T3")

    # Port specification
    if NMAP_CUSTOM_PORTS:
        args.append(f"-p {NMAP_CUSTOM_PORTS}")
    elif NMAP_TOP_PORTS > 0:
        args.append(f"--top-ports {NMAP_TOP_PORTS}")

    # Service/version detection (required for vuln scanning)
    if NMAP_SERVICE_DETECTION or NMAP_VULN_SCAN:
        args.append("-sV")
        args.append("--version-intensity 7")  # Higher intensity for better CVE matching

    # OS detection (requires root) - only for IPs, not hostnames, and NOT through proxy
    # In Docker mode, nmap runs as root inside the container, so OS detection works
    can_do_os_detection = use_docker or is_root()
    if NMAP_OS_DETECTION and not for_hostname and not use_tor and can_do_os_detection:
        args.append("-O")
        args.append("--osscan-guess")  # Guess OS if not certain

    # Build script list
    all_scripts = []

    # Base safe scripts
    if NMAP_SCRIPT_SCAN:
        all_scripts.extend(["default", "banner", "http-title", "ssl-cert", "ssh-hostkey"])

    # Vulnerability scripts
    if NMAP_VULN_SCAN:
        vuln_scripts = get_vuln_scripts()
        all_scripts.extend(vuln_scripts)
        scripts_used = vuln_scripts

    # Add scripts if any
    if all_scripts:
        # Remove duplicates
        unique_scripts = list(dict.fromkeys(all_scripts))
        script_str = ",".join(unique_scripts)
        args.append(f"--script={script_str}")

        # Script timeout
        if NMAP_SCRIPT_TIMEOUT > 0:
            args.append(f"--script-timeout {NMAP_SCRIPT_TIMEOUT}s")

        # Script arguments for better detection
        # Note: Use simple user agent without spaces to avoid argument parsing issues
        script_args = [
            "http.useragent=Mozilla/5.0",
            "vulners.mincvss=0.0",  # Report all CVEs
        ]
        args.append(f"--script-args={','.join(script_args)}")

    # Timeout
    if NMAP_TIMEOUT > 0:
        args.append(f"--host-timeout {NMAP_TIMEOUT}s")

    # Always include these
    args.append("-Pn")  # Treat all hosts as online (skip host discovery)
    args.append("--open")  # Only show open ports
    # Note: Do NOT add -oX here - python-nmap handles XML output internally

    return " ".join(args), scripts_used


def extract_cves_from_script(script_id: str, script_output: str) -> List[Dict]:
    """
    Extract CVE information from script output.

    Args:
        script_id: NSE script identifier
        script_output: Raw script output text

    Returns:
        List of CVE dictionaries with id, cvss, description
    """
    cves = []

    # Pattern for CVE IDs
    cve_pattern = r'(CVE-\d{4}-\d+)'

    # Pattern for vulners output (CVE with CVSS score)
    vulners_pattern = r'(CVE-\d{4}-\d+)\s+(\d+\.?\d*)\s+(https?://\S+)?'

    # Check for vulners script output
    if script_id == "vulners" or "vulners" in script_output.lower():
        for match in re.finditer(vulners_pattern, script_output):
            cves.append({
                "id": match.group(1),
                "cvss": float(match.group(2)) if match.group(2) else None,
                "url": match.group(3) if match.group(3) else f"https://nvd.nist.gov/vuln/detail/{match.group(1)}",
                "source": "vulners"
            })

    # Generic CVE extraction
    if not cves:
        for match in re.finditer(cve_pattern, script_output):
            cve_id = match.group(1)
            if not any(c["id"] == cve_id for c in cves):
                cves.append({
                    "id": cve_id,
                    "cvss": None,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "source": script_id
                })

    return cves


def classify_vulnerability(script_id: str, script_output: str) -> Dict:
    """
    Classify a vulnerability finding from script output.

    Vulnerability is confirmed ONLY if:
    1. CVEs are found in the output, OR
    2. Script explicitly states "State: VULNERABLE" or "VULNERABLE:" (nmap standard format)

    Args:
        script_id: NSE script identifier
        script_output: Raw script output

    Returns:
        Vulnerability classification dict
    """
    vuln = {
        "script_id": script_id,
        "output": script_output,
        "severity": "info",
        "category": "unknown",
        "is_vulnerable": False,
        "cves": [],
        "description": "",
    }

    output_lower = script_output.lower()

    # Extract CVEs FIRST - this is the most reliable indicator
    vuln["cves"] = extract_cves_from_script(script_id, script_output)

    # Determine if vulnerable using STRICT criteria:
    # 1. CVEs found = definitely vulnerable
    # 2. Nmap's standard vulnerability output format: "State: VULNERABLE" or "VULNERABLE:"
    # 3. Explicit confirmation phrases

    if vuln["cves"]:
        # CVEs found = confirmed vulnerability
        vuln["is_vulnerable"] = True
    else:
        # Scripts that only produce output when they find something (vuln-detection scripts)
        # If these scripts have substantive output, it means they found a vulnerability
        vuln_detection_scripts = [
            "http-sql-injection", "http-stored-xss", "http-dombased-xss",
            "http-phpself-xss", "http-csrf", "http-shellshock",
            "http-rfi-spider", "http-fileupload-exploiter",
            "ssl-heartbleed", "ssl-poodle", "ssl-ccs-injection",
            "sslv2", "sslv2-drown",
            "ftp-anon", "ftp-vsftpd-backdoor", "ftp-proftpd-backdoor",
            "dns-zone-transfer",
            "smtp-open-relay",
            "smb-vuln-ms17-010", "smb-vuln-ms08-067", "smb-double-pulsar-backdoor",
        ]

        # Check if this is a vuln-detection script with findings
        is_vuln_script = (
            script_id in vuln_detection_scripts or
            "vuln" in script_id or
            script_id.endswith("-backdoor")
        )

        # For vuln scripts: substantive output (>50 chars, contains URLs/paths) = finding
        has_findings = False
        if is_vuln_script and len(script_output.strip()) > 50:
            # Check for indicators of actual findings (URLs, paths, specific data)
            if any(indicator in script_output for indicator in ["http://", "https://", "://", "State: VULNERABLE"]):
                has_findings = True
            # Or check for nmap's standard "VULNERABLE" output format
            elif "vulnerable" in output_lower and "not vulnerable" not in output_lower:
                has_findings = True

        if has_findings:
            vuln["is_vulnerable"] = True
        else:
            # Negative phrases that indicate NO vulnerability was found
            # If any of these appear, don't mark as vulnerable
            negative_phrases = [
                "couldn't find any",
                "could not find any",
                "no vulnerabilities",
                "not vulnerable",
                "no previously reported",
                "does not appear",
                "doesn't appear",
                "not found",
                "no issues",
                "appears to be safe",
                "is not vulnerable",
                "are not vulnerable",
            ]

            # Check for negative phrases first - if found, skip vulnerability check
            has_negative = any(neg in output_lower for neg in negative_phrases)

            if has_negative:
                vuln["is_vulnerable"] = False
            else:
                # Comprehensive list of nmap NSE vulnerability output patterns
                explicit_vuln_patterns = [
                    # Standard nmap vuln script format (most common)
                    "state: vulnerable",
                    "state: likely vulnerable",
                    "state: vulnerable (exploitable)",
                    # Explicit vulnerability statements
                    "is vulnerable",
                    "are vulnerable",
                    "vulnerable to",
                    "vulnerable:",
                    "vulnerability found",
                    "vulnerabilities found",
                    # Exploit indicators
                    "exploitable",
                    "exploit available",
                    "remote code execution",
                    "arbitrary code execution",
                    "command execution",
                    "code injection",
                    # SQL Injection
                    "possible sqli",
                    "sql injection",
                    "sqli:",
                    # XSS
                    "xss vulnerability",
                    "cross-site scripting",
                    "xss:",
                    "reflected xss",
                    "stored xss",
                    # File vulnerabilities
                    "file inclusion",
                    "directory traversal",
                    "path traversal",
                    "lfi:",
                    "rfi:",
                    # Authentication issues
                    "anonymous ftp login allowed",
                    "anonymous login allowed",
                    "anonymous access allowed",
                    "anonymous access:",
                    "ftp allows",
                    "default credentials",
                    "default password",
                    "weak password",
                    "no authentication",
                    "authentication bypass",
                    # DNS
                    "allows zone transfer",
                    "zone transfer allowed",
                    "zone transfer successful",
                    "axfr successful",
                    # SMTP
                    "open relay",
                    "relay allowed",
                    "mail relay",
                    # SSL/TLS
                    "supports sslv2",
                    "supports sslv3",
                    "accepts weak",
                    "weak cipher",
                    "weak ssl",
                    "ssl vulnerability",
                    "heartbleed",
                    "poodle",
                    "beast",
                    "crime",
                    "breach",
                    "drown",
                    # Backdoors
                    "backdoor",
                    "back door",
                    "rootkit",
                    "trojan",
                    # Information disclosure
                    "information disclosure",
                    "sensitive data",
                    "data leak",
                    "credentials found",
                    "password found",
                    "private key",
                    # Misconfigurations
                    "misconfiguration",
                    "dangerous method",
                    "debug enabled",
                    "trace enabled",
                    "put enabled",
                    "webdav enabled",
                    # Directory/file exposure
                    "directory listing",
                    "index of",
                    "git repository found",
                    ".git found",
                    "config backup",
                    "backup file",
                    ".bak",
                    ".backup",
                    ".old",
                    ".orig",
                    ".swp",
                    ".save",
                    # Admin/sensitive paths found
                    "possible admin",
                    "/admin",
                    "admin folder",
                    # CSRF
                    "possible csrf",
                    "csrf vulnerabilities",
                    # DoS
                    "denial of service",
                    "dos vulnerability",
                    # General findings
                    "risk:",
                    "critical:",
                    "high risk",
                    "security issue",
                    "potentially dangerous",
                ]
                for pattern in explicit_vuln_patterns:
                    if pattern in output_lower:
                        vuln["is_vulnerable"] = True
                        break

    # Categorize by script type
    if script_id.startswith("ssl-") or "ssl" in script_id:
        vuln["category"] = "ssl_tls"
    elif script_id.startswith("http-"):
        vuln["category"] = "web"
    elif script_id.startswith("smb-"):
        vuln["category"] = "smb"
    elif script_id.startswith("ssh-"):
        vuln["category"] = "ssh"
    elif script_id.startswith("ftp-"):
        vuln["category"] = "ftp"
    elif script_id.startswith("dns-"):
        vuln["category"] = "dns"
    elif script_id.startswith("smtp-"):
        vuln["category"] = "smtp"
    elif "brute" in script_id:
        vuln["category"] = "authentication"
    elif "vuln" in script_id:
        vuln["category"] = "vulnerability"
    else:
        vuln["category"] = "general"

    # Determine severity based on script and output (only if vulnerable)
    critical_scripts = [
        "smb-vuln-ms17-010", "smb-vuln-ms08-067", "ssl-heartbleed",
        "http-shellshock", "ftp-vsftpd-backdoor", "ftp-proftpd-backdoor",
        "rmi-vuln-classloader", "http-vuln-cve2017-5638", "smb-double-pulsar"
    ]
    high_scripts = [
        "ssl-poodle", "ssl-ccs-injection", "smb-vuln-",
        "http-sql-injection", "http-vuln-", "rdp-vuln-ms12-020",
        "mysql-vuln-cve2012-2122", "sslv2-drown", "sslv2"
    ]
    medium_scripts = [
        "http-stored-xss", "http-dombased-xss", "http-csrf",
        "dns-zone-transfer", "smtp-open-relay", "ftp-anon",
        "http-trace", "http-put", "http-phpself-xss"
    ]

    if vuln["is_vulnerable"]:
        if any(s in script_id for s in critical_scripts):
            vuln["severity"] = "critical"
        elif any(s in script_id for s in high_scripts):
            vuln["severity"] = "high"
        elif any(s in script_id for s in medium_scripts):
            vuln["severity"] = "medium"
        else:
            vuln["severity"] = "low"
    else:
        vuln["severity"] = "info"

    # Upgrade severity based on CVSS scores
    for cve in vuln["cves"]:
        if cve.get("cvss"):
            cvss = cve["cvss"]
            if cvss >= 9.0 and vuln["severity"] not in ["critical"]:
                vuln["severity"] = "critical"
            elif cvss >= 7.0 and vuln["severity"] not in ["critical", "high"]:
                vuln["severity"] = "high"
            elif cvss >= 4.0 and vuln["severity"] not in ["critical", "high", "medium"]:
                vuln["severity"] = "medium"

    # Extract first meaningful line as description
    lines = script_output.strip().split('\n')
    vuln["description"] = lines[0][:200] if lines else ""

    return vuln


def parse_nmap_result(nm: nmap.PortScanner, target: str, is_hostname: bool = False) -> Dict:
    """
    Parse nmap scan results for a single target into a structured dictionary.
    Extracts full vulnerability data, CVEs, and security findings.
    Saves ALL script outputs (vulnerable and non-vulnerable) for complete audit trail.

    Args:
        nm: nmap.PortScanner instance with scan results
        target: IP or hostname that was scanned
        is_hostname: Whether the target is a hostname (vs IP)

    Returns:
        Dictionary with parsed scan data including vulnerabilities
    """
    result = {
        "target": target,
        "target_type": "hostname" if is_hostname else "ip",
        "scan_timestamp": datetime.now().isoformat(),
        "status": None,
        "resolved_ips": [],
        "hostnames": [],
        "os_detection": [],
        "ports_scripts": {
            "tcp": [],
            "udp": []
        },
        "host_scripts": {},
        "vulnerabilities": {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "findings": [],
            "cves": [],
            "by_category": {}
        },
        # NEW: Store ALL script results regardless of vulnerability status
        "all_script_results": {
            "total_scripts_run": 0,
            "vulnerable": [],      # Scripts that found vulnerabilities
            "not_vulnerable": []   # Scripts that ran but found no vulnerabilities
        }
    }

    # Find the host in results (nmap might resolve hostname to IP)
    all_hosts = nm.all_hosts()
    if not all_hosts:
        result["status"] = "down"
        return result

    # Use first host found (for hostname scans, this is the resolved IP)
    host_key = all_hosts[0] if all_hosts else target

    if host_key not in nm.all_hosts():
        result["status"] = "down"
        return result

    host_data = nm[host_key]

    # If scanning hostname, record the resolved IP
    if is_hostname and host_key != target:
        result["resolved_ips"].append(host_key)

    # Host status
    result["status"] = host_data.state()

    # Hostnames from nmap
    if "hostnames" in host_data:
        result["hostnames"] = [
            {"name": h.get("name", ""), "type": h.get("type", "")}
            for h in host_data["hostnames"]
            if h.get("name")
        ]

    # OS detection with full details
    if "osmatch" in host_data:
        for os_match in host_data["osmatch"][:5]:  # Top 5 matches
            os_info = {
                "name": os_match.get("name", "Unknown"),
                "accuracy": os_match.get("accuracy", "0"),
                "os_family": "",
                "os_gen": "",
                "vendor": "",
                "cpe": []
            }
            if os_match.get("osclass"):
                for osclass in os_match["osclass"]:
                    os_info["os_family"] = osclass.get("osfamily", "")
                    os_info["os_gen"] = osclass.get("osgen", "")
                    os_info["vendor"] = osclass.get("vendor", "")
                    if osclass.get("cpe"):
                        if isinstance(osclass["cpe"], list):
                            os_info["cpe"].extend(osclass["cpe"])
                        else:
                            os_info["cpe"].append(osclass["cpe"])
            result["os_detection"].append(os_info)

    all_cves = []
    all_findings = []

    # TCP ports with full script results
    if "tcp" in host_data:
        for port, port_data in host_data["tcp"].items():
            port_info = {
                "port": port,
                "state": port_data.get("state", "unknown"),
                "reason": port_data.get("reason", ""),
                "service": port_data.get("name", "unknown"),
                "product": port_data.get("product", ""),
                "version": port_data.get("version", ""),
                "extrainfo": port_data.get("extrainfo", ""),
                "conf": port_data.get("conf", ""),
                "cpe": [],
                "scripts": {},
                "vulnerabilities": []
            }

            # Extract CPE(s)
            if port_data.get("cpe"):
                if isinstance(port_data["cpe"], list):
                    port_info["cpe"] = port_data["cpe"]
                else:
                    port_info["cpe"] = [port_data["cpe"]]

            # Parse script results for vulnerabilities
            if "script" in port_data:
                for script_id, script_output in port_data["script"].items():
                    port_info["scripts"][script_id] = script_output

                    # Classify vulnerability
                    vuln_info = classify_vulnerability(script_id, script_output)
                    vuln_info["port"] = port
                    vuln_info["protocol"] = "tcp"
                    vuln_info["service"] = port_info["service"]

                    # Count total scripts run
                    result["all_script_results"]["total_scripts_run"] += 1

                    # Create script result entry for all_script_results
                    script_result = {
                        "script_id": script_id,
                        "port": port,
                        "protocol": "tcp",
                        "service": port_info["service"],
                        "is_vulnerable": vuln_info["is_vulnerable"],
                        "severity": vuln_info["severity"],
                        "category": vuln_info["category"],
                        "cves": vuln_info["cves"],
                        "output": script_output,
                        "description": vuln_info["description"]
                    }

                    # Add to vulnerable or not_vulnerable list
                    if vuln_info["is_vulnerable"] or vuln_info["cves"]:
                        result["all_script_results"]["vulnerable"].append(script_result)
                        port_info["vulnerabilities"].append(vuln_info)
                        all_findings.append(vuln_info)
                    else:
                        result["all_script_results"]["not_vulnerable"].append(script_result)

                    # Collect CVEs
                    all_cves.extend(vuln_info["cves"])

            result["ports_scripts"]["tcp"].append(port_info)

    # UDP ports
    if "udp" in host_data:
        for port, port_data in host_data["udp"].items():
            port_info = {
                "port": port,
                "state": port_data.get("state", "unknown"),
                "reason": port_data.get("reason", ""),
                "service": port_data.get("name", "unknown"),
                "product": port_data.get("product", ""),
                "version": port_data.get("version", ""),
                "cpe": [],
                "scripts": {},
                "vulnerabilities": []
            }

            # Extract CPE(s)
            if port_data.get("cpe"):
                if isinstance(port_data["cpe"], list):
                    port_info["cpe"] = port_data["cpe"]
                else:
                    port_info["cpe"] = [port_data["cpe"]]

            # Parse script results
            if "script" in port_data:
                for script_id, script_output in port_data["script"].items():
                    port_info["scripts"][script_id] = script_output
                    vuln_info = classify_vulnerability(script_id, script_output)
                    vuln_info["port"] = port
                    vuln_info["protocol"] = "udp"
                    vuln_info["service"] = port_info["service"]

                    # Count total scripts run
                    result["all_script_results"]["total_scripts_run"] += 1

                    # Create script result entry for all_script_results
                    script_result = {
                        "script_id": script_id,
                        "port": port,
                        "protocol": "udp",
                        "service": port_info["service"],
                        "is_vulnerable": vuln_info["is_vulnerable"],
                        "severity": vuln_info["severity"],
                        "category": vuln_info["category"],
                        "cves": vuln_info["cves"],
                        "output": script_output,
                        "description": vuln_info["description"]
                    }

                    # Add to vulnerable or not_vulnerable list
                    if vuln_info["is_vulnerable"] or vuln_info["cves"]:
                        result["all_script_results"]["vulnerable"].append(script_result)
                        port_info["vulnerabilities"].append(vuln_info)
                        all_findings.append(vuln_info)
                    else:
                        result["all_script_results"]["not_vulnerable"].append(script_result)

                    all_cves.extend(vuln_info["cves"])

            result["ports_scripts"]["udp"].append(port_info)

    # Host-level scripts
    if "hostscript" in host_data:
        for script in host_data["hostscript"]:
            script_id = script.get("id", "unknown")
            script_output = script.get("output", "")
            result["host_scripts"][script_id] = script_output

            # Classify host-level vulnerabilities
            vuln_info = classify_vulnerability(script_id, script_output)
            vuln_info["port"] = None
            vuln_info["protocol"] = None
            vuln_info["service"] = "host"

            # Count total scripts run
            result["all_script_results"]["total_scripts_run"] += 1

            # Create script result entry for all_script_results
            script_result = {
                "script_id": script_id,
                "port": None,
                "protocol": None,
                "service": "host",
                "is_vulnerable": vuln_info["is_vulnerable"],
                "severity": vuln_info["severity"],
                "category": vuln_info["category"],
                "cves": vuln_info["cves"],
                "output": script_output,
                "description": vuln_info["description"]
            }

            # Add to vulnerable or not_vulnerable list
            if vuln_info["is_vulnerable"] or vuln_info["cves"]:
                result["all_script_results"]["vulnerable"].append(script_result)
                all_findings.append(vuln_info)
            else:
                result["all_script_results"]["not_vulnerable"].append(script_result)

            all_cves.extend(vuln_info["cves"])

    # Compile vulnerability summary
    result["vulnerabilities"]["findings"] = all_findings
    result["vulnerabilities"]["total"] = len(all_findings)

    # Count by severity
    for finding in all_findings:
        severity = finding.get("severity", "info")
        if severity in result["vulnerabilities"]:
            result["vulnerabilities"][severity] += 1

    # Deduplicate CVEs
    seen_cves = set()
    unique_cves = []
    for cve in all_cves:
        if cve["id"] not in seen_cves:
            seen_cves.add(cve["id"])
            unique_cves.append(cve)

    # Sort CVEs by CVSS (highest first)
    unique_cves.sort(key=lambda x: x.get("cvss", 0) or 0, reverse=True)
    result["vulnerabilities"]["cves"] = unique_cves

    # Group by category
    for finding in all_findings:
        category = finding.get("category", "unknown")
        if category not in result["vulnerabilities"]["by_category"]:
            result["vulnerabilities"]["by_category"][category] = []
        result["vulnerabilities"]["by_category"][category].append(finding)

    return result


def scan_with_proxychains(target: str, arguments: str, proxychains_cmd: str) -> Optional[str]:
    """
    Run nmap through proxychains and return XML output.
    
    Args:
        target: IP or hostname to scan
        arguments: nmap arguments string
        proxychains_cmd: proxychains command (proxychains4 or proxychains)
        
    Returns:
        XML output string or None on error
    """
    # Build the command
    cmd = [proxychains_cmd, "-q", "nmap", "-oX", "-"]  # -oX - outputs XML to stdout
    cmd.extend(arguments.split())
    cmd.append(target)
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=NMAP_TIMEOUT + 60 if NMAP_TIMEOUT > 0 else 600
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


def scan_target(nm: nmap.PortScanner, target: str, arguments: str,
                is_hostname: bool = False, label: str = "",
                proxychains_cmd: Optional[str] = None,
                use_docker: bool = False, output_dir: Path = None) -> Dict:
    """
    Scan a single target with nmap, optionally through Docker or proxychains.
    Includes full vulnerability detection and CVE extraction.

    Args:
        nm: nmap.PortScanner instance
        target: IP or hostname to scan
        arguments: nmap arguments string
        is_hostname: Whether target is a hostname
        label: Optional label for display
        proxychains_cmd: If provided, run nmap through this proxychains command
        use_docker: If True, run nmap via Docker container
        output_dir: Directory for Docker output files

    Returns:
        Dictionary with scan results including vulnerabilities
    """
    display = label or target
    target_type = "hostname" if is_hostname else "IP"
    docker_indicator = " [🐳]" if use_docker else ""
    tor_indicator = " [🧅]" if proxychains_cmd else ""
    vuln_indicator = " [VULN]" if NMAP_VULN_SCAN else ""

    try:
        print(f"    [*] Scanning {target_type}: {display}{docker_indicator}{tor_indicator}{vuln_indicator}...")

        if use_docker and output_dir:
            # Run via Docker container
            use_proxy = proxychains_cmd is not None
            xml_output = run_nmap_docker(target, arguments, output_dir, use_proxy)
            if xml_output:
                nm.analyse_nmap_xml_scan(xml_output)
            else:
                raise Exception("Docker nmap scan failed or timed out")
        elif proxychains_cmd:
            # Run through proxychains (native nmap)
            xml_output = scan_with_proxychains(target, arguments, proxychains_cmd)
            if xml_output:
                nm.analyse_nmap_xml_scan(xml_output)
            else:
                raise Exception("Proxychains scan failed or timed out")
        else:
            # Direct scan (native nmap)
            scan_result = nm.scan(hosts=target, arguments=arguments)
            # Debug: check if scan actually ran
            if 'nmap' in scan_result and 'scaninfo' in scan_result['nmap']:
                if 'error' in scan_result['nmap']['scaninfo']:
                    print(f"        [!] Nmap error: {scan_result['nmap']['scaninfo']['error']}")
            # Check command line that was actually executed
            if hasattr(nm, 'command_line') and nm.command_line():
                print(f"        [DEBUG] Command: {nm.command_line()[:150]}...")

        result = parse_nmap_result(nm, target, is_hostname)

        # Summary with vulnerability info
        tcp_count = len(result["ports_scripts"]["tcp"])
        udp_count = len(result["ports_scripts"]["udp"])
        vuln_summary = result.get("vulnerabilities", {})
        vuln_total = vuln_summary.get("total", 0)
        cve_count = len(vuln_summary.get("cves", []))

        if tcp_count > 0 or udp_count > 0:
            port_msg = f"{tcp_count} TCP, {udp_count} UDP ports"
            if NMAP_VULN_SCAN:
                vuln_msg = f" | {vuln_total} vulns"
                if vuln_summary.get("critical", 0) > 0:
                    vuln_msg += f" ({vuln_summary['critical']} CRITICAL!)"
                elif vuln_summary.get("high", 0) > 0:
                    vuln_msg += f" ({vuln_summary['high']} HIGH)"
                if cve_count > 0:
                    vuln_msg += f" | {cve_count} CVEs"
                print(f"        [+] {display}: {port_msg}{vuln_msg}")
            else:
                print(f"        [+] {display}: {port_msg}")
        else:
            print(f"        [-] {display}: No open ports found")

        return result

    except Exception as e:
        print(f"        [!] Error scanning {display}: {e}")
        return {
            "target": target,
            "target_type": "hostname" if is_hostname else "ip",
            "scan_timestamp": datetime.now().isoformat(),
            "status": "error",
            "error": str(e),
            "ports": {"tcp": [], "udp": []},
            "vulnerabilities": {
                "total": 0, "critical": 0, "high": 0,
                "medium": 0, "low": 0, "info": 0,
                "findings": [], "cves": [], "by_category": {}
            }
        }


def run_nmap_scan(recon_data: dict, output_file: Path = None) -> dict:
    """
    Run nmap scan on all IPs and hostnames from recon data.
    Includes full vulnerability scanning with CVE detection.
    Saves results incrementally after each target scan.

    Args:
        recon_data: Domain reconnaissance data dictionary
        output_file: Optional path to save incremental results

    Returns:
        Updated recon_data with nmap results added
    """
    print("\n" + "=" * 70)
    print("         RedAmon - Nmap Port & Vulnerability Scanner")
    print("=" * 70)

    # Check Tor/proxychains status
    use_tor = False
    proxychains_cmd = None

    if USE_TOR_FOR_RECON:
        if is_tor_running():
            proxychains_cmd = get_proxychains_cmd()
            if proxychains_cmd:
                use_tor = True
                print(f"  [🧅] ANONYMOUS MODE: Using {proxychains_cmd} + Tor")
                print(f"  [!] Note: OS detection disabled through proxy")
                print(f"  [!] Note: Using connect scan (-sT) for proxy compatibility")
            else:
                print("  [!] Tor is running but proxychains not found")
                print("  [!] Install: sudo apt install proxychains4")
                print("  [!] Falling back to direct scanning")
        else:
            print("  [!] USE_TOR_FOR_RECON enabled but Tor not running")
            print("  [!] Start Tor: sudo systemctl start tor")
            print("  [!] Falling back to direct scanning")

    # Extract targets
    ips, hostnames, ip_to_hostnames = extract_targets_from_recon(recon_data)

    if not ips and not hostnames:
        print("[!] No targets found in recon data")
        return recon_data

    print(f"  Unique IPs: {len(ips)}")
    print(f"  Unique Hostnames: {len(hostnames)}")
    print(f"  Hostname scanning: {'ENABLED' if NMAP_SCAN_HOSTNAMES else 'DISABLED'}")
    print(f"  Scan type: {NMAP_SCAN_TYPE}")
    print(f"  Service detection: {NMAP_SERVICE_DETECTION}")

    # Vulnerability scanning info
    if NMAP_VULN_SCAN:
        print(f"  Vulnerability scanning: ENABLED ({NMAP_VULN_INTENSITY})")
        if NMAP_BRUTE_SCAN:
            print(f"  Brute force scanning: ENABLED (WARNING: may lock accounts!)")
    else:
        print(f"  Vulnerability scanning: DISABLED")

    # Docker mode - check first since it affects OS detection
    use_docker = NMAP_USE_DOCKER
    nmap_temp_dir = None
    
    # Show OS detection status with explanation if disabled
    # In Docker mode, nmap runs as root inside container, so OS detection works
    # In native mode, requires sudo
    if use_docker:
        os_detection_enabled = NMAP_OS_DETECTION and not use_tor
        if NMAP_OS_DETECTION and not use_tor:
            print(f"  OS detection: ENABLED (Docker runs as root)")
        elif use_tor:
            print(f"  OS detection: DISABLED (not compatible with Tor)")
        else:
            print(f"  OS detection: DISABLED")
    else:
        os_detection_enabled = NMAP_OS_DETECTION and not use_tor and is_root()
        if NMAP_OS_DETECTION and not use_tor and not is_root():
            print(f"  OS detection: DISABLED (requires sudo)")
        elif use_tor:
            print(f"  OS detection: DISABLED (not compatible with Tor)")
        else:
            print(f"  OS detection: {os_detection_enabled}")
    
    if use_docker:
        print(f"  Execution mode: DOCKER ({NMAP_DOCKER_IMAGE})")
    else:
        print(f"  Execution mode: NATIVE (system nmap)")
    print("=" * 70 + "\n")

    # Initialize scanner based on mode
    if use_docker:
        # Docker mode: Check Docker is available
        if not is_docker_installed():
            print("[!] Docker not found. Please install Docker or set NMAP_USE_DOCKER = False")
            print("[!] Skipping nmap scan.")
            return recon_data
        
        if not is_docker_running():
            print("[!] Docker daemon is not running. Start it with: sudo systemctl start docker")
            print("[!] Skipping nmap scan.")
            return recon_data
        
        # Pull image if needed
        pull_nmap_docker_image()
        
        # Create temp directory for Docker output
        output_dir = Path(__file__).parent / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        nmap_temp_dir = output_dir / ".nmap_temp"
        nmap_temp_dir.mkdir(parents=True, exist_ok=True)
        
        # Get version from Docker
        nmap_version = get_nmap_version_docker()
        
    else:
        # Native mode: Check nmap is installed
        nmap_version = None
    
    # Initialize python-nmap scanner (used for parsing XML output)
    try:
        nm = nmap.PortScanner()
        if not use_docker:
            nmap_version = nm.nmap_version()
    except nmap.PortScannerError as e:
        if not use_docker:
            print(f"[!] Nmap not found or not installed: {e}")
            print("[!] Install nmap: sudo apt install nmap")
            print("[!] Or set NMAP_USE_DOCKER = True to use Docker")
            return recon_data
        # In Docker mode, we don't need native nmap, just use for parsing
        nm = nmap.PortScanner.__new__(nmap.PortScanner)
        nm._nmap_last_output = ""
        nm._nmap_subversion = ""
        nm._nmap_version_number = 0
        nm._nmap_path = "nmap"
        nm._scan_result = {}

    # Build arguments (with Tor and Docker adjustments if needed)
    ip_arguments, ip_scripts = build_nmap_arguments(for_hostname=False, use_tor=use_tor, use_docker=use_docker)
    hostname_arguments, hostname_scripts = build_nmap_arguments(for_hostname=True, use_tor=use_tor, use_docker=use_docker)

    print(f"[*] Nmap arguments (IPs): {ip_arguments[:100]}...")
    if NMAP_VULN_SCAN:
        print(f"[*] Vulnerability scripts: {len(ip_scripts)} scripts loaded")
    if NMAP_SCAN_HOSTNAMES:
        print(f"[*] Nmap arguments (hostnames): {hostname_arguments[:100]}...")
    if use_tor:
        print(f"[*] Proxychains: {proxychains_cmd}")
    print()

    # Initialize results structure with vulnerability tracking
    nmap_results = {
        "scan_metadata": {
            "scan_timestamp": datetime.now().isoformat(),
            "scanner_version": nmap_version if nmap_version else "unknown",
            "execution_mode": "docker" if use_docker else "native",
            "docker_image": NMAP_DOCKER_IMAGE if use_docker else None,
            "scan_type": NMAP_SCAN_TYPE,
            "vuln_scan_enabled": NMAP_VULN_SCAN,
            "vuln_intensity": NMAP_VULN_INTENSITY if NMAP_VULN_SCAN else None,
            "scripts_loaded": len(ip_scripts) if NMAP_VULN_SCAN else 0,
            "anonymous_mode": use_tor,
            "proxychains_cmd": proxychains_cmd if use_tor else None,
            "ip_arguments": ip_arguments,
            "hostname_arguments": hostname_arguments if NMAP_SCAN_HOSTNAMES else None,
            "total_ips": len(ips),
            "total_hostnames": len(hostnames) if NMAP_SCAN_HOSTNAMES else 0,
        },
        "by_ip": {},
        "by_hostname": {},
        "ip_to_hostnames": ip_to_hostnames,
        "summary": {
            "ips_scanned": 0,
            "ips_up": 0,
            "hostnames_scanned": 0,
            "hostnames_up": 0,
            "total_tcp_ports": 0,
            "total_udp_ports": 0,
        },
        "vulnerabilities": {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "all_cves": [],
            "by_severity": {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
                "info": []
            }
        },
        # NEW: Global summary of ALL script results across all targets
        "all_script_results_summary": {
            "total_scripts_run": 0,
            "total_vulnerable": 0,
            "total_not_vulnerable": 0
        }
    }

    def update_vuln_summary(result: Dict):
        """Update global vulnerability summary from scan result."""
        vuln_data = result.get("vulnerabilities", {})
        nmap_results["vulnerabilities"]["total"] += vuln_data.get("total", 0)
        nmap_results["vulnerabilities"]["critical"] += vuln_data.get("critical", 0)
        nmap_results["vulnerabilities"]["high"] += vuln_data.get("high", 0)
        nmap_results["vulnerabilities"]["medium"] += vuln_data.get("medium", 0)
        nmap_results["vulnerabilities"]["low"] += vuln_data.get("low", 0)
        nmap_results["vulnerabilities"]["info"] += vuln_data.get("info", 0)

        # Collect CVEs
        for cve in vuln_data.get("cves", []):
            if not any(c["id"] == cve["id"] for c in nmap_results["vulnerabilities"]["all_cves"]):
                nmap_results["vulnerabilities"]["all_cves"].append(cve)

        # Group findings by severity
        for finding in vuln_data.get("findings", []):
            severity = finding.get("severity", "info")
            finding_summary = {
                "target": result.get("target"),
                "port": finding.get("port"),
                "service": finding.get("service"),
                "script": finding.get("script_id"),
                "description": finding.get("description", "")[:100],
                "cves": [c["id"] for c in finding.get("cves", [])]
            }
            if severity in nmap_results["vulnerabilities"]["by_severity"]:
                nmap_results["vulnerabilities"]["by_severity"][severity].append(finding_summary)

        # Update global all_script_results_summary
        all_scripts_data = result.get("all_script_results", {})
        nmap_results["all_script_results_summary"]["total_scripts_run"] += all_scripts_data.get("total_scripts_run", 0)
        nmap_results["all_script_results_summary"]["total_vulnerable"] += len(all_scripts_data.get("vulnerable", []))
        nmap_results["all_script_results_summary"]["total_not_vulnerable"] += len(all_scripts_data.get("not_vulnerable", []))

    def save_incremental():
        """Save current results to file incrementally."""
        if output_file:
            recon_data["nmap"] = nmap_results
            with open(output_file, 'w') as f:
                json.dump(recon_data, f, indent=2)

    # =========================================================================
    # PHASE 1: Scan all unique IPs
    # =========================================================================
    if ips:
        print("[*] PHASE 1: Scanning IPs...")
        print("-" * 40)

        for ip in sorted(ips):
            result = scan_target(nm, ip, ip_arguments, is_hostname=False,
                               proxychains_cmd=proxychains_cmd if use_tor else None,
                               use_docker=use_docker, output_dir=nmap_temp_dir)
            nmap_results["by_ip"][ip] = result
            nmap_results["summary"]["ips_scanned"] += 1
            if result.get("status") == "up":
                nmap_results["summary"]["ips_up"] += 1
            nmap_results["summary"]["total_tcp_ports"] += len(result["ports_scripts"]["tcp"])
            nmap_results["summary"]["total_udp_ports"] += len(result["ports_scripts"]["udp"])
            update_vuln_summary(result)
            save_incremental()  # Save after each IP

    # =========================================================================
    # PHASE 2: Scan all hostnames (if enabled)
    # =========================================================================
    if NMAP_SCAN_HOSTNAMES and hostnames:
        print(f"\n[*] PHASE 2: Scanning Hostnames...")
        print("-" * 40)

        for hostname in sorted(hostnames):
            result = scan_target(nm, hostname, hostname_arguments, is_hostname=True,
                               label=hostname, proxychains_cmd=proxychains_cmd if use_tor else None,
                               use_docker=use_docker, output_dir=nmap_temp_dir)
            nmap_results["by_hostname"][hostname] = result
            nmap_results["summary"]["hostnames_scanned"] += 1
            if result.get("status") == "up":
                nmap_results["summary"]["hostnames_up"] += 1
            update_vuln_summary(result)
            save_incremental()  # Save after each hostname

    # =========================================================================
    # PHASE 3: UDP scan (if enabled)
    # =========================================================================
    if NMAP_SCAN_UDP and ips:
        if use_tor:
            print("\n[!] UDP scans are not reliable through Tor/proxychains - skipping")
        else:
            print("\n[*] PHASE 3: UDP Scans (this may take a while)...")
            print("-" * 40)
            udp_args = "-sU --top-ports 100 -T4 -Pn"

            for ip in sorted(ips):
                try:
                    docker_indicator = " [🐳]" if use_docker else ""
                    print(f"    [*] UDP scanning {ip}{docker_indicator}...")
                    
                    if use_docker and nmap_temp_dir:
                        # Run UDP scan via Docker
                        xml_output = run_nmap_docker(ip, udp_args, nmap_temp_dir, use_proxy=False)
                        if xml_output:
                            nm.analyse_nmap_xml_scan(xml_output)
                    else:
                        nm.scan(hosts=ip, arguments=udp_args)
                    
                    if ip in nm.all_hosts() and "udp" in nm[ip]:
                        for port, port_data in nm[ip]["udp"].items():
                            nmap_results["by_ip"][ip]["ports"]["udp"].append({
                                "port": port,
                                "state": port_data.get("state", "unknown"),
                                "service": port_data.get("name", "unknown"),
                            })
                            nmap_results["summary"]["total_udp_ports"] += 1
                    save_incremental()  # Save after each UDP scan
                except Exception as e:
                    print(f"        [!] UDP scan error for {ip}: {e}")

    # Sort CVEs by CVSS score
    nmap_results["vulnerabilities"]["all_cves"].sort(
        key=lambda x: x.get("cvss", 0) or 0, reverse=True
    )

    # Add nmap results to recon data
    recon_data["nmap"] = nmap_results

    # Print summary
    summary = nmap_results["summary"]
    vuln_summary = nmap_results["vulnerabilities"]
    print(f"\n{'=' * 70}")
    print(f"[+] NMAP SCAN COMPLETE")
    if use_tor:
        print(f"[+] Anonymous mode: YES (via {proxychains_cmd})")
    print(f"[+] IPs scanned: {summary['ips_scanned']} ({summary['ips_up']} up)")
    if NMAP_SCAN_HOSTNAMES:
        print(f"[+] Hostnames scanned: {summary['hostnames_scanned']} ({summary['hostnames_up']} up)")
    print(f"[+] Total open TCP ports: {summary['total_tcp_ports']}")
    print(f"[+] Total open UDP ports: {summary['total_udp_ports']}")

    # Vulnerability summary
    if NMAP_VULN_SCAN:
        print(f"\n[+] VULNERABILITY SUMMARY:")
        print(f"    Total findings: {vuln_summary['total']}")
        if vuln_summary['critical'] > 0:
            print(f"    🔴 CRITICAL: {vuln_summary['critical']}")
        if vuln_summary['high'] > 0:
            print(f"    🟠 HIGH: {vuln_summary['high']}")
        if vuln_summary['medium'] > 0:
            print(f"    🟡 MEDIUM: {vuln_summary['medium']}")
        if vuln_summary['low'] > 0:
            print(f"    🔵 LOW: {vuln_summary['low']}")
        if vuln_summary['info'] > 0:
            print(f"    ⚪ INFO: {vuln_summary['info']}")

        cve_count = len(vuln_summary['all_cves'])
        if cve_count > 0:
            print(f"\n[+] CVEs FOUND: {cve_count}")
            # Show top 5 by CVSS
            for cve in vuln_summary['all_cves'][:5]:
                cvss_str = f"CVSS {cve['cvss']}" if cve.get('cvss') else "CVSS N/A"
                print(f"    - {cve['id']} ({cvss_str})")
            if cve_count > 5:
                print(f"    ... and {cve_count - 5} more")

        # Script execution summary
        script_summary = nmap_results.get("all_script_results_summary", {})
        total_scripts = script_summary.get("total_scripts_run", 0)
        if total_scripts > 0:
            print(f"\n[+] SCRIPT EXECUTION SUMMARY:")
            print(f"    Total scripts executed: {total_scripts}")
            print(f"    Scripts with findings: {script_summary.get('total_vulnerable', 0)}")
            print(f"    Scripts without findings: {script_summary.get('total_not_vulnerable', 0)}")

    print(f"{'=' * 70}")

    # Cleanup Docker temp directory
    if use_docker and nmap_temp_dir and nmap_temp_dir.exists():
        try:
            # Remove any remaining temp files
            for f in nmap_temp_dir.glob("*"):
                try:
                    f.unlink()
                except Exception:
                    pass
            nmap_temp_dir.rmdir()
        except Exception:
            pass  # Ignore cleanup errors

    return recon_data


def enrich_recon_file(recon_file: Path) -> dict:
    """
    Load a recon JSON file, enrich it with nmap data, and save it back.
    
    Args:
        recon_file: Path to the recon JSON file
        
    Returns:
        Enriched recon data
    """
    # Load existing data
    with open(recon_file, 'r') as f:
        recon_data = json.load(f)
    
    # Run nmap scan
    enriched_data = run_nmap_scan(recon_data)
    
    # Save enriched data
    with open(recon_file, 'w') as f:
        json.dump(enriched_data, f, indent=2)
    
    print(f"[+] Enriched data saved to: {recon_file}")
    
    return enriched_data
