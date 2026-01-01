"""
RedAmon - Global Parameters
Configure target URL and other settings here.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv(Path(__file__).parent / ".env")

# Target for RECON
# Smart mode auto-detects target type:
# - Root domain (e.g., "example.com"): full subdomain discovery + WHOIS + DNS + Nmap on all
# - Subdomain (e.g., "www.example.com"): WHOIS on root, DNS + Nmap only on that subdomain
TARGET_DOMAIN = "testphp.vulnweb.com"

# =============================================================================
# SCAN MODULES - Control which modules to run
# =============================================================================
# Available modules:
#   - "initial_recon" : WHOIS + Subdomain discovery + DNS (creates initial JSON)
#   - "nmap"          : Port scanning + vulnerability detection (updates JSON)
#   - "nuclei"        : Web application vulnerability scanning (updates JSON)
#   - "github"        : GitHub secret hunting (creates separate JSON)
#
# Examples:
#   ["initial_recon"]                          - Only domain recon
#   ["initial_recon", "nmap"]                  - Recon + port scanning
#   ["initial_recon", "nmap", "nuclei"]        - Full web scan
#   ["initial_recon", "nmap", "nuclei", "github"] - Complete scan
#   ["nmap", "nuclei"]                         - Update existing recon file (no initial_recon)

SCAN_MODULES = ["initial_recon", "nmap", "nuclei"]

# Hide your real IP during subdomain enumeration (uses Tor + proxychains)
# Requires: Tor running (sudo systemctl start tor) + proxychains4 installed
USE_TOR_FOR_RECON = False
USE_BRUTEFORCE_FOR_SUBDOMAINS = False

# =============================================================================
# GitHub Secret Hunt Configuration
# =============================================================================

# GitHub Personal Access Token (loaded from .env file)
# Generate at: https://github.com/settings/tokens
# Required scopes: repo (for private repos) or public_repo (for public only)
GITHUB_ACCESS_TOKEN = os.getenv("GITHUB_ACCESS_TOKEN", "")

# Target organization or username to scan
GITHUB_TARGET_ORG = "samugit83"

# Also scan repos of organization members (slower but more thorough)
GITHUB_SCAN_MEMBERS = False

# Also scan gists of organization members
GITHUB_SCAN_GISTS = True

# Scan commit history for leaked secrets (much slower but finds deleted secrets)
GITHUB_SCAN_COMMITS = True

# Maximum number of commits to scan per repo (0 = all commits)
GITHUB_MAX_COMMITS = 100

# Output results to JSON file
GITHUB_OUTPUT_JSON = True

# =============================================================================
# Nmap Port Scanner Configuration
# =============================================================================

# Use Docker to run nmap instead of system binary (recommended)
# Requires: Docker installed and running
# Benefits: No need to install nmap, consistent environment, no sudo required for most scans
NMAP_USE_DOCKER = True

# Docker image for Nmap
NMAP_DOCKER_IMAGE = "instrumentisto/nmap:latest"

# Scan type: "fast", "thorough", "stealth", or "default"
# - fast: Quick scan with aggressive timing (-T4)
# - thorough: Comprehensive scan with OS/version detection (-T3 -A)
# - stealth: Slow, stealthy SYN scan (-T2 -sS)
# - default: Standard scan (-T3)
NMAP_SCAN_TYPE = "thorough"

# Number of top ports to scan (0 = use nmap default, ignored if CUSTOM_PORTS set)
NMAP_TOP_PORTS = 1000

# Custom port specification (e.g., "22,80,443,8080" or "1-1000")
# Leave empty to use TOP_PORTS setting
NMAP_CUSTOM_PORTS = ""

# Enable service/version detection (-sV)
NMAP_SERVICE_DETECTION = True

# Enable OS fingerprinting (-O) - requires root/sudo
NMAP_OS_DETECTION = True

# Enable safe script scanning (banner, http-title, ssl-cert, etc.)
NMAP_SCRIPT_SCAN = True

# =============================================================================
# Nmap Vulnerability Scanning (NSE Scripts)
# =============================================================================

# Enable vulnerability scanning with NSE scripts
# WARNING: This actively tests for vulnerabilities - use only with authorization!
NMAP_VULN_SCAN = True

# Vulnerability scan intensity level:
# - "light"    : Only safe vuln checks (ssl-*, http-headers, etc.)
# - "standard" : Common CVE checks + safe exploits (recommended)
# - "aggressive": All vuln scripts including intrusive ones (may crash services!)
NMAP_VULN_INTENSITY = "standard"

# Specific vulnerability categories to scan (empty = all based on intensity)
# Options: "ssl", "http", "smb", "ftp", "ssh", "dns", "smtp", "auth", "dos" (careful!)
NMAP_VULN_CATEGORIES = []  # Empty = auto based on intensity

# Custom NSE scripts to run (in addition to auto-selected)
# Example: ["http-sql-injection", "http-shellshock", "smb-vuln-ms17-010"]
NMAP_CUSTOM_SCRIPTS = []

# Enable brute force scripts (default credentials, weak passwords)
# WARNING: May trigger account lockouts!
NMAP_BRUTE_SCAN = True

# Maximum time per script execution (seconds)
NMAP_SCRIPT_TIMEOUT = 300

# Host timeout in seconds (0 = no timeout)
NMAP_TIMEOUT = 300

# Scan UDP ports (slower but finds more services)
NMAP_SCAN_UDP = True

# Scan hostnames/subdomains in addition to IPs
# Useful for virtual hosts where services respond differently per hostname
NMAP_SCAN_HOSTNAMES = True

# =============================================================================
# Nuclei Vulnerability Scanner Configuration
# =============================================================================
# Template-based vulnerability scanning using ProjectDiscovery's Nuclei
# Complements nmap by providing deep web application vulnerability detection
# Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Severity levels to scan (empty = all severities)
# Options: "critical", "high", "medium", "low", "info"
NUCLEI_SEVERITY = ["critical", "high", "medium", "low"]  # Exclude info by default

# Template folders to use (empty = all templates)
# Options: "cves", "vulnerabilities", "misconfiguration", "exposures",
#          "technologies", "default-logins", "takeovers", "file", "fuzzing"
NUCLEI_TEMPLATES = []  # Empty = use all templates

# Template PATHS to exclude (directories or files, NOT tag names)
# Example: ["http/vulnerabilities/generic/", "dast/command-injection/"]
# For excluding by TAG, use NUCLEI_EXCLUDE_TAGS instead
NUCLEI_EXCLUDE_TEMPLATES = []  # Empty - use NUCLEI_EXCLUDE_TAGS for tag-based exclusion

# Custom template paths (your own templates)
# Example: ["/path/to/custom-templates", "~/my-nuclei-templates"]
NUCLEI_CUSTOM_TEMPLATES = []

# Rate limiting (requests per second, 0 = no limit)
# Recommended: 100-150 for most targets, lower for sensitive systems
NUCLEI_RATE_LIMIT = 100

# Bulk size (number of hosts to process in parallel)
NUCLEI_BULK_SIZE = 25

# Concurrency (number of templates to execute in parallel)
NUCLEI_CONCURRENCY = 25

# Request timeout in seconds
NUCLEI_TIMEOUT = 10

# Number of retries for failed requests
NUCLEI_RETRIES = 1

# Template tags to include (empty = all tags)
# Popular tags: "cve", "xss", "sqli", "rce", "lfi", "ssrf", "xxe", "ssti",
#               "exposure", "misconfig", "default-login", "takeover", "tech"
NUCLEI_TAGS = []  # Empty = no tag filter

# Template tags to exclude
# Example: ["dos", "fuzz"] - exclude denial of service
NUCLEI_EXCLUDE_TAGS = ["dos", "ddos"]

# Enable DAST mode (-dast flag) for active vulnerability fuzzing
# This mode actively injects payloads to find XSS, SQLi, etc.
# WARNING: This is more aggressive and may trigger security alerts
# NOTE: DAST requires URLs with parameters - Katana crawler will discover them
NUCLEI_DAST_MODE = True

# =============================================================================
# Katana Web Crawler Configuration (for DAST mode)
# =============================================================================
# Katana crawls the website to discover URLs with parameters for DAST fuzzing
# Only runs when NUCLEI_DAST_MODE is True

# Docker image for Katana crawler
KATANA_DOCKER_IMAGE = "projectdiscovery/katana:latest"

# Maximum crawl depth (how many links deep to follow)
# Higher = more URLs found, but slower
KATANA_DEPTH = 3

# Maximum number of URLs to crawl
KATANA_MAX_URLS = 500

# Request rate limit (requests per second)
KATANA_RATE_LIMIT = 50

# Timeout for the entire crawl (seconds)
KATANA_TIMEOUT = 300  # 5 minutes

# Include URLs from JavaScript parsing
KATANA_JS_CRAWL = True

# Only keep URLs with query parameters (for DAST fuzzing)
KATANA_PARAMS_ONLY = True

# Crawl scope: "dn" (domain name), "rdn" (root domain), "fqdn" (exact hostname)
# "dn" = stays within same domain
KATANA_SCOPE = "dn"

# Custom headers for authenticated crawling (optional)
# Example: ["Cookie: session=abc123", "Authorization: Bearer token"]
KATANA_CUSTOM_HEADERS = []

# =============================================================================

# Auto-update nuclei templates before each scan
# Checks for new templates and downloads them (adds ~10-30 seconds to scan)
# Recommended: True for production, False for faster testing
NUCLEI_AUTO_UPDATE_TEMPLATES = True

# Only use newly added templates (within last nuclei-templates update)
NUCLEI_NEW_TEMPLATES_ONLY = False

# Enable headless browser for JavaScript-rendered pages
# Requires: Chrome/Chromium installed
NUCLEI_HEADLESS = False

# Use system DNS resolvers instead of nuclei's default resolvers
NUCLEI_SYSTEM_RESOLVERS = True

# Follow HTTP redirects
NUCLEI_FOLLOW_REDIRECTS = True

# Maximum number of redirects to follow
NUCLEI_MAX_REDIRECTS = 10

# Scan IP addresses in addition to hostnames
# Set to False to only scan hostnames (faster, avoids duplicate findings)
NUCLEI_SCAN_ALL_IPS = False

# Enable Interactsh for Out-of-Band (OOB) testing
# Detects blind vulnerabilities like blind SSRF, XXE, RCE
# Note: Requires internet access to interactsh servers
NUCLEI_INTERACTSH = True

# Docker image to use (can pin to specific version)
# Nuclei runs exclusively via Docker - requires Docker installed and running
NUCLEI_DOCKER_IMAGE = "projectdiscovery/nuclei:latest"








# =============================================================================
# GVM/OpenVAS Vulnerability Scanner Configuration
# =============================================================================

USE_RECON_FOR_TARGET=True
GVM_IP_LIST=[]
GVM_HOSTNAME_LIST=[]

# GVM connection settings (for Docker deployment)
GVM_SOCKET_PATH = "/run/gvmd/gvmd.sock"  # Unix socket path inside container
GVM_USERNAME = "admin"
GVM_PASSWORD = os.getenv("GVM_PASSWORD", "admin")  # Set in .env for security

# Scan configuration preset:
# - "Full and fast" - Comprehensive scan, good performance (recommended)
# - "Full and fast ultimate" - Most thorough, slower
# - "Full and very deep" - Deep scan, very slow
# - "Full and very deep ultimate" - Maximum coverage, very slow
# - "Discovery" - Network discovery only, no vulnerability tests
# - "Host Discovery" - Basic host enumeration
# - "System Discovery" - System enumeration
GVM_SCAN_CONFIG = "Full and fast"

# Scan targets strategy:
# - "both" - Scan IPs and hostnames separately for thorough coverage
# - "ips_only" - Only scan IP addresses
# - "hostnames_only" - Only scan hostnames/subdomains
GVM_SCAN_TARGETS = "both"

# Maximum time to wait for a single scan task (seconds, 0 = unlimited)
# Note: "Full and fast" scans can take 1-2+ hours per target
GVM_TASK_TIMEOUT = 14400  # 4 hours (increase if needed for many targets)

# Poll interval for checking scan status (seconds)
GVM_POLL_INTERVAL = 30

# Cleanup targets and tasks after scan completion
GVM_CLEANUP_AFTER_SCAN = True

