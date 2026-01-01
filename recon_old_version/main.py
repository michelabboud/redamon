#!/usr/bin/env python3
"""
RedAmon - Main Reconnaissance Controller
=========================================
Orchestrates all OSINT reconnaissance modules:
1. WHOIS lookup (integrated into domain recon JSON)
2. Subdomain discovery & DNS resolution
3. Nmap port & service scanning (enriches domain recon JSON)
4. GitHub secret hunting (separate JSON output)

Run this file to execute the full recon pipeline.
"""

import sys
import json
from pathlib import Path
from datetime import datetime
import tldextract

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from params import (
    TARGET_DOMAIN,
    USE_TOR_FOR_RECON,
    USE_BRUTEFORCE_FOR_SUBDOMAINS,
    SCAN_MODULES,
    GITHUB_ACCESS_TOKEN,
    GITHUB_TARGET_ORG,
)

# Import recon modules
from recon.whois_recon import whois_lookup
from recon.domain_recon import discover_subdomains
from recon.github_secret_hunt import GitHubSecretHunter
from recon.nmap_scan import run_nmap_scan
from recon.nuclei_scan import run_nuclei_scan

# Output directory
OUTPUT_DIR = Path(__file__).parent / "output"


def parse_target(target: str) -> dict:
    """
    Parse target and determine if it's a root domain or subdomain.

    Args:
        target: Target string (e.g., "example.com" or "www.example.com")

    Returns:
        Dictionary with:
        - target: original target
        - root_domain: the root domain (e.g., "example.com")
        - is_subdomain: True if target is a subdomain
        - subdomain_part: the subdomain prefix (e.g., "www") or empty string
    """
    extracted = tldextract.extract(target)
    root_domain = f"{extracted.domain}.{extracted.suffix}"

    is_subdomain = bool(extracted.subdomain)

    return {
        "target": target,
        "root_domain": root_domain,
        "is_subdomain": is_subdomain,
        "subdomain_part": extracted.subdomain
    }


def build_scan_type() -> str:
    """Build dynamic scan type based on enabled modules."""
    modules = []
    if "initial_recon" in SCAN_MODULES:
        modules.append("domain_recon")
    if "nmap" in SCAN_MODULES:
        modules.append("nmap")
    if "nuclei" in SCAN_MODULES:
        modules.append("nuclei")
    if "github" in SCAN_MODULES:
        modules.append("github")
    return "_".join(modules) if modules else "custom"


def save_recon_file(data: dict, output_file: Path):
    """Save recon data to JSON file."""
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)


def run_domain_recon(target: str, anonymous: bool = False, bruteforce: bool = False,
                     target_info: dict = None) -> dict:
    """
    Run combined WHOIS + subdomain discovery + DNS resolution.
    Produces a single unified JSON file with incremental saves.

    Smart mode:
    - If target is a root domain (e.g., "example.com"): full subdomain discovery
    - If target is a subdomain (e.g., "www.example.com"): scan only that subdomain,
      but perform WHOIS on the root domain

    Args:
        target: Target domain or subdomain (e.g., "example.com" or "www.example.com")
        anonymous: Use Tor to hide real IP
        bruteforce: Enable Knockpy bruteforce mode (only for root domain mode)
        target_info: Parsed target info from parse_target()

    Returns:
        Complete reconnaissance data including WHOIS and subdomains
    """
    # Parse target if not provided
    if target_info is None:
        target_info = parse_target(target)

    is_subdomain_mode = target_info["is_subdomain"]
    root_domain = target_info["root_domain"]

    print("\n" + "=" * 70)
    print("               RedAmon - Domain Reconnaissance")
    print("=" * 70)
    print(f"  Target: {target}")
    if is_subdomain_mode:
        print(f"  Mode: SUBDOMAIN ONLY (root domain: {root_domain})")
    else:
        print(f"  Mode: FULL DOMAIN SCAN")
    print(f"  Anonymous Mode: {anonymous}")
    if not is_subdomain_mode:
        print(f"  Bruteforce Mode: {bruteforce}")
    print("=" * 70 + "\n")

    # Setup output file
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_file = OUTPUT_DIR / f"recon_{target}.json"

    # Initialize result structure with dynamic scan_type and empty modules_executed
    combined_result = {
        "metadata": {
            "scan_type": build_scan_type(),
            "scan_timestamp": datetime.now().isoformat(),
            "target": target,
            "root_domain": root_domain,
            "is_subdomain_mode": is_subdomain_mode,
            "anonymous_mode": anonymous,
            "bruteforce_mode": bruteforce if not is_subdomain_mode else False,
            "modules_executed": []
        },
        "whois": {},
        "subdomains": [],
        "subdomain_count": 0,
        "dns": {}
    }

    # Step 1: WHOIS lookup (always on root domain)
    print("[PHASE 1] WHOIS Lookup")
    print("-" * 40)
    whois_target = root_domain
    print(f"[*] Performing WHOIS on root domain: {whois_target}")
    try:
        whois_result = whois_lookup(whois_target, save_output=False)
        combined_result["whois"] = whois_result.get("whois_data", {})
        print(f"[+] WHOIS data retrieved successfully")
    except Exception as e:
        print(f"[!] WHOIS lookup failed: {e}")
        combined_result["whois"] = {"error": str(e)}

    combined_result["metadata"]["modules_executed"].append("whois")
    save_recon_file(combined_result, output_file)
    print(f"[+] Saved: {output_file}")

    # Step 2: Subdomain discovery & DNS resolution
    if is_subdomain_mode:
        # SUBDOMAIN MODE: Only scan the specific subdomain
        print(f"\n[PHASE 2] Single Subdomain DNS Resolution")
        print("-" * 40)
        print(f"[*] Resolving DNS for: {target}")

        # Import dns_lookup from domain_recon
        from recon.domain_recon import dns_lookup

        # Resolve only the specific subdomain
        subdomain_dns = dns_lookup(target)

        combined_result["subdomains"] = [target]
        combined_result["subdomain_count"] = 1
        combined_result["dns"] = {
            "domain": {},  # No root domain DNS in subdomain mode
            "subdomains": {
                target: subdomain_dns
            }
        }

        if subdomain_dns["ips"]["ipv4"] or subdomain_dns["ips"]["ipv6"]:
            all_ips = subdomain_dns["ips"]["ipv4"] + subdomain_dns["ips"]["ipv6"]
            print(f"[+] {target} -> {', '.join(all_ips)}")
        else:
            print(f"[-] {target}: No DNS records found")

        combined_result["metadata"]["modules_executed"].append("dns_resolution")
    else:
        # FULL DOMAIN MODE: Discover all subdomains
        print(f"\n[PHASE 2] Subdomain Discovery & DNS Resolution")
        print("-" * 40)
        recon_result = discover_subdomains(
            target,
            anonymous=anonymous,
            bruteforce=bruteforce,
            resolve=True,
            save_output=False
        )

        combined_result["subdomains"] = recon_result.get("subdomains", [])
        combined_result["subdomain_count"] = recon_result.get("subdomain_count", 0)
        combined_result["metadata"]["modules_executed"].append("subdomain_discovery")
        save_recon_file(combined_result, output_file)
        print(f"[+] Saved: {output_file}")

        # Step 3: DNS resolution (already done in discover_subdomains)
        combined_result["dns"] = recon_result.get("dns", {})
        combined_result["metadata"]["modules_executed"].append("dns_resolution")

    save_recon_file(combined_result, output_file)
    print(f"[+] Saved: {output_file}")

    # Step 4: Nmap port scanning (enriches the data, saves incrementally)
    if "nmap" in SCAN_MODULES:
        combined_result = run_nmap_scan(combined_result, output_file=output_file)
        combined_result["metadata"]["modules_executed"].append("nmap_scan")
        save_recon_file(combined_result, output_file)

    # Step 5: Nuclei vulnerability scanning (enriches the data, saves incrementally)
    if "nuclei" in SCAN_MODULES:
        combined_result = run_nuclei_scan(combined_result, output_file=output_file)
        combined_result["metadata"]["modules_executed"].append("nuclei_scan")
        save_recon_file(combined_result, output_file)

    print(f"\n{'=' * 70}")
    print(f"[+] DOMAIN RECON COMPLETE")
    if is_subdomain_mode:
        print(f"[+] Mode: Subdomain only ({target})")
    else:
        print(f"[+] Subdomains found: {combined_result['subdomain_count']}")
    if "nmap" in SCAN_MODULES and "nmap" in combined_result:
        nmap_data = combined_result["nmap"]
        summary = nmap_data.get("summary", {})
        total_ports = summary.get("total_tcp_ports", 0) + summary.get("total_udp_ports", 0)
        print(f"[+] Open ports found: {total_ports}")
    if "nuclei" in SCAN_MODULES and "nuclei" in combined_result:
        nuclei_data = combined_result["nuclei"]
        nuclei_summary = nuclei_data.get("summary", {})
        nuclei_vulns = nuclei_data.get("vulnerabilities", {}).get("total", 0)
        print(f"[+] Nuclei findings: {nuclei_summary.get('total_findings', 0)} ({nuclei_vulns} vulnerabilities)")
    print(f"[+] Output saved: {output_file}")
    print(f"{'=' * 70}")

    return combined_result


def run_github_recon(token: str, target: str) -> list:
    """
    Run GitHub secret hunting.
    Produces a separate JSON file for GitHub findings.
    
    Args:
        token: GitHub personal access token
        target: Organization or username to scan
        
    Returns:
        List of findings
    """
    print("\n" + "=" * 70)
    print("               RedAmon - GitHub Secret Hunt")
    print("=" * 70)
    print(f"  Target: {target}")
    print("=" * 70 + "\n")
    
    if not token:
        print("[!] GitHub access token not configured. Skipping GitHub recon.")
        return []
    
    hunter = GitHubSecretHunter(token, target)
    findings = hunter.run()
    
    return findings


def main():
    """
    Main entry point - runs the complete recon pipeline.

    Smart target detection:
    - If TARGET_DOMAIN is a root domain (e.g., "example.com"): full subdomain discovery
    - If TARGET_DOMAIN is a subdomain (e.g., "www.example.com"): scan only that subdomain
    """
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 20 + "RedAmon OSINT Framework" + " " * 25 + "║")
    print("║" + " " * 15 + "Automated Reconnaissance Pipeline" + " " * 18 + "║")
    print("╚" + "═" * 68 + "╝")
    print()

    start_time = datetime.now()

    # Parse target to determine if it's a subdomain or root domain
    target_info = parse_target(TARGET_DOMAIN)
    is_subdomain_mode = target_info["is_subdomain"]

    print(f"[*] Target: {TARGET_DOMAIN}")
    if is_subdomain_mode:
        print(f"[*] Detected: SUBDOMAIN (root domain: {target_info['root_domain']})")
        print(f"[*] Mode: Scanning only this specific subdomain")
    else:
        print(f"[*] Detected: ROOT DOMAIN")
        print(f"[*] Mode: Full subdomain discovery")
    print()

    # Check anonymity status if Tor is enabled
    if USE_TOR_FOR_RECON:
        try:
            from utils.anonymity import print_anonymity_status
            print_anonymity_status()
        except ImportError:
            print("[!] Anonymity module not found, proceeding without Tor status check")

    # Phase 1 & 2: Domain recon (WHOIS + Subdomains + DNS) - Combined JSON
    output_file = Path(__file__).parent / "output" / f"recon_{TARGET_DOMAIN}.json"
    
    if "initial_recon" in SCAN_MODULES:
        domain_result = run_domain_recon(
            TARGET_DOMAIN,
            anonymous=USE_TOR_FOR_RECON,
            bruteforce=USE_BRUTEFORCE_FOR_SUBDOMAINS,
            target_info=target_info
        )
    else:
        # Load existing recon file if initial_recon not in modules
        if output_file.exists():
            import json
            with open(output_file, 'r') as f:
                domain_result = json.load(f)
            print(f"[*] Loaded existing recon file: {output_file}")
        else:
            print(f"[!] No existing recon file found: {output_file}")
            print(f"[!] Add 'initial_recon' to SCAN_MODULES to create it first")
            return 1
        
        # Run nmap if in SCAN_MODULES (when initial_recon is skipped)
        if "nmap" in SCAN_MODULES:
            domain_result = run_nmap_scan(domain_result, output_file=output_file)
            if "metadata" in domain_result and "modules_executed" in domain_result["metadata"]:
                if "nmap_scan" not in domain_result["metadata"]["modules_executed"]:
                    domain_result["metadata"]["modules_executed"].append("nmap_scan")
            with open(output_file, 'w') as f:
                json.dump(domain_result, f, indent=2)
        
        # Run nuclei if in SCAN_MODULES (when initial_recon is skipped)
        if "nuclei" in SCAN_MODULES:
            domain_result = run_nuclei_scan(domain_result, output_file=output_file)
            if "metadata" in domain_result and "modules_executed" in domain_result["metadata"]:
                if "nuclei_scan" not in domain_result["metadata"]["modules_executed"]:
                    domain_result["metadata"]["modules_executed"].append("nuclei_scan")
            with open(output_file, 'w') as f:
                json.dump(domain_result, f, indent=2)

    # Phase 3: GitHub secret hunt - Separate JSON (if enabled)
    github_findings = []
    if "github" in SCAN_MODULES:
        github_findings = run_github_recon(GITHUB_ACCESS_TOKEN, GITHUB_TARGET_ORG)
    else:
        print("\n[*] GitHub Secret Hunt: SKIPPED (add 'github' to SCAN_MODULES to enable)")

    # Final summary
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 22 + "RECON PIPELINE COMPLETE" + " " * 23 + "║")
    print("╠" + "═" * 68 + "╣")
    print(f"║  Duration: {duration:.2f} seconds" + " " * (55 - len(f"{duration:.2f}")) + "║")
    print(f"║  Target: {TARGET_DOMAIN}" + " " * (58 - len(TARGET_DOMAIN)) + "║")
    if is_subdomain_mode:
        print(f"║  Mode: Subdomain only" + " " * 46 + "║")
        print(f"║  Root domain: {target_info['root_domain']}" + " " * (53 - len(target_info['root_domain'])) + "║")
    else:
        print(f"║  Mode: Full domain scan" + " " * 44 + "║")
        print(f"║  Subdomains found: {domain_result['subdomain_count']}" + " " * (48 - len(str(domain_result['subdomain_count']))) + "║")

    # Nmap stats
    if "nmap" in SCAN_MODULES and "nmap" in domain_result:
        nmap_data = domain_result["nmap"]
        summary = nmap_data.get("summary", {})
        ips_scanned = summary.get("ips_scanned", 0)
        hostnames_scanned = summary.get("hostnames_scanned", 0)
        total_ports = summary.get("total_tcp_ports", 0) + summary.get("total_udp_ports", 0)
        nmap_info = f"{ips_scanned} IPs, {hostnames_scanned} hosts, {total_ports} ports"
        print(f"║  Nmap: {nmap_info}" + " " * (60 - len(nmap_info)) + "║")
    elif "nmap" not in SCAN_MODULES:
        print(f"║  Nmap scan: SKIPPED" + " " * 48 + "║")

    # Nuclei stats
    if "nuclei" in SCAN_MODULES and "nuclei" in domain_result:
        nuclei_data = domain_result["nuclei"]
        nuclei_summary = nuclei_data.get("summary", {})
        total_findings = nuclei_summary.get("total_findings", 0)
        crit = nuclei_summary.get("critical", 0)
        high = nuclei_summary.get("high", 0)
        nuclei_info = f"{total_findings} findings"
        if crit > 0 or high > 0:
            nuclei_info += f" ({crit} critical, {high} high)"
        print(f"║  Nuclei: {nuclei_info}" + " " * (58 - len(nuclei_info)) + "║")
    elif "nuclei" not in SCAN_MODULES:
        print(f"║  Nuclei scan: SKIPPED" + " " * 46 + "║")

    github_status = str(len(github_findings)) if "github" in SCAN_MODULES else "SKIPPED"
    print(f"║  GitHub findings: {github_status}" + " " * (49 - len(github_status)) + "║")
    print("╠" + "═" * 68 + "╣")
    print("║  Output Files:" + " " * 53 + "║")
    nmap_suffix = " + Nmap" if "nmap" in SCAN_MODULES else ""
    nuclei_suffix = " + Nuclei" if "nuclei" in SCAN_MODULES else ""
    all_suffixes = nmap_suffix + nuclei_suffix
    if is_subdomain_mode:
        print(f"║    • recon_{TARGET_DOMAIN}.json (WHOIS + DNS{all_suffixes})" + " " * max(0, 18 - len(TARGET_DOMAIN) - len(all_suffixes)) + "║")
    else:
        print(f"║    • recon_{TARGET_DOMAIN}.json (WHOIS + DNS + Subs{all_suffixes})" + " " * max(0, 10 - len(TARGET_DOMAIN) - len(all_suffixes)) + "║")
    if "github" in SCAN_MODULES:
        print(f"║    • github_secrets_{GITHUB_TARGET_ORG}.json" + " " * max(0, 24 - len(GITHUB_TARGET_ORG)) + "║")
    print("╚" + "═" * 68 + "╝")
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())

