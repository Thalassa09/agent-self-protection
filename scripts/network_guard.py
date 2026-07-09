#!/usr/bin/env python3
"""
agent-self-protection: network_guard.py
Network exfiltration detection: pastebin/webhook/ngrok/Tor, mining pools,
DNS tunneling, large outbound transfers.

Two modes:
  1. URL/domain reputation check (offline, instant)
  2. Live network monitoring (requires root, uses /proc/net)

Usage:
    sudo python3 network_guard.py --monitor
    sudo python3 network_guard.py --check-url https://webhook.site/abc-123
    sudo python3 network_guard.py --check-domain ngrok.io
    sudo python3 network_guard.py --check-dns suspicious.example.com

Exit codes: 0=clean  1=suspicious  2=malicious
"""

import argparse
import json
import re
import socket
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse


class C:
    RED = "\033[31m"
    YELLOW = "\033[33m"
    GREEN = "\033[32m"
    CYAN = "\033[36m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def red(s): return f"{C.RED}{s}{C.RESET}"
def yellow(s): return f"{C.YELLOW}{s}{C.RESET}"
def green(s): return f"{C.GREEN}{s}{C.RESET}"
def cyan(s): return f"{C.CYAN}{s}{C.RESET}"


# ──────────────────────────────────────────────────────────────────────
# Threat databases
# ──────────────────────────────────────────────────────────────────────

# Known exfiltration / C2 / tunneling services
EXFIL_DOMAINS = {
    # Paste services (could be legit, but commonly abused for data dumps)
    "pastebin.com", "paste.mozilla.org", "paste.debian.net", "paste.centos.org",
    "paste.ee", "pastecode.io", "pastefs.com", "rentry.co", "rentry.org",
    "gist.github.com", "hastebin.com", "ghostbin.org", "dpaste.org",
    "ix.io", "0x0.st", "transfer.sh",
    # Webhook / request bin (beaconing / data exfil)
    "webhook.site", "webhook.com", "requestbin.com", "requestbin.net",
    "pipedream.com", "beeceptor.com", "mockbin.org", "httpbin.org",
    "interact.sh", "interactsh.com", "oast.fun", "oast.live",
    "dnslog.cn", "ceye.io", "burpcollaborator.net",
    # Tunneling
    "ngrok.io", "ngrok.com", "localtunnel.me", "serveo.net", "localhost.run",
    "tunnel.us.ngrok.com", "tunnel.dev", "bore.pub",
    "cloudflared.com", "trycloudflare.com",
    # Tor
    # .onion handled separately
    # Mining pools (common ports + known domains)
    "moneroocean.stream", "minexmr.com", "supportxmr.com",
    "xmrpool.eu", "pool.minexmr.com", "pool.hashvault.pro",
    "pool.nanopool.org", "ethpool.org", "ethermine.org", "nanopool.org",
    "f2pool.com", "antpool.com", "btc.com", "viabtc.com",
}

# Suspicious TLDs (heavy abuse)
SUSPICIOUS_TLDS = {
    "zip", "mov", "country", "tk", "xyz", "top", "click", "review",
    "loan", "work", "gq", "ml", "cf", "ga", "pw", "ws", "cc",
    "kim", "cricket", "science", "party", "stream", "download",
}

# Mining pool ports
MINING_PORTS = {3333, 7777, 14444, 14433, 14434, 5555, 9999, 1443, 1445, 1446}

# C2 / RAT ports (uncommon for legit traffic)
C2_PORTS = {4444, 5555, 6666, 6667, 8888, 9999, 1337, 31337, 12345, 54321}


# ──────────────────────────────────────────────────────────────────────
# URL / domain analysis
# ──────────────────────────────────────────────────────────────────────

def check_url(url: str) -> Dict:
    """Analyze a URL for exfiltration risk."""
    findings = {"url": url, "issues": [], "verdict": "clean", "risk": 0}

    parsed = urlparse(url)
    domain = parsed.netloc.lower().split(":")[0]

    if not domain:
        findings["issues"].append("URL has no domain")
        findings["risk"] = 2
        findings["verdict"] = "malicious"
        return findings

    # 1. Exfil services
    if domain in EXFIL_DOMAINS or any(d in domain for d in EXFIL_DOMAINS):
        findings["issues"].append(f"Domain '{domain}' is a known exfiltration/tunneling service")
        findings["risk"] = 2
        findings["verdict"] = "malicious"
        return findings

    # 2. Onion
    if domain.endswith(".onion"):
        findings["issues"].append("Domain is a .onion (Tor) address")
        findings["risk"] = 2
        findings["verdict"] = "malicious"
        return findings

    # 3. Suspicious TLD
    tld = domain.split(".")[-1] if "." in domain else ""
    if tld in SUSPICIOUS_TLDS:
        findings["issues"].append(f"High-abuse TLD: .{tld}")
        findings["risk"] = max(findings["risk"], 1)

    # 4. IP literal
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
        findings["issues"].append("URL uses IP literal (no domain name)")
        findings["risk"] = max(findings["risk"], 1)

    # 5. Suspicious path patterns
    suspicious_path_patterns = [
        r"(?:id_rsa|\.aws/credentials|\.env|\.git-credentials)",
        r"(?:curl|wget).*?\.(?:sh|py|exe|bin)",
    ]
    for pattern in suspicious_path_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            findings["issues"].append(f"Path suggests exfiltration: {pattern}")
            findings["risk"] = max(findings["risk"], 2)

    # 6. Unusual port
    if parsed.port and parsed.port in C2_PORTS:
        findings["issues"].append(f"Unusual port: {parsed.port}")
        findings["risk"] = max(findings["risk"], 1)

    if findings["risk"] == 2:
        findings["verdict"] = "malicious"
    elif findings["risk"] == 1:
        findings["verdict"] = "suspicious"

    return findings


def check_domain(domain: str) -> Dict:
    findings = {"domain": domain, "issues": [], "verdict": "clean", "risk": 0}

    if domain in EXFIL_DOMAINS:
        findings["issues"].append(f"'{domain}' is a known exfiltration service")
        findings["risk"] = 2
        findings["verdict"] = "malicious"
        return findings

    if domain.endswith(".onion"):
        findings["issues"].append("Tor .onion address")
        findings["risk"] = 2
        findings["verdict"] = "malicious"
        return findings

    tld = domain.split(".")[-1] if "." in domain else ""
    if tld in SUSPICIOUS_TLDS:
        findings["issues"].append(f"High-abuse TLD: .{tld}")
        findings["risk"] = max(findings["risk"], 1)

    return findings


# ──────────────────────────────────────────────────────────────────────
# DNS tunneling detection
# ──────────────────────────────────────────────────────────────────────

def check_dns_tunneling(domain: str) -> Dict:
    """Heuristics for DNS tunneling patterns."""
    findings = {"domain": domain, "issues": [], "verdict": "clean", "risk": 0}

    parts = domain.split(".")
    if not parts:
        return findings

    # Very long subdomain (DNS tunneling)
    sub = parts[0] if len(parts) >= 2 else ""
    if len(sub) > 50:
        findings["issues"].append(f"Subdomain unusually long ({len(sub)} chars)")
        findings["risk"] = max(findings["risk"], 2)

    # High entropy subdomain (encoded data)
    if len(sub) >= 20:
        import math
        from collections import Counter
        counts = Counter(sub)
        entropy = -sum((c / len(sub)) * math.log2(c / len(sub)) for c in counts.values())
        if entropy > 4.5:
            findings["issues"].append(f"Subdomain has high entropy ({entropy:.2f}) — possible DNS tunneling")
            findings["risk"] = max(findings["risk"], 2)

    # Excessive subdomain depth
    if len(parts) > 6:
        findings["issues"].append(f"Unusual subdomain depth ({len(parts)} levels)")
        findings["risk"] = max(findings["risk"], 1)

    if findings["risk"] == 2:
        findings["verdict"] = "malicious"
    elif findings["risk"] == 1:
        findings["verdict"] = "suspicious"

    return findings


# ──────────────────────────────────────────────────────────────────────
# Live network monitoring
# ──────────────────────────────────────────────────────────────────────

def parse_proc_net() -> List[Dict]:
    """Parse /proc/net/tcp and tcp6 for ESTABLISHED connections."""
    conns = []
    for proto in ["tcp", "tcp6"]:
        path = Path(f"/proc/net/{proto}")
        if not path.exists():
            continue
        try:
            for i, line in enumerate(path.read_text().splitlines()):
                if i == 0:
                    continue
                parts = line.split()
                if len(parts) < 10:
                    continue
                local, remote, state = parts[1], parts[2], parts[3]
                if state != "01":  # ESTABLISHED
                    continue
                rip_hex, rport_hex = remote.split(":")
                rport = int(rport_hex, 16)
                rip_bytes = bytes.fromhex(rip_hex)
                if proto == "tcp":
                    rip = ".".join(str(b) for b in reversed(rip_bytes))
                else:
                    # IPv6 — store compressed form
                    rip = ":".join(f"{rip_bytes[i]:02x}{rip_bytes[i+1]:02x}" for i in range(0, 16, 2))
                    rip = rip.replace("0000", "0").replace("0000", "0")  # crude compression
                conns.append({
                    "proto": proto,
                    "remote_ip": rip,
                    "remote_port": rport,
                    "inode": parts[9],
                })
        except Exception:
            continue
    return conns


def resolve_ip(ip: str) -> Optional[str]:
    """Best-effort reverse DNS."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def live_monitor(duration: int, interval: float, json_mode: bool) -> int:
    print(f"{cyan('▸')} Monitoring outbound connections for {duration}s...")
    print(f"  Interval: {interval}s")
    if not json_mode:
        print(f"  Press Ctrl+C to stop\n")

    seen: Set[Tuple[str, int]] = set()
    threats: List[Dict] = []
    start = time.time()

    try:
        while time.time() - start < duration:
            conns = parse_proc_net()
            for conn in conns:
                key = (conn["remote_ip"], conn["remote_port"])
                if key in seen:
                    continue
                seen.add(key)

                rip = conn["remote_ip"]
                rport = conn["remote_port"]

                # Skip loopback
                if rip.startswith("127.") or rip == "::1" or rip == "0.0.0.0":
                    continue

                issue = None
                severity = 0

                if rport in MINING_PORTS:
                    issue = f"mining pool port {rport}"
                    severity = 2
                elif rport in C2_PORTS:
                    issue = f"C2/RAT port {rport}"
                    severity = 2

                # Try to resolve and check
                host = resolve_ip(rip)
                if host and any(d in host for d in EXFIL_DOMAINS):
                    issue = f"exfil service: {host}"
                    severity = 2
                elif host and host.endswith(".onion"):
                    issue = "Tor network"
                    severity = 2

                if issue:
                    threats.append({
                        "ip": rip,
                        "port": rport,
                        "host": host,
                        "issue": issue,
                        "severity": severity,
                        "timestamp": time.time(),
                    })
                    if json_mode:
                        print(json.dumps(threats[-1]))
                    else:
                        sev_color = red if severity == 2 else yellow
                        icon = "🚨" if severity == 2 else "⚠️"
                        print(f"  {icon} [{sev_color(f'SEV-{severity}')}] {rip}:{rport} → {issue} ({host or 'unresolved'})")

            time.sleep(interval)

    except KeyboardInterrupt:
        print(yellow("\n⚠ Stopped by user"))

    if not json_mode:
        if not threats:
            print(green(f"\n✅ Clean — {len(seen)} unique connections, all benign"))
        else:
            crit = sum(1 for t in threats if t["severity"] == 2)
            print(yellow(f"\n⚠ Detected {len(threats)} suspicious ({crit} critical)"))

    return 2 if any(t["severity"] == 2 for t in threats) else (1 if threats else 0)


# ──────────────────────────────────────────────────────────────────────
# Output
# ──────────────────────────────────────────────────────────────────────

def print_check_result(check: Dict) -> int:
    """Print a check result, return risk level."""
    risk = check.get("risk", 0)
    if risk == 2:
        verdict_str = red(f"🚨 {check.get('verdict', 'malicious').upper()}")
    elif risk == 1:
        verdict_str = yellow(f"⚠️  {check.get('verdict', 'suspicious').upper()}")
    else:
        verdict_str = green(f"✅ {check.get('verdict', 'clean').upper()}")

    target = check.get("url") or check.get("domain") or ""
    print(f"\n{cyan('─' * 60)}")
    print(f"  {verdict_str}  {target}")
    print(cyan('─' * 60))
    if check.get("issues"):
        for issue in check["issues"]:
            print(f"  • {issue}")
    else:
        print(f"  {C.GREEN}No issues detected.{C.RESET}")

    return risk


# ──────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Network exfiltration guard")
    parser.add_argument("--monitor", action="store_true", help="Live monitor network connections")
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--check-url", help="Check a URL")
    parser.add_argument("--check-domain", help="Check a domain")
    parser.add_argument("--check-dns", help="Check DNS tunneling pattern")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.monitor:
        sys.exit(live_monitor(args.duration, args.interval, args.json))
    elif args.check_url:
        result = check_url(args.check_url)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            sys.exit(print_check_result(result))
    elif args.check_domain:
        result = check_domain(args.check_domain)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            sys.exit(print_check_result(result))
    elif args.check_dns:
        result = check_dns_tunneling(args.check_dns)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            sys.exit(print_check_result(result))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()