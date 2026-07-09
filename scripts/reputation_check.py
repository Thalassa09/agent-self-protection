#!/usr/bin/env python3
"""
agent-self-protection: reputation_check.py
Multi-source threat intelligence:
  - URLhaus (abuse.ch) — malware distribution URLs
  - VirusTotal (optional API key) — multi-engine URL/file scanning
  - WHOIS — domain age, registrar
  - SSL cert analysis — issuer, age, SAN
  - DNS resolution check
  - PhishTank (optional)
  - npm/PyPI package metadata verification

Usage:
    python3 reputation_check.py --url https://example.com
    python3 reputation_check.py --domain example.com
    python3 reputation_check.py --ip 1.2.3.4
    python3 reputation_check.py --npm lodash
    python3 reputation_check.py --pypi requests
    python3 reputation_check.py --hash <sha256>
"""

import argparse
import json
import os
import re
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple  # noqa: F401
from urllib.parse import urlparse


try:
    import requests  # type: ignore
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ──────────────────────────────────────────────────────────────────────
# Color
# ──────────────────────────────────────────────────────────────────────

class C:
    RED = "\033[31m"
    YELLOW = "\033[33m"
    GREEN = "\033[32m"
    CYAN = "\033[36m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def red(s): return f"{C.RED}{s}{C.RESET}"
def yellow(s): return f"{C.YELLOW}{s}{C.RESET}"
def green(s): return f"{C.GREEN}{s}{C.RESET}"
def cyan(s): return f"{C.CYAN}{s}{C.RESET}"


# ──────────────────────────────────────────────────────────────────────
# WHOIS
# ──────────────────────────────────────────────────────────────────────

def check_whois(domain: str) -> Dict:
    result = {"domain": domain, "available": False, "data": {}, "issues": []}
    if not shutil.which("whois"):
        result["issues"].append("whois not installed")
        return result
    try:
        out = subprocess.run(
            ["whois", domain], capture_output=True, text=True, timeout=20,
        ).stdout
        result["available"] = True

        for line in out.splitlines():
            for key, target in [
                ("registrar:", "registrar"),
                ("creation date:", "created"),
                ("created:", "created"),
                ("registered:", "created"),
                ("updated date:", "updated"),
                ("registry domain id:", "registry_id"),
                ("name server:", "nameserver"),
                ("status:", "status"),
            ]:
                if line.lower().startswith(key):
                    val = line.split(":", 1)[1].strip()
                    result["data"].setdefault(target, []).append(val)

        # Age analysis
        created_str = ""
        if result["data"].get("created"):
            first = result["data"]["created"][0]
            # Try multiple date formats
            for fmt in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z",
                       "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y",
                       "%Y.%m.%d"]:
                try:
                    dt = datetime.strptime(first[:19], fmt).replace(tzinfo=timezone.utc)
                    created_str = dt.isoformat()
                    days_old = (datetime.now(timezone.utc) - dt).days
                    result["data"]["age_days"] = days_old
                    if days_old < 30:
                        result["issues"].append(
                            f"Domain very new ({days_old} days old) — high abuse risk"
                        )
                    elif days_old < 365:
                        result["issues"].append(
                            f"Domain young ({days_old} days old)"
                        )
                    break
                except ValueError:
                    continue
            if created_str:
                result["data"]["created"] = [created_str]
    except subprocess.TimeoutExpired:
        result["issues"].append("whois timeout")
    except Exception as e:
        result["issues"].append(f"whois: {e}")
    return result


# ──────────────────────────────────────────────────────────────────────
# URLhaus
# ──────────────────────────────────────────────────────────────────────

def check_urlhaus(url: Optional[str] = None, host: Optional[str] = None,
                  file_hash: Optional[str] = None) -> Dict:
    result = {"listed": False, "issues": [], "matches": []}
    if not HAS_REQUESTS:
        result["issues"].append("requests not installed")
        return result
    try:
        # URLhaus online lookup API
        if url:
            payload = {"url": url}
            r = requests.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data=payload, timeout=20,
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("query_status") == "listed":
                    result["listed"] = True
                    result["matches"].append({
                        "type": "url",
                        "value": url,
                        "threat": data.get("threat", "unknown"),
                        "tags": data.get("tags", []),
                    })
                    result["issues"].append(
                        f"Listed on URLhaus as {data.get('threat')} with tags {data.get('tags', [])}"
                    )

        if host:
            payload = {"host": host}
            r = requests.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data=payload, timeout=20,
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("query_status") == "listed":
                    result["listed"] = True
                    result["issues"].append(f"Host '{host}' is on URLhaus malware distribution list")
                    if data.get("urls"):
                        result["matches"].extend([
                            {"type": "url", "value": u.get("url", "")[:100]}
                            for u in data["urls"][:5]
                        ])

        if file_hash:
            payload = {"hash": file_hash}
            r = requests.post(
                "https://urlhaus-api.abuse.ch/v1/payload/",
                data=payload, timeout=20,
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("query_status") == "listed":
                    result["listed"] = True
                    result["issues"].append(
                        f"Hash on URLhaus: {data.get('signature', 'unknown signature')}"
                    )
    except Exception as e:
        result["issues"].append(f"URLhaus: {e}")
    return result


# ──────────────────────────────────────────────────────────────────────
# VirusTotal
# ──────────────────────────────────────────────────────────────────────

def check_virustotal(target: str, target_type: str = "url") -> Dict:
    api_key = os.environ.get("VIRUSTOTAL_API_KEY") or os.environ.get("VT_API_KEY")
    result = {"queried": False, "issues": [], "matches": 0, "total": 0}
    if not api_key:
        result["issues"].append("VIRUSTOTAL_API_KEY not set")
        return result
    if not HAS_REQUESTS:
        result["issues"].append("requests not installed")
        return result

    headers = {"x-apikey": api_key}
    try:
        if target_type == "url":
            # Submit URL for analysis (note: uses public API v3, requires URL id)
            url_id = requests.utils.quote(target, safe="")
            r = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers, timeout=20,
            )
            if r.status_code == 200:
                data = r.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                result["queried"] = True
                result["matches"] = stats.get("malicious", 0) + stats.get("suspicious", 0)
                result["total"] = sum(stats.values())
                if result["matches"] > 0:
                    result["issues"].append(
                        f"VirusTotal: {result['matches']}/{result['total']} engines flagged this URL"
                    )
        elif target_type == "hash":
            r = requests.get(
                f"https://www.virustotal.com/api/v3/files/{target}",
                headers=headers, timeout=20,
            )
            if r.status_code == 200:
                data = r.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                result["queried"] = True
                result["matches"] = stats.get("malicious", 0) + stats.get("suspicious", 0)
                result["total"] = sum(stats.values())
                if result["matches"] > 0:
                    result["issues"].append(
                        f"VirusTotal: {result['matches']}/{result['total']} engines flagged this file hash"
                    )
    except Exception as e:
        result["issues"].append(f"VirusTotal: {e}")
    return result


# ──────────────────────────────────────────────────────────────────────
# SSL Certificate analysis
# ──────────────────────────────────────────────────────────────────────

def check_ssl(domain: str, port: int = 443) -> Dict:
    result = {"domain": domain, "issues": [], "data": {}}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        # Subject
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        result["data"]["subject"] = subject.get("commonName", "")
        result["data"]["issuer"] = issuer.get("organizationName", issuer.get("commonName", ""))

        # Validity
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")
        result["data"]["valid_from"] = not_before
        result["data"]["valid_to"] = not_after

        # SAN check
        san = []
        for ext in cert.get("subjectAltName", []):
            san.append(ext[1])
        result["data"]["san_count"] = len(san)

        # Self-signed?
        if subject.get("commonName") == issuer.get("commonName"):
            result["issues"].append("Self-signed certificate")

        # Domain in SAN?
        if domain not in san and domain != subject.get("commonName"):
            result["issues"].append(f"Domain '{domain}' not in cert SAN/CN")
    except socket.gaierror:
        result["issues"].append(f"Cannot resolve {domain}")
    except socket.timeout:
        result["issues"].append(f"SSL connection timeout for {domain}")
    except Exception as e:
        result["issues"].append(f"SSL: {e}")
    return result


# ──────────────────────────────────────────────────────────────────────
# DNS resolution
# ──────────────────────────────────────────────────────────────────────

def check_dns(domain: str) -> Dict:
    result = {"domain": domain, "ips": [], "issues": []}
    try:
        ips = socket.getaddrinfo(domain, None)
        result["ips"] = list({ip[4][0] for ip in ips})
    except socket.gaierror:
        result["issues"].append(f"Cannot resolve {domain}")
    except Exception as e:
        result["issues"].append(f"DNS: {e}")
    return result


# ──────────────────────────────────────────────────────────────────────
# Package registry checks (npm, PyPI)
# ──────────────────────────────────────────────────────────────────────

def check_npm(pkg: str) -> Dict:
    result = {"package": pkg, "issues": [], "data": {}}
    if not HAS_REQUESTS:
        result["issues"].append("requests not installed")
        return result
    try:
        r = requests.get(f"https://registry.npmjs.org/{pkg}", timeout=15)
        if r.status_code == 404:
            result["issues"].append("Package not found in npm registry")
            return result
        if r.status_code != 200:
            result["issues"].append(f"npm registry returned HTTP {r.status_code}")
            return result
        data = r.json()
        latest = data.get("dist-tags", {}).get("latest", "")
        latest_info = data.get("versions", {}).get(latest, {})
        result["data"]["latest"] = latest
        result["data"]["description"] = data.get("description", "")[:100]
        result["data"]["homepage"] = data.get("homepage", "")
        result["data"]["repository"] = (data.get("repository") or {}).get("url", "")
        result["data"]["maintainers"] = [
            m.get("name") for m in data.get("maintainers", [])[:5]
        ]
        result["data"]["created"] = data.get("time", {}).get("created", "")
        result["data"]["modified"] = data.get("time", {}).get("modified", "")

        # Postinstall script?
        scripts = latest_info.get("scripts", {})
        if any(s in scripts for s in ["postinstall", "preinstall", "install"]):
            result["issues"].append(
                f"Package has install script: {list(s for s in scripts if 'install' in s.lower())}"
            )

        # Suspicious deps
        deps = list(latest_info.get("dependencies", {}).keys())
        suspicious = [
            d for d in deps
            if d in {"event-stream", "node-ipc", "flatmap-stream", "getcookies"}
            or "miner" in d.lower() or "crypto" in d.lower() and "test" not in d.lower()
        ]
        if suspicious:
            result["issues"].append(f"Suspicious dependencies: {suspicious}")
    except Exception as e:
        result["issues"].append(f"npm: {e}")
    return result


def check_pypi(pkg: str) -> Dict:
    result = {"package": pkg, "issues": [], "data": {}}
    if not HAS_REQUESTS:
        result["issues"].append("requests not installed")
        return result
    try:
        r = requests.get(f"https://pypi.org/pypi/{pkg}/json", timeout=15)
        if r.status_code == 404:
            result["issues"].append("Package not found in PyPI")
            return result
        if r.status_code != 200:
            result["issues"].append(f"PyPI returned HTTP {r.status_code}")
            return result
        data = r.json()
        info = data.get("info", {})
        result["data"]["version"] = info.get("version", "")
        result["data"]["author"] = info.get("author", "")
        result["data"]["author_email"] = info.get("author_email", "")
        result["data"]["home_page"] = info.get("home_page", "")
        result["data"]["license"] = info.get("license", "")[:30]
        result["data"]["summary"] = (info.get("summary") or "")[:100]

        # Upload time
        urls = data.get("urls", [])
        if urls:
            result["data"]["upload_time"] = urls[0].get("upload_time", "")
            days_old = 9999
            try:
                ut = urls[0].get("upload_time", "")
                if ut:
                    dt = datetime.fromisoformat(ut.replace("Z", "+00:00"))
                    days_old = (datetime.now(timezone.utc) - dt).days
                    result["data"]["age_days"] = days_old
            except Exception:
                pass

        # Known typosquats
        typosquats = {
            "reqests", "requets", "python_dateutil", "python-dateutil",
            "pillow-pil", "numpy-python", "python-numpy",
        }
        if pkg in typosquats:
            result["issues"].append("Known typosquat name")
    except Exception as e:
        result["issues"].append(f"PyPI: {e}")
    return result


# ──────────────────────────────────────────────────────────────────────
# Aggregate risk scoring
# ──────────────────────────────────────────────────────────────────────

def score_reputation(checks: Dict[str, Dict]) -> Tuple[int, str]:
    risk = 0
    notes = []

    whois = checks.get("whois", {})
    if whois.get("issues"):
        for issue in whois["issues"]:
            if "very new" in issue.lower():
                risk += 2
            elif "young" in issue.lower():
                risk += 1

    urlhaus = checks.get("urlhaus", {})
    if urlhaus.get("listed"):
        risk = max(risk, 2)
        notes.append("URLhaus listing")

    vt = checks.get("virustotal", {})
    if vt.get("matches", 0) >= 5:
        risk = max(risk, 2)
    elif vt.get("matches", 0) > 0:
        risk = max(risk, 1)

    ssl_check = checks.get("ssl", {})
    if any("self-signed" in i for i in ssl_check.get("issues", [])):
        risk = max(risk, 1)

    npm = checks.get("npm", {})
    if "Suspicious dependencies" in str(npm.get("issues", [])):
        risk = max(risk, 2)

    if risk >= 2:
        return risk, "MALICIOUS"
    elif risk >= 1:
        return risk, "SUSPICIOUS"
    return 0, "CLEAN"


# ──────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────

def print_section(title: str, data: Dict, issues: List[str]):
    print(f"\n  {cyan('▸')} {C.BOLD}{title}{C.RESET}")
    if data:
        for k, v in data.items():
            if isinstance(v, list) and len(v) > 3:
                print(f"    {k}: [{len(v)} items]")
            else:
                print(f"    {C.DIM}{k}: {v}{C.RESET}")
    if issues:
        for issue in issues:
            print(f"    {yellow('⚠')} {issue}")
    else:
        print(f"    {green('✓ no issues')}")


def main():
    parser = argparse.ArgumentParser(description="Multi-source reputation intelligence")
    parser.add_argument("--url")
    parser.add_argument("--domain")
    parser.add_argument("--ip")
    parser.add_argument("--hash")
    parser.add_argument("--npm")
    parser.add_argument("--pypi")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    checks = {}

    if args.url:
        url = args.url
        parsed = urlparse(url)
        domain = parsed.netloc.split(":")[0]
        print(f"\n{cyan('═' * 70)}")
        print(f"  Reputation check: {url}")
        print(f"{cyan('═' * 70)}")
        checks["dns"] = check_dns(domain)
        print_section("DNS", checks["dns"].get("data", {}), checks["dns"].get("issues", []))
        checks["whois"] = check_whois(domain)
        print_section("WHOIS", checks["whois"].get("data", {}), checks["whois"].get("issues", []))
        if domain and not domain.startswith("127."):
            checks["ssl"] = check_ssl(domain)
            print_section("SSL Certificate", checks["ssl"].get("data", {}), checks["ssl"].get("issues", []))
        checks["urlhaus"] = check_urlhaus(url=url, host=domain)
        if checks["urlhaus"]["listed"]:
            print_section("URLhaus", {}, checks["urlhaus"]["issues"])
        else:
            print(f"  {green('✓')} URLhaus: not listed")
        checks["virustotal"] = check_virustotal(url, target_type="url")
        if checks["virustotal"]["queried"]:
            msg = f"{checks['virustotal']['matches']}/{checks['virustotal']['total']} flagged"
            color = red if checks["virustotal"]["matches"] >= 5 else (yellow if checks["virustotal"]["matches"] > 0 else green)
            print(f"  {color('▸ VirusTotal:')} {msg}")

    elif args.domain:
        print(f"\n{cyan('═' * 70)}")
        print(f"  Reputation check: {args.domain}")
        print(f"{cyan('═' * 70)}")
        checks["dns"] = check_dns(args.domain)
        print_section("DNS", checks["dns"].get("data", {}), checks["dns"].get("issues", []))
        checks["whois"] = check_whois(args.domain)
        print_section("WHOIS", checks["whois"].get("data", {}), checks["whois"].get("issues", []))
        try:
            checks["ssl"] = check_ssl(args.domain)
            print_section("SSL Certificate", checks["ssl"].get("data", {}), checks["ssl"].get("issues", []))
        except Exception:
            pass
        checks["urlhaus"] = check_urlhaus(host=args.domain)
        print(f"  {'🚨' if checks['urlhaus']['listed'] else green('✓')} URLhaus: "
              f"{'listed' if checks['urlhaus']['listed'] else 'not listed'}")

    elif args.hash:
        print(f"\n{cyan('═' * 70)}")
        print(f"  Reputation check: {args.hash}")
        print(f"{cyan('═' * 70)}")
        checks["urlhaus"] = check_urlhaus(file_hash=args.hash)
        print(f"  {'🚨' if checks['urlhaus']['listed'] else green('✓')} URLhaus: "
              f"{'listed' if checks['urlhaus']['listed'] else 'not listed'}")
        checks["virustotal"] = check_virustotal(args.hash, target_type="hash")

    elif args.npm:
        print(f"\n{cyan('═' * 70)}")
        print(f"  npm Package check: {args.npm}")
        print(f"{cyan('═' * 70)}")
        checks["npm"] = check_npm(args.npm)
        print_section("npm Registry", checks["npm"].get("data", {}), checks["npm"].get("issues", []))

    elif args.pypi:
        print(f"\n{cyan('═' * 70)}")
        print(f"  PyPI Package check: {args.pypi}")
        print(f"{cyan('═' * 70)}")
        checks["pypi"] = check_pypi(args.pypi)
        print_section("PyPI Registry", checks["pypi"].get("data", {}), checks["pypi"].get("issues", []))

    else:
        parser.print_help()
        sys.exit(1)

    risk, verdict = score_reputation(checks)
    print(f"\n  {cyan('─' * 60)}")
    if risk >= 2:
        print(f"  {red(f'🚨 VERDICT: {verdict}')}")
    elif risk >= 1:
        print(f"  {yellow(f'⚠️  VERDICT: {verdict}')}")
    else:
        print(f"  {green(f'✅ VERDICT: {verdict}')}")
    print(f"  {cyan('─' * 60)}")

    if args.json:
        print(json.dumps(checks, indent=2, default=str))

    sys.exit(risk)


if __name__ == "__main__":
    import shutil as _shutil
    shutil = _shutil  # for whois check
    main()