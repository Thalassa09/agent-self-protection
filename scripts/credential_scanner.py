#!/usr/bin/env python3
"""
agent-self-protection: credential_scanner.py
Detect leaked credentials in files/text: API keys, private keys, JWT tokens,
passwords, connection strings, high-entropy strings.

Usage:
    python3 credential_scanner.py file.txt
    python3 credential_scanner.py --recursive /path/to/dir
    python3 credential_scanner.py --redact file.txt  # print with secrets masked
    cat output.log | python3 credential_scanner.py -

Exit codes: 0=clean  1=secrets found  2=critical (private keys, etc.)
"""

import argparse
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple


# ──────────────────────────────────────────────────────────────────────
# Color helpers
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
# Credential patterns
# Severity: 1=warn, 2=critical (private keys, high-entropy long secrets)
# ──────────────────────────────────────────────────────────────────────

CREDENTIAL_PATTERNS: List[Tuple[str, int, str, str]] = [
    # AWS
    (r"AKIA[0-9A-Z]{16}", 2, "AWS Access Key ID",
     "AKIA[A-Z0-9]{16}"),
    (r"aws_secret_access_key\s*=\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?", 2,
     "AWS Secret Access Key", r"(?:aws_secret_access_key|AWS_SECRET).{0,30}"),

    # Google
    (r"AIza[0-9A-Za-z\-_]{35}", 2, "Google API Key",
     r"AIza[0-9A-Za-z\-_]{35}"),
    (r"ya29\.[0-9A-Za-z\-_]+", 2, "Google OAuth Token", r"ya29\.[A-Za-z0-9_\-]+"),

    # GitHub
    (r"gh[pousr]_[A-Za-z0-9]{36,255}", 2, "GitHub Token",
     r"gh[pousr]_[A-Za-z0-9_]{36,}"),
    (r"github_pat_[A-Za-z0-9_]{82}", 2, "GitHub PAT (fine-grained)",
     r"github_pat_[A-Za-z0-9_]{82}"),
    (r"gho_[A-Za-z0-9]{36}", 2, "GitHub OAuth Token", r"gho_[A-Za-z0-9]{36}"),

    # Slack
    (r"xox[bpoars]-[A-Za-z0-9-]{10,}", 2, "Slack Token",
     r"xox[bpoars]-[A-Za-z0-9-]+"),

    # Stripe
    (r"sk_live_[0-9a-zA-Z]{24,}", 2, "Stripe Live Secret Key",
     r"sk_live_[0-9a-zA-Z]+"),
    (r"pk_live_[0-9a-zA-Z]{24,}", 2, "Stripe Live Publishable Key",
     r"pk_live_[0-9a-zA-Z]+"),
    (r"rk_live_[0-9a-zA-Z]{24,}", 2, "Stripe Live Restricted Key",
     r"rk_live_[0-9a-zA-Z]+"),

    # OpenAI / Anthropic
    (r"sk-[A-Za-z0-9]{20,}", 1, "OpenAI-style API Key", r"sk-[A-Za-z0-9]{20,}"),
    (r"sk-ant-[A-Za-z0-9\-]{20,}", 2, "Anthropic API Key",
     r"sk-ant-[A-Za-z0-9\-]+"),

    # Telegram
    (r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b", 2, "Telegram Bot Token",
     r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"),

    # Discord
    (r"[MN][A-Za-z\d]{23,}\.[A-Za-z\d]{6,}\.[A-Za-z\d]{27,}", 2,
     "Discord Bot Token",
     r"[MN][A-Za-z\d]{23,}\.[A-Za-z\d]{6,}\.[A-Za-z\d]{27,}"),
    (r"https://discord(?:app)?\.com/api/webhooks/\d+/[\w-]+", 2,
     "Discord Webhook URL",
     r"https://discord(?:app)?\.com/api/webhooks/\d+/[\w-]+"),

    # Twilio
    (r"SK[a-f0-9]{32}", 2, "Twilio API Key", r"SK[a-f0-9]{32}"),
    (r"AC[a-f0-9]{32}", 2, "Twilio Account SID", r"AC[a-f0-9]{32}"),

    # SendGrid
    (r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}", 2, "SendGrid API Key",
     r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"),

    # Mailgun
    (r"key-[a-z0-9]{32}", 2, "Mailgun API Key", r"key-[a-z0-9]{32}"),

    # Cloudflare
    (r"v1\.0[A-Za-z0-9_\-]{30,}", 1, "Cloudflare API Key (legacy)",
     r"v1\.0[A-Za-z0-9_\-]+"),

    # Private keys
    (r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
     2, "Private Key (PEM)", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    (r"-----BEGIN CERTIFICATE REQUEST-----", 1, "CSR",
     r"-----BEGIN CERTIFICATE REQUEST-----"),

    # JWT (heuristic)
    (r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", 1,
     "JSON Web Token (JWT)", r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),

    # Database connection strings
    (r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s\"'<>]+:[^\s\"'<>@]+@[\w.-]+",
     2, "Database Connection String with Credentials",
     r"(?:postgres|...)://[^:]+:[^@]+@"),

    # Common password patterns
    (r"(?:password|passwd|pwd|secret|api_?key|token)\s*[:=]\s*['\"]([^'\"\\]{8,})['\"]",
     1, "Hardcoded Password/Secret",
     r"(?:password|passwd|...)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
    (r"Bearer\s+[A-Za-z0-9\-_\.]{20,}", 1, "Bearer Token",
     r"Bearer\s+[A-Za-z0-9\-_\.]{20,}"),
    (r"Basic\s+[A-Za-z0-9+/=]{20,}", 1, "Basic Auth Header",
     r"Basic\s+[A-Za-z0-9+/=]{20,}"),

    # SSH keys in non-standard locations
    (r"ssh-rsa\s+AAAA[0-9A-Za-z+/=]{40,}\s+", 1, "SSH Public Key (might be exfil)",
     r"ssh-rsa\s+AAAA[0-9A-Za-z+/=]+"),
    (r"ssh-ed25519\s+AAAA[0-9A-Za-z+/=]{40,}\s+", 1,
     "SSH Public Key (ed25519)", r"ssh-ed25519\s+AAAA[0-9A-Za-z+/=]+"),

    # npm tokens
    (r"npm_[A-Za-z0-9]{36}", 2, "npm Auth Token", r"npm_[A-Za-z0-9]{36}"),

    # PyPI tokens
    (r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}", 2, "PyPI Token",
     r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]+"),

    # Heroku
    (r"[hH]eroku[a-z0-9_\-]{32}", 1, "Heroku API Key (heuristic)",
     r"[hH]eroku[a-z0-9_\-]+"),

    # Generic high-entropy quoted string (40+ chars, entropy > 4.5)
    # — handled separately in scan_content
]

# Allowlist of known safe patterns (don't flag)
SAFE_PATTERNS = [
    r"^placeholder$",
    r"^example\.com$",
    r"^your[-_]?key[-_]?here$",
    r"^xxx+$",
    r"^test$",
    r"^change[-_]?me$",
    r"^0{16,}$",  # All zeros
    r"^1{16,}$",  # All ones
]


# ──────────────────────────────────────────────────────────────────────
# Entropy helpers
# ──────────────────────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def find_high_entropy_secrets(content: str, min_len: int = 30) -> List[Dict]:
    """Find high-entropy strings in quoted contexts."""
    findings = []
    # Look for quoted strings or after `=`
    for match in re.finditer(r"(?:[\"']|=\s*)([A-Za-z0-9+/=_\-]{%d,})(?=[\"'\s;,)\]])" % min_len,
                             content):
        s = match.group(1)
        if re.match(r"^[A-Z_]+$", s):
            continue  # Skip constant names like API_KEY_NAME
        ent = shannon_entropy(s)
        if ent >= 4.8 and len(s) >= 30:
            # Check it's not a known safe pattern
            if not any(re.match(p, s) for p in SAFE_PATTERNS):
                findings.append({
                    "secret": s,
                    "entropy": round(ent, 2),
                    "length": len(s),
                    "line": content[:match.start()].count("\n") + 1,
                })
    return findings


# ──────────────────────────────────────────────────────────────────────
# Scanner
# ──────────────────────────────────────────────────────────────────────

def scan_content(content: str, source: str = "<input>") -> Dict:
    """Scan content for credential leaks. Returns dict with findings + risk."""
    findings = {
        "source": source,
        "verdict": "clean",
        "risk": 0,
        "matches": [],
        "high_entropy": [],
    }

    # Known patterns
    for pattern, severity, label, _ in CREDENTIAL_PATTERNS:
        for match in re.finditer(pattern, content):
            secret = match.group()
            # Mask middle of secret for safe display
            if len(secret) > 16:
                masked = secret[:8] + "..." + secret[-4:]
            else:
                masked = secret[:4] + "..." + secret[-2:]
            findings["matches"].append({
                "type": label,
                "severity": severity,
                "match": masked,
                "full_match": secret[:80] + ("..." if len(secret) > 80 else ""),
                "line": content[:match.start()].count("\n") + 1,
            })

    # High-entropy strings
    findings["high_entropy"] = find_high_entropy_secrets(content)

    # Score
    max_sev = 0
    for m in findings["matches"]:
        max_sev = max(max_sev, m["severity"])
    if findings["high_entropy"]:
        max_sev = max(max_sev, 1)

    findings["risk"] = 2 if max_sev >= 2 else (1 if max_sev >= 1 or findings["high_entropy"] else 0)
    findings["verdict"] = "critical" if findings["risk"] == 2 else ("suspicious" if findings["risk"] == 1 else "clean")

    return findings


# ──────────────────────────────────────────────────────────────────────
# Redaction
# ──────────────────────────────────────────────────────────────────────

def redact_content(content: str) -> str:
    """Replace secrets with [REDACTED:TYPE] markers."""
    redacted = content
    for pattern, severity, label, _ in CREDENTIAL_PATTERNS:
        marker = f"[REDACTED:{label.split()[0].upper()}]"
        redacted = re.sub(pattern, marker, redacted)
    return redacted


# ──────────────────────────────────────────────────────────────────────
# Output
# ──────────────────────────────────────────────────────────────────────

def print_findings(findings: Dict) -> int:
    risk = findings["risk"]
    if risk == 2:
        verdict_str = red(f"🚨 {findings['verdict'].upper()}")
    elif risk == 1:
        verdict_str = yellow(f"⚠️  {findings['verdict'].upper()}")
    else:
        verdict_str = green(f"✅ {findings['verdict'].upper()}")

    print(f"\n{cyan('═' * 70)}")
    print(f"  {verdict_str}  {findings['source']}")
    print(cyan('═' * 70))

    if not findings["matches"] and not findings["high_entropy"]:
        print(f"  {C.GREEN}No credentials detected.{C.RESET}")
        return 0

    if findings["matches"]:
        print(f"\n  {cyan('▸ Pattern matches')}")
        # Group by type
        by_type: Dict[str, List[Dict]] = {}
        for m in findings["matches"]:
            by_type.setdefault(m["type"], []).append(m)
        for type_name, items in sorted(by_type.items()):
            sev_color = red if items[0]["severity"] == 2 else yellow
            print(f"      [{sev_color(type_name)}]  ({len(items)} match{'es' if len(items) != 1 else ''})")
            for item in items[:5]:
                print(f"          line {item['line']}: {item['match']}")
            if len(items) > 5:
                print(f"          {C.DIM}... and {len(items) - 5} more{C.RESET}")

    if findings["high_entropy"]:
        print(f"\n  {cyan('▸ High-entropy strings ({len})'.format(len=len(findings['high_entropy'])))}")
        for s in findings["high_entropy"][:5]:
            print(f"      line {s['line']}, len={s['length']}, ent={s['entropy']:.2f}: "
                  f"{C.DIM}{s['secret'][:40]}...{C.RESET}")

    return risk


# ──────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Credential leakage scanner")
    parser.add_argument("path", help="File, directory (with --recursive), or '-' for stdin")
    parser.add_argument("--recursive", "-r", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--redact", action="store_true",
                        help="Print content with secrets redacted")
    parser.add_argument("--max-bytes", type=int, default=10_000_000)
    args = parser.parse_args()

    max_risk = 0

    if args.path == "-":
        content = sys.stdin.read()
        if args.redact:
            print(redact_content(content), end="")
            sys.exit(0)
        result = scan_content(content, source="<stdin>")
        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            max_risk = print_findings(result)
    else:
        target = Path(args.path)
        files = []
        if target.is_file():
            files.append(target)
        elif target.is_dir() and args.recursive:
            for f in target.rglob("*"):
                if f.is_file() and f.stat().st_size <= args.max_bytes:
                    files.append(f)
        else:
            print(red(f"Error: {target} not found or not a directory (use --recursive)"))
            sys.exit(2)

        for f in files:
            try:
                content = f.read_text(errors="ignore")
            except Exception:
                continue

            if args.redact:
                print(f"=== {f} ===")
                print(redact_content(content))
                continue

            result = scan_content(content, source=str(f))
            max_risk = max(max_risk, result["risk"])

            if args.json:
                print(json.dumps(result, indent=2, default=str))
            else:
                print_findings(result)

    sys.exit(max_risk)


if __name__ == "__main__":
    main()