#!/usr/bin/env python3
"""
agent-self-protection: output_sanitizer.py
Outbound filter — sanitize content before display or handoff to next LLM call.

Strips:
- Hardcoded credentials (uses regex from credential_scanner.py)
- Script tags + javascript: URIs in HTML
- Suspicious URLs in any rendered content
- Zero-width Unicode (hidden instruction channels)
- ANSI escape codes that could hide malicious output
- Bidi overrides (used to obfuscate source code)
- Hidden HTML elements (display:none, visibility:hidden)

Usage:
    cat raw_output.txt | python3 output_sanitizer.py
    python3 output_sanitizer.py --sanitize-html page.html > safe.html
    python3 output_sanitizer.py --check raw_output.txt
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple


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


# Credential patterns (subset of credential_scanner)
CREDENTIAL_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS_KEY"),
    (r"AIza[0-9A-Za-z\-_]{35}", "GOOGLE_KEY"),
    (r"gh[pousr]_[A-Za-z0-9]{36,255}", "GH_TOKEN"),
    (r"github_pat_[A-Za-z0-9_]{82}", "GH_PAT"),
    (r"xox[bpoars]-[A-Za-z0-9-]{10,}", "SLACK_TOKEN"),
    (r"sk_live_[0-9a-zA-Z]{24,}", "STRIPE_LIVE"),
    (r"pk_live_[0-9a-zA-Z]{24,}", "STRIPE_LIVE_PUB"),
    (r"sk-ant-[A-Za-z0-9\-]{20,}", "ANTHROPIC_KEY"),
    (r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b", "TG_BOT"),
    (r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}", "SENDGRID"),
    (r"npm_[A-Za-z0-9]{36}", "NPM_TOKEN"),
    (r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}", "PYPI_TOKEN"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "PRIVATE_KEY"),
    (r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "JWT"),
]

# Zero-width / bidi override chars to strip
ZERO_WIDTH_CHARS = set("\u200b\u200c\u200d\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\ufeff\u00ad")

# ANSI escape code (full CSI)
ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def sanitize_credentials(text: str) -> Tuple[str, int]:
    """Replace credentials with [REDACTED:TYPE] markers."""
    redactions = 0
    for pattern, label in CREDENTIAL_PATTERNS:
        text, n = re.subn(pattern, f"[REDACTED:{label}]", text)
        redactions += n
    return text, redactions


def sanitize_html(text: str) -> Tuple[str, int]:
    """Strip dangerous HTML constructs."""
    removed = 0

    # Remove <script>...</script>
    text, n = re.subn(r"<script\b[^>]*>.*?</script>", "[SCRIPT_REMOVED]", text, flags=re.DOTALL | re.IGNORECASE)
    removed += n

    # Remove <iframe>...</iframe>
    text, n = re.subn(r"<iframe\b[^>]*>.*?</iframe>", "[IFRAME_REMOVED]", text, flags=re.DOTALL | re.IGNORECASE)
    removed += n

    # Remove <object>, <embed>, <form>
    for tag in ["object", "embed", "form", "base"]:
        text, n = re.subn(rf"<{tag}\b[^>]*>.*?</{tag}>", f"[{tag.upper()}_REMOVED]", text, flags=re.DOTALL | re.IGNORECASE)
        removed += n
        text, n = re.subn(rf"<{tag}\b[^>]*/?>", f"[{tag.upper()}_REMOVED]", text, flags=re.IGNORECASE)
        removed += n

    # Remove inline event handlers (onclick=, onerror=, etc.)
    text, n = re.subn(r'\s+on[a-z]+\s*=\s*["\'][^"\']*["\']', " ", text, flags=re.IGNORECASE)
    removed += n

    # Remove javascript: URIs
    text, n = re.subn(r'(?:href|src|action)\s*=\s*["\']?\s*javascript:[^"\'\s>]*',
                      '[JAVASCRIPT_REMOVED]', text, flags=re.IGNORECASE)
    removed += n

    # Remove data: URIs (can carry HTML/JS payloads)
    text, n = re.subn(r'(?:href|src)\s*=\s*["\']?\s*data:(?!image/)[^"\'\s>]*',
                      '[DATA_URI_REMOVED]', text, flags=re.IGNORECASE)
    removed += n

    # Remove hidden elements
    text, n = re.subn(r'style\s*=\s*["\'][^"\']*display\s*:\s*none[^"\']*["\']', " ", text, flags=re.IGNORECASE)
    removed += n
    text, n = re.subn(r'style\s*=\s*["\'][^"\']*visibility\s*:\s*hidden[^"\']*["\']', " ", text, flags=re.IGNORECASE)
    removed += n

    return text, removed


def sanitize_zero_width(text: str) -> Tuple[str, int]:
    """Strip zero-width Unicode that could smuggle instructions."""
    removed = 0
    result = []
    for char in text:
        if char in ZERO_WIDTH_CHARS:
            removed += 1
        else:
            result.append(char)
    return "".join(result), removed


def sanitize_ansi(text: str) -> Tuple[str, int]:
    """Strip ANSI escape codes (could hide malicious output)."""
    text, n = ANSI_ESCAPE.subn("", text)
    return text, n


def sanitize_paths(text: str) -> Tuple[str, int]:
    """Redact sensitive file paths."""
    sensitive_paths = [
        r"/root/\.ssh/[^\s]*",
        r"/home/[\w.-]+/\.ssh/[^\s]*",
        r"/root/\.aws/[^\s]*",
        r"/root/\.gnupg/[^\s]*",
        r"/root/\.docker/config\.json",
        r"/root/\.kube/config",
        r"/root/\.netrc",
        r"/etc/shadow",
    ]
    redactions = 0
    for pattern in sensitive_paths:
        text, n = re.subn(pattern, "[SENSITIVE_PATH]", text)
        redactions += n
    return text, redactions


# ──────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Output sanitizer")
    parser.add_argument("path", nargs="?", help="File (or stdin if omitted)")
    parser.add_argument("--sanitize-html", action="store_true",
                        help="Apply HTML sanitization")
    parser.add_argument("--check", action="store_true",
                        help="Check only, don't print sanitized output")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.path:
        content = Path(args.path).read_text(errors="ignore")
        source = args.path
    else:
        content = sys.stdin.read()
        source = "<stdin>"

    total_redactions = 0
    checks = {}

    # Credentials
    content, n = sanitize_credentials(content)
    checks["credentials"] = n
    total_redactions += n

    # Paths
    content, n = sanitize_paths(content)
    checks["sensitive_paths"] = n
    total_redactions += n

    # Zero-width
    content, n = sanitize_zero_width(content)
    checks["zero_width"] = n
    total_redactions += n

    # ANSI
    content, n = sanitize_ansi(content)
    checks["ansi"] = n
    total_redactions += n

    # HTML (optional)
    html_removed = 0
    if args.sanitize_html:
        content, html_removed = sanitize_html(content)
    checks["html"] = html_removed
    total_redactions += html_removed

    if args.json:
        print(json.dumps({"source": source, "checks": checks,
                          "total_redactions": total_redactions}, indent=2))
    elif args.check:
        print(f"\n{C.CYAN}{'═' * 50}{C.RESET}")
        print(f"  Source: {source}")
        print(f"{C.CYAN}{'═' * 50}{C.RESET}")
        for k, v in checks.items():
            icon = green("✓") if v == 0 else yellow(f"⚠ {v}")
            print(f"  {icon}  {k}: {v}")
        print(f"\n  Total redactions: {total_redactions}")
    else:
        sys.stdout.write(content)
        sys.stderr.write(
            f"\n[{C.DIM}sanitized: {total_redactions} redactions "
            f"(creds={checks['credentials']}, "
            f"paths={checks['sensitive_paths']}, "
            f"zwsp={checks['zero_width']}, "
            f"ansi={checks['ansi']}, "
            f"html={checks['html']}){C.RESET}]\n"
        )


if __name__ == "__main__":
    main()