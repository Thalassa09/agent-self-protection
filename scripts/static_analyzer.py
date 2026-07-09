#!/usr/bin/env python3
"""
agent-self-protection: static_analyzer.py
Static code analysis: reverse shells, eval/exec abuse, exfiltration,
obfuscation, persistence, cryptominers, prompt injection in code.

Supports: shell (.sh/.bash), Python (.py), JavaScript (.js), PHP (.php),
and generic text/code blobs.

Usage:
    python3 static_analyzer.py script.sh
    python3 static_analyzer.py --recursive /path/to/repo
    python3 static_analyzer.py --format json script.py

Exit codes: 0=clean  1=suspicious  2=malicious
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
# Pattern database (curated, opinionated)
# ──────────────────────────────────────────────────────────────────────

# Each pattern: (regex, severity, category, description, language)
PATTERNS = [
    # ── Reverse shells (CRITICAL) ──
    (r"bash\s+-i\s+>&\s*/dev/tcp/", 2, "reverse_shell",
     "Bash TCP reverse shell", "*"),
    (r"/dev/tcp/[\w.-]+/\d+", 2, "reverse_shell",
     "Direct /dev/tcp connection", "*"),
    (r"nc\s+(?:-[a-zA-Z]+\s+)*-e\s+/bin/(?:ba)?sh", 2, "reverse_shell",
     "Netcat reverse shell (-e)", "*"),
    (r"ncat\s+.*-e\s+", 2, "reverse_shell",
     "Ncat reverse shell", "*"),
    (r"socat\s+exec:.*tcp:", 2, "reverse_shell",
     "Socat reverse shell", "*"),
    (r"python[23]?\s+-c\s+['\"].*socket.*connect.*['\"]", 2, "reverse_shell",
     "Python reverse shell", "*"),
    (r"socket\.socket.*connect\([^)]*\)", 1, "reverse_shell",
     "Python socket connect", "python"),
    (r"subprocess\.Popen.*shellin=True", 1, "reverse_shell",
     "Python subprocess shell", "python"),
    (r"msfvenom|metasploit", 1, "reverse_shell",
     "Metasploit reference", "*"),
    (r"\bperl\s+-e\s+['\"].*socket", 2, "reverse_shell",
     "Perl reverse shell", "*"),
    (r"ruby\s+-rsocket\s+-e", 2, "reverse_shell",
     "Ruby reverse shell", "*"),
    (r"php\s+-r\s+.*fsockopen", 2, "reverse_shell",
     "PHP reverse shell", "*"),

    # ── Eval/exec abuse ──
    (r"\beval\s*\(\s*(?:base64_decode|atob|Buffer\.from)", 2, "eval_abuse",
     "Eval of base64-decoded string", "php"),
    (r"\beval\s*\(\s*(?:base64\.b64decode|b64decode)", 2, "eval_abuse",
     "Eval of base64-decoded string", "python"),
    (r"\beval\s*\(\s*atob\s*\(", 2, "eval_abuse",
     "Eval of base64 in JavaScript", "javascript"),
    (r"\bFunction\s*\(\s*['\"][^'\"]*['\"]\s*\)\s*\(", 1, "eval_abuse",
     "Dynamic Function constructor", "javascript"),
    (r"\bexec\s*\(\s*(?:compile|input|__import__)\s*\(", 2, "eval_abuse",
     "Exec of dynamic code", "python"),
    (r"child_process\.exec\s*\(\s*[`'\"]", 1, "eval_abuse",
     "Child process exec of string", "javascript"),
    (r"\bos\.system\s*\(\s*['\"`].*?(?:curl|wget|nc|bash)", 2, "eval_abuse",
     "os.system with network tool", "python"),
    (r"\bos\.popen\s*\(", 1, "eval_abuse",
     "os.popen (shell command)", "python"),
    (r"`\$\(.*?(?:curl|wget).*?`", 1, "eval_abuse",
     "Command substitution with network tool", "shell"),
    (r"\$\([^)]*(?:curl|wget|nc)[^)]*\)", 1, "eval_abuse",
     "Command substitution with network tool", "shell"),

    # ── Exfiltration ──
    (r"curl\s+(?:-[a-zA-Z]+\s+)*-d\s+@?\$\{?(?:HOME|~)\}", 2, "exfiltration",
     "curl POST home contents", "shell"),
    (r"curl\s+.*--data-binary\s+@.*(?:id_rsa|\.aws|\.ssh)", 2, "exfiltration",
     "curl POST of SSH/AWS keys", "shell"),
    (r"curl\s+(?:-X\s+POST|--data|-d)\s+.*\.ssh", 2, "exfiltration",
     "curl POST of .ssh contents", "shell"),
    (r"curl\s+(?:-T|--upload-file)\s+", 1, "exfiltration",
     "curl file upload", "shell"),
    (r"scp\s+-r\s+.*(?:\.ssh|\.aws|\.gnupg)", 2, "exfiltration",
     "Recursive scp of credential dirs", "shell"),
    (r"rsync\s+.*(?:\.ssh|id_rsa|\.aws)", 2, "exfiltration",
     "rsync of credential dirs", "shell"),
    (r"\b(?:cat|less|head|tail)\s+[^\n]*(?:\.ssh/id_rsa|\.aws/credentials)", 2, "exfiltration",
     "Reading credential files", "shell"),
    (r"requests\.post\([^)]*files\s*=", 1, "exfiltration",
     "Python requests POST with file upload", "python"),
    (r"\bopen\s*\([^)]*(?:\.ssh|id_rsa|\.aws|\.gnupg|\.env|credentials|netrc|shadow)", 2, "exfiltration",
     "Opening sensitive credential file", "python"),
    (r"\bopen\s*\(\s*['\"]?(/etc/(?:passwd|shadow|sudoers))", 2, "exfiltration",
     "Opening /etc/passwd or shadow", "python"),
    (r"\bsendmail\b.*\b(?:id_rsa|\.env|credentials)", 2, "exfiltration",
     "Mail-based credential exfiltration", "shell"),
    (r"\bnc\s+[\w.-]+\s+\d+\s*<\s*[^\n]*(?:\.ssh|\.aws|\.env)", 2, "exfiltration",
     "Netcat file exfiltration", "shell"),

    # ── Persistence ──
    (r"crontab\s+(?:-[a-zA-Z]+\s+)*-[le]\b", 1, "persistence",
     "Crontab modification", "shell"),
    (r"/etc/cron\.\w+/", 1, "persistence",
     "Direct cron.d modification", "shell"),
    (r"/etc/systemd/system/[^\s]+\.service", 1, "persistence",
     "systemd service file", "*"),
    (r"systemctl\s+enable\s+", 1, "persistence",
     "systemd enable (persistence)", "shell"),
    (r"~/\.bashrc|~/\.zshrc|~/\.profile|~/\.bash_profile", 1, "persistence",
     "Shell startup file modification", "*"),
    (r"~/\.config/autostart/", 1, "persistence",
     "XDG autostart entry", "*"),
    (r"launchctl\s+load\s+", 1, "persistence",
     "macOS launchd persistence", "shell"),
    (r"Add-MpPreference\s+-ExclusionPath", 1, "persistence",
     "Windows Defender exclusion", "shell"),

    # ── Cryptominers ──
    (r"\bxmrig\b", 2, "cryptominer",
     "XMRig miner reference", "*"),
    (r"\bminerd\b", 2, "cryptominer",
     "minerd reference", "*"),
    (r"\bcryptonight\b", 2, "cryptominer",
     "CryptoNight algorithm", "*"),
    (r"\bstratum\+tcp://[\w.-]+:\d+", 2, "cryptominer",
     "Mining pool URL", "*"),
    (r"monero(?:ocean|hash)" , 1, "cryptominer",
     "Monero mining pool reference", "*"),
    (r"--cpu-priority\s+\d+\s+--donate-level", 1, "cryptominer",
     "XMRig donate-level flag (mining)", "*"),
    (r"wallet\.monero(?:ocean)?\.com", 1, "cryptominer",
     "MoneroOcean wallet reference", "*"),
    (r"\b(?:nicehash|hashcity|nanopool)\b", 1, "cryptominer",
     "Mining pool service reference", "*"),

    # ── Backdoors / privilege escalation ──
    (r"chmod\s+(\+?[0-7]*\s+)*\+?s\b", 2, "backdoor",
     "Setting SUID bit", "shell"),
    (r"chmod\s+\+?s\s+/bin/(?:ba)?sh", 2, "backdoor",
     "SUID shell", "shell"),
    (r"echo\s+[\w.-]+\s*\|\s*chpasswd", 2, "backdoor",
     "Adding user via chpasswd", "shell"),
    (r"useradd\s+.*-o\s+.*-u\s+0", 2, "backdoor",
     "Adding root UID 0 user", "shell"),
    (r"/etc/passwd.*\+", 1, "backdoor",
     "Modifying /etc/passwd", "shell"),
    (r"ssh-keyscan.*>>\s*[^\n]*\.ssh/authorized_keys", 2, "backdoor",
     "Injecting SSH authorized key", "shell"),
    (r"iptables\s+-F", 1, "backdoor",
     "Flushing firewall rules", "shell"),
    (r"ufw\s+disable", 1, "backdoor",
     "Disabling UFW firewall", "shell"),
    (r"setenforce\s+0", 1, "backdoor",
     "Disabling SELinux", "shell"),

    # ── Network downloaders ──
    (r"(?:curl|wget)\s+[^\n]*\|\s*(?:ba)?sh", 2, "download_exec",
     "Pipe-to-shell pattern (curl|bash)", "shell"),
    (r"(?:curl|wget)\s+[^\n]*\|\s*python[3]?", 2, "download_exec",
     "Pipe-to-python pattern", "shell"),
    (r"(?:curl|wget)\s+-O\s+/(?:tmp|var)/", 1, "download_exec",
     "Downloading to /tmp or /var", "shell"),
    (r"Invoke-WebRequest.*\|\s*IEX", 2, "download_exec",
     "PowerShell download-and-execute", "shell"),
    (r"iwr\s+.*\|\s*iex", 2, "download_exec",
     "PowerShell IWR|iex", "shell"),
    (r"bitsadmin\s+/transfer", 2, "download_exec",
     "Bitsadmin transfer", "shell"),
    (r"certutil\s+-urlcache\s+-split\s+-f", 2, "download_exec",
     "Certutil download (LOLBin)", "shell"),

    # ── Anti-forensics / log tampering ──
    (r"history\s+-c", 1, "anti_forensics",
     "Clearing bash history", "shell"),
    (r"unset\s+HISTFILE", 1, "anti_forensics",
     "Disabling history recording", "shell"),
    (r">\s*/var/log/(?:auth|syslog|secure)", 2, "anti_forensics",
     "Truncating system logs", "shell"),
    (r"rm\s+-rf\s+/(?:var/log|tmp/\.\w+|/\.cache)", 1, "anti_forensics",
     "Log/cache deletion", "shell"),
    (r"shred\s+", 1, "anti_forensics",
     "Secure file deletion (shred)", "shell"),
    (r"touch\s+-a\s+", 1, "anti_forensics",
     "Timestamp manipulation", "shell"),

    # ── Obfuscation indicators ──
    (r"['\"`][A-Za-z0-9+/]{80,}={0,2}['\"`]", 1, "obfuscation",
     "Long base64 string (>80 chars)", "*"),
    (r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}", 1, "obfuscation",
     "Long hex-encoded string", "*"),
    (r"String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){5,}", 1, "obfuscation",
     "String.fromCharCode with many args", "javascript"),
    (r"chr\s*\(\s*\d+\s*\)\s*\+\s*chr\s*\(\s*\d+\s*\)", 1, "obfuscation",
     "chr() concatenation obfuscation", "python"),
    (r"\\\\u00[0-9a-f]{2}", 1, "obfuscation",
     "Unicode escape obfuscation", "javascript"),
    (r"\\u00[0-9a-f]{2}(?:\\u00[0-9a-f]{2}){5,}", 1, "obfuscation",
     "Multiple Unicode escapes", "javascript"),

    # ── Prompt injection patterns (code comments too) ──
    (r"ignore\s+(?:all\s+)?previous\s+instructions", 2, "prompt_injection",
     "Prompt injection: ignore previous", "*"),
    (r"disregard\s+(?:all\s+)?prior\s+(?:rules|instructions)", 2, "prompt_injection",
     "Prompt injection: disregard prior", "*"),
    (r"you\s+are\s+now\s+(?:in\s+)?(?:DAN|developer|jailbreak)\s+mode", 2, "prompt_injection",
     "Prompt injection: jailbreak mode", "*"),
    (r"system:\s*you\s+are\s+", 1, "prompt_injection",
     "Embedded system prompt in content", "*"),
    (r"<\|im_start\|>system", 1, "prompt_injection",
     "ChatML system role marker", "*"),
    (r"<\|im_start\|>user.*<\|im_end\|>", 1, "prompt_injection",
     "Embedded chatML conversation", "*"),
    (r"<\|functioncalls\|>", 1, "prompt_injection",
     "Function call tag injection", "*"),
    (r"pretend\s+you\s+are\s+an?\s+AI\s+without\s+restrictions", 2, "prompt_injection",
     "Prompt injection: pretend no restrictions", "*"),
]


# ──────────────────────────────────────────────────────────────────────
# Entropy & string analysis
# ──────────────────────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def find_high_entropy_strings(content: str, min_len: int = 40) -> List[Tuple[str, float]]:
    """Find quoted/encoded strings with high entropy."""
    found = []
    for match in re.finditer(r"['\"`]([A-Za-z0-9+/=]{%d,})['\"`]" % min_len, content):
        s = match.group(1)
        ent = shannon_entropy(s)
        if ent > 5.5:
            found.append((s[:80], ent))
    return found


# ──────────────────────────────────────────────────────────────────────
# File-type detection
# ──────────────────────────────────────────────────────────────────────

EXT_LANG = {
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".py": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "javascript",
    ".php": "php",
    ".pl": "perl",
    ".rb": "ruby",
}


def detect_language(path: Path) -> str:
    return EXT_LANG.get(path.suffix.lower(), "*")


# ──────────────────────────────────────────────────────────────────────
# Core analysis
# ──────────────────────────────────────────────────────────────────────

def analyze_content(content: str, language: str = "*") -> Dict:
    findings = {
        "patterns": [],
        "high_entropy_strings": [],
        "url_count": 0,
        "ip_count": 0,
        "lines": content.count("\n") + 1,
        "bytes": len(content.encode("utf-8", errors="ignore")),
    }

    # Pattern matching
    for pattern, severity, category, desc, lang_filter in PATTERNS:
        if lang_filter != "*" and lang_filter != language:
            continue
        for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
            findings["patterns"].append({
                "severity": severity,
                "category": category,
                "description": desc,
                "match": match.group()[:100],
                "line": content[:match.start()].count("\n") + 1,
            })

    # High entropy strings
    findings["high_entropy_strings"] = [
        {"snippet": s, "entropy": round(e, 2)}
        for s, e in find_high_entropy_strings(content)
    ]

    # IOC counts
    findings["url_count"] = len(set(re.findall(r"https?://[^\s\"'<>]+", content)))
    findings["ip_count"] = len(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content)))

    return findings


def score_findings(findings: Dict) -> Tuple[str, int]:
    score = 0
    max_severity = 0
    for p in findings["patterns"]:
        score += p["severity"] * 15
        max_severity = max(max_severity, p["severity"])
    score += len(findings["high_entropy_strings"]) * 5
    score += min(findings["url_count"], 10) * 2
    score += min(findings["ip_count"], 10) * 3

    if score >= 50 or max_severity >= 2:
        return "MALICIOUS", 2
    elif score >= 15 or max_severity == 1:
        return "SUSPICIOUS", 1
    return "CLEAN", 0


# ──────────────────────────────────────────────────────────────────────
# Output
# ──────────────────────────────────────────────────────────────────────

class C:
    RED = "\033[31m"
    YELLOW = "\033[33m"
    GREEN = "\033[32m"
    CYAN = "\033[36m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def color_for_severity(sev: int) -> str:
    if sev == 2:
        return f"{C.RED}CRITICAL{C.RESET}"
    elif sev == 1:
        return f"{C.YELLOW}WARN{C.RESET}"
    return f"{C.GREEN}INFO{C.RESET}"


def print_findings(path: str, language: str, findings: Dict, verdict: str, risk: int) -> None:
    if risk == 2:
        verdict_str = f"{C.RED}🚨 {verdict}{C.RESET}"
    elif risk == 1:
        verdict_str = f"{C.YELLOW}⚠️  {verdict}{C.RESET}"
    else:
        verdict_str = f"{C.GREEN}✅ {verdict}{C.RESET}"

    print(f"\n{C.CYAN}{'═' * 70}{C.RESET}")
    print(f"  {verdict_str}  {path}")
    print(f"  Language: {language}  |  Lines: {findings['lines']:,}  |  Bytes: {findings['bytes']:,}")
    print(f"{C.CYAN}{'═' * 70}{C.RESET}")

    if not findings["patterns"] and not findings["high_entropy_strings"]:
        print(f"  {C.GREEN}No malicious patterns detected.{C.RESET}")
        return

    # Group patterns by category
    by_category: Dict[str, List[Dict]] = {}
    for p in findings["patterns"]:
        by_category.setdefault(p["category"], []).append(p)

    for category, items in sorted(by_category.items()):
        print(f"\n  {C.CYAN}▸ {category.replace('_', ' ').title()}{C.RESET} ({len(items)} match{'es' if len(items) != 1 else ''})")
        for item in items[:10]:
            sev = color_for_severity(item["severity"])
            print(f"      [{sev}] line {item['line']}: {item['description']}")
            print(f"           {C.DIM}{item['match']}{C.RESET}")
        if len(items) > 10:
            print(f"      {C.DIM}... and {len(items) - 10} more{C.RESET}")

    if findings["high_entropy_strings"]:
        print(f"\n  {C.YELLOW}▸ High-entropy strings ({len(findings['high_entropy_strings'])}){C.RESET}")
        for s in findings["high_entropy_strings"][:5]:
            print(f"      entropy={s['entropy']:.2f}: {C.DIM}{s['snippet']}{C.RESET}")


# ──────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Static code analysis")
    parser.add_argument("path", help="File or directory to analyze")
    parser.add_argument("--recursive", "-r", action="store_true")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--max-bytes", type=int, default=5_000_000,
                        help="Skip files larger than this (default 5MB)")
    args = parser.parse_args()

    target = Path(args.path)
    files_to_scan = []
    if target.is_file():
        files_to_scan.append(target)
    elif target.is_dir() and args.recursive:
        for ext in EXT_LANG.keys():
            files_to_scan.extend(target.rglob(f"*{ext}"))
    else:
        print(f"{C.RED}Error: {target} not found or not a directory (use --recursive){C.RESET}")
        sys.exit(2)

    all_results = []
    max_risk = 0
    for f in files_to_scan:
        try:
            if f.stat().st_size > args.max_bytes:
                continue
            content = f.read_text(errors="ignore")
        except Exception as e:
            continue

        lang = detect_language(f)
        findings = analyze_content(content, lang)
        verdict, risk = score_findings(findings)
        max_risk = max(max_risk, risk)

        result = {
            "path": str(f),
            "language": lang,
            "verdict": verdict,
            "risk": risk,
            "findings": findings,
        }
        all_results.append(result)

        if args.format == "text":
            print_findings(str(f), lang, findings, verdict, risk)

    if args.format == "json":
        # Trim large findings for JSON output
        for r in all_results:
            r["findings"]["patterns"] = r["findings"]["patterns"][:100]
        print(json.dumps(all_results, indent=2, default=str))

    sys.exit(max_risk)


if __name__ == "__main__":
    main()