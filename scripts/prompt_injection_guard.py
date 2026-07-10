#!/usr/bin/env python3
"""
agent-self-protection: prompt_injection_guard.py
Indirect prompt injection defense.

Scans text content (web pages, PDFs, fetched files, HTML) for:
- Direct injection: "ignore previous instructions", "you are now..."
- Indirect injection: markdown mimicking user commands, HTML with hidden instructions
- Smuggled tool calls: JSON inside text that looks like function calls
- Disguised channels: zero-width Unicode, bidi overrides
- Suspicious roleplay: "pretend you are...", "in this hypothetical..."
- Coercion patterns: urgency + authority

Usage:
    python3 prompt_injection_guard.py page.html
    python3 prompt_injection_guard.py --scan-text "ignore all instructions and..."
    cat fetched.md | python3 prompt_injection_guard.py -

Exit codes: 0=clean  1=suspicious  2=malicious
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List


class C:
    RED = "\033[31m"
    YELLOW = "\033[33m"
    GREEN = "\033[32m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def red(s): return f"{C.RED}{s}{C.RESET}"
def yellow(s): return f"{C.YELLOW}{s}{C.RESET}"
def green(s): return f"{C.GREEN}{s}{C.RESET}"
def cyan(s): return f"{C.CYAN}{s}{C.RESET}"


# ──────────────────────────────────────────────────────────────────────
# Patterns
# ──────────────────────────────────────────────────────────────────────

# Direct injection phrases (severity: critical)
DIRECT_PATTERNS = [
    (r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|rules?|prompts?|context)\b",
     "ignore previous instructions"),
    (r"\bdisregard\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|rules?|prompts?)\b",
     "disregard prior rules"),
    (r"\bforget\s+(?:everything|all)\s+(?:above|before|prior)\b",
     "forget everything above"),
    (r"\byou\s+are\s+now\s+(?:in\s+)?(?:DAN|developer|jailbreak|AIM|Chaos)\s+mode\b",
     "jailbreak mode activation"),
    (r"\bpretend\s+(?:you\s+)?(?:are|have)\s+(?:no|a\s+lack\s+of)\s+restrictions\b",
     "pretend no restrictions"),
    (r"\bdo\s+not\s+follow\s+(?:your|the)\s+(?:original|initial)\s+(?:instructions?|guidelines?)\b",
     "override original instructions"),
    (r"\bin\s+this\s+hypothetical\s+scenario[,.]\s+you\s+must\b",
     "hypothetical coercion"),
    (r"\b(?:the\s+)?user\s+(?:has\s+)?(?:already\s+)?(?:said|confirmed|approved)\s+(?:that\s+)?you\s+(?:must|should|will)\b",
     "fake user authorization"),
    (r"\b(?:act|behave)\s+as\s+(?:if\s+)?(?:you\s+)?(?:are|were)\s+(?:not\s+)?(?:an?\s+)?(?:AI|assistant|chatbot|language\s+model)\b",
     "identity override attempt"),
]

# Indirect injection — embedded system/role markers
ROLE_MARKER_PATTERNS = [
    (r"<\|im_start\|>\s*system", "ChatML system role marker"),
    (r"<\|im_end\|>", "ChatML end marker"),
    (r"<\|functioncalls\|>", "Function call tag injection"),
    (r"<\|tool_call\|>", "Tool call tag injection"),
    (r"\bsystem\s*:\s*you\s+are\b", "embedded 'system: you are' marker"),
    (r"\bHuman\s*:\s*(?:Assistant|AI)\s*:", "multi-turn conversation injection"),
    (r"\bAssistant\s*:\s*\[?(?:Sure|Of course|I'd be happy|Let me)\b",
     "model response pre-fill attempt"),
    (r"\{[\"']?(?:role|content)[\"']?\s*:\s*[\"'](?:system|assistant)[\"']",
     "JSON-style role injection"),
]

# Markdown / HTML smuggling
SMUGGLING_PATTERNS = [
    (r"<!--.*?ignore.*?(?:previous|instructions).*?-->", "HTML comment injection"),
    (r"\[[^\]]*\]\([^)]*javascript:[^)]*\)", "javascript: URI in markdown link"),
    (r"<[^>]*style\s*=\s*[\"'][^\"']*display\s*:\s*none[^\"']*[\"'][^>]*>",
     "display:none HTML injection"),
    (r"<[^>]*visibility\s*:\s*hidden[^>]*>", "visibility:hidden injection"),
]

# Disguised channels (zero-width Unicode, bidi overrides)
DISGUISED_CHANNEL_CHARS = {
    "\u200b": "zero-width space",
    "\u200c": "zero-width non-joiner",
    "\u200d": "zero-width joiner",
    "\u202a": "left-to-right embedding",
    "\u202b": "right-to-left embedding",
    "\u202c": "pop directional formatting",
    "\u202d": "left-to-right override",
    "\u202e": "right-to-left override",
    "\u2066": "left-to-right isolate",
    "\u2067": "right-to-left isolate",
    "\u2068": "first strong isolate",
    "\u2069": "pop directional isolate",
    "\ufeff": "zero-width no-break space (BOM)",
    "\u00ad": "soft hyphen",
}

# Coercion patterns (urgency + authority)
COERCION_PATTERNS = [
    (r"\b(?:urgent|immediate(?:ly)?|asap|right\s+now)\s*[:.,!].*?(?:do|run|execute|install)\b",
     "urgency-based coercion"),
    (r"\bthe\s+(?:CEO|CTO|admin|root|owner|boss|manager)\s+(?:said|ordered|requires|demands)\s+(?:you\s+)?(?:must|to)\b",
     "fake authority coercion"),
    (r"\byou\s+(?:will|must|have\s+to)\s+(?:do|execute|run|install)\s+(?:this|the\s+following)\s+(?:right\s+)?(?:now|immediately)?\b",
     "directive coercion"),
    (r"\b(?:if\s+you\s+)?(?:don't|refuse\s+to)\s+(?:do\s+)?(?:this|run\s+this|execute\s+this)[,.]\s+(?:you(?:'ll)?|\bi\s+will)\b",
     "threat-based coercion"),
]

# Function-call smuggling (smuggled JSON tool calls in plain text)
TOOL_CALL_SMUGGLING = [
    (r'\{[\s\n]*"(?:function|tool)_?(?:call|name)"[\s\n]*:', "smuggled function call JSON"),
    (r'<invoke\s+name\s*=', "smuggled <invoke> tag"),
    (r'\b(?:call|invoke|run)_tool\s*\(\s*[\'"]', "tool invocation pseudo-syntax"),
    (r'```json\s*\n\s*\{\s*"(?:action|tool|function)"\s*:', "JSON codeblock with action"),
]


# ──────────────────────────────────────────────────────────────────────
# Detection
# ──────────────────────────────────────────────────────────────────────

def scan_text(content: str) -> Dict:
    findings = {
        "direct": [],
        "role_markers": [],
        "smuggling": [],
        "disguised_channels": [],
        "coercion": [],
        "tool_call_smuggling": [],
        "verdict": "clean",
        "risk": 0,
    }

    # Direct patterns
    for pattern, label in DIRECT_PATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
            findings["direct"].append({
                "label": label,
                "match": match.group()[:80],
                "line": content[:match.start()].count("\n") + 1,
            })

    # Role markers
    for pattern, label in ROLE_MARKER_PATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            findings["role_markers"].append({
                "label": label,
                "match": match.group()[:80],
                "line": content[:match.start()].count("\n") + 1,
            })

    # Smuggling
    for pattern, label in SMUGGLING_PATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
            findings["smuggling"].append({
                "label": label,
                "match": match.group()[:80],
                "line": content[:match.start()].count("\n") + 1,
            })

    # Disguised channels
    for char, label in DISGUISED_CHANNEL_CHARS.items():
        count = content.count(char)
        if count > 0:
            findings["disguised_channels"].append({
                "label": label,
                "char": f"U+{ord(char):04X}",
                "count": count,
            })

    # Coercion
    for pattern, label in COERCION_PATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
            findings["coercion"].append({
                "label": label,
                "match": match.group()[:80],
                "line": content[:match.start()].count("\n") + 1,
            })

    # Tool call smuggling
    for pattern, label in TOOL_CALL_SMUGGLING:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            findings["tool_call_smuggling"].append({
                "label": label,
                "match": match.group()[:80],
                "line": content[:match.start()].count("\n") + 1,
            })

    # Scoring
    score = 0
    if findings["direct"]:
        score = max(score, 2)
    if findings["role_markers"]:
        score = max(score, 2)
    if findings["tool_call_smuggling"]:
        score = max(score, 2)
    if findings["smuggling"]:
        score = max(score, 2)
    if findings["coercion"]:
        score = max(score, 1)
    if findings["disguised_channels"]:
        score = max(score, 1)

    findings["risk"] = score
    findings["verdict"] = "malicious" if score >= 2 else ("suspicious" if score >= 1 else "clean")

    return findings


# ──────────────────────────────────────────────────────────────────────
# Output
# ──────────────────────────────────────────────────────────────────────

def print_findings(findings: Dict, source: str) -> int:
    risk = findings["risk"]
    if risk == 2:
        verdict_str = red(f"🚨 {findings['verdict'].upper()}")
    elif risk == 1:
        verdict_str = yellow(f"⚠️  {findings['verdict'].upper()}")
    else:
        verdict_str = green(f"✅ {findings['verdict'].upper()}")

    print(f"\n{C.CYAN}{'═' * 70}{C.RESET}")
    print(f"  {verdict_str}  {source}")
    print(f"{C.CYAN}{'═' * 70}{C.RESET}")

    if risk == 0:
        print(f"  {C.GREEN}No prompt-injection indicators found.{C.RESET}")
        return 0

    sections = [
        ("Direct Injection", "direct", red),
        ("Role Markers", "role_markers", red),
        ("Smuggling", "smuggling", red),
        ("Disguised Channels", "disguised_channels", yellow),
        ("Coercion", "coercion", yellow),
        ("Tool-Call Smuggling", "tool_call_smuggling", red),
    ]
    for title, key, color_fn in sections:
        items = findings.get(key, [])
        if items:
            print(f"\n  {color_fn('▸ ' + title)} ({len(items)} match{'es' if len(items) != 1 else ''})")
            for item in items[:10]:
                if "line" in item:
                    print(f"      line {item['line']}: {item['label']}")
                    if "match" in item:
                        print(f"           {C.DIM}{item['match']}{C.RESET}")
                elif "char" in item:
                    print(f"      {item['char']} ({item['label']}): {item['count']} occurrences")

    return risk


# ──────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Prompt-injection guard")
    parser.add_argument("path", nargs="?", help="File path or '-' for stdin")
    parser.add_argument("--scan-text", help="Scan inline text")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    max_risk = 0

    if args.scan_text:
        result = scan_text(args.scan_text)
        result["source"] = "<inline>"
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            max_risk = print_findings(result, "<inline text>")
    elif args.path == "-" or not args.path:
        content = sys.stdin.read()
        result = scan_text(content)
        result["source"] = "<stdin>"
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            max_risk = print_findings(result, "<stdin>")
    else:
        path = Path(args.path)
        if not path.exists():
            print(red(f"File not found: {path}"))
            sys.exit(2)
        try:
            content = path.read_text(errors="ignore")
        except Exception as e:
            print(red(f"Read error: {e}"))
            sys.exit(2)
        result = scan_text(content)
        result["source"] = str(path)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            max_risk = print_findings(result, str(path))

    sys.exit(max_risk)


if __name__ == "__main__":
    main()