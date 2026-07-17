#!/usr/bin/env python3
"""
agent-self-protection: prompt_injection_guard.py
Indirect prompt injection & conversation-integrity defense.

Scans text content (web pages, PDFs, fetched files, HTML, MCP tool
output) for:
- Direct injection: "ignore previous instructions", "you are now..."
- Indirect injection: markdown mimicking user commands, HTML with hidden instructions
- Smuggled tool calls: JSON inside text that looks like function calls
- Disguised channels: zero-width Unicode, bidi overrides
- Suspicious roleplay: "pretend you are...", "in this hypothetical..."
- Coercion patterns: urgency + authority
- Role confusion: fake [SYSTEM]/developer speaker tags, fabricated turn boundaries
- System-prompt extraction attempts: "repeat the text above", "print your instructions"
- HTML injection: <script>/<iframe>/event handlers/meta-refresh/base64 data: URIs
- Encoded payloads: base64/hex blobs that decode to injection content (recursive,
  depth-limited — catches "prompt laundering" through one or two layers of encoding)
- Unicode confusables: Latin words with Cyrillic/Greek look-alike letters mixed in,
  used to dodge plain-text regex while rendering identically to the reader

Usage:
    python3 prompt_injection_guard.py page.html
    python3 prompt_injection_guard.py --scan-text "ignore all instructions and..."
    cat fetched.md | python3 prompt_injection_guard.py -
    python3 prompt_injection_guard.py --scan-text "..." --max-decode-depth 3

Exit codes: 0=clean  1=suspicious  2=malicious
"""

import argparse
import base64
import json
import re
import sys
import unicodedata
from pathlib import Path
from typing import Dict, List, Optional


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

# System-prompt extraction attempts
SYSTEM_EXTRACTION_PATTERNS = [
    (r"\b(?:repeat|print|show|output|leak|expose|copy)(?:\s+(?:me|us|him|her))?\s+(?:the|your)?\s*(?:system\s+)?(?:prompt|instructions?|rules?|directives?)\b",
     "system prompt leak/leakage attempt"),
    (r"\b(?:repeat|output|show)\s+(?:the\s+)?(?:text|sentences|lines)\s+(?:above|before|prior)\b",
     "context replication request"),
    (r"\bwhat\s+(?:are\s+your|is\s+your)\s+(?:system\s+)?(?:instructions?|directives?|rules?)\b",
     "system prompt inquiry"),
]

# HTML injection patterns
HTML_INJECTION_PATTERNS = [
    (r"<script\b[^>]*>.*?</script>", "HTML script tag injection"),
    (r"<iframe\b[^>]*>", "HTML iframe injection"),
    (r"\bon[a-z]+\s*=\s*[\"'][^\"']*javascript:[^\"']*[\"']", "HTML event handler script"),
    (r"\bhref\s*=\s*[\"']\s*data:\s*text/html\s*;.*base64\s*,", "HTML base64 data link"),
    (r"<meta\b[^>]*http-equiv\s*=\s*[\"']refresh[\"']", "HTML meta refresh redirection"),
]


# ──────────────────────────────────────────────────────────────────────
# Unicode Confusables Detection
# ──────────────────────────────────────────────────────────────────────

# Mapping of lookalike letters from different script blocks
# (Cyrillic/Greek letters commonly used to spoof Latin characters)
LOOKALIKES = {
    'а': 'a', 'е': 'e', 'і': 'i', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
    'ѕ': 's', 'ԁ': 'd', 'һ': 'h', 'ј': 'j', 'Ӏ': 'l', 'ո': 'n', '𝖻': 'b', '𝗄': 'k',
    'α': 'a', 'ο': 'o', 'ρ': 'p', 'ϲ': 'c', 'υ': 'y', 'χ': 'x', 'т': 't', 'м': 'm', 
    'і': 'i', 'е': 'e'
}

SUSPICIOUS_LATIN_KEYWORDS = ["system", "ignore", "instruction", "prompt", "rule", "jailbreak", "dan"]

def scan_unicode_confusables(content: str) -> List[Dict]:
    findings = []
    # Tokenize content by simple word boundaries
    words = re.findall(r"\b\w+\b", content)
    for word in words:
        # Check if the word is a mixture of Latin and other scripts (Cyrillic/Greek lookalikes)
        has_latin = False
        has_non_latin_lookalike = False
        normalized_chars = []
        
        for char in word:
            name = unicodedata.name(char, "")
            if "LATIN" in name:
                has_latin = True
                normalized_chars.append(char.lower())
            elif char in LOOKALIKES:
                has_non_latin_lookalike = True
                normalized_chars.append(LOOKALIKES[char])
            else:
                normalized_chars.append(char.lower())
                
        # If it's a mixed-script word containing lookalikes
        if has_latin and has_non_latin_lookalike:
            normalized_word = "".join(normalized_chars)
            # Check if it normalizes to one of our critical keywords
            for kw in SUSPICIOUS_LATIN_KEYWORDS:
                if kw in normalized_word:
                    findings.append({
                        "label": "Unicode confusable homoglyph spoofing",
                        "match": word,
                        "normalized": normalized_word,
                        "keyword_targeted": kw
                    })
                    break
    return findings


# ──────────────────────────────────────────────────────────────────────
# Recursive Encoded Payloads Decoder
# ──────────────────────────────────────────────────────────────────────

# Regex pattern matching potential base64 strings (minimum 16 chars long)
BASE64_PATTERN = re.compile(r"\b[A-Za-z0-9+/]{16,}=*\b")
# Regex pattern matching hex strings (minimum 32 chars long)
HEX_PATTERN = re.compile(r"\b[0-9a-fA-F]{32,}\b")

def scan_encoded_payloads(content: str, current_depth: int = 1, max_depth: int = 2) -> List[Dict]:
    findings = []
    if current_depth > max_depth:
        return findings

    # Scan for Base64 blobs
    for match in BASE64_PATTERN.finditer(content):
        blob = match.group()
        try:
            # Pad if necessary
            missing_padding = len(blob) % 4
            if missing_padding:
                padded_blob = blob + '=' * (4 - missing_padding)
            else:
                padded_blob = blob
                
            decoded = base64.b64decode(padded_blob, validate=True).decode("utf-8", errors="ignore")
            # If successfully decoded into a string with alphanumeric tokens
            if len(decoded.strip()) > 8 and any(c.isalnum() for c in decoded):
                # Run recursive check on the decoded content
                nested_findings = scan_text_internal(decoded, current_depth + 1, max_depth)
                if nested_findings["risk"] > 0:
                    findings.append({
                        "label": f"Base64-encoded payload (depth {current_depth})",
                        "match": blob[:80],
                        "decoded_preview": decoded[:120].strip().replace("\n", " "),
                        "nested_risk": nested_findings["risk"]
                    })
        except Exception:
            pass

    # Scan for Hex blobs
    for match in HEX_PATTERN.finditer(content):
        blob = match.group()
        try:
            decoded = bytes.fromhex(blob).decode("utf-8", errors="ignore")
            if len(decoded.strip()) > 8 and any(c.isalnum() for c in decoded):
                nested_findings = scan_text_internal(decoded, current_depth + 1, max_depth)
                if nested_findings["risk"] > 0:
                    findings.append({
                        "label": f"Hex-encoded payload (depth {current_depth})",
                        "match": blob[:80],
                        "decoded_preview": decoded[:120].strip().replace("\n", " "),
                        "nested_risk": nested_findings["risk"]
                    })
        except Exception:
            pass

    return findings


# ──────────────────────────────────────────────────────────────────────
# Unified Scan Logic
# ──────────────────────────────────────────────────────────────────────

def scan_text_internal(content: str, current_depth: int = 1, max_depth: int = 2) -> Dict:
    findings = {
        "direct": [],
        "role_markers": [],
        "smuggling": [],
        "disguised_channels": [],
        "coercion": [],
        "tool_call_smuggling": [],
        "system_extraction": [],
        "html_injection": [],
        "unicode_confusables": [],
        "encoded_payloads": [],
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

    # System extraction
    for pattern, label in SYSTEM_EXTRACTION_PATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
            findings["system_extraction"].append({
                "label": label,
                "match": match.group()[:80],
                "line": content[:match.start()].count("\n") + 1,
            })

    # HTML Injection
    for pattern, label in HTML_INJECTION_PATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
            findings["html_injection"].append({
                "label": label,
                "match": match.group()[:80],
                "line": content[:match.start()].count("\n") + 1,
            })

    # Unicode Confusables
    findings["unicode_confusables"] = scan_unicode_confusables(content)

    # Recursive Encoded Payloads
    findings["encoded_payloads"] = scan_encoded_payloads(content, current_depth, max_depth)

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
    if findings["system_extraction"]:
        score = max(score, 2)
    if findings["html_injection"]:
        score = max(score, 2)
    if findings["unicode_confusables"]:
        score = max(score, 2)
    if any(item["nested_risk"] >= 2 for item in findings["encoded_payloads"]):
        score = max(score, 2)
        
    if findings["coercion"]:
        score = max(score, 1)
    if findings["disguised_channels"]:
        score = max(score, 1)
    if any(item["nested_risk"] == 1 for item in findings["encoded_payloads"]):
        score = max(score, 1)

    findings["risk"] = score
    findings["verdict"] = "malicious" if score >= 2 else ("suspicious" if score >= 1 else "clean")

    return findings


def scan_text(content: str, max_depth: int = 2) -> Dict:
    return scan_text_internal(content, current_depth=1, max_depth=max_depth)


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
        ("System-Prompt Extraction", "system_extraction", red),
        ("HTML Injection", "html_injection", red),
        ("Unicode Confusables", "unicode_confusables", red),
        ("Encoded Payloads", "encoded_payloads", red),
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
                elif "normalized" in item:
                    print(f"      homoglyph target: {item['keyword_targeted']}")
                    print(f"           original:   {C.BOLD}{item['match']}{C.RESET}")
                    print(f"           normalized: {item['normalized']}")
                elif "decoded_preview" in item:
                    print(f"      type: {item['label']}")
                    print(f"           encoded: {C.DIM}{item['match'][:50]}...{C.RESET}")
                    print(f"           decoded: {C.BOLD}{item['decoded_preview'][:80]}...{C.RESET}")

    return risk


# ──────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Prompt-injection guard (Upgraded)")
    parser.add_argument("path", nargs="?", help="File path or '-' for stdin")
    parser.add_argument("--scan-text", help="Scan inline text")
    parser.add_argument("--max-decode-depth", type=int, default=2, help="Max depth for recursive decoding scan")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    max_risk = 0

    if args.scan_text:
        result = scan_text(args.scan_text, max_depth=args.max_decode_depth)
        result["source"] = "<inline>"
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            max_risk = print_findings(result, "<inline text>")
    elif args.path == "-" or not args.path:
        content = sys.stdin.read()
        result = scan_text(content, max_depth=args.max_decode_depth)
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
        result = scan_text(content, max_depth=args.max_decode_depth)
        result["source"] = str(path)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            max_risk = print_findings(result, str(path))

    sys.exit(max_risk)


if __name__ == "__main__":
    main()
