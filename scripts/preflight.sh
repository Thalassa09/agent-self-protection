#!/usr/bin/env bash
# agent-self-protection: preflight.sh (v2.0)
# Layered pre-flight scan: orchestrates all engines based on input type.
# Usage:
#   bash preflight.sh <url>
#   bash preflight.sh <file>
#   bash preflight.sh npm <package>
#   bash preflight.sh pip <package>
#   bash preflight.sh --text "..."   (prompt-injection check)
#
# Exit codes:
#   0 = clean
#   1 = caution — review warnings
#   2 = high risk — ask user before proceeding

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RISK=0
WARN=()

red()    { printf '\033[31m%s\033[0m\n' "$1"; }
yellow() { printf '\033[33m%s\033[0m\n' "$1"; }
green()  { printf '\033[32m%s\033[0m\n' "$1"; }
cyan()   { printf '\033[36m%s\033[0m\n' "$1"; }

run_check() {
    local cmd="$1"
    local label="$2"
    cyan "▸ $label"
    local output
    local exit_code
    output=$(eval "$cmd" 2>&1)
    exit_code=$?
    # Always show output briefly
    echo "$output" | head -8 | sed 's/^/      /'
    if [ $exit_code -eq 2 ] || echo "$output" | grep -qE "(MALICIOUS|🚨|CRITICAL)"; then
        red "    ✗ THREAT DETECTED (exit $exit_code)"
        RISK=2
        WARN+=("$label: malicious")
    elif [ $exit_code -eq 1 ] || echo "$output" | grep -qE "(SUSPICIOUS|⚠|CAUTION|WARN)"; then
        yellow "    ! CAUTION (exit $exit_code)"
        [ $RISK -lt 1 ] && RISK=1
        WARN+=("$label: caution")
    elif [ $exit_code -gt 2 ]; then
        yellow "    ? Check failed (exit $exit_code)"
    else
        green "    ✓ Clean"
    fi
    echo ""
}

# ─── Dispatch by input type ───

if [ $# -eq 0 ]; then
    echo "Usage: $0 <url|file|npm <pkg>|pip <pkg>|--text <text>>"
    echo ""
    echo "Engines (run all that apply):"
    echo "  - reputation_check.py  (URLhaus, WHOIS, SSL)"
    echo "  - network_guard.py     (pastebin/webhook/ngrok/Tor)"
    echo "  - malware_scan.py      (ClamAV, YARA, entropy, magic bytes)"
    echo "  - static_analyzer.py   (reverse shells, eval, exfiltration, obfuscation)"
    echo "  - credential_scanner.py (API keys, tokens, private keys)"
    echo "  - prompt_injection_guard.py (indirect injection, zero-width, smuggling)"
    exit 1
fi

case "${1:-}" in
    npm)
        PKG="${2:?usage: $0 npm <package>}"
        cyan "═══ npm package: $PKG ═══"
        echo ""
        run_check "python3 '$SCRIPT_DIR/reputation_check.py' --npm '$PKG'" "npm Registry"
        run_check "python3 '$SCRIPT_DIR/reputation_check.py' --npm '$PKG' | grep -E 'install|postinstall'" "postinstall scripts"
        ;;
    pip)
        PKG="${2:?usage: $0 pip <package>}"
        cyan "═══ PyPI package: $PKG ═══"
        echo ""
        run_check "python3 '$SCRIPT_DIR/reputation_check.py' --pypi '$PKG'" "PyPI Registry"
        ;;
    --text)
        TEXT="${2:?usage: $0 --text <text>}"
        cyan "═══ Prompt-injection scan ═══"
        echo ""
        run_check "python3 '$SCRIPT_DIR/prompt_injection_guard.py' --scan-text '$TEXT'" "prompt injection"
        ;;
    http://*|https://*)
        URL="$1"
        cyan "═══ URL: $URL ═══"
        echo ""

        DOMAIN=$(echo "$URL" | awk -F/ '{print $3}' | sed 's/:.*//')
        [ -z "$DOMAIN" ] && DOMAIN="$URL"

        # Layer 1: URL reputation (simplified — just check URLhaus listing)
        run_check "python3 '$SCRIPT_DIR/reputation_check.py' --url '$URL' 2>&1 | grep -E 'VERDICT|URLhaus'" "URLhaus / reputation"

        # Layer 2: Network exfil
        run_check "python3 '$SCRIPT_DIR/network_guard.py' --check-url '$URL'" "Network exfiltration"

        # Layer 3: IP literal / homoglyph
        if echo "$DOMAIN" | grep -qP '^\d+\.\d+\.\d+\.\d+$'; then
            red "  [HIGH] IP literal in URL"
            RISK=2
        elif echo "$DOMAIN" | grep -qP 'xn--'; then
            red "  [HIGH] Punycode domain (homoglyph)"
            RISK=2
        fi
        ;;
    *)
        FILE="$1"
        if [ ! -f "$FILE" ]; then
            red "Error: file not found: $FILE"
            exit 2
        fi

        cyan "═══ File: $FILE ═══"
        echo ""

        # Layer 1: Malware scan
        run_check "python3 '$SCRIPT_DIR/malware_scan.py' '$FILE' 2>/dev/null" "Multi-engine malware scan"

        # Layer 2: Static analysis (if it's code)
        case "$FILE" in
            *.sh|*.bash|*.py|*.js|*.php)
                run_check "python3 '$SCRIPT_DIR/static_analyzer.py' '$FILE' 2>/dev/null" "Static code analysis"
                ;;
        esac

        # Layer 3: Credential scan
        run_check "python3 '$SCRIPT_DIR/credential_scanner.py' '$FILE' 2>/dev/null" "Credential leak scan"
        ;;
esac

# ─── Summary ───

cyan "═══ Summary ═══"
if [ $RISK -eq 0 ]; then
    green "✅ SAFE — no threats detected. Proceed with normal caution."
elif [ $RISK -eq 1 ]; then
    yellow "⚠️  CAUTION — review warnings before proceeding:"
    for w in "${WARN[@]}"; do echo "  - $w"; done
else
    red "🚨 HIGH RISK — ask user before proceeding:"
    for w in "${WARN[@]}"; do echo "  - $w"; done
    echo ""
    red "Recommendation: quarantine + manual audit before any execution."
fi
echo ""

# Exit with risk level so callers can branch on it
exit $RISK

exit $RISK