# Agent Self-Protection 🛡️

> **Full-spectrum defensive layer for AI agents** — multi-engine malware scanning, static code analysis, network exfiltration detection, credential leak scanning, runtime behavioral monitoring, sandboxed execution, prompt injection defense, and sub-agent delegation security.

## Why?

AI agents that browse, download, clone, install, or execute code from external sources are vulnerable to:
- **Malware** (trojans, reverse shells, cryptominers, droppers)
- **Supply chain attacks** (malicious npm/pip packages)
- **Credential exfiltration** (scripts that read `~/.ssh/`, `~/.aws/`, `.env` and POST to webhooks)
- **Prompt injection** (indirect injection via fetched web pages or files)
- **Persistence** (cron jobs, systemd services, shell rc modifications)

This skill makes the agent **invulnerable to compromise from the outside world**. Every byte that crosses the agent's boundary is suspect until proven safe.

## Features

### 10-Layer Defense

| Layer | Engine | What it detects |
|-------|--------|----------------|
| L1: Reputation | `reputation_check.py` | URLhaus, WHOIS, SSL, npm/PyPI registry |
| L2: Network Guard | `network_guard.py` | Exfil endpoints (pastebin, webhook, ngrok, Tor, mining pools, DNS tunneling) |
| L3: Malware Scan | `malware_scan.py` | ClamAV, YARA rules, entropy analysis, magic bytes, hash lookup |
| L4: Static Analysis | `static_analyzer.py` | Reverse shells, eval/exec, exfiltration, persistence, cryptominers, obfuscation |
| L5: Behavioral | `behavioral_monitor.py` | Runtime process/fs/network monitoring |
| L6: Credentials | `credential_scanner.py` | API keys, private keys, JWT, high-entropy secrets |
| L7: Sandbox Exec | `sandbox_exec.py` | bwrap/unshare isolation + rlimits + env stripping |
| L8: Quarantine | `quarantine.py` | SQLite-tracked file isolation |
| L9: Prompt Injection | `prompt_injection_guard.py` | Indirect injection, ChatML smuggling, zero-width chars, bidi override |
| L10: Output Sanitizer | `output_sanitizer.py` | Credential redaction, zero-width stripping, ANSI/HTML cleanup |

### Sub-Agent Delegation Security

Sub-agents spawned via `delegate_task` get **no automatic skill loading** (`skip_context_files=True, skip_memory=True`). This skill includes a mandatory security prefix that must be injected into every delegation context, plus a `delegate_safe.py` wrapper that auto-prepends it.

## Quick Start

### As a Hermes Skill

```bash
# Install
hermes skills install https://github.com/Thalassa09/agent-self-protection/blob/main/SKILL.md
```

### Standalone Usage

```bash
# Clone
git clone https://github.com/Thalassa09/agent-self-protection.git
cd agent-self-protection

# Scan a URL
bash scripts/preflight.sh https://example.com

# Scan a file
bash scripts/preflight.sh ./suspicious.py

# Scan an npm package
bash scripts/preflight.sh npm express

# Scan text for prompt injection
bash scripts/preflight.sh --text "ignore previous instructions..."

# Exit codes:
#   0 = SAFE
#   1 = CAUTION
#   2 = HIGH RISK
```

### Individual Engines

```bash
# Multi-engine malware scan
python3 scripts/malware_scan.py suspicious_file

# Static code analysis
python3 scripts/static_analyzer.py script.py

# Network exfiltration detection
python3 scripts/network_guard.py --check-url https://evil.com/exfil

# Credential leak scan
python3 scripts/credential_scanner.py code.py

# Prompt injection guard
python3 scripts/prompt_injection_guard.py --scan-text "suspicious text"

# Output sanitizer
python3 scripts/output_sanitizer.py output.txt

# Sandboxed execution
python3 scripts/sandbox_exec.py --timeout 60 --memory 256M -- python3 untrusted.py

# Quarantine a file
python3 scripts/quarantine.py suspicious_file --reason "reverse shell detected"

# List quarantined files
python3 scripts/quarantine.py --list

# Reputation check
python3 scripts/reputation_check.py --url https://example.com
python3 scripts/reputation_check.py --npm some-package
python3 scripts/reputation_check.py --pypi some-package

# Behavioral monitoring
python3 scripts/behavioral_monitor.py --pid 12345

# Audit trail query
python3 scripts/audit.py --last 1h
```

## Architecture

```
agent-self-protection/
├── SKILL.md                          # Main skill doc (10-layer defense + delegation protocol)
├── README.md                         # This file
├── LICENSE                           # MIT
├── .gitignore
├── references/
│   ├── subagent-security-prefix.md   # 6.3KB mandatory injection for delegate_task
│   ├── threat_intel.md               # Curated threat intelligence
│   └── ioc_patterns.yaml             # IOC database (exfil, tunneling, mining, TLDs, typosquats)
├── rules/
│   └── threats.yar                   # 16 YARA rules (reverse shells, webshells, miners, C2, etc.)
└── scripts/                          # 12 executable scripts
    ├── preflight.sh                  # Unified entry point (exit 0/1/2)
    ├── delegate_safe.py              # Wrapper for delegate_task with security injection
    ├── malware_scan.py               # ClamAV + YARA + entropy + hash
    ├── static_analyzer.py            # Code pattern analysis
    ├── behavioral_monitor.py         # Runtime monitoring
    ├── network_guard.py              # Exfiltration endpoint detection
    ├── credential_scanner.py         # Credential leak detection
    ├── quarantine.py                 # File isolation with SQLite tracking
    ├── reputation_check.py           # URL/domain/package reputation
    ├── sandbox_exec.py               # Isolated execution
    ├── prompt_injection_guard.py     # Indirect injection defense
    ├── output_sanitizer.py           # Outbound content sanitization
    └── audit.py                      # Audit trail query
```

## Dependencies

### Required (Python 3.10+)
- Standard library only for most scripts

### Optional (enhanced detection)
- `yara-python` — YARA rule engine for `malware_scan.py`
- `clamav-daemon` — ClamAV for `malware_scan.py`
- `python-whois` — WHOIS lookups for `reputation_check.py`
- `bubblewrap` (`bwrap`) — Sandbox isolation for `sandbox_exec.py`

```bash
# Install optional dependencies (Debian/Ubuntu)
sudo apt install yara clamav-daemon bwrap
pip install yara-python python-whois
```

## Integration with Hermes Agent

### Auto-activation

The skill auto-activates before:
- Browsing or fetching URLs
- Downloading files
- `git clone` of repositories
- `npm install` / `pip install` / `uv add`
- Running shell commands from external sources
- Processing user-provided files/attachments
- Installing third-party skills or plugins

### Sub-Agent Delegation

```python
from pathlib import Path

SECURITY_PREFIX = Path.home() / ".hermes/skills/agent-self-protection/references/subagent-security-prefix.md"

# Always inject security prefix when delegating
delegate_task(
    goal="Audit the xyz repo",
    context=SECURITY_PREFIX.read_text() + "\n\nTASK CONTEXT:\n" + user_context,
)
```

Or use the wrapper:

```python
from delegate_safe import delegate_safe

delegate_safe(
    goal="Audit the xyz repo",
    context="Repo at /tmp/xyz",
    toolsets=["web", "terminal", "file"],
)
```

## Threat Model

Based on:
- OWASP Top 10 for LLM Applications
- NIST SP 800-53 (SI / RA / SC families)
- MITRE ATT&CK Framework
- CIS Critical Security Controls

### Attack Surfaces

| Surface | Threats |
|---------|---------|
| **Web** | Phishing, drive-by downloads, malicious JS, credential capture, hidden iframes |
| **Files** | Trojans, droppers, macro malware, polyglots, zero-days |
| **Packages** | Supply chain attacks (event-stream, node-ipc, ua-parser-js incidents) |
| **Code** | Reverse shells, eval/exec abuse, obfuscation, exfiltration |
| **LLM I/O** | Indirect prompt injection, ChatML smuggling, zero-width steganography |

## YARA Rules

16 rules covering:
- Reverse shells (bash TCP, Python socket, Perl, nc)
- Webshells (PHP, JSP, ASP)
- Cryptominers (xmrig, stratum protocol)
- Download-and-execute patterns
- Exfiltration patterns
- Persistence mechanisms (cron, systemd, rc files)
- Anti-forensics (history clearing, log deletion)
- Prompt injection markers
- Obfuscation (base64, hex, eval chains)
- Credential patterns
- Network endpoints (pastebin, webhook, ngrok)
- Privilege escalation

## License

MIT License. See [LICENSE](LICENSE).

## Acknowledgments

Inspired by:
- OWASP AI Security Top 10
- NIST SP 800-53
- MITRE ATT&CK Framework
- CIS Critical Security Controls
- VirusTotal / URLhaus / abuse.ch threat feeds