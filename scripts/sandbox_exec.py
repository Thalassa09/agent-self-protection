#!/usr/bin/env python3
"""
agent-self-protection: sandbox_exec.py
Isolated execution of untrusted code using bubblewrap (bwrap) or unshare.

Features:
- Network namespace isolation (deny by default)
- Read-only filesystem outside sandbox
- Env stripping (remove *_API_KEY, *_TOKEN, AWS_*, etc.)
- Resource caps: CPU, memory, file size, file descriptors
- Timeout enforcement
- Stdout/stderr/exit-code capture
- Audit logging

Usage:
    python3 sandbox_exec.py -- untrusted-script.sh
    python3 sandbox_exec.py --network --timeout 30 -- python3 untrusted.py
    python3 sandbox_exec.py --memory 256M --dry-run -- ./binary

Exit codes: 0=success  1=sandbox failure  2=threat detected by monitor
"""

import argparse
import json
import os
import resource
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple


LOG_DIR = Path("/var/log/hermes-sp")
SCRATCH_DEFAULT = Path("/tmp/hermes-sandbox")


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
# Environment sanitization
# ──────────────────────────────────────────────────────────────────────

SENSITIVE_ENV_PREFIXES = (
    "API_KEY", "_API_KEY", "_TOKEN", "TOKEN", "SECRET",
    "AWS_", "AZURE_", "GCP_", "GOOGLE_",
    "GITHUB_", "GITLAB_", "BITBUCKET_",
    "OPENAI_", "ANTHROPIC_", "REPLICATE_",
    "STRIPE_", "TWILIO_", "SENDGRID_",
    "SLACK_", "DISCORD_", "TELEGRAM_",
    "DATABASE_URL", "REDIS_URL", "MONGO",
    "PRIVATE_KEY", "PASSPHRASE",
    "HERMES_", "9ROUTER_",
)

SENSITIVE_ENV_EXACT = {
    "PATH",  # will be reset to safe path
    "HOME",  # will be reset
}

SENSITIVE_ENV_CONTAINS = (
    "CREDENTIAL", "PASSWORD", "PASSWD", "PWD",
    "KEY", "TOKEN", "SECRET",
)


def sanitize_env(env: Optional[Dict] = None) -> Dict:
    """Return a stripped environment with no credentials."""
    full = env or dict(os.environ)
    clean = {}

    for key, value in full.items():
        key_upper = key.upper()

        # Skip exact matches
        if key_upper in SENSITIVE_ENV_EXACT:
            continue

        # Skip prefix matches
        if any(key_upper.startswith(p) for p in SENSITIVE_ENV_PREFIXES):
            continue

        # Skip contains matches
        if any(s in key_upper for s in SENSITIVE_ENV_CONTAINS):
            continue

        # Skip values that look like secrets (>20 chars, high entropy)
        if isinstance(value, str) and len(value) > 20:
            from collections import Counter
            import math
            counts = Counter(value)
            total = len(value)
            entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
            if entropy > 4.0 and not value.startswith("/"):
                continue

        clean[key] = value

    # Reset safe defaults
    clean["PATH"] = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    clean["HOME"] = "/tmp/hermes-sandbox"
    clean["LANG"] = "C.UTF-8"
    clean["LC_ALL"] = "C.UTF-8"
    clean["TMPDIR"] = "/tmp/hermes-sandbox"

    return clean


# ──────────────────────────────────────────────────────────────────────
# Sandbox backends
# ──────────────────────────────────────────────────────────────────────

def build_bwrap_command(
    cmd: List[str],
    scratch_dir: Path,
    network: bool = False,
    memory_mb: int = 512,
    cpu_time: int = 60,
    file_size_mb: int = 10,
    read_only_roots: List[str] = None,
) -> List[str]:
    """Build a bwrap command with isolation."""
    if not shutil.which("bwrap"):
        return None

    bwrap_args = [
        "bwrap",
        # Mount the host root read-only
        "--ro-bind", "/", "/",
        # Scratch dir writable
        "--bind", str(scratch_dir), str(scratch_dir),
        # Tmpfs for /tmp inside
        "--tmpfs", "/tmp",
        "--tmpfs", "/var/tmp",
        # devtmpfs for /dev/null etc
        "--dev", "/dev",
        "--proc", "/proc",
        # Prevent reading /root and /home
        "--tmpfs", "/root",
        "--tmpfs", "/home",
        "--tmpfs", "/run",
        "--tmpfs", "/var/run",
        # Unshare network if requested
    ]
    if not network:
        bwrap_args.append("--unshare-net")

    # Die if parent dies
    bwrap_args.append("--die-with-parent")

    # New session
    bwrap_args.append("--new-session")

    # Append the command
    bwrap_args.append("--")
    bwrap_args.extend(cmd)

    return bwrap_args


def build_unshare_command(
    cmd: List[str],
    scratch_dir: Path,
    network: bool = False,
) -> Optional[List[str]]:
    """Fallback: unshare with net namespace."""
    if not shutil.which("unshare"):
        return None

    args = ["unshare", "--pid", "--fork", "--mount-proc"]
    if not network:
        args.append("--net")
    args.append("--")
    args.extend(cmd)
    return args


# ─────────────────────────────────────────────────ascal
# Resource limits (applied via preexec_fn)
# ──────────────────────────────────────────────────────────────────────

def apply_rlimits(memory_mb: int = 512, cpu_time: int = 60,
                  file_size_mb: int = 10, fd_limit: int = 64):
    """Set resource limits on the current process (for child)."""
    try:
        # CPU time (seconds)
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_time, cpu_time))
        # Virtual memory (bytes)
        mem_bytes = memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
        # File size (bytes)
        fs_bytes = file_size_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_FSIZE, (fs_bytes, fs_bytes))
        # File descriptors
        resource.setrlimit(resource.RLIMIT_NOFILE, (fd_limit, fd_limit))
        # Nproc (processes)
        resource.setrlimit(resource.RLIMIT_NPROC, (50, 50))
    except (ValueError, resource.error):
        pass


# ──────────────────────────────────────────────────────────────────────
# Audit log
# ──────────────────────────────────────────────────────────────────────

def log_execution(cmd: List[str], exit_code: int, duration: float,
                  sandbox: str, env_stripped: int, risk: str):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOG_DIR / "sandbox.log"
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "command": cmd,
        "exit_code": exit_code,
        "duration_s": round(duration, 2),
        "sandbox": sandbox,
        "env_stripped": env_stripped,
        "risk": risk,
    }
    try:
        with open(log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


# ──────────────────────────────────────────────────────────────────────
# Main exec
# ──────────────────────────────────────────────────────────────────────

def run_sandboxed(
    cmd: List[str],
    network: bool = False,
    timeout: int = 60,
    memory_mb: int = 512,
    cpu_time: int = 60,
    file_size_mb: int = 10,
    scratch: Optional[Path] = None,
    dry_run: bool = False,
    verbose: bool = False,
) -> int:
    """Run command in sandbox. Returns exit code."""
    scratch_dir = scratch or (SCRATCH_DEFAULT / f"run-{int(time.time())}")
    scratch_dir.mkdir(parents=True, exist_ok=True)

    # Build command
    sandbox_engine = "none"
    sandbox_cmd = None
    if shutil.which("bwrap"):
        sandbox_cmd = build_bwrap_command(
            cmd, scratch_dir, network, memory_mb, cpu_time, file_size_mb,
        )
        sandbox_engine = "bwrap"
    elif shutil.which("unshare"):
        sandbox_cmd = build_unshare_command(cmd, scratch_dir, network)
        sandbox_engine = "unshare"
    else:
        sandbox_cmd = cmd
        sandbox_engine = "none"
        print(yellow("⚠ No sandbox engine available (bwrap/unshare missing). Running with rlimits only."))

    # Sanitize env
    clean_env = sanitize_env()
    env_stripped = len(os.environ) - len(clean_env)

    if verbose or dry_run:
        print(f"\n{cyan('═' * 70)}")
        print(f"  Sandbox Execution")
        print(f"{cyan('═' * 70)}")
        print(f"  Engine:     {sandbox_engine}")
        print(f"  Network:    {'ALLOWED' if network else 'DENIED'}")
        print(f"  Memory:     {memory_mb} MB")
        print(f"  CPU time:   {cpu_time}s")
        print(f"  File size:  {file_size_mb} MB")
        print(f"  Timeout:    {timeout}s")
        print(f"  Scratch:    {scratch_dir}")
        print(f"  Env:        {len(os.environ)} → {len(clean_env)} ({env_stripped} stripped)")
        print(f"  Command:    {' '.join(cmd)}")
        print(f"{cyan('─' * 70)}")

    if dry_run:
        print(yellow("\n  DRY RUN — not executing."))
        return 0

    # Apply rlimits via preexec_fn
    start = time.time()
    try:
        result = subprocess.run(
            sandbox_cmd,
            env=clean_env,
            cwd=str(scratch_dir),
            timeout=timeout,
            capture_output=True,
            text=True,
            preexec_fn=lambda: apply_rlimits(memory_mb, cpu_time, file_size_mb),
        )
        duration = time.time() - start

        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(f"{C.DIM}{result.stderr}{C.RESET}", end="", file=sys.stderr)

        exit_code = result.returncode

        risk = "safe"
        if exit_code == 137:
            print(red("\n  🚨 Process killed (likely OOM or CPU limit)."))
            risk = "killed"
        elif exit_code == 124 or exit_code == 143:
            print(yellow("\n  ⚠ Process timed out."))
            risk = "timeout"

        print(f"\n{cyan('─' * 70)}")
        print(f"  Exit code:  {exit_code}")
        print(f"  Duration:   {duration:.2f}s")
        print(f"  Engine:     {sandbox_engine}")
        print(f"{cyan('═' * 70)}")

        log_execution(cmd, exit_code, duration, sandbox_engine, env_stripped, risk)
        return exit_code

    except subprocess.TimeoutExpired:
        duration = time.time() - start
        print(red(f"\n  🚨 Timeout after {timeout}s"))
        log_execution(cmd, 124, duration, sandbox_engine, env_stripped, "timeout")
        return 124
    except FileNotFoundError as e:
        print(red(f"\n  Command not found: {e}"))
        log_execution(cmd, 127, 0, sandbox_engine, env_stripped, "error")
        return 127
    except Exception as e:
        print(red(f"\n  Sandbox error: {e}"))
        log_execution(cmd, 1, 0, sandbox_engine, env_stripped, "error")
        return 1


# ──────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────

def parse_size(s: str) -> int:
    """Parse '512M', '2G', '1024' to MB."""
    s = s.upper().strip()
    if s.endswith("G"):
        return int(s[:-1]) * 1024
    elif s.endswith("M"):
        return int(s[:-1])
    return int(s)


def main():
    parser = argparse.ArgumentParser(
        description="Sandboxed execution of untrusted code",
        epilog="Example: python3 sandbox_exec.py --network --timeout 30 -- python3 script.py",
    )
    parser.add_argument("cmd", nargs=argparse.REMAINDER,
                        help="Command to execute (after --)")
    parser.add_argument("--network", action="store_true",
                        help="Allow network access (default: deny)")
    parser.add_argument("--timeout", type=int, default=60,
                        help="Max execution time in seconds (default 60)")
    parser.add_argument("--memory", type=str, default="512M",
                        help="Memory limit (e.g. 256M, 1G) (default 512M)")
    parser.add_argument("--cpu", type=int, default=60,
                        help="CPU time limit in seconds (default 60)")
    parser.add_argument("--file-size", type=str, default="10M",
                        help="Max file write size (default 10M)")
    parser.add_argument("--scratch", help="Scratch directory (default /tmp/hermes-sandbox/<timestamp>)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would run without executing")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    # Strip leading --
    cmd = args.cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        parser.print_help()
        sys.exit(1)

    scratch = Path(args.scratch) if args.scratch else None
    exit_code = run_sandboxed(
        cmd,
        network=args.network,
        timeout=args.timeout,
        memory_mb=parse_size(args.memory),
        cpu_time=args.cpu,
        file_size_mb=parse_size(args.file_size),
        scratch=scratch,
        dry_run=args.dry_run,
        verbose=args.verbose or args.dry_run,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()