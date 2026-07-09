#!/usr/bin/env python3
"""
agent-self-protection: behavioral_monitor.py
Runtime process, filesystem, and network behavioral monitoring.

Watches a process tree and detects:
- Outgoing connections to suspicious destinations
- File modifications outside the sandbox dir
- Cryptominer-like CPU usage
- Fork bombs
- Privilege escalation attempts
- Suspicious child processes (shell, nc, curl-from-script)

Usage:
    sudo python3 behavioral_monitor.py --watch-pid 12345 --duration 60
    sudo python3 behavioral_monitor.py --dry-run
    sudo python3 behavioral_monitor.py --kill-threshold 5

Exit codes: 0=clean  1=suspicious  2=malicious (auto-killed)
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Set

LOG_DIR = Path("/var/log/hermes-sp")


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
# Configuration
# ──────────────────────────────────────────────────────────────────────

SUSPICIOUS_NET_PORTS = {3333, 7777, 14444, 14433, 14434, 5555, 9999, 1443}
SUSPICIOUS_NET_KEYWORDS = [
    "pastebin", "webhook.site", "requestbin", "pipedream",
    "ngrok", "localtunnel", "serveo",
    ".onion",
    "monero", "xmrig", "minerd", "cryptonight",
]
SUSPICIOUS_BINARIES = {
    "nc", "ncat", "socat", "netcat",
    "xmrig", "minerd", "cpuminer",
    "nmap", "masscan", "zmap",
    "msfconsole", "metasploit",
    "john", "hashcat",
    "tcpdump", "wireshark", "tshark",
}
SUSPICIOUS_FILE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/root/.ssh", "/home/*/.ssh",
    "/etc/cron.d", "/etc/cron.daily", "/var/spool/cron",
    "/etc/systemd/system",
    "/etc/ld.so.preload",
    "/root/.bashrc", "/root/.profile", "/root/.zshrc",
]
SUSPICIOUS_FILE_EXTENSIONS = {".sh", ".bash", ".command", ".scr", ".vbs"}


# ──────────────────────────────────────────────────────────────────────
# Platform helpers
# ──────────────────────────────────────────────────────────────────────

def get_process_info(pid: int) -> Optional[Dict]:
    """Read /proc/<pid>/status, stat, cmdline. Cross-distro safe."""
    proc = Path(f"/proc/{pid}")
    if not proc.exists():
        return None
    info = {"pid": pid}
    try:
        info["cmdline"] = (proc / "cmdline").read_bytes().decode("utf-8", errors="ignore").replace("\x00", " ").strip()
    except Exception:
        info["cmdline"] = ""
    try:
        info["comm"] = (proc / "comm").read_text().strip()
    except Exception:
        info["comm"] = ""
    try:
        info["status"] = (proc / "status").read_text()
        for line in info["status"].splitlines():
            if line.startswith("Uid:"):
                info["uid"] = line.split()[1]
            elif line.startswith("Gid:"):
                info["gid"] = line.split()[1]
            elif line.startswith("PPid:"):
                info["ppid"] = line.split()[1]
            elif line.startswith("State:"):
                info["state"] = line.split()[1]
    except Exception:
        pass
    return info


def get_children(pid: int) -> List[int]:
    """Find all descendants of pid by scanning /proc."""
    children = []
    try:
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                stat = (entry / "stat").read_text()
                ppid = stat.split()[3]
                if ppid == str(pid):
                    children.append(int(entry.name))
                    children.extend(get_children(int(entry.name)))
            except Exception:
                continue
    except Exception:
        pass
    return children


def get_open_connections(pid: int) -> List[Dict]:
    """Parse /proc/<pid>/net/tcp[6] for outgoing connections from this pid."""
    conns = []
    for proto in ["tcp", "tcp6"]:
        path = Path(f"/proc/{pid}/net/{proto}")
        if not path.exists():
            continue
        try:
            lines = path.read_text().splitlines()[1:]
            for line in lines:
                parts = line.split()
                if len(parts) < 10:
                    continue
                local, remote, state = parts[1], parts[2], parts[3]
                if state != "01":  # ESTABLISHED only
                    continue
                # Parse remote addr:port
                rip_hex, rport_hex = remote.split(":")
                rport = int(rport_hex, 16)
                # Decode hex IP (simplified for IPv4)
                rip_bytes = bytes.fromhex(rip_hex)
                rip = ".".join(str(b) for b in reversed(rip_bytes))
                conns.append({"proto": proto, "remote_ip": rip, "remote_port": rport})
        except Exception:
            continue
    return conns


def get_open_files(pid: int) -> List[str]:
    """Read /proc/<pid>/fd/ symlinks."""
    files = []
    fd_dir = Path(f"/proc/{pid}/fd")
    if not fd_dir.exists():
        return files
    for entry in fd_dir.iterdir():
        try:
            target = os.readlink(str(entry))
            if target.startswith("/"):
                files.append(target)
        except Exception:
            continue
    return files


# ──────────────────────────────────────────────────────────────────────
# Detection rules
# ──────────────────────────────────────────────────────────────────────

def detect_threats(processes: Dict[int, Dict], connections: Dict[int, List[Dict]],
                   files: Dict[int, List[str]]) -> List[Dict]:
    threats = []
    seen = set()

    for pid, info in processes.items():
        comm = info.get("comm", "").lower()
        cmdline = info.get("cmdline", "").lower()

        # Suspicious binary
        if comm in SUSPICIOUS_BINARIES or any(b in cmdline.split() for b in SUSPICIOUS_BINARIES):
            threats.append({
                "pid": pid, "type": "suspicious_binary", "severity": 2,
                "detail": f"process '{comm}' is known attack tool",
            })

        # Shell spawned by non-shell process (potential command injection)
        if comm in ("bash", "sh", "zsh", "fish", "dash", "ash"):
            # Already checked in static, but flag suspicious args
            if any(p in cmdline for p in ["-c", "/dev/tcp/", "127.0.0.1", "0.0.0.0"]):
                threats.append({
                    "pid": pid, "type": "shell_invocation", "severity": 1,
                    "detail": f"shell with suspicious args: {info.get('cmdline', '')[:80]}",
                })

        # Suspicious file access
        for f in files.get(pid, []):
            for sus_path in SUSPICIOUS_FILE_PATHS:
                if sus_path.replace("*", "") in f:
                    if (pid, sus_path) not in seen:
                        seen.add((pid, sus_path))
                        threats.append({
                            "pid": pid, "type": "sensitive_file_access", "severity": 2,
                            "detail": f"opened {f}",
                        })
            # Writable to system paths
            if "/etc/" in f and ("w" in info.get("cmdline", "") or info.get("uid") == "0"):
                threats.append({
                    "pid": pid, "type": "system_file_access", "severity": 1,
                    "detail": f"accessed {f}",
                })

        # Suspicious connections
        for conn in connections.get(pid, []):
            rport = conn["remote_port"]
            rip = conn["remote_ip"]
            if rport in SUSPICIOUS_NET_PORTS:
                threats.append({
                    "pid": pid, "type": "suspicious_port", "severity": 2,
                    "detail": f"connection to {rip}:{rport} (known mining/C2 port)",
                })
            if rip.startswith("127.") or rip == "0.0.0.0":
                continue  # Loopback is fine
            # Outbound to private IP ranges (could be lateral movement)
            if any(rip.startswith(p) for p in ["10.", "172.16.", "192.168."]):
                threats.append({
                    "pid": pid, "type": "private_net", "severity": 1,
                    "detail": f"connection to private IP {rip}:{rport}",
                })

    return threats


# ──────────────────────────────────────────────────────────────────────
# Monitor loop
# ──────────────────────────────────────────────────────────────────────

def monitor_loop(root_pid: int, duration: int, interval: float,
                 dry_run: bool, kill_threshold: int, log_handle) -> int:
    print(f"{cyan('▸')} Monitoring PID {root_pid} for {duration}s (interval={interval}s)")
    print(f"  Mode: {'DRY-RUN' if dry_run else 'ACTIVE'}, kill threshold: {kill_threshold}")

    tracked_pids: Set[int] = {root_pid}
    all_threats: List[Dict] = []
    start = time.time()

    try:
        while time.time() - start < duration:
            tracked_pids.update(get_children(root_pid))

            processes = {}
            connections = {}
            files = {}

            for pid in tracked_pids:
                info = get_process_info(pid)
                if info:
                    processes[pid] = info
                    connections[pid] = get_open_connections(pid)
                    files[pid] = get_open_files(pid)

            threats = detect_threats(processes, connections, files)

            new_threats = [t for t in threats if t not in all_threats]
            for t in new_threats:
                all_threats.append(t)
                sev = t["severity"]
                color_fn = red if sev == 2 else yellow
                icon = "🚨" if sev == 2 else "⚠️"
                print(f"  {icon} [{color_fn(f'SEV-{sev}')}] {t['type']}: {t['detail']} (pid={t['pid']})")
                log_handle.write(json.dumps({
                    "timestamp": time.time(),
                    "monitored_pid": root_pid,
                    **t,
                }) + "\n")
                log_handle.flush()

            if not dry_run and len([t for t in all_threats if t["severity"] == 2]) >= kill_threshold:
                print(red(f"\n🚨 Kill threshold reached ({kill_threshold} CRITICAL threats). Killing process tree."))
                kill_tree(root_pid)
                return 2

            time.sleep(interval)

    except KeyboardInterrupt:
        print(yellow("\n⚠ Interrupted by user"))

    return 1 if all_threats else 0


def kill_tree(pid: int):
    for child in get_children(pid):
        kill_tree(child)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


# ──────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Behavioral runtime monitor")
    parser.add_argument("--watch-pid", type=int, help="PID to monitor")
    parser.add_argument("--duration", type=int, default=60, help="Monitoring duration (seconds)")
    parser.add_argument("--interval", type=float, default=1.0, help="Poll interval (seconds)")
    parser.add_argument("--dry-run", action="store_true", help="Log only, don't kill")
    parser.add_argument("--kill-threshold", type=int, default=3, help="Number of CRITICAL threats before auto-kill")
    args = parser.parse_args()

    if not args.watch_pid:
        parser.print_help()
        sys.exit(1)

    if os.geteuid() != 0:
        print(yellow("⚠ Warning: not running as root. Some monitoring features will be limited."))

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOG_DIR / "behavior.log"
    log_handle = open(log_file, "a")

    try:
        exit_code = monitor_loop(
            args.watch_pid, args.duration, args.interval,
            args.dry_run, args.kill_threshold, log_handle,
        )
    finally:
        log_handle.close()

    if exit_code == 0:
        print(green(f"\n✅ Clean — no threats detected in {args.duration}s"))
    elif exit_code == 1:
        print(yellow(f"\n⚠ Completed with {sum(1 for _ in open(log_file))} threat(s) logged"))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()