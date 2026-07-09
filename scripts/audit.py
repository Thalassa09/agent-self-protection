#!/usr/bin/env python3
"""
agent-self-protection: audit.py
Query the audit trail for agent security events.

Usage:
    python3 audit.py --today
    python3 audit.py --threats-only
    python3 audit.py --export json
    python3 audit.py --last 24h
"""

import argparse
import datetime
import json
import sys
from pathlib import Path
from typing import Dict, List


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


def load_events(log_file: Path, since: datetime.datetime = None) -> List[Dict]:
    if not log_file.exists():
        return []
    events = []
    for line in log_file.read_text(errors="ignore").splitlines():
        try:
            event = json.loads(line)
            if since:
                ts = datetime.datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
                if ts < since:
                    continue
            events.append(event)
        except Exception:
            continue
    return events


def main():
    parser = argparse.ArgumentParser(description="Audit trail query")
    parser.add_argument("--today", action="store_true", help="Events from today")
    parser.add_argument("--last", help="Last duration: e.g. 24h, 7d, 1h")
    parser.add_argument("--threats-only", action="store_true", help="Only malicious/suspicious")
    parser.add_argument("--export", choices=["json"], help="Export format")
    parser.add_argument("--limit", type=int, default=50)
    args = parser.parse_args()

    if not LOG_DIR.exists():
        print(yellow(f"Log dir not found: {LOG_DIR}"))
        return

    since = None
    if args.today:
        since = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0)
    elif args.last:
        n = int(args.last[:-1])
        unit = args.last[-1]
        delta = {"h": datetime.timedelta(hours=n),
                "d": datetime.timedelta(days=n),
                "m": datetime.timedelta(minutes=n)}.get(unit)
        if delta:
            since = datetime.datetime.now(datetime.timezone.utc) - delta

    all_events = []
    for log_file in LOG_DIR.glob("*.log"):
        all_events.extend(load_events(log_file, since))

    # Sort by timestamp desc
    all_events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)

    if args.threats_only:
        all_events = [e for e in all_events
                     if "severity" in e and e["severity"] >= 1
                     or "risk" in e and e["risk"] in ("malicious", "suspicious")
                     or "issue" in e and "kill" in str(e.get("issue", "")).lower()]

    all_events = all_events[:args.limit]

    if args.export == "json":
        print(json.dumps(all_events, indent=2))
    else:
        print(f"\n{cyan('═' * 70)}")
        print(f"  Audit Trail — {len(all_events)} event(s)")
        print(f"{cyan('═' * 70)}\n")
        if not all_events:
            print(f"  {green('No events found.')}")
            return
        for event in all_events:
            ts = event.get("timestamp", "?")[:19]
            print(f"  {C.DIM}{ts}{C.RESET}")
            for k, v in event.items():
                if k == "timestamp":
                    continue
                v_str = str(v)[:120]
                print(f"    {k}: {v_str}")
            print()


if __name__ == "__main__":
    main()