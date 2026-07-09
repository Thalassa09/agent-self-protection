#!/usr/bin/env python3
"""
agent-self-protection: quarantine.py
File isolation manager with SQLite tracking.

Usage:
    python3 quarantine.py <file> --reason "YARA: ReverseShell"
    python3 quarantine.py --list
    python3 quarantine.py --restore <id>
    python3 quarantine.py --purge
    python3 quarantine.py --purge --older-than 30
    python3 quarantine.py --init
"""

import argparse
import datetime
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional


QUARANTINE_DIR = Path("/var/quarantine/hermes-sp")
QUARANTINE_DB = QUARANTINE_DIR / "quarantine.db"


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
# DB helpers
# ──────────────────────────────────────────────────────────────────────

def get_conn() -> sqlite3.Connection:
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(QUARANTINE_DB))
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS quarantined (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_path TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            size INTEGER,
            reason TEXT,
            detection_engine TEXT,
            quarantined_at TEXT NOT NULL,
            restored_at TEXT,
            status TEXT DEFAULT 'quarantined'
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sha256 ON quarantined(sha256)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_status ON quarantined(status)")
    return conn


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ──────────────────────────────────────────────────────────────────────
# Operations
# ──────────────────────────────────────────────────────────────────────

def quarantine_file(path: Path, reason: str, engine: str = "manual") -> int:
    """Move file to quarantine, log to DB. Returns file_id."""
    if not path.exists():
        print(red(f"File not found: {path}"))
        return -1

    sha = sha256_file(path)
    size = path.stat().st_size
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

    conn = get_conn()
    cur = conn.cursor()

    # Check if already quarantined
    cur.execute("SELECT id FROM quarantined WHERE sha256 = ? AND status = 'quarantined'", (sha,))
    existing = cur.fetchone()
    if existing:
        print(yellow(f"⚠ File already quarantined as #{existing['id']} (same SHA-256)"))
        conn.close()
        return existing["id"]

    cur.execute(
        """INSERT INTO quarantined
           (original_path, sha256, size, reason, detection_engine, quarantined_at, status)
           VALUES (?,?,?,?,?,?,?)""",
        (str(path.absolute()), sha, size, reason, engine, ts, "quarantined"),
    )
    file_id = cur.lastrowid
    conn.commit()
    conn.close()

    # Move file
    dest = QUARANTINE_DIR / f"{file_id:06d}_{sha[:16]}_{path.name}"
    try:
        shutil.copy2(path, dest)
        # Lock down: read-only, no execute
        os.chmod(dest, 0o400)
        # Try to remove original (best-effort)
        try:
            path.unlink()
        except Exception:
            pass
    except Exception as e:
        print(red(f"Move failed: {e}"))
        return -1

    print(green(f"✅ Quarantined as #{file_id}"))
    print(f"   Original:  {path}")
    print(f"   SHA-256:   {C.DIM}{sha}{C.RESET}")
    print(f"   Location:  {dest}")
    print(f"   Reason:    {reason}")
    return file_id


def list_quarantined(status: str = "quarantined") -> List[Dict]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM quarantined WHERE status = ? ORDER BY quarantined_at DESC",
        (status,),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def restore_quarantined(file_id: int, dest_dir: Optional[Path] = None) -> bool:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM quarantined WHERE id = ?", (file_id,))
    row = cur.fetchone()
    if not row:
        print(red(f"#{file_id} not found"))
        conn.close()
        return False
    row = dict(row)
    if row["status"] == "restored":
        print(yellow(f"#{file_id} already restored at {row['restored_at']}"))
        conn.close()
        return False

    # Find file
    candidates = list(QUARANTINE_DIR.glob(f"{file_id:06d}_*"))
    if not candidates:
        print(red(f"Quarantined file for #{file_id} missing on disk"))
        conn.close()
        return False
    src = candidates[0]
    dest = (dest_dir or Path("/tmp/hermes-restore")) / src.name.split("_", 2)[-1]
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    os.chmod(dest, 0o644)

    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cur.execute(
        "UPDATE quarantined SET status = 'restored', restored_at = ? WHERE id = ?",
        (ts, file_id),
    )
    conn.commit()
    conn.close()

    print(green(f"✅ Restored #{file_id} → {dest}"))
    print(yellow(f"   ⚠ Manual review recommended — file was quarantined for: {row['reason']}"))
    return True


def purge_older_than(days: int = 30) -> int:
    """Delete quarantined entries older than N days."""
    cutoff = (
        datetime.datetime.now(datetime.timezone.utc) -
        datetime.timedelta(days=days)
    ).isoformat()

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, sha256 FROM quarantined WHERE quarantined_at < ? AND status = 'quarantined'", (cutoff,))
    rows = cur.fetchall()
    deleted = 0
    for row in rows:
        candidates = list(QUARANTINE_DIR.glob(f"{row['id']:06d}_*"))
        for f in candidates:
            try:
                f.unlink()
            except Exception:
                pass
        cur.execute("UPDATE quarantined SET status = 'purged' WHERE id = ?", (row["id"],))
        deleted += 1
    conn.commit()
    conn.close()
    return deleted


# ──────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="File quarantine manager")
    parser.add_argument("path", nargs="?", help="File to quarantine")
    parser.add_argument("--reason", default="manual",
                        help="Reason for quarantine (e.g. 'YARA: ReverseShell')")
    parser.add_argument("--engine", default="manual",
                        help="Detection engine that triggered quarantine")
    parser.add_argument("--list", action="store_true", help="List quarantined files")
    parser.add_argument("--list-status", default="quarantined",
                        choices=["quarantined", "restored", "purged", "all"])
    parser.add_argument("--restore", type=int, metavar="ID",
                        help="Restore file by ID")
    parser.add_argument("--restore-to", help="Destination directory for restore")
    parser.add_argument("--purge", action="store_true", help="Purge old quarantined files")
    parser.add_argument("--older-than", type=int, default=30,
                        help="Purge threshold in days (default 30)")
    parser.add_argument("--init", action="store_true", help="Initialize quarantine dir + DB")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.init:
        get_conn().close()
        print(green(f"✅ Initialized {QUARANTINE_DIR} + {QUARANTINE_DB}"))
        return

    if args.list:
        status = None if args.list_status == "all" else args.list_status
        items = list_quarantined(status) if status else list_quarantined()
        if not items:
            print(yellow("Quarantine empty."))
            return
        if args.json:
            print(json.dumps(items, indent=2))
        else:
            print(f"\n{cyan('═' * 90)}")
            print(f"  {'ID':<6} {'SHA-256':<20} {'Size':<10} {'Engine':<14} {'Quarantined':<22} Reason")
            print(cyan('═' * 90))
            for item in items:
                print(f"  {item['id']:<6} {item['sha256'][:16]+'...':<20} "
                      f"{item['size'] or 0:<10} {item['detection_engine']:<14} "
                      f"{item['quarantined_at'][:19]:<22} {item['reason'][:60]}")
            print(f"\n  Total: {len(items)}\n")
        return

    if args.restore:
        restore_quarantined(args.restore, Path(args.restore_to) if args.restore_to else None)
        return

    if args.purge:
        n = purge_older_than(args.older_than)
        print(green(f"✅ Purged {n} file(s) older than {args.older_than} days"))
        return

    if args.path:
        if not Path(args.path).exists():
            print(red(f"File not found: {args.path}"))
            sys.exit(2)
        file_id = quarantine_file(Path(args.path), args.reason, args.engine)
        sys.exit(0 if file_id > 0 else 1)

    parser.print_help()


if __name__ == "__main__":
    main()