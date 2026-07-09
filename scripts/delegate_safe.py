#!/usr/bin/env python3
"""
agent-self-protection: delegate_safe.py
Drop-in wrapper around delegate_task that auto-prepends the sub-agent
security prefix to the context. Makes skill self-protection apply to
every sub-agent by default.

Usage (from agent code):
    from delegate_safe import delegate_safe

    delegate_safe(
        goal="Audit the xyz repo",
        context="Repo at /tmp/xyz",
        toolsets=["web", "terminal", "file"],
    )

Usage (CLI):
    python3 delegate_safe.py --goal "..." --context "..." [--dry-run]

The wrapper:
1. Loads ~/.hermes/skills/agent-self-protection/references/subagent-security-prefix.md
2. Prepends it to the user's context
3. Calls delegate_task with the augmented context

If the prefix file is missing, the wrapper REFUSES to delegate (fail-safe).
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


PREFIX_PATH = Path.home() / ".hermes/skills/agent-self-protection/references/subagent-security-prefix.md"


def load_security_prefix() -> str:
    """Load the mandatory sub-agent security prefix. Refuse if missing."""
    if not PREFIX_PATH.exists():
        print(
            f"❌ SECURITY PREFIX MISSING: {PREFIX_PATH}\n"
            f"   Refusing to delegate without agent-self-protection.\n"
            f"   Run: claude skill install /root/.hermes/skills/agent-self-protection\n",
            file=sys.stderr,
        )
        sys.exit(2)

    content = PREFIX_PATH.read_text()
    if len(content) < 500:
        print(
            f"⚠️  Security prefix suspiciously short ({len(content)} bytes).\n"
            f"   Investigate: {PREFIX_PATH}",
            file=sys.stderr,
        )
    return content


def build_context(user_context: Optional[str], security_prefix: str) -> str:
    """Build the augmented context with security prefix prepended."""
    parts = [
        "=" * 70,
        "MANDATORY SECURITY PROTOCOL (read first, obey always)",
        "=" * 70,
        "",
        security_prefix,
        "",
        "=" * 70,
        "TASK-SPECIFIC CONTEXT",
        "=" * 70,
        "",
    ]
    if user_context:
        parts.append(user_context)
    else:
        parts.append("(no additional context provided)")
    return "\n".join(parts)


def delegate_safe(
    goal: str,
    context: Optional[str] = None,
    toolsets: Optional[List[str]] = None,
    role: str = "leaf",
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    Delegate a task to a sub-agent WITH mandatory security prefix injection.

    Args:
        goal: Task description for the sub-agent
        context: Task-specific context (security prefix will be auto-prepended)
        toolsets: List of toolsets for the sub-agent
        role: 'leaf' (default) or 'orchestrator'
        **kwargs: Other delegate_task arguments

    Returns:
        The result dict from delegate_task
    """
    try:
        from tools.delegate_tool import delegate_task as _delegate_task  # type: ignore
    except ImportError:
        try:
            from hermes_tools import delegate_task as _delegate_task  # type: ignore
        except ImportError:
            print(
                "❌ Cannot import delegate_task. This wrapper must be run from "
                "inside Hermes Agent.",
                file=sys.stderr,
            )
            sys.exit(1)

    security_prefix = load_security_prefix()
    augmented_context = build_context(context, security_prefix)

    # Strip our internal kwargs before passing through
    safe_kwargs = {k: v for k, v in kwargs.items()
                   if k not in {"dry_run"}}

    return _delegate_task(
        goal=goal,
        context=augmented_context,
        toolsets=toolsets,
        role=role,
        **safe_kwargs,
    )


# ──────────────────────────────────────────────────────────────────────
# CLI for dry-run testing
# ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Test/preview delegation with security prefix injection",
    )
    parser.add_argument("--goal", required=True, help="Task goal")
    parser.add_argument("--context", help="Task context")
    parser.add_argument("--toolsets", help="Comma-separated toolsets")
    parser.add_argument("--role", default="leaf", choices=["leaf", "orchestrator"])
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the augmented context instead of delegating")
    parser.add_argument("--execute", action="store_true",
                        help="Actually call delegate_task")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    security_prefix = load_security_prefix()
    augmented_context = build_context(args.context, security_prefix)

    toolsets = None
    if args.toolsets:
        toolsets = [t.strip() for t in args.toolsets.split(",") if t.strip()]

    if args.json:
        out = {
            "goal": args.goal,
            "context_length": len(augmented_context),
            "security_prefix_length": len(security_prefix),
            "user_context_length": len(args.context or ""),
            "toolsets": toolsets,
            "role": args.role,
        }
        print(json.dumps(out, indent=2))
        return

    if args.execute and not args.dry_run:
        print("⚠️  --execute actually calls delegate_task.")
        result = delegate_safe(
            goal=args.goal,
            context=args.context,
            toolsets=toolsets,
            role=args.role,
        )
        print(json.dumps(result, indent=2, default=str))
        return

    # Default: dry-run preview
    print("=" * 70)
    print(f"  DRY-RUN — augmented context preview")
    print("=" * 70)
    print(f"  Goal:      {args.goal}")
    print(f"  Role:      {args.role}")
    print(f"  Toolsets:  {toolsets}")
    print(f"  Prefix:    {len(security_prefix)} chars from {PREFIX_PATH}")
    print(f"  User ctx:  {len(args.context or '')} chars")
    print(f"  Total ctx: {len(augmented_context)} chars")
    print("=" * 70)
    print()
    print(augmented_context[:3000])
    if len(augmented_context) > 3000:
        print(f"\n... [{len(augmented_context) - 3000} more characters truncated] ...")


if __name__ == "__main__":
    main()