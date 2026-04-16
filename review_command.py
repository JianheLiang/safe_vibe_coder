"""CLI for reviewing risky shell or SQL commands with VibeGuard rules."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from vibeguard.core import load_rules, review_command_text


def _read_command(command: Optional[str]) -> str:
    if command:
        return command
    return sys.stdin.read().strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Review a shell or SQL command using VibeGuard rules.")
    parser.add_argument("command", nargs="?", help="Command text to review.")
    parser.add_argument("--rules", default="rules.yaml", help="Path to the shared rules file.")
    args = parser.parse_args()

    rules = load_rules(Path(args.rules))
    result = review_command_text(_read_command(args.command), rules)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
