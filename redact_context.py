"""CLI for redacting sensitive content with VibeGuard rules."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from vibeguard.core import apply_sensitive_rules, load_rules


def _read_input(input_path: Optional[str]) -> str:
    if input_path:
        return Path(input_path).read_text(encoding="utf-8")
    return sys.stdin.read()


def main() -> int:
    parser = argparse.ArgumentParser(description="Redact sensitive context using VibeGuard rules.")
    parser.add_argument("--rules", default="rules.yaml", help="Path to the shared rules file.")
    parser.add_argument("--input", help="Optional file to read instead of stdin.")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print a JSON summary instead of only the redacted text.",
    )
    args = parser.parse_args()

    rules = load_rules(Path(args.rules))
    original_text = _read_input(args.input)
    result = apply_sensitive_rules(original_text, rules)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        sys.stdout.write(result["redacted_text"])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
