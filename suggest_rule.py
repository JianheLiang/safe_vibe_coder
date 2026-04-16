"""CLI for suggesting or applying a new sensitive-field rule."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from vibeguard.core import find_sensitive_candidate, upsert_sensitive_rule


def _read_sample(sample: Optional[str], input_path: Optional[str]) -> str:
    if sample:
        return sample
    if input_path:
        return Path(input_path).read_text(encoding="utf-8")
    return sys.stdin.read()


def main() -> int:
    parser = argparse.ArgumentParser(description="Suggest or apply a learned VibeGuard rule.")
    parser.add_argument("--sample", help="Inline sample text that may contain a secret.")
    parser.add_argument("--input", help="Optional file to scan for a candidate rule.")
    parser.add_argument("--rules", default="rules.yaml", help="Path to the shared rules file.")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Append the candidate rule to the rules file after the caller has confirmed it.",
    )
    args = parser.parse_args()

    sample_text = _read_sample(args.sample, args.input)
    candidate = find_sensitive_candidate(sample_text)

    if not candidate:
        print(
            json.dumps(
                {
                    "candidate": None,
                    "applied": False,
                    "message": "No high-confidence sensitive pattern was inferred from the sample.",
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    payload = {"candidate": candidate, "applied": False}

    if args.apply:
        payload.update(upsert_sensitive_rule(Path(args.rules), candidate))

    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
