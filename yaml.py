"""Tiny YAML compatibility shim for validation scripts in environments without PyYAML."""

from __future__ import annotations

import ast


class YAMLError(Exception):
    """Raised when the minimal YAML parser cannot understand the input."""


def safe_load(text):
    data = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise YAMLError(f"Unsupported YAML line: {raw_line}")

        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()

        if not key:
            raise YAMLError("Missing key in YAML line.")

        if not value:
            data[key] = ""
            continue

        if value[0] in {'"', "'"}:
            try:
                data[key] = ast.literal_eval(value)
            except Exception as exc:  # pragma: no cover - defensive fallback
                raise YAMLError(str(exc)) from exc
        else:
            lowered = value.lower()
            if lowered == "true":
                data[key] = True
            elif lowered == "false":
                data[key] = False
            else:
                data[key] = value

    return data
