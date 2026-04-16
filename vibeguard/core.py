"""Shared redaction, command review, and rule suggestion helpers."""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

DEFAULT_RULES = {"metadata": {}, "sensitive_fields": [], "dangerous_commands": []}
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SENSITIVE_KEYWORDS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "credential",
    "access_key",
)


def _ensure_rules_shape(rules: Dict[str, Any]) -> Dict[str, Any]:
    normalized = copy.deepcopy(DEFAULT_RULES)
    normalized.update(rules or {})
    normalized["metadata"] = dict(normalized.get("metadata") or {})
    normalized["sensitive_fields"] = list(normalized.get("sensitive_fields") or [])
    normalized["dangerous_commands"] = list(normalized.get("dangerous_commands") or [])
    return normalized


def load_rules(rules_path: Path) -> Dict[str, Any]:
    """Load the json-compatible YAML rules file."""
    rules_path = Path(rules_path)
    if not rules_path.exists():
        return copy.deepcopy(DEFAULT_RULES)

    raw_text = rules_path.read_text(encoding="utf-8").strip()
    if not raw_text:
        return copy.deepcopy(DEFAULT_RULES)

    try:
        return _ensure_rules_shape(json.loads(raw_text))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Failed to parse {rules_path}. This prototype expects JSON-compatible YAML."
        ) from exc


def save_rules(rules_path: Path, rules: Dict[str, Any]) -> None:
    """Persist rules using pretty-printed JSON, which is valid YAML."""
    rules_path = Path(rules_path)
    rules_path.write_text(
        json.dumps(_ensure_rules_shape(rules), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _compile_rule(rule: Dict[str, Any], *, default_ignore_case: bool = False) -> re.Pattern:
    flags = 0
    if rule.get("ignore_case", default_ignore_case):
        flags |= re.IGNORECASE
    return re.compile(rule["pattern"], flags)


def _active_rules(rules: Dict[str, Any], section: str) -> Iterable[Dict[str, Any]]:
    for rule in rules.get(section, []):
        if rule.get("enabled", True) and rule.get("pattern"):
            yield rule


def apply_sensitive_rules(text: str, rules: Dict[str, Any]) -> Dict[str, Any]:
    """Apply redaction rules and return the transformed text plus a summary."""
    redacted_text = text
    matches: List[Dict[str, Any]] = []

    for rule in _active_rules(rules, "sensitive_fields"):
        pattern = _compile_rule(rule)
        redacted_text, count = pattern.subn(rule.get("replacement", "<REDACTED>"), redacted_text)
        if count:
            matches.append(
                {
                    "name": rule.get("name", "unnamed-sensitive-rule"),
                    "count": count,
                    "replacement": rule.get("replacement", "<REDACTED>"),
                    "severity": rule.get("severity", "medium"),
                    "source": rule.get("source", "unknown"),
                }
            )

    return {
        "modified": redacted_text != text,
        "match_count": sum(match["count"] for match in matches),
        "matches": matches,
        "redacted_text": redacted_text,
    }


def review_command_text(command: str, rules: Dict[str, Any]) -> Dict[str, Any]:
    """Review a shell or SQL command against dangerous command rules."""
    matches: List[Dict[str, Any]] = []

    for rule in _active_rules(rules, "dangerous_commands"):
        pattern = _compile_rule(rule, default_ignore_case=True)
        if pattern.search(command):
            matches.append(
                {
                    "name": rule.get("name", "unnamed-command-rule"),
                    "severity": rule.get("severity", "medium"),
                    "message": rule.get("message", "Matched a dangerous command rule."),
                    "safer_alternative": rule.get(
                        "safer_alternative",
                        "Review the command manually before executing it.",
                    ),
                    "source": rule.get("source", "unknown"),
                }
            )

    if not matches:
        return {
            "matched": False,
            "risk_level": "none",
            "rule_name": None,
            "why_flagged": "No dangerous command rule matched.",
            "safer_alternative": "Proceed with normal tool-side permission checks.",
            "matches": [],
            "command": command,
        }

    highest = max(matches, key=lambda item: SEVERITY_ORDER.get(item["severity"], 0))
    return {
        "matched": True,
        "risk_level": highest["severity"],
        "rule_name": highest["name"],
        "why_flagged": highest["message"],
        "safer_alternative": highest["safer_alternative"],
        "matches": matches,
        "command": command,
    }


def _sensitive_key_score(key: str) -> int:
    lowered = key.lower()
    return sum(1 for keyword in SENSITIVE_KEYWORDS if keyword in lowered)


def _build_env_rule(key: str) -> Dict[str, Any]:
    escaped = re.escape(key)
    return {
        "name": f"{key.lower()}-env",
        "pattern": rf"(?im)\b{escaped}\s*=\s*[^\r\n#]+",
        "replacement": f"{key}=<REDACTED>",
        "enabled": True,
        "source": "learned",
        "severity": "high",
        "reason": f"Detected sensitive environment-style assignment for {key}.",
    }


def _build_json_rule(key: str) -> Dict[str, Any]:
    escaped = re.escape(key)
    return {
        "name": f"{key.lower()}-json",
        "pattern": rf'(?im)(["\']{escaped}["\']\s*:\s*["\'])[^"\']+(["\'])',
        "replacement": rf'\1<REDACTED>\2',
        "enabled": True,
        "source": "learned",
        "severity": "high",
        "reason": f"Detected sensitive JSON-style assignment for {key}.",
    }


def suggest_sensitive_rule(sample: str) -> Optional[Dict[str, Any]]:
    """Infer a candidate rule from a raw sample string."""
    text = sample.strip()
    if not text:
        return None

    env_match = re.search(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$", text)
    if env_match and _sensitive_key_score(env_match.group(1)) > 0:
        return _build_env_rule(env_match.group(1))

    json_match = re.search(r'["\']([A-Za-z_][A-Za-z0-9_]*)["\']\s*:\s*["\']([^"\']+)["\']', text)
    if json_match and _sensitive_key_score(json_match.group(1)) > 0:
        return _build_json_rule(json_match.group(1))

    if re.search(r"sk-[A-Za-z0-9_-]{8,}", text):
        return {
            "name": "learned-api-key-pattern",
            "pattern": r"sk-[A-Za-z0-9_-]{8,}",
            "replacement": "<API_KEY_REDACTED>",
            "enabled": True,
            "source": "learned",
            "severity": "high",
            "reason": "Detected an API key that matches the common sk- prefix pattern.",
        }

    if re.search(r"(?<!\d)1[3-9]\d{9}(?!\d)", text):
        return {
            "name": "learned-phone-pattern",
            "pattern": r"(?<!\d)1[3-9]\d{9}(?!\d)",
            "replacement": "<PHONE_REDACTED>",
            "enabled": True,
            "source": "learned",
            "severity": "medium",
            "reason": "Detected a phone number in the sample.",
        }

    if re.search(r"(?<!\d)\d{17}[\dXx](?!\d)", text):
        return {
            "name": "learned-id-pattern",
            "pattern": r"(?<!\d)\d{17}[\dXx](?!\d)",
            "replacement": "<ID_REDACTED>",
            "enabled": True,
            "source": "learned",
            "severity": "high",
            "reason": "Detected an identity-card style number in the sample.",
        }

    return None


def find_sensitive_candidate(text: str) -> Optional[Dict[str, Any]]:
    """Scan a multi-line blob and return the first candidate rule."""
    for line in text.splitlines():
        candidate = suggest_sensitive_rule(line)
        if candidate:
            candidate["sample"] = line.strip()
            return candidate
    return suggest_sensitive_rule(text)


def upsert_sensitive_rule(rules_path: Path, candidate: Dict[str, Any]) -> Dict[str, Any]:
    """Add a learned rule if it is not already present."""
    rules = load_rules(rules_path)
    existing = rules.get("sensitive_fields", [])
    names = {rule.get("name") for rule in existing}
    patterns = {rule.get("pattern") for rule in existing}

    applied = False
    if candidate.get("name") not in names and candidate.get("pattern") not in patterns:
        cleaned_candidate = {
            key: value
            for key, value in candidate.items()
            if key in {"name", "pattern", "replacement", "enabled", "source", "severity"}
        }
        existing.append(cleaned_candidate)
        rules["sensitive_fields"] = existing
        save_rules(rules_path, rules)
        applied = True

    return {
        "applied": applied,
        "rule_name": candidate.get("name"),
        "rules_path": str(rules_path),
        "sensitive_rule_count": len(existing),
    }
