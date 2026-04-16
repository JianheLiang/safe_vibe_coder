import tempfile
import unittest
from pathlib import Path

from vibeguard.core import (
    apply_sensitive_rules,
    find_sensitive_candidate,
    load_rules,
    review_command_text,
    save_rules,
    upsert_sensitive_rule,
)


ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = ROOT / "rules.yaml"


class VibeGuardTests(unittest.TestCase):
    def test_redaction_masks_built_in_secrets(self):
        rules = load_rules(RULES_PATH)
        result = apply_sensitive_rules(
            "DB_PASSWORD=abc123\nOPENAI_API_KEY=sk-test-123456789\n",
            rules,
        )
        self.assertTrue(result["modified"])
        self.assertNotIn("abc123", result["redacted_text"])
        self.assertNotIn("sk-test-123456789", result["redacted_text"])
        self.assertGreaterEqual(result["match_count"], 2)

    def test_command_review_flags_recursive_delete(self):
        rules = load_rules(RULES_PATH)
        result = review_command_text("rm -rf /data", rules)
        self.assertTrue(result["matched"])
        self.assertEqual(result["risk_level"], "critical")
        self.assertEqual(result["rule_name"], "recursive-force-delete")

    def test_safe_command_remains_unmatched(self):
        rules = load_rules(RULES_PATH)
        result = review_command_text("ls -la", rules)
        self.assertFalse(result["matched"])
        self.assertEqual(result["risk_level"], "none")

    def test_learned_rule_can_be_persisted(self):
        candidate = find_sensitive_candidate("INTERNAL_TOKEN=abc999")
        self.assertIsNotNone(candidate)

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_rules_path = Path(temp_dir) / "rules.yaml"
            save_rules(temp_rules_path, load_rules(RULES_PATH))

            update = upsert_sensitive_rule(temp_rules_path, candidate)
            updated_rules = load_rules(temp_rules_path)

        self.assertTrue(update["applied"])
        self.assertIn("internal_token-env", {rule["name"] for rule in updated_rules["sensitive_fields"]})


if __name__ == "__main__":
    unittest.main()
