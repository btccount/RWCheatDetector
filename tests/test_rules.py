"""Тесты базы сигнатур."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rwcd.rules import DEFAULT_RULES_PATH, RulesError, load_rules, parse_rule


class LoadRulesTest(unittest.TestCase):
    def test_default_database_loads(self) -> None:
        rules = load_rules()
        self.assertGreaterEqual(len(rules), 10)
        identifiers = {rule.id for rule in rules}
        self.assertIn("nursultan", identifiers)
        self.assertIn("expensive", identifiers)
        self.assertIn("wurst", identifiers)

    def test_default_path_points_to_repository_file(self) -> None:
        self.assertTrue(DEFAULT_RULES_PATH.is_file(), DEFAULT_RULES_PATH)

    def test_rules_are_unique(self) -> None:
        rules = load_rules()
        self.assertEqual(len(rules), len({rule.id for rule in rules}))

    def test_missing_file_raises(self) -> None:
        with self.assertRaises(RulesError):
            load_rules("/nonexistent/cheats.json")

    def test_duplicate_ids_raise(self) -> None:
        payload = {
            "rules": [
                {"id": "same", "name": "A", "severity": "low"},
                {"id": "same", "name": "B", "severity": "low"},
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(RulesError):
                load_rules(path)

    def test_invalid_severity_raises(self) -> None:
        with self.assertRaises(RulesError):
            parse_rule({"id": "x", "name": "X", "severity": "critical"})

    def test_invalid_hash_raises(self) -> None:
        with self.assertRaises(RulesError):
            parse_rule({"id": "x", "name": "X", "severity": "low", "sha256": ["abc"]})

    def test_broken_json_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.json"
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(RulesError):
                load_rules(path)


if __name__ == "__main__":
    unittest.main()