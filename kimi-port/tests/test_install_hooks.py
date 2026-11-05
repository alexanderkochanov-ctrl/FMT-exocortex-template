import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

PORT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PORT_DIR))

import install_hooks


class InstallHooksTest(unittest.TestCase):
    def test_merge_preserves_existing_configuration(self):
        merged = install_hooks.merge_config("model = \"kimi\"\n", "[[hooks]]\nevent = \"Stop\"\n")
        self.assertIn("model = \"kimi\"", merged)
        self.assertIn(install_hooks.BEGIN, merged)
        self.assertIn("event = \"Stop\"", merged)

    def test_merge_replaces_managed_block_only(self):
        existing = (
            "model = \"kimi\"\n\n"
            + install_hooks.BEGIN
            + "\nold\n"
            + install_hooks.END
            + "\nother = true\n"
        )
        merged = install_hooks.merge_config(existing, "new\n")
        self.assertIn("new", merged)
        self.assertNotIn("old", merged)
        self.assertIn("other = true", merged)

    def test_unpaired_markers_stop_merge(self):
        with self.assertRaisesRegex(ValueError, "непарные"):
            install_hooks.merge_config(install_hooks.BEGIN + "\n", "new\n")

    def test_report_must_cover_same_successful_candidate(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            candidate = root / "hooks.toml"
            raw = b"[[hooks]]\nevent = \"Stop\"\ncommand = \"true\"\n"
            candidate.write_bytes(raw)
            report = root / "report.json"
            report.write_text(
                json.dumps(
                    {
                        "candidate_sha256": hashlib.sha256(raw).hexdigest(),
                        "target_rule_count": 1,
                        "failed_count": 0,
                        "disposition": "pass",
                    }
                ),
                encoding="utf-8",
            )
            install_hooks.validate_candidate(candidate, report, allow_narrow=False)
            report.write_text(
                json.dumps(
                    {
                        "candidate_sha256": hashlib.sha256(raw).hexdigest(),
                        "target_rule_count": 1,
                        "failed_count": 1,
                        "disposition": "stop",
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "ошибки"):
                install_hooks.validate_candidate(candidate, report, allow_narrow=False)

    def test_narrow_candidate_requires_explicit_permission(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            candidate = root / "hooks.toml"
            raw = b"[[hooks]]\nevent = \"Stop\"\ncommand = \"true\"\n"
            candidate.write_bytes(raw)
            report = root / "report.json"
            report.write_text(
                json.dumps(
                    {
                        "candidate_sha256": hashlib.sha256(raw).hexdigest(),
                        "target_rule_count": 1,
                        "failed_count": 0,
                        "disposition": "narrow",
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "allow-narrow"):
                install_hooks.validate_candidate(candidate, report, allow_narrow=False)
            install_hooks.validate_candidate(candidate, report, allow_narrow=True)


if __name__ == "__main__":
    unittest.main()
