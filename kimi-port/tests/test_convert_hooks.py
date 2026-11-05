import copy
import json
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

PORT_DIR = Path(__file__).resolve().parent.parent
REPO_DIR = PORT_DIR.parent
sys.path.insert(0, str(PORT_DIR))

import convert_hooks


class ConvertHooksTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ruleset = json.loads((PORT_DIR / "hook-rules.json").read_text(encoding="utf-8"))
        cls.settings = json.loads(
            (REPO_DIR / ".claude" / "settings.json").read_text(encoding="utf-8")
        )

    def minimal_settings(self, event="PreToolUse", matcher="Bash", timeout=None):
        hook = {
            "type": "command",
            "command": "$CLAUDE_PROJECT_DIR/.claude/hooks/example.sh",
        }
        if timeout is not None:
            hook["timeout"] = timeout
        group = {"hooks": [hook]}
        if matcher is not None:
            group["matcher"] = matcher
        return {"hooks": {event: [group]}}

    def convert_minimal(self, **kwargs):
        return convert_hooks.convert_settings(self.minimal_settings(**kwargs), self.ruleset)

    def test_current_template_counts_and_toml_contract(self):
        conversion = convert_hooks.convert_settings(self.settings, self.ruleset)
        self.assertEqual(conversion.source_group_count, 30)
        self.assertEqual(conversion.source_command_count, 32)
        self.assertEqual(len(conversion.rules), 34)

        output = convert_hooks.render_toml(conversion, "a" * 64, "b" * 64)
        parsed = tomllib.loads(output)
        self.assertEqual(len(parsed["hooks"]), 34)
        for rule in parsed["hooks"]:
            self.assertLessEqual(set(rule), {"event", "matcher", "command", "timeout"})
            self.assertTrue(rule["command"].startswith("bash ./.claude/hooks/"))
            self.assertNotIn("$CLAUDE_PROJECT_DIR", rule["command"])
            self.assertGreaterEqual(rule["timeout"], 1)
            self.assertLessEqual(rule["timeout"], 600)

    def test_current_template_report_is_machine_readable(self):
        conversion = convert_hooks.convert_settings(self.settings, self.ruleset)
        output = convert_hooks.render_toml(conversion, "a" * 64, "b" * 64)
        report = convert_hooks.build_report(conversion, "a" * 64, "b" * 64, output)
        self.assertEqual(report["target_event_counts"]["PostCompact"], 3)
        self.assertEqual(report["target_event_counts"]["SessionStart"], 2)
        self.assertEqual(report["target_event_counts"]["PreToolUse"], 14)
        self.assertEqual(report["ignored_sections"], ["env", "permissions"])
        self.assertEqual(report["source_command_count"], 32)
        self.assertEqual(report["target_rule_count"], 34)
        self.assertEqual(len(report["output_sha256"]), 64)

    def test_compact_matcher_moves_to_post_compact(self):
        conversion = self.convert_minimal(event="SessionStart", matcher="compact")
        self.assertEqual(len(conversion.rules), 1)
        self.assertEqual(conversion.rules[0]["event"], "PostCompact")
        self.assertEqual(conversion.rules[0]["matcher"], "auto|manual")
        self.assertEqual(conversion.adaptations[0]["kind"], "matcher_mapping")

    def test_plain_session_start_fans_out_and_declares_clear_loss(self):
        conversion = self.convert_minimal(event="SessionStart", matcher=None)
        self.assertEqual(
            [rule["event"] for rule in conversion.rules],
            ["SessionStart", "PostCompact"],
        )
        adaptation = conversion.adaptations[0]
        self.assertEqual(adaptation["kind"], "session_start_fanout")
        self.assertEqual(adaptation["accepted_source_only_matchers"], ["clear"])

    def test_explicit_clear_matcher_is_rejected(self):
        with self.assertRaisesRegex(convert_hooks.ConversionError, "clear"):
            self.convert_minimal(event="SessionStart", matcher="clear")

    def test_unknown_event_is_rejected(self):
        settings = self.minimal_settings()
        settings["hooks"]["FutureEvent"] = settings["hooks"].pop("PreToolUse")
        with self.assertRaisesRegex(convert_hooks.ConversionError, "FutureEvent"):
            convert_hooks.convert_settings(settings, self.ruleset)

    def test_non_command_hook_is_rejected(self):
        settings = self.minimal_settings()
        settings["hooks"]["PreToolUse"][0]["hooks"][0]["type"] = "prompt"
        with self.assertRaisesRegex(convert_hooks.ConversionError, "type = command"):
            convert_hooks.convert_settings(settings, self.ruleset)

    def test_unknown_hook_field_is_rejected(self):
        settings = self.minimal_settings()
        settings["hooks"]["PreToolUse"][0]["hooks"][0]["async"] = True
        with self.assertRaisesRegex(convert_hooks.ConversionError, "async"):
            convert_hooks.convert_settings(settings, self.ruleset)

    def test_unknown_command_is_rejected(self):
        settings = self.minimal_settings()
        settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = "echo hello"
        with self.assertRaisesRegex(convert_hooks.ConversionError, "поддерживаются только команды"):
            convert_hooks.convert_settings(settings, self.ruleset)

    def test_timeout_out_of_range_is_rejected(self):
        with self.assertRaisesRegex(convert_hooks.ConversionError, "timeout"):
            self.convert_minimal(timeout=601)

    def test_explicit_timeout_is_preserved(self):
        conversion = self.convert_minimal(timeout=17)
        self.assertEqual(conversion.rules[0]["timeout"], 17)

    def test_session_end_default_is_conservative_and_reported(self):
        conversion = self.convert_minimal(event="SessionEnd", matcher=None)
        self.assertEqual(conversion.rules[0]["timeout"], 1)
        self.assertEqual(conversion.adaptations[0]["kind"], "default_timeout_rounding")
        self.assertEqual(conversion.adaptations[0]["source_timeout"], 1.5)

    def test_repeated_generation_is_byte_identical(self):
        first = convert_hooks.convert_settings(self.settings, self.ruleset)
        second = convert_hooks.convert_settings(copy.deepcopy(self.settings), self.ruleset)
        first_toml = convert_hooks.render_toml(first, "a" * 64, "b" * 64)
        second_toml = convert_hooks.render_toml(second, "a" * 64, "b" * 64)
        self.assertEqual(first_toml, second_toml)

    def test_cli_write_and_check(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "hooks.toml"
            report = Path(temp_dir) / "report.json"
            command = [
                sys.executable,
                str(PORT_DIR / "convert_hooks.py"),
                "--source",
                str(REPO_DIR / ".claude" / "settings.json"),
                "--rules",
                str(PORT_DIR / "hook-rules.json"),
                "--output",
                str(output),
                "--report",
                str(report),
            ]
            subprocess.run(command, check=True, capture_output=True, text=True, encoding="utf-8")
            first_output = output.read_bytes()
            first_report = report.read_bytes()
            subprocess.run(command, check=True, capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(output.read_bytes(), first_output)
            self.assertEqual(report.read_bytes(), first_report)
            subprocess.run(command + ["--check"], check=True, capture_output=True, text=True, encoding="utf-8")

            output.write_text("outdated\n", encoding="utf-8")
            mismatch = subprocess.run(command + ["--check"], capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(mismatch.returncode, 1)
            self.assertIn("устарел", mismatch.stderr)


if __name__ == "__main__":
    unittest.main()
