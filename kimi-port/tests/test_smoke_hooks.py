import sys
import tempfile
import unittest
from pathlib import Path

PORT_DIR = Path(__file__).resolve().parent.parent
REPO_DIR = PORT_DIR.parent
sys.path.insert(0, str(PORT_DIR))

import smoke_hooks


class SmokeHooksTest(unittest.TestCase):
    def test_sanitize_accepts_missing_and_byte_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            sandbox = Path(temp_dir)
            self.assertEqual(smoke_hooks._sanitize(None, sandbox), "")
            self.assertEqual(smoke_hooks._sanitize(b"ok", sandbox), "ok")

    def test_compact_payload_contains_both_source_conventions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            transcript = Path(temp_dir) / "transcript.jsonl"
            payload = smoke_hooks._payload(
                {"event": "PostCompact", "command": "bash ./hook.sh"},
                REPO_DIR,
                transcript,
            )
            self.assertEqual(payload["source"], "compact")
            self.assertEqual(payload["trigger"], "manual")

    def test_secret_file_hook_uses_safe_read(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            payload = smoke_hooks._payload(
                {
                    "event": "PreToolUse",
                    "matcher": "Read|Edit|MultiEdit|Grep",
                    "command": "bash ./.claude/hooks/secret-file-read-block.sh",
                },
                REPO_DIR,
                Path(temp_dir) / "transcript.jsonl",
            )
            self.assertEqual(payload["tool_name"], "Read")
            self.assertTrue(payload["tool_input"]["file_path"].endswith("params.yaml.example"))

    def test_bash_hook_uses_non_mutating_command(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            payload = smoke_hooks._payload(
                {
                    "event": "PreToolUse",
                    "matcher": "Bash",
                    "command": "bash ./.claude/hooks/destructive-guard.sh",
                },
                REPO_DIR,
                Path(temp_dir) / "transcript.jsonl",
            )
            self.assertEqual(payload["tool_name"], "Bash")
            self.assertIn("status --short", payload["tool_input"]["command"])


if __name__ == "__main__":
    unittest.main()
