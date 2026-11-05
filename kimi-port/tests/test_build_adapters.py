import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PORT_DIR = Path(__file__).resolve().parent.parent
REPO_DIR = PORT_DIR.parent
sys.path.insert(0, str(PORT_DIR))

import build_adapters


def bash_path(path):
    if os.name != "nt":
        return str(path)
    return subprocess.check_output(
        ["bash", "-lc", f"cygpath -u {shlex.quote(str(path))}"],
        text=True,
        encoding="utf-8",
    ).strip()


class BuildAdaptersTest(unittest.TestCase):
    def test_path_normalization_detects_secret_and_allows_safe_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            build_adapters.build_adapters(
                REPO_DIR / ".claude" / "hooks" / "secret-bypass-analyzer.py",
                Path(temp_dir),
            )
            analyzer = Path(temp_dir) / "secret-bypass-analyzer.py"
            for command, expected in (
                ("cat ~/.config/aist/env", True),
                ("cat ./notes.md", False),
            ):
                payload = json.dumps(
                    {
                        "session_id": "test",
                        "hook_event_name": "PreToolUse",
                        "tool_name": "Bash",
                        "tool_input": {"command": command},
                    }
                )
                result = subprocess.run(
                    [sys.executable, str(analyzer), "analyze-bash"],
                    input=payload,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    check=True,
                )
                analysis = json.loads(result.stdout)
                self.assertEqual(analysis["direct_sensitive_read"], expected)

    def test_shim_selects_adapted_analyzer(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            build_adapters.build_adapters(
                REPO_DIR / ".claude" / "hooks" / "secret-bypass-analyzer.py",
                output_dir,
            )
            shim_dir = bash_path(output_dir / "bin")
            hook_dir = bash_path(REPO_DIR / ".claude" / "hooks")
            script = (
                f'PATH="{shim_dir}:$PATH"; export PATH; '
                f'. "{hook_dir}/secret-bypass-lib.sh"; '
                "secret_pattern_process analyze-bash"
            )
            payload = json.dumps(
                {
                    "session_id": "test",
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": "cat ~/.config/aist/env"},
                }
            )
            result = subprocess.run(
                ["bash", "-c", script],
                input=payload,
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=True,
            )
            self.assertTrue(json.loads(result.stdout)["direct_sensitive_read"])

    @unittest.skipUnless(os.name == "nt", "Проверка ACL относится к Windows")
    def test_checkpoint_wrapper_restricts_acl_to_current_user(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_dir = root / "adapters"
            build_adapters.build_adapters(
                REPO_DIR / ".claude" / "hooks" / "secret-bypass-analyzer.py",
                output_dir,
            )
            config_dir = root / "config"
            transcript = root / "transcript.jsonl"
            transcript.write_text(
                '{"type":"user","message":{"role":"user","content":"проверка"}}\n',
                encoding="utf-8",
            )
            payload = json.dumps(
                {
                    "session_id": "acl-test",
                    "cwd": bash_path(root),
                    "transcript_path": bash_path(transcript),
                    "hook_event_name": "PreCompact",
                    "trigger": "manual",
                }
            )
            env = os.environ.copy()
            env["CLAUDE_PROJECT_DIR"] = bash_path(REPO_DIR)
            env["CLAUDE_CONFIG_DIR"] = bash_path(config_dir)
            env["LC_ALL"] = "C.UTF-8"
            result = subprocess.run(
                ["bash", str(output_dir / "precompact-checkpoint.sh")],
                input=payload,
                capture_output=True,
                text=True,
                encoding="utf-8",
                env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(
                (config_dir / "iwe-checkpoints" / "checkpoint-acl-test.md").exists()
            )
            acl = subprocess.check_output(
                ["icacls", str(config_dir / "iwe-checkpoints")],
                text=True,
                errors="replace",
            )
            self.assertNotIn("(I)", acl)

    def test_build_is_deterministic_and_source_drift_stops(self):
        source = REPO_DIR / ".claude" / "hooks" / "secret-bypass-analyzer.py"
        with tempfile.TemporaryDirectory() as first_dir, tempfile.TemporaryDirectory() as second_dir:
            first = build_adapters.build_adapters(source, Path(first_dir))
            second = build_adapters.build_adapters(source, Path(second_dir))
            self.assertEqual(first, second)

        with tempfile.TemporaryDirectory() as temp_dir:
            changed = Path(temp_dir) / "analyzer.py"
            changed.write_text(
                source.read_text(encoding="utf-8").replace(
                    "normalized = os.path.normpath(value.lower())",
                    "normalized = os.path.normpath(value)",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, build_adapters.NORMALIZATION_ID):
                build_adapters.build_adapters(changed, Path(temp_dir) / "out")


if __name__ == "__main__":
    unittest.main()
