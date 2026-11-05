#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import shutil
import site
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _bash_path(path: Path) -> str:
    if os.name != "nt":
        return str(path)
    result = subprocess.check_output(
        ["bash", "-lc", f"cygpath -u '{path}'"], text=True, encoding="utf-8"
    )
    return result.strip()


def _payload(rule: dict, repo: Path, transcript: Path) -> dict:
    event = rule["event"]
    matcher = rule.get("matcher", "")
    command = rule["command"]
    payload = {
        "hook_event_name": event,
        "session_id": "kimi-smoke",
        "session_title": "Kimi hook smoke",
        "client_type": "kimi_code_cli",
        "cwd": _bash_path(repo),
    }
    if event == "UserPromptSubmit":
        payload["prompt"] = "Продолжи текущую задачу"
    elif event in {"PreToolUse", "PostToolUse"}:
        if "secret-file-read-block.sh" in command:
            tool_name = "Read"
        elif matcher == "Bash" or any(
            name in command
            for name in (
                "pull-on-touch.sh",
                "destructive-guard.sh",
                "protocol-artifact-validate.sh",
                "dry-run-gate.sh",
                "secret-leak-block.sh",
                "session-open-gate.sh",
            )
        ):
            tool_name = "Bash"
        elif matcher == "Skill":
            tool_name = "Skill"
        elif matcher == "mcp__.*":
            tool_name = "mcp__smoke__safe"
        elif matcher and "Read" in matcher and "Edit" not in matcher:
            tool_name = "Read"
        elif matcher and "Write" in matcher:
            tool_name = "Write"
        else:
            tool_name = "Edit"

        if tool_name == "Bash":
            payload["tool_input"] = {"command": f"git -C '{_bash_path(repo)}' status --short"}
        elif tool_name == "Skill":
            payload["tool_input"] = {"skill": "think", "args": ""}
        elif tool_name == "mcp__smoke__safe":
            payload["tool_input"] = {"action": "read", "value": "ordinary"}
        elif tool_name == "Read":
            payload["tool_input"] = {"file_path": _bash_path(repo / "params.yaml.example")}
        elif "sql-pii-guard.sh" in command:
            payload["tool_input"] = {
                "file_path": _bash_path(repo / "smoke.sql"),
                "new_string": "SELECT 1;",
            }
        else:
            payload["tool_input"] = {
                "file_path": _bash_path(repo / "smoke-note.md"),
                "old_string": "old",
                "new_string": "new",
            }
        payload["tool_name"] = tool_name
        if event == "PostToolUse":
            payload["tool_response"] = {"success": True}
    elif event == "Stop":
        payload["stop_hook_active"] = True
        payload["last_assistant_message"] = "Проверка завершена"
    elif event in {"PreCompact", "PostCompact"}:
        payload["transcript_path"] = _bash_path(transcript)
        payload["trigger"] = "manual"
        if event == "PostCompact":
            payload["source"] = "compact"
    elif event == "SessionStart":
        payload["source"] = "startup"
    elif event == "SessionEnd":
        payload["reason"] = "exit"
    return payload


def _sanitize(value: str | bytes | None, sandbox: Path) -> str:
    if value is None:
        value = ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    variants = {
        str(sandbox): "<SANDBOX>",
        _bash_path(sandbox): "<SANDBOX>",
    }
    for source, replacement in variants.items():
        value = value.replace(source, replacement)
    return value[-1500:]


def run_smoke(source: Path, report_path: Path, timeout_seconds: int) -> dict:
    port_dir = source.resolve().parent.parent
    repo_root = port_dir.parent
    with tempfile.TemporaryDirectory() as temp_dir:
        sandbox = Path(temp_dir)
        workspace = sandbox / "IWE"
        repo = workspace / "FMT-exocortex-template"
        workspace.mkdir(parents=True)
        subprocess.run(
            ["git", "clone", "--quiet", "--no-hardlinks", str(repo_root), str(repo)],
            check=True,
        )
        shutil.copytree(
            port_dir,
            repo / "kimi-port",
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        subprocess.run(["git", "-C", str(repo), "remote", "remove", "origin"], check=True)

        config_dir = sandbox / "config"
        home_dir = sandbox / "home"
        config_dir.mkdir()
        home_dir.mkdir()
        (repo / "smoke.sql").write_text("SELECT 1;\n", encoding="utf-8")
        (repo / "smoke-note.md").write_text("old\n", encoding="utf-8")
        transcript = sandbox / "transcript.jsonl"
        transcript.write_text(
            '{"type":"user","message":{"role":"user","content":"Продолжи задачу"}}\n'
            '{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"Шаг 2 из 3"}]}}\n',
            encoding="utf-8",
        )

        env = os.environ.copy()
        env.update(
            {
                "HOME": _bash_path(home_dir),
                "CLAUDE_CONFIG_DIR": _bash_path(config_dir),
                "WORKSPACE_DIR": _bash_path(workspace),
                "IWE_ROOT": _bash_path(workspace),
                "IWE_WORKSPACE": _bash_path(workspace),
                "IWE_TEMPLATE": _bash_path(repo),
                "IWE_SCRIPTS": _bash_path(repo / "scripts"),
                "CLAUDE_PROJECT_DIR": _bash_path(repo),
                "IWE_AGENT": "kimi",
                "LC_ALL": "C.UTF-8",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": site.getusersitepackages(),
                "GIT_AUTHOR_NAME": "Smoke",
                "GIT_AUTHOR_EMAIL": "smoke@example.invalid",
                "GIT_COMMITTER_NAME": "Smoke",
                "GIT_COMMITTER_EMAIL": "smoke@example.invalid",
            }
        )

        candidate_raw = (repo / "kimi-port" / "generated" / "hooks.toml").read_bytes()
        candidate = tomllib.loads(candidate_raw.decode("utf-8"))
        results = []
        for index, rule in enumerate(candidate["hooks"], start=1):
            payload = _payload(rule, repo, transcript)
            try:
                completed = subprocess.run(
                    ["bash", "-c", rule["command"]],
                    input=json.dumps(payload, ensure_ascii=False),
                    cwd=repo,
                    env=env,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout_seconds + 5,
                )
                code = completed.returncode
                outcome = "pass" if code == 0 else "blocked" if code == 2 else "failed"
                stdout = _sanitize(completed.stdout, sandbox)
                stderr = _sanitize(completed.stderr, sandbox)
            except subprocess.TimeoutExpired as exc:
                code = 124
                outcome = "failed"
                stdout = _sanitize(exc.stdout or "", sandbox)
                stderr = _sanitize(exc.stderr or "", sandbox)

            results.append(
                {
                    "index": index,
                    "event": rule["event"],
                    "matcher": rule.get("matcher"),
                    "command": rule["command"],
                    "exit_code": code,
                    "outcome": outcome,
                    "stdout": stdout,
                    "stderr": stderr,
                }
            )
            print(f"{index:02d} {outcome.upper():7} exit={code:<3} {rule['command']}")

        failed = sum(item["outcome"] == "failed" for item in results)
        blocked = sum(item["outcome"] == "blocked" for item in results)
        passed = sum(item["outcome"] == "pass" for item in results)
        report = {
            "schema_version": 1,
            "candidate_sha256": _sha256(candidate_raw),
            "target_rule_count": len(results),
            "unique_command_count": len({item["command"] for item in results}),
            "pass_count": passed,
            "blocked_count": blocked,
            "failed_count": failed,
            "disposition": "stop" if failed else "narrow" if blocked else "pass",
            "environment": {
                "os": sys.platform,
                "shell": "Git Bash",
                "timeout_seconds": timeout_seconds,
            },
            "results": results,
        }
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_bytes(
            (json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
                "utf-8"
            )
        )
        return report


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

    repo_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Изолированный запуск сгенерированных хуков Kimi")
    parser.add_argument(
        "--source", type=Path, default=repo_root / "kimi-port" / "generated" / "hooks.toml"
    )
    parser.add_argument(
        "--report", type=Path, default=repo_root / "kimi-port" / "generated" / "hooks-smoke-report.json"
    )
    parser.add_argument("--timeout", type=int, default=20)
    args = parser.parse_args(argv)
    try:
        report = run_smoke(args.source, args.report, args.timeout)
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        print(f"Ошибка стенда: {exc}", file=sys.stderr)
        return 2
    print(
        f"Итог: {report['disposition']}; разрешено={report['pass_count']}, "
        f"заблокировано={report['blocked_count']}, ошибок={report['failed_count']}"
    )
    return 1 if report["failed_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
