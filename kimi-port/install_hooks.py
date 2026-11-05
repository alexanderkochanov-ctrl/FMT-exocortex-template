#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
import tomllib
from datetime import datetime, timezone
from pathlib import Path


BEGIN = "# BEGIN KIMI-PORT GENERATED HOOKS"
END = "# END KIMI-PORT GENERATED HOOKS"


def _candidate_block(candidate: str) -> str:
    return f"{BEGIN}\n{candidate.rstrip()}\n{END}\n"


def merge_config(existing: str, candidate: str) -> str:
    block = _candidate_block(candidate)
    has_begin = BEGIN in existing
    has_end = END in existing
    if has_begin != has_end:
        raise ValueError("В конфигурации непарные маркеры KIMI-PORT")
    if not has_begin:
        return existing.rstrip() + "\n\n" + block
    if existing.count(BEGIN) != 1 or existing.count(END) != 1:
        raise ValueError("В конфигурации повторяются маркеры KIMI-PORT")
    start = existing.index(BEGIN)
    finish = existing.index(END) + len(END)
    if finish < start:
        raise ValueError("Маркеры KIMI-PORT расположены в неверном порядке")
    return existing[:start] + block.rstrip() + existing[finish:]


def validate_candidate(candidate_path: Path, report_path: Path, allow_narrow: bool) -> None:
    candidate_raw = candidate_path.read_bytes()
    rules = tomllib.loads(candidate_raw.decode("utf-8"))["hooks"]
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report["candidate_sha256"] != hashlib.sha256(candidate_raw).hexdigest():
        raise ValueError("Отчёт относится к другому кандидату")
    if report["target_rule_count"] != len(rules):
        raise ValueError("Число правил в отчёте не совпадает с кандидатом")
    if report["failed_count"] != 0 or report["disposition"] == "stop":
        raise ValueError("У кандидата есть ошибки испытаний")
    if report["disposition"] == "narrow" and not allow_narrow:
        raise ValueError("Ограниченный кандидат требует явного --allow-narrow")


def install(config_path: Path, candidate_path: Path, apply: bool) -> bool:
    candidate = candidate_path.read_text(encoding="utf-8")
    existing = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
    merged = merge_config(existing, candidate)
    if merged == existing:
        return False
    if not apply:
        return True
    config_path.parent.mkdir(parents=True, exist_ok=True)
    if config_path.exists():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        shutil.copy2(config_path, config_path.with_name(config_path.name + f".{stamp}.bak"))
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=config_path.parent, delete=False, newline="\n"
    ) as stream:
        stream.write(merged)
        temporary = Path(stream.name)
    os.replace(temporary, config_path)
    return True


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

    repo_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Установка проверенных правил Kimi-Port")
    parser.add_argument("--config", type=Path, default=Path.home() / ".kimi-code" / "config.toml")
    parser.add_argument(
        "--candidate", type=Path, default=repo_root / "kimi-port" / "generated" / "hooks.toml"
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=repo_root / "kimi-port" / "generated" / "hooks-smoke-report.json",
    )
    parser.add_argument("--allow-narrow", action="store_true")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        validate_candidate(args.candidate, args.report, args.allow_narrow)
        changed = install(args.config, args.candidate, args.apply)
    except (OSError, ValueError, tomllib.TOMLDecodeError, json.JSONDecodeError) as exc:
        print(f"Установка отклонена: {exc}", file=sys.stderr)
        return 2
    if not args.apply:
        print("Кандидат допущен к установке; текущая конфигурация отличается" if changed else "Управляемый блок уже актуален")
        return 1 if changed else 0
    print("Правила установлены; создана резервная копия" if changed else "Изменения не требуются")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
