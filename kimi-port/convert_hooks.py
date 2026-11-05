#!/usr/bin/env python3

import argparse
import hashlib
import json
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


class ConversionError(ValueError):
    pass


@dataclass
class Conversion:
    rules: list[dict]
    source_group_count: int
    source_command_count: int
    ignored_sections: list[str]
    adaptations: list[dict]


def _read_json(path: Path) -> tuple[dict, bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except OSError as exc:
        raise ConversionError(f"Не удалось прочитать {path}: {exc}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConversionError(f"Некорректный JSON в {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ConversionError(f"Ожидался JSON-объект в {path}")
    return value, raw


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _ensure_keys(value: dict, allowed: set[str], path: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ConversionError(f"{path}: неподдерживаемые поля: {', '.join(unknown)}")


def _convert_command(command: object, source: dict, path: str) -> str:
    if not isinstance(command, str) or not command.strip():
        raise ConversionError(f"{path}: command должен быть непустой строкой")
    try:
        parts = shlex.split(command, posix=True)
    except ValueError as exc:
        raise ConversionError(f"{path}: не удалось разобрать command: {exc}") from exc
    if not parts:
        raise ConversionError(f"{path}: пустая command")

    project_variable = source["project_variable"]
    expected_prefix = f"{project_variable}/{source['hook_path_prefix']}"
    if not parts[0].startswith(expected_prefix) or not parts[0].endswith(".sh"):
        raise ConversionError(
            f"{path}: поддерживаются только команды {expected_prefix}<имя>.sh"
        )

    relative = parts[0][len(project_variable) + 1 :]
    posix_path = PurePosixPath(relative)
    if posix_path.is_absolute() or ".." in posix_path.parts:
        raise ConversionError(f"{path}: небезопасный путь {relative}")

    operators = {";", "&", "&&", "||", "|", ">", ">>", "<", "<<"}
    if any(part in operators or "$" in part or "`" in part for part in parts[1:]):
        raise ConversionError(f"{path}: подстановки и shell-операторы требуют отдельного правила")

    return shlex.join(["bash", f"./{relative}", *parts[1:]])


def _timeout(hook: dict, event_rule: dict, path: str) -> int:
    if "timeout" not in hook:
        return event_rule["target_default_timeout"]
    value = hook["timeout"]
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 600:
        raise ConversionError(f"{path}: timeout должен быть целым числом от 1 до 600")
    return value


def _targets(event_rule: dict, matcher: object, path: str) -> list[dict]:
    policy = event_rule["matcher_policy"]
    if matcher is not None and (not isinstance(matcher, str) or not matcher):
        raise ConversionError(f"{path}: matcher должен быть непустой строкой")

    if policy == "forbid":
        if matcher is not None:
            raise ConversionError(f"{path}: matcher для этого события не поддерживается")
        return [{"target_event": event_rule["target_event"]}]

    if policy == "preserve":
        target = {"target_event": event_rule["target_event"]}
        if matcher is not None:
            target["target_matcher"] = matcher
        return [target]

    if policy == "session_start":
        if matcher is None:
            return event_rule["unmatched_targets"]
        if matcher in event_rule["direct_matchers"]:
            return [
                {
                    "target_event": event_rule["target_event"],
                    "target_matcher": matcher,
                }
            ]
        if matcher in event_rule["matcher_map"]:
            return [event_rule["matcher_map"][matcher]]
        raise ConversionError(f"{path}: неизвестный SessionStart matcher {matcher!r}")

    raise ConversionError(f"{path}: неизвестная политика matcher {policy!r}")


def convert_settings(settings: dict, ruleset: dict) -> Conversion:
    _ensure_keys(ruleset, {"schema_version", "source", "target", "event_rules"}, "rules")
    if ruleset.get("schema_version") != 1:
        raise ConversionError("rules: поддерживается только schema_version = 1")

    source = ruleset["source"]
    target = ruleset["target"]
    event_rules = ruleset["event_rules"]
    ignored = source["ignored_sections"]
    _ensure_keys(settings, {"hooks", *ignored}, "settings")

    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        raise ConversionError("settings.hooks: ожидался объект")

    output_rules: list[dict] = []
    adaptations: list[dict] = []
    group_count = 0
    command_count = 0

    for source_event, groups in hooks.items():
        path = f"settings.hooks.{source_event}"
        if source_event not in event_rules:
            raise ConversionError(f"{path}: неизвестное событие")
        if not isinstance(groups, list):
            raise ConversionError(f"{path}: ожидался массив групп")
        event_rule = event_rules[source_event]

        for group_index, group in enumerate(groups):
            group_path = f"{path}[{group_index}]"
            if not isinstance(group, dict):
                raise ConversionError(f"{group_path}: ожидался объект группы")
            _ensure_keys(group, {"matcher", "hooks"}, group_path)
            group_hooks = group.get("hooks")
            if not isinstance(group_hooks, list) or not group_hooks:
                raise ConversionError(f"{group_path}.hooks: ожидался непустой массив")
            group_count += 1
            matcher = group.get("matcher")
            targets = _targets(event_rule, matcher, group_path)

            if source_event == "SessionStart" and matcher is None:
                adaptation = {
                    "kind": "session_start_fanout",
                    "source_event": source_event,
                    "source_matcher": None,
                    "target_events": [item["target_event"] for item in targets],
                }
                accepted_losses = event_rule.get("accepted_source_only_matchers", [])
                if accepted_losses:
                    adaptation["accepted_source_only_matchers"] = accepted_losses
                adaptations.append(adaptation)
            elif source_event == "SessionStart" and matcher in event_rule["matcher_map"]:
                adaptations.append(
                    {
                        "kind": "matcher_mapping",
                        "source_event": source_event,
                        "source_matcher": matcher,
                        "target_event": targets[0]["target_event"],
                        "target_matcher": targets[0].get("target_matcher"),
                    }
                )

            for hook_index, hook in enumerate(group_hooks):
                hook_path = f"{group_path}.hooks[{hook_index}]"
                if not isinstance(hook, dict):
                    raise ConversionError(f"{hook_path}: ожидался объект хука")
                _ensure_keys(hook, {"type", "command", "timeout"}, hook_path)
                if hook.get("type") != "command":
                    raise ConversionError(f"{hook_path}: поддерживается только type = command")
                command = _convert_command(hook.get("command"), source, hook_path)
                timeout = _timeout(hook, event_rule, hook_path)
                command_count += 1

                if "timeout" not in hook and (
                    event_rule["source_default_timeout"]
                    != event_rule["target_default_timeout"]
                ):
                    adaptations.append(
                        {
                            "kind": "default_timeout_rounding",
                            "source_event": source_event,
                            "source_timeout": event_rule["source_default_timeout"],
                            "target_timeout": timeout,
                        }
                    )

                for target_item in targets:
                    target_event = target_item["target_event"]
                    if target_event not in target["events"]:
                        raise ConversionError(
                            f"{hook_path}: целевое событие {target_event!r} отсутствует в контракте Kimi"
                        )
                    converted = {
                        "event": target_event,
                        "command": command,
                        "timeout": timeout,
                    }
                    if "target_matcher" in target_item:
                        converted["matcher"] = target_item["target_matcher"]
                    output_rules.append(converted)

    return Conversion(
        rules=output_rules,
        source_group_count=group_count,
        source_command_count=command_count,
        ignored_sections=sorted(section for section in ignored if section in settings),
        adaptations=adaptations,
    )


def render_toml(conversion: Conversion, source_sha256: str, rules_sha256: str) -> str:
    lines = [
        "# GENERATED by kimi-port/convert_hooks.py. DO NOT EDIT.",
        "# Source schema: claude-code-settings-hooks",
        f"# Source SHA-256: {source_sha256}",
        f"# Rules SHA-256: {rules_sha256}",
        "# Install by merging these rules into the user-level Kimi config.toml.",
        "",
    ]
    for rule in conversion.rules:
        lines.append("[[hooks]]")
        lines.append(f"event = {json.dumps(rule['event'], ensure_ascii=False)}")
        if "matcher" in rule:
            lines.append(f"matcher = {json.dumps(rule['matcher'], ensure_ascii=False)}")
        lines.append(f"command = {json.dumps(rule['command'], ensure_ascii=False)}")
        lines.append(f"timeout = {rule['timeout']}")
        lines.append("")
    return "\n".join(lines)


def build_report(
    conversion: Conversion,
    source_sha256: str,
    rules_sha256: str,
    output: str,
) -> dict:
    event_counts: dict[str, int] = {}
    for rule in conversion.rules:
        event = rule["event"]
        event_counts[event] = event_counts.get(event, 0) + 1
    return {
        "schema_version": 1,
        "source_schema": "claude-code-settings-hooks",
        "target_schema": "kimi-code-config-hooks",
        "source_sha256": source_sha256,
        "rules_sha256": rules_sha256,
        "output_sha256": _sha256(output.encode("utf-8")),
        "source_group_count": conversion.source_group_count,
        "source_command_count": conversion.source_command_count,
        "target_rule_count": len(conversion.rules),
        "target_event_counts": dict(sorted(event_counts.items())),
        "ignored_sections": conversion.ignored_sections,
        "adaptations": conversion.adaptations,
        "unverified": [
            "Execution of converted hook commands under Kimi Code on Windows",
            "Claude SessionStart source=clear has no direct Kimi event",
        ],
    }


def _write_if_changed(path: Path, content: str) -> None:
    encoded = content.encode("utf-8")
    if path.exists() and path.read_bytes() == encoded:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded)


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        description="Конвертер секции hooks Claude Code settings.json в [[hooks]] Kimi Code"
    )
    parser.add_argument("--source", type=Path, default=Path(".claude/settings.json"))
    parser.add_argument(
        "--rules", type=Path, default=Path(__file__).with_name("hook-rules.json")
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    try:
        settings, source_raw = _read_json(args.source)
        ruleset, rules_raw = _read_json(args.rules)
        conversion = convert_settings(settings, ruleset)
        source_hash = _sha256(source_raw)
        rules_hash = _sha256(rules_raw)
        output = render_toml(conversion, source_hash, rules_hash)
        report = build_report(conversion, source_hash, rules_hash, output)
        report_text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"

        if args.check:
            mismatches = []
            if not args.output.exists() or args.output.read_bytes() != output.encode("utf-8"):
                mismatches.append(str(args.output))
            if args.report and (
                not args.report.exists()
                or args.report.read_bytes() != report_text.encode("utf-8")
            ):
                mismatches.append(str(args.report))
            if mismatches:
                print("Результат генерации устарел: " + ", ".join(mismatches), file=sys.stderr)
                return 1
        else:
            _write_if_changed(args.output, output)
            if args.report:
                _write_if_changed(args.report, report_text)

        print(
            f"Готово: {conversion.source_command_count} команд, "
            f"{len(conversion.rules)} правил Kimi, {len(conversion.adaptations)} адаптаций"
        )
        return 0
    except ConversionError as exc:
        print(f"Ошибка конвертации: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"Ошибка файла: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
