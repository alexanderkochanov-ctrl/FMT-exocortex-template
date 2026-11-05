#!/usr/bin/env python3

import argparse
import hashlib
import json
import sys
from pathlib import Path


NORMALIZATION_ID = "WIN-PATH-001"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write_if_changed(path: Path, content: bytes) -> None:
    if path.exists() and path.read_bytes() == content:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def build_adapters(source_path: Path, output_dir: Path) -> dict:
    source_raw = source_path.read_bytes()
    source_text = source_raw.decode("utf-8")
    old = "normalized = os.path.normpath(value.lower())"
    new = 'normalized = os.path.normpath(value.lower()).replace("\\\\", "/")'
    if source_text.count(old) != 1:
        raise ValueError(f"{NORMALIZATION_ID}: ожидалась одна строка нормализации")

    analyzer = source_text.replace(old, new).encode("utf-8")
    shim = b'''#!/usr/bin/env bash
set -u
adapter_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ "$#" -ge 1 ] && [ "$(basename -- "$1")" = "secret-bypass-analyzer.py" ]; then
  exec python "$adapter_dir/secret-bypass-analyzer.py" "${@:2}"
fi
exec python "$@"
'''
    checkpoint = b'''#!/usr/bin/env bash
set -uo pipefail
bash "$CLAUDE_PROJECT_DIR/.claude/hooks/precompact-checkpoint.sh"
status=$?
[ "$status" -eq 0 ] || exit "$status"
checkpoint_dir="${CLAUDE_CONFIG_DIR:-}/iwe-checkpoints"
[ -n "${CLAUDE_CONFIG_DIR:-}" ] && [ -d "$checkpoint_dir" ] || exit 0
command -v icacls >/dev/null 2>&1 || {
  echo "Windows checkpoint protection requires icacls" >&2
  exit 2
}
account=$(whoami) || exit 2
icacls "$checkpoint_dir" /inheritance:r /grant:r "$account:(OI)(CI)F" >/dev/null || exit 2
icacls "$checkpoint_dir" /grant:r "$account:F" >/dev/null || exit 2
exit 0
'''

    outputs = {
        "secret-bypass-analyzer.py": analyzer,
        "bin/python3": shim,
        "precompact-checkpoint.sh": checkpoint,
    }
    for relative, content in outputs.items():
        _write_if_changed(output_dir / relative, content)

    report = {
        "schema_version": 1,
        "source_sha256": _sha256(source_raw),
        "transformations": [
            NORMALIZATION_ID,
            "WIN-SECRET-PYTHON-SHIM-001",
            "WIN-CHECKPOINT-ACL-001",
        ],
        "files": {
            relative: _sha256(content) for relative, content in sorted(outputs.items())
        },
    }
    report_raw = (json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    _write_if_changed(output_dir / "adapters-report.json", report_raw)
    return report


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

    repo_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Генерация Windows-адаптеров хуков Kimi")
    parser.add_argument(
        "--source",
        type=Path,
        default=repo_root / ".claude" / "hooks" / "secret-bypass-analyzer.py",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=repo_root / "kimi-port" / "generated" / "adapters"
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    try:
        if args.check:
            import tempfile

            with tempfile.TemporaryDirectory() as temp_dir:
                expected = build_adapters(args.source, Path(temp_dir))
                for relative in [*expected["files"], "adapters-report.json"]:
                    actual = args.output_dir / relative
                    candidate = Path(temp_dir) / relative
                    if not actual.exists() or actual.read_bytes() != candidate.read_bytes():
                        print(f"Адаптер устарел: {actual}", file=sys.stderr)
                        return 1
        else:
            build_adapters(args.source, args.output_dir)
        print("Windows-адаптеры готовы и проверены")
        return 0
    except (OSError, ValueError) as exc:
        print(f"Ошибка генерации адаптеров: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
