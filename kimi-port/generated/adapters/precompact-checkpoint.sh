#!/usr/bin/env bash
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
