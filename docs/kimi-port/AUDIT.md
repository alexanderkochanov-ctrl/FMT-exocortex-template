# Аудит переносимости FMT-exocortex-template на Kimi Code как основной движок

> Дата: 2026-11-03. Исполнитель: Kimi Code (Desktop, Windows). Пилот: alexanderkochanov-ctrl.
> Цель: карта «переносится / адаптируется / переписывается» для запуска IWE с Kimi как главным агентом и вторым агентом, доступным в РФ (вместо Claude).

## Итог одним абзацем

Перенос возможен без «реверсинжиниринга»: вся логика шаблона — открытые Markdown-инструкции, shell-скрипты и YAML. Слои L2 (знания) и L3 (личное) переносятся без изменений. Работа сосредоточена в слое L1: хуки (32 команды в 30 группах), скиллы (52 шт.) и peer-адаптеры второго агента. Критических несовместимостей на уровне контракта событий не обнаружено; Windows-адаптеры описаны в `ARCHITECTURE.md`.

## Хуки: 32 команды, 7 исходных событий — у всех есть аналог в Kimi Code

| Событие Claude (settings.json) | Команд | Аналог в Kimi Code (`[[hooks]]` в config.toml) | Статус |
|---|---|---|---|
| UserPromptSubmit | 6 | `UserPromptSubmit` (блокирующее) | прямой перенос |
| PreToolUse | 14 | `PreToolUse` (блокирующее, matcher по имени инструмента) | прямой перенос |
| PostToolUse | 4 | `PostToolUse` | прямой перенос |
| Stop | 3 | `Stop` (блокирующее) | прямой перенос |
| PreCompact | 1 | `PreCompact` | прямой перенос |
| SessionStart (matcher compact) | 3 | `SessionStart` + `PostCompact` (матчера `compact` нет, восстановление после сжатия переносится на PostCompact) | адаптация матчера |
| SessionEnd | 1 | `SessionEnd` | прямой перенос |

Формат данных совместим по сути: JSON на stdin, коды возврата 0/2, fail-open. Работа: конвертер settings.json → TOML + замена `$CLAUDE_PROJECT_DIR` на cwd + прогон каждого скрипта под Git Bash на Windows.

Бонус: у Kimi есть `SessionHeartbeat` (каждые 60 с) — нативно закрывает то, что шаблон эмулирует скриптом `kimi-auto-heartbeat.sh`.

## Скиллы: 52 штуки — три категории

По числу упоминаний Claude-специфики в SKILL.md:

- **Переносятся как есть (15 шт., 0 упоминаний):** think, decompose, fpf, vdv, consent, artifactor, agent-fault, bottleneck-pick, discovery-session, integration-gate, iwe-bug-report, local-llm, platform-bottleneck, w-reflection, week-close-pilot.
- **Лёгкая адаптация (33 шт., 1–17 упоминаний):** типовые замены:
  - `TodoWrite` → `TodoList` (у Kimi свой аналог);
  - `$CLAUDE_CODE_SESSION_ID` → `session_id` из payload хука;
  - чтение `CLAUDE.md` → чтение `AGENTS.md` (файл остаётся в репо, Kimi читает его как источник правил);
  - рекомендации модели «Opus/Sonnet» → K3.1 Pro / K3;
  - env `CLAUDE_CODE_ENABLE_TODO_TOOLS` → не нужна, у Kimi TodoList встроен.
- **Тяжёлая адаптация (2 шт.):** `kimi-peer-writer` (41), `peer-conversation` (29) — механика peer-сессий. Ключевая находка: `peer-conversation` **уже мультивендорный** (kimi/codex/hermes/claude-headless), добавление нового напарника = одна строка в таблице вендоров + файл `<vendor>-peer-adapter.sh` по задокументированному контракту (§0в.1). Это штатная точка расширения, а не хак.

## Второй агент вместо Claude (условия РФ)

Требования к напарнику (из контракта §0в.1): headless CLI-режим, приём промпта через `-p`/stdin, text-only достаточно. Кандидаты, доступные в РФ без обходов:

- **Qwen Code** (Alibaba) — CLI-агент, open-source;
- **DeepSeek** — API + CLI-обёртки;
- **Hermes** — уже зарегистрирован в шаблоне как вендор (но позиционирован как оркестратор, не кодер);
- **GigaChat / YandexGPT** — через API, потребуется адаптер.

Выбор за пилотом — отдельным решением после поднятия основы на Kimi.

## План работ (порядок)

1. ✅ Форк, клон, аудит (этот файл).
2. Конвертер `.claude/settings.json` → `[[hooks]]` TOML + прогон хуков под Git Bash.
3. Пакетная адаптация 33 скиллов (типовые замены выше).
4. Smoke-тест цикла Day Open → работа → Day Close на Kimi standalone.
5. Peer-адаптер второго агента (после выбора вендора).
