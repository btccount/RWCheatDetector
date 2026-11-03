"""Загрузка и проверка базы сигнатур.

База — обычный JSON-файл со списком правил. Правило описывает, как искать
один чит-клиент или класс модов: по имени JAR-файла, по SHA-256, по путям
внутри архива и по имени процесса.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

# Уровни важности. Порядок используется для сортировки и порога --fail-on.
SEVERITIES = ("low", "medium", "high")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}

# Путь по умолчанию: <корень репозитория>/signatures/cheats.json
DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "signatures" / "cheats.json"


class RulesError(ValueError):
    """База сигнатур повреждена или содержит недопустимые значения."""


@dataclass(frozen=True)
class Rule:
    """Одно правило обнаружения."""

    id: str
    name: str
    severity: str
    description: str = ""
    filenames: tuple[str, ...] = ()
    sha256: tuple[str, ...] = ()
    jar_prefixes: tuple[str, ...] = ()
    processes: tuple[str, ...] = ()

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self.severity]


def _as_tuple(value: Any, field: str, rule_id: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RulesError(f"Правило {rule_id!r}: поле {field!r} должно быть списком строк")
    return tuple(value)


def parse_rule(raw: Any) -> Rule:
    """Превращает словарь из JSON в правило и проверяет обязательные поля."""
    if not isinstance(raw, dict):
        raise RulesError("Каждое правило должно быть объектом JSON")

    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise RulesError("У правила отсутствует непустое поле 'id'")

    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        raise RulesError(f"Правило {rule_id!r}: отсутствует непустое поле 'name'")

    severity = raw.get("severity")
    if severity not in SEVERITIES:
        raise RulesError(
            f"Правило {rule_id!r}: 'severity' должно быть одним из {', '.join(SEVERITIES)}"
        )

    description = raw.get("description", "")
    if not isinstance(description, str):
        raise RulesError(f"Правило {rule_id!r}: 'description' должно быть строкой")

    hashes = _as_tuple(raw.get("sha256"), "sha256", rule_id)
    for digest in hashes:
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest.lower()):
            raise RulesError(f"Правило {rule_id!r}: некорректный SHA-256 {digest!r}")

    return Rule(
        id=rule_id,
        name=name,
        severity=severity,
        description=description,
        filenames=_as_tuple(raw.get("filenames"), "filenames", rule_id),
        sha256=hashes,
        jar_prefixes=_as_tuple(raw.get("jar_prefixes"), "jar_prefixes", rule_id),
        processes=_as_tuple(raw.get("processes"), "processes", rule_id),
    )


def load_rules(path: str | Path | None = None) -> list[Rule]:
    """Читает базу сигнатур и возвращает список правил."""
    rules_path = Path(path) if path is not None else DEFAULT_RULES_PATH
    try:
        payload = json.loads(rules_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RulesError(f"Файл сигнатур не найден: {rules_path}") from exc
    except json.JSONDecodeError as exc:
        raise RulesError(f"Некорректный JSON в {rules_path}: {exc}") from exc

    if not isinstance(payload, dict) or "rules" not in payload:
        raise RulesError("В базе сигнатур отсутствует ключ 'rules'")

    rules = [parse_rule(item) for item in payload["rules"]]
    seen: set[str] = set()
    for rule in rules:
        if rule.id in seen:
            raise RulesError(f"Повторяющийся идентификатор правила: {rule.id!r}")
        seen.add(rule.id)
    return rules


def rules_to_dict(rules: Iterable[Rule]) -> list[dict[str, Any]]:
    """Обратное преобразование — удобно для тестов и экспорта."""
    return [
        {
            "id": rule.id,
            "name": rule.name,
            "severity": rule.severity,
            "description": rule.description,
            "filenames": list(rule.filenames),
            "sha256": list(rule.sha256),
            "jar_prefixes": list(rule.jar_prefixes),
            "processes": list(rule.processes),
        }
        for rule in rules
    ]