"""Формирование текстового и JSON-отчёта."""

from __future__ import annotations

import json
from typing import Sequence

from . import __version__
from .scanner import Finding


SEVERITY_LABELS = {
    "low": "НИЗКИЙ",
    "medium": "СРЕДНИЙ",
    "high": "ВЫСОКИЙ",
}

KIND_LABELS = {
    "file": "имя файла",
    "content": "содержимое JAR",
    "hash": "SHA-256",
    "process": "процесс",
}


def build_payload(findings: Sequence[Finding], stats: dict[str, int]) -> dict:
    """Данные для --json и для интеграций."""
    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        counts[finding.severity] += 1

    return {
        "tool": "RWCheatDetector",
        "version": __version__,
        "stats": stats,
        "counts": counts,
        "findings": [finding.to_dict() for finding in findings],
    }


def render_json(findings: Sequence[Finding], stats: dict[str, int]) -> str:
    return json.dumps(build_payload(findings, stats), ensure_ascii=False, indent=2)


def render_text(findings: Sequence[Finding], stats: dict[str, int]) -> str:
    """Человекочитаемый отчёт на русском."""
    lines: list[str] = []
    lines.append(f"RWCheatDetector {__version__}")
    lines.append(
        "Проверено: JAR-файлов — {jars}, процессов — {processes}".format(**stats)
    )

    if not findings:
        lines.append("")
        lines.append("Совпадений не найдено.")
        lines.append(
            "Это не гарантия чистоты: база не знает все клиенты, а приватные сборки "
            "могут не совпадать ни с одним правилом."
        )
        return "\n".join(lines)

    lines.append(f"Найдено совпадений: {len(findings)}")
    for finding in findings:
        lines.append("")
        lines.append(f"[{SEVERITY_LABELS.get(finding.severity, finding.severity)}] {finding.name}")
        lines.append(f"  правило:   {finding.rule_id}")
        lines.append(f"  тип:       {KIND_LABELS.get(finding.kind, finding.kind)}")
        lines.append(f"  объект:    {finding.target}")
        lines.append(f"  признак:   {finding.evidence}")
        if finding.description:
            lines.append(f"  описание:  {finding.description}")

    lines.append("")
    lines.append(
        "Совпадение — повод для ручной проверки, а не доказательство читерства: "
        "имя файла легко подделать, а база может ошибаться."
    )
    return "\n".join(lines)