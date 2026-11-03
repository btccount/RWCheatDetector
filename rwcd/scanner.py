"""Сканирование папки игры и запущенных процессов.

Модуль намеренно не запускает найденные файлы и не распаковывает их на диск:
JAR читается как ZIP-архив, проверяются только имена записей и хэш.
"""

from __future__ import annotations

import csv
import fnmatch
import hashlib
import io
import os
import subprocess
import sys
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence

from .rules import Rule, SEVERITY_RANK

CHUNK_SIZE = 1 << 20

# Каталоги, которые не имеют отношения к модам и только замедляют обход.
SKIP_DIRS = {"libraries", "assets", "natives", ".git", "logs", "screenshots"}


@dataclass
class Finding:
    """Одно совпадение с правилом."""

    rule_id: str
    name: str
    severity: str
    kind: str
    target: str
    evidence: str
    description: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self.severity]


def sha256_file(path: Path) -> str:
    """Считает SHA-256 файла потоково, не загружая его целиком в память."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iter_jars(root: Path, max_depth: int = 6) -> list[Path]:
    """Возвращает JAR-файлы под указанным путём.

    Если передан один файл, возвращается он сам (при расширении .jar).
    Глубина ограничена, чтобы случайный запуск от корня диска не длился вечно.
    """
    if root.is_file():
        return [root] if root.suffix.lower() == ".jar" else []

    jars: list[Path] = []
    base_parts = len(root.parts)

    for dirpath, dirnames, filenames in os.walk(root):
        depth = len(Path(dirpath).parts) - base_parts
        if depth >= max_depth:
            dirnames[:] = []
        else:
            dirnames[:] = [name for name in dirnames if name.lower() not in SKIP_DIRS]

        for filename in filenames:
            if filename.lower().endswith(".jar"):
                jars.append(Path(dirpath) / filename)

    return sorted(jars)


def _matches_any(value: str, patterns: Sequence[str]) -> bool:
    lowered = value.lower()
    return any(fnmatch.fnmatch(lowered, pattern.lower()) for pattern in patterns)


def _jar_entries(path: Path) -> list[str]:
    """Список имён записей внутри JAR. Битые архивы считаются пустыми."""
    try:
        with zipfile.ZipFile(path) as archive:
            return archive.namelist()
    except (zipfile.BadZipFile, OSError):
        return []


def scan_jar(path: Path, rules: Sequence[Rule], digest: str | None = None) -> list[Finding]:
    """Проверяет один JAR по всем правилам.

    Совпадение по содержимому приоритетнее совпадения по имени файла:
    имя легко подделать, структуру классов — сложнее.
    """
    findings: dict[tuple[str, str], Finding] = {}
    entries: list[str] | None = None

    for rule in rules:
        by_content = None
        if rule.jar_prefixes:
            if entries is None:
                entries = _jar_entries(path)
            for entry in entries:
                if any(entry.startswith(prefix) for prefix in rule.jar_prefixes):
                    by_content = entry
                    break
        if by_content is not None:
            findings[(rule.id, "content")] = Finding(
                rule_id=rule.id,
                name=rule.name,
                severity=rule.severity,
                kind="content",
                target=str(path),
                evidence=by_content,
                description=rule.description,
            )
            continue

        if rule.sha256:
            if digest is None:
                digest = sha256_file(path)
            if digest in rule.sha256:
                findings[(rule.id, "hash")] = Finding(
                    rule_id=rule.id,
                    name=rule.name,
                    severity=rule.severity,
                    kind="hash",
                    target=str(path),
                    evidence=digest,
                    description=rule.description,
                )
                continue

        if rule.filenames and _matches_any(path.name, rule.filenames):
            findings[(rule.id, "file")] = Finding(
                rule_id=rule.id,
                name=rule.name,
                severity=rule.severity,
                kind="file",
                target=str(path),
                evidence=path.name,
                description=rule.description,
            )

    return list(findings.values())


def scan_directory(
    root: Path,
    rules: Sequence[Rule],
    max_depth: int = 6,
) -> tuple[list[Finding], int]:
    """Сканирует каталог и возвращает находки и число проверенных JAR."""
    jars = iter_jars(root, max_depth=max_depth)
    findings: list[Finding] = []
    for jar in jars:
        findings.extend(scan_jar(jar, rules))
    return findings, len(jars)


def list_processes() -> list[tuple[int, str]]:
    """Возвращает пары (PID, имя процесса) для текущей ОС."""
    if sys.platform == "win32":
        return _list_processes_windows()
    return _list_processes_posix()


def _list_processes_posix() -> list[tuple[int, str]]:
    try:
        output = subprocess.check_output(
            ["ps", "-axo", "pid=,comm="],
            text=True,
            errors="replace",
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return []

    processes: list[tuple[int, str]] = []
    for line in output.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2:
            continue
        pid_text, command = parts
        try:
            pid = int(pid_text)
        except ValueError:
            continue
        processes.append((pid, Path(command).name))
    return processes


def _list_processes_windows() -> list[tuple[int, str]]:
    try:
        output = subprocess.check_output(
            ["tasklist", "/fo", "csv", "/nh"],
            text=True,
            errors="replace",
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return []

    processes: list[tuple[int, str]] = []
    for row in csv.reader(io.StringIO(output)):
        if len(row) < 2:
            continue
        name, pid_text = row[0], row[1]
        try:
            pid = int(pid_text)
        except ValueError:
            continue
        processes.append((pid, name))
    return processes


def _normalize_process(name: str) -> str:
    lowered = name.lower()
    for suffix in (".exe", ".jar"):
        if lowered.endswith(suffix):
            lowered = lowered[: -len(suffix)]
    return lowered


def scan_processes(
    rules: Sequence[Rule],
    processes: Iterable[tuple[int, str]] | None = None,
) -> list[Finding]:
    """Сопоставляет имена процессов с правилами."""
    if processes is None:
        processes = list_processes()

    findings: list[Finding] = []
    for pid, name in processes:
        normalized = _normalize_process(name)
        for rule in rules:
            if rule.processes and _matches_any(normalized, rule.processes):
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        name=rule.name,
                        severity=rule.severity,
                        kind="process",
                        target=f"{name} (PID {pid})",
                        evidence=name,
                        description=rule.description,
                    )
                )
    return findings


def scan(
    root: Path,
    rules: Sequence[Rule],
    include_processes: bool = True,
    max_depth: int = 6,
    processes: Iterable[tuple[int, str]] | None = None,
) -> tuple[list[Finding], dict[str, int]]:
    """Полное сканирование: файлы + процессы.

    Возвращает находки и краткую статистику для отчёта.
    """
    findings, jar_count = scan_directory(root, rules, max_depth=max_depth)
    stats = {"jars": jar_count, "processes": 0}

    if include_processes:
        process_list = list(processes) if processes is not None else list_processes()
        stats["processes"] = len(process_list)
        findings.extend(scan_processes(rules, process_list))

    findings.sort(key=lambda item: (-item.rank, item.rule_id, item.target))
    return findings, stats