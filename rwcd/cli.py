"""Командная строка RWCheatDetector."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .report import render_json, render_text
from .rules import SEVERITIES, SEVERITY_RANK, RulesError, load_rules
from .scanner import scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rwcd",
        description="Открытый детектор чит-клиентов Minecraft.",
        epilog=(
            "Пример: rwcd scan ~/.minecraft --json > report.json. "
            "Совпадение с правилом не доказывает читерство."
        ),
    )
    parser.add_argument("--version", action="version", version=f"RWCheatDetector {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="проверить папку игры и процессы")
    scan_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="папка .minecraft или отдельный JAR (по умолчанию текущая папка)",
    )
    scan_parser.add_argument(
        "--rules",
        metavar="ФАЙЛ",
        help="своя база сигнатур вместо signatures/cheats.json",
    )
    scan_parser.add_argument(
        "--no-processes",
        action="store_true",
        help="не проверять запущенные процессы",
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="вывести отчёт в JSON",
    )
    scan_parser.add_argument(
        "--max-depth",
        type=int,
        default=6,
        metavar="N",
        help="максимальная глубина обхода каталогов (по умолчанию 6)",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=("none",) + SEVERITIES,
        default="high",
        help="код возврата 1 при находке указанного уровня и выше (по умолчанию high)",
    )

    subparsers.add_parser("rules", help="показать загруженную базу сигнатур")

    return parser


def _print_rules(rules) -> None:
    print(f"Правил в базе: {len(rules)}")
    print()
    for rule in rules:
        print(f"{rule.severity.upper():7} {rule.id:22} {rule.name}")
        if rule.description:
            print(f"        {rule.description}")


def _cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path).expanduser()
    if not root.exists():
        print(f"Ошибка: путь не существует: {root}", file=sys.stderr)
        return 2

    try:
        rules = load_rules(args.rules)
    except RulesError as exc:
        print(f"Ошибка базы сигнатур: {exc}", file=sys.stderr)
        return 2

    findings, stats = scan(
        root,
        rules,
        include_processes=not args.no_processes,
        max_depth=max(1, args.max_depth),
    )

    output = render_json(findings, stats) if args.json else render_text(findings, stats)
    print(output)

    if args.fail_on == "none":
        return 0

    threshold = SEVERITY_RANK[args.fail_on]
    if any(finding.rank >= threshold for finding in findings):
        return 1
    return 0


def _cmd_rules(args: argparse.Namespace) -> int:
    try:
        rules = load_rules(getattr(args, "rules", None))
    except RulesError as exc:
        print(f"Ошибка базы сигнатур: {exc}", file=sys.stderr)
        return 2
    _print_rules(rules)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "rules":
        return _cmd_rules(args)

    parser.print_help()
    return 2