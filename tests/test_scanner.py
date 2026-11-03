"""Тесты движка сканирования."""

from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from rwcd.rules import Rule
from rwcd.scanner import (
    iter_jars,
    scan,
    scan_directory,
    scan_jar,
    scan_processes,
    sha256_file,
)


def make_jar(path: Path, entries: list[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        for entry in entries:
            archive.writestr(entry, b"")
    return path


NURSULTAN = Rule(
    id="nursultan",
    name="Nursultan",
    severity="high",
    description="тестовое правило",
    filenames=("nursultan*.jar",),
    jar_prefixes=("nursultan/",),
    processes=("nursultan*",),
)

METEOR = Rule(
    id="meteor",
    name="Meteor Client",
    severity="high",
    jar_prefixes=("meteordevelopment/meteorclient/",),
)

XRAY = Rule(
    id="xray",
    name="X-Ray",
    severity="medium",
    filenames=("*xray*.jar",),
)

LOW = Rule(
    id="generic",
    name="Generic",
    severity="low",
    filenames=("*cheat*.jar",),
)


class JarScanTest(unittest.TestCase):
    def test_detects_by_filename(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jar = make_jar(Path(tmp) / "nursultan-1.16.5.jar", ["a/b.class"])
            findings = scan_jar(jar, [NURSULTAN])
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].kind, "file")
            self.assertEqual(findings[0].severity, "high")

    def test_detects_by_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jar = make_jar(
                Path(tmp) / "mod.jar",
                ["meteordevelopment/meteorclient/MeteorClient.class"],
            )
            findings = scan_jar(jar, [METEOR])
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].kind, "content")
            self.assertEqual(findings[0].evidence, "meteordevelopment/meteorclient/MeteorClient.class")

    def test_detects_by_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jar = make_jar(Path(tmp) / "anything.jar", ["x.class"])
            rule = Rule(
                id="by-hash",
                name="By hash",
                severity="high",
                sha256=(sha256_file(jar),),
            )
            findings = scan_jar(jar, [rule])
            self.assertEqual([item.kind for item in findings], ["hash"])

    def test_clean_jar_has_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jar = make_jar(Path(tmp) / "sodium.jar", ["net/caffeinemc/sodium/Sodium.class"])
            findings = scan_jar(jar, [NURSULTAN, METEOR, XRAY, LOW])
            self.assertEqual(findings, [])

    def test_broken_archive_does_not_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp) / "broken.jar"
            jar.write_bytes(b"not a zip at all")
            findings = scan_jar(jar, [METEOR])
            self.assertEqual(findings, [])

    def test_medium_rule_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jar = make_jar(Path(tmp) / "my-xray-pack.jar", ["a.class"])
            findings = scan_jar(jar, [XRAY])
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "medium")


class DirectoryScanTest(unittest.TestCase):
    def test_skips_libraries_and_assets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_jar(root / "mods" / "nursultan.jar", ["a.class"])
            make_jar(root / "libraries" / "lib.jar", ["a.class"])
            make_jar(root / "assets" / "asset.jar", ["a.class"])

            jars = iter_jars(root)
            self.assertEqual([path.name for path in jars], ["nursultan.jar"])

    def test_max_depth_limits_walk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_jar(root / "a.jar", ["a.class"])
            make_jar(root / "one" / "two" / "three" / "deep.jar", ["a.class"])

            shallow = iter_jars(root, max_depth=1)
            self.assertEqual([path.name for path in shallow], ["a.jar"])

    def test_scan_directory_counts_and_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_jar(root / "mods" / "nursultan.jar", ["a.class"])
            make_jar(root / "mods" / "ok.jar", ["b.class"])

            findings, count = scan_directory(root, [NURSULTAN])
            self.assertEqual(count, 2)
            self.assertEqual(len(findings), 1)


class ProcessScanTest(unittest.TestCase):
    def test_matches_process_name(self) -> None:
        rule = Rule(
            id="nursultan",
            name="Nursultan",
            severity="high",
            processes=("nursultan*",),
        )
        findings = scan_processes([rule], [(101, "Nursultan.exe"), (102, "java")])
        self.assertEqual(len(findings), 1)
        self.assertIn("PID 101", findings[0].target)

    def test_no_matches(self) -> None:
        rule = Rule(id="x", name="X", severity="low", processes=("cheat*",))
        self.assertEqual(scan_processes([rule], [(1, "java"), (2, "bash")]), [])


class ScanAggregateTest(unittest.TestCase):
    def test_scan_combines_and_sorts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_jar(root / "mods" / "nursultan.jar", ["a.class"])
            make_jar(root / "mods" / "my-cheat.jar", ["b.class"])

            findings, stats = scan(
                root,
                [NURSULTAN, LOW],
                include_processes=True,
                processes=[(5, "Nursultan.exe")],
            )
            self.assertEqual(stats["jars"], 2)
            self.assertEqual(stats["processes"], 1)
            self.assertEqual(findings[0].severity, "high")
            self.assertEqual(findings[-1].severity, "low")
            self.assertEqual(len(findings), 3)


if __name__ == "__main__":
    unittest.main()