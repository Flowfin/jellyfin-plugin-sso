#!/usr/bin/env python3
"""Proof that the wiki lint's dead-source-link check bites for the reason it names (#1780).

The fixture is a bare repository standing in for GitHub with two branches, `trunk` and
`other`, and a clone of `trunk` standing in for the CI checkout. Every case is a one-page
wiki with one blob link, so a red case names the link that produced it. The git
configuration is isolated to the fixture, so the developer's signing and identity settings
never reach it and it never touches theirs.

Usage: wiki-lint-test.py
Exit code 0 when every case holds; unittest's report otherwise.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def _load_lint():
    spec = importlib.util.spec_from_file_location("wiki_lint", _HERE / "wiki-lint.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DeadSourceLinksHonourTheRef(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lint = _load_lint()
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.env = {
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": str(root / "no-global-gitconfig"),
            "GIT_AUTHOR_NAME": "fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        }
        (root / "no-global-gitconfig").write_text("", encoding="utf-8")
        cls.origin = root / "origin.git"
        cls.code = root / "checkout"
        cls.wiki = root / "wiki"
        cls.wiki.mkdir()

        work = root / "seed"
        cls._git("init", "-q", "-b", "trunk", str(work))
        (work / "docs").mkdir()
        (work / "docs" / "on-both.md").write_text("both\n", encoding="utf-8")
        (work / "only-on-trunk.txt").write_text("trunk\n", encoding="utf-8")
        cls._git("-C", str(work), "add", "-A")
        cls._git("-C", str(work), "commit", "-q", "-m", "trunk")
        cls._git("-C", str(work), "checkout", "-q", "-b", "other")
        (work / "only-on-trunk.txt").unlink()
        (work / "only-on-other.txt").write_text("other\n", encoding="utf-8")
        cls._git("-C", str(work), "add", "-A")
        cls._git("-C", str(work), "commit", "-q", "-m", "other")
        cls._git("init", "-q", "--bare", str(cls.origin))
        cls._git("-C", str(work), "push", "-q", str(cls.origin), "trunk", "other")
        cls._git("clone", "-q", "--branch", "trunk", str(cls.origin), str(cls.code))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    @classmethod
    def _git(cls, *args: str) -> None:
        subprocess.run(["git", *args], check=True, env=cls.env, capture_output=True)

    def _findings(self, link: str) -> list[str]:
        for stale in self.wiki.glob("*.md"):
            stale.unlink()
        (self.wiki / "Page.md").write_text(
            f"See [it](https://github.com/example/repo/blob/{link}).\n", encoding="utf-8"
        )
        return self.lint.check_dead_source_links(self.wiki, self.code)

    def test_a_path_on_the_checked_out_branch_is_live(self) -> None:
        self.assertEqual([], self._findings("trunk/only-on-trunk.txt"))

    def test_head_names_the_checkout(self) -> None:
        self.assertEqual([], self._findings("HEAD/docs/on-both.md"))

    def test_a_path_only_on_the_other_branch_is_live_at_that_ref(self) -> None:
        # The #1780 case: the checkout is trunk, the file is on other, and the link says so.
        self.assertEqual([], self._findings("other/only-on-other.txt"))

    def test_a_path_absent_at_its_named_ref_is_dead_even_when_the_checkout_has_it(self) -> None:
        findings = self._findings("other/only-on-trunk.txt")
        self.assertEqual(1, len(findings), findings)
        self.assertIn("dead source link 'only-on-trunk.txt' (not at 'other')", findings[0])

    def test_a_path_absent_on_the_checked_out_branch_is_dead(self) -> None:
        findings = self._findings("trunk/only-on-other.txt")
        self.assertEqual(1, len(findings), findings)
        self.assertIn("dead source link 'only-on-other.txt' (not in the code tree)", findings[0])

    def test_a_ref_origin_does_not_serve_is_a_finding_that_names_it(self) -> None:
        findings = self._findings("nowhere/docs/on-both.md")
        self.assertEqual(1, len(findings), findings)
        self.assertIn("ref 'nowhere' could not be fetched from origin", findings[0])

    def test_a_directory_at_the_other_ref_is_live(self) -> None:
        self.assertEqual([], self._findings("other/docs/"))

    def test_the_fetch_leaves_a_full_clone_full(self) -> None:
        self._findings("other/only-on-other.txt")
        out = subprocess.run(
            ["git", "-C", str(self.code), "rev-parse", "--is-shallow-repository"],
            check=True, env=self.env, capture_output=True,
        ).stdout.strip()
        self.assertEqual(b"false", out)


if __name__ == "__main__":
    sys.exit(unittest.main(verbosity=2))
